"""Minimal offline evaluator for Sigma rules, used to unit-test detections.

pySigma parses each rule into a condition tree; this module walks that tree
against a single event (a flat dict of field -> value). It supports the
features our rules use: wildcards (contains/startswith/endswith), |re, |cidr,
numbers, and value_count/event_count correlations. It is a test aid, not a
SIEM: anything it does not understand raises NotImplementedError so a test
can never pass by accident.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from datetime import datetime
from functools import lru_cache

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)
from sigma.correlations import (
    SigmaCorrelationConditionOperator,
    SigmaCorrelationRule,
    SigmaCorrelationType,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaCIDRExpression,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
)


@lru_cache(maxsize=None)
def _compile(pattern: str, flags: int) -> re.Pattern:
    return re.compile(pattern, flags)


def _match_value(value, actual) -> bool:
    if isinstance(value, SigmaNull):
        return actual is None
    if actual is None:
        return False
    if isinstance(value, SigmaNumber):
        try:
            return int(actual) == int(value.number)
        except (TypeError, ValueError):
            return False
    if isinstance(value, SigmaString):
        # Sigma string matching is case-insensitive; wildcards become regex.
        pattern = str(value.to_regex().regexp)
        return _compile(pattern, re.IGNORECASE | re.DOTALL).fullmatch(str(actual)) is not None
    if isinstance(value, SigmaRegularExpression):
        # |re is case-sensitive unless the pattern says otherwise, and unanchored.
        return _compile(str(value.regexp), 0).search(str(actual)) is not None
    if isinstance(value, SigmaCIDRExpression):
        try:
            return ipaddress.ip_address(str(actual)) in value.network
        except ValueError:
            return False
    raise NotImplementedError(f"Unsupported Sigma value type: {type(value).__name__}")


def _eval(node, event: dict) -> bool:
    if isinstance(node, ConditionAND):
        return all(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _match_value(node.value, event.get(node.field))
    raise NotImplementedError(f"Unsupported condition node: {type(node).__name__}")


def rule_matches(rule: SigmaRule, event: dict) -> bool:
    """True if the event satisfies any of the rule's conditions."""
    return any(_eval(c.parse(), event) for c in rule.detection.parsed_condition)


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def correlation_hits(corr: SigmaCorrelationRule, events: list[dict]) -> list[tuple[tuple, list[dict]]]:
    """Groups that satisfy the correlation, with the events in the first matching window.

    Events need a `_time` ISO-8601 timestamp. Windows slide per event, so a burst
    split across a fixed bucket boundary still counts. Each group key is the tuple
    of the correlation's `group-by` values.
    """
    base_rules = [ref.rule for ref in corr.rules]
    matched = [e for e in events if any(rule_matches(r, e) for r in base_rules)]

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for e in matched:
        groups[tuple(e.get(f) for f in corr.group_by or [])].append(e)

    cond = corr.condition
    ops = {
        SigmaCorrelationConditionOperator.GTE: lambda n: n >= cond.count,
        SigmaCorrelationConditionOperator.GT: lambda n: n > cond.count,
        SigmaCorrelationConditionOperator.LTE: lambda n: n <= cond.count,
        SigmaCorrelationConditionOperator.LT: lambda n: n < cond.count,
        SigmaCorrelationConditionOperator.EQ: lambda n: n == cond.count,
    }
    passes = ops[cond.op]

    hits = []
    for key, group in groups.items():
        group.sort(key=lambda e: _parse_time(e["_time"]))
        for i, start in enumerate(group):
            t0 = _parse_time(start["_time"])
            window = [
                e for e in group[i:]
                if (_parse_time(e["_time"]) - t0).total_seconds() <= corr.timespan.seconds
            ]
            if corr.type == SigmaCorrelationType.VALUE_COUNT:
                n = len({e.get(cond.fieldref) for e in window if e.get(cond.fieldref) is not None})
            elif corr.type == SigmaCorrelationType.EVENT_COUNT:
                n = len(window)
            else:
                raise NotImplementedError(f"Unsupported correlation type: {corr.type}")
            if passes(n):
                hits.append((key, window))
                break
    return hits


def correlation_matches(corr: SigmaCorrelationRule, events: list[dict]) -> bool:
    """True if any group of events satisfies the correlation inside one timespan."""
    return bool(correlation_hits(corr, events))
