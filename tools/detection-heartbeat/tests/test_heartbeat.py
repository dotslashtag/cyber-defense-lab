"""Static checks for the Detection Heartbeat probe, manifest and verifier searches."""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PROBE = (ROOT / "hb-probe.ps1").read_text(encoding="utf-8")
MANIFEST = yaml.safe_load((ROOT / "manifest.yml").read_text(encoding="utf-8"))
SPL_FILES = sorted((ROOT / "verifier").glob("*.spl"))

# Same pattern as Wazuh rule 510140 (detections/wazuh/local_rules.xml).
RULE_510140 = re.compile(r"(?i)\s[-/](ep|ex[a-z]*)\s+bypass")


def _entries():
    return MANIFEST["detections"] + MANIFEST["canaries"]


def test_probe_never_uses_execution_policy_bypass():
    code = PROBE.split("#>", 1)[1]
    assert not RULE_510140.search(code)
    assert "bypass" not in code.lower()


def test_probe_marker_format():
    assert "'HB-{0}-{1}'" in PROBE
    assert "ToString('yyyyMMddHHmm')" in PROBE
    assert MANIFEST["marker_format"] == "HB-<HOST>-<yyyyMMddHHmm>"


def test_probe_has_no_network_or_download_cmdlets():
    body = PROBE.split("#>", 1)[1].lower()
    for bad in ("invoke-webrequest", "invoke-restmethod", "net.webclient", "downloadstring",
                "start-bitstransfer", "test-netconnection", "mimikatz", "lsass"):
        assert bad not in body, bad


def test_probe_cleans_up_run_value():
    body = PROBE.split("#>", 1)[1]
    assert "Remove-StaleRunValues" in body
    assert body.index("New-ItemProperty") < body.rindex("Remove-ItemProperty")


def test_manifest_probes_match_script():
    for probe in MANIFEST["probes"]:
        assert f"{probe} = {{" in PROBE, probe


def test_every_entry_references_known_probe_and_existing_search():
    for entry in _entries():
        assert entry["probe"] in MANIFEST["probes"], entry["id"]
        assert (ROOT / entry["search"]).is_file(), entry["search"]
    for probe in MANIFEST["probes"].values():
        assert (ROOT / probe["evidence"]["search"]).is_file()
    assert (ROOT / MANIFEST["health"]["search"]).is_file()
    assert (ROOT / MANIFEST["health"]["scheduler_check"]).is_file()


def test_every_probe_is_covered_by_a_detection():
    covered = {d["probe"] for d in MANIFEST["detections"]}
    assert covered == set(MANIFEST["probes"])


def test_canary_rule_ids_are_not_real_rules():
    rules = (ROOT.parents[1] / "detections" / "wazuh" / "local_rules.xml").read_text(encoding="utf-8")
    real = set(re.findall(r'<rule id="(\d+)"', rules))
    for canary in MANIFEST["canaries"]:
        assert canary["rule_id"] not in real
        assert canary["expect"] == "DEAD DETECTION"
    for det in MANIFEST["detections"]:
        if det["kind"] == "wazuh_alert":
            assert det["rule_id"] in real


def test_saved_search_names_exist():
    conf = (ROOT.parents[1] / "detections" / "splunk" / "savedsearches.conf").read_text(encoding="utf-8")
    for det in MANIFEST["detections"]:
        if det["kind"] == "splunk_search":
            assert f"[{det['saved_search']}]" in conf
            assert det["saved_search"] in (ROOT / det["search"]).read_text(encoding="utf-8")


def test_spl_files_have_header_comment_and_no_exclusion_of_markers():
    assert len(SPL_FILES) == 6
    for spl in SPL_FILES:
        text = spl.read_text(encoding="utf-8")
        assert text.startswith("```Detection Heartbeat V"), spl.name
        assert not re.search(r'(?i)NOT\s+\S*"?\*?HB-', text), spl.name
