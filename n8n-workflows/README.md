# n8n Workflows

The lab's SOAR workflows, sanitized for publishing. Design, call map and testing notes:
**[Approval-Gated SOAR](https://dotslashtag.github.io/cyber-defense-lab/lab/soar/)**.

| File | Workflow |
|---|---|
| `workflows/soar-master-v2.json` | SOAR Master: intake and router v2 |
| `workflows/brute-force-v2.json` | Brute-force response, approval-gated v2 |
| `workflows/response-handler-slack-approval.json` | Response Handler: Slack approval |
| `workflows/enrich-ip.json`, `enrich-domain.json`, `enrich-hash.json` | Enrichment sub-workflows |
| `workflows/evtx-hunter-thehive.json` | EVTX Hunter findings to TheHive alert |
| `workflows/automation-failure-alert.json` | Error Workflow: posts failed runs of the workflows above to Slack |

## What they look like

<!-- Screenshots made from these sanitized files in a throwaway local n8n, not the live one. -->

**SOAR Master v2**
![SOAR Master v2 canvas](../docs/assets/img/n8n/soar-master-v2.png)

**Brute Force v2**
![Brute Force v2 canvas](../docs/assets/img/n8n/brute-force-v2.png)

**Response Handler: Slack approval**
![Response Handler canvas](../docs/assets/img/n8n/response-handler-slack-approval.png)

**Enrich IP** (Domain and Hash have the same shape)
![Enrich IP canvas](../docs/assets/img/n8n/enrich-ip.png)

**EVTX Hunter to TheHive**
![EVTX Hunter to TheHive canvas](../docs/assets/img/n8n/evtx-hunter-thehive.png)

**Automation Failure Alert**
![Automation Failure Alert canvas](../docs/assets/img/n8n/automation-failure-alert.png)

All eight, larger and with descriptions: [Approval-Gated SOAR](https://dotslashtag.github.io/cyber-defense-lab/lab/soar/#what-they-look-like-in-n8n).

## Importing

In n8n, use **Import from File** to bring a workflow in. Credentials are deliberately reduced
to their type, for example `<slackApi credential>`, so attach your own before activating it.
Slack IDs are placeholders (`C0SLACKCHANNEL`, `U0SLACKUSER`), and secrets are read from
environment variables, never from the workflow.

## Sanitizing a new export

```bash
python n8n-workflows/sanitize.py raw-export.json -o n8n-workflows/workflows/<name>.json
python n8n-workflows/sanitize.py --check n8n-workflows/workflows/*.json
```

The sanitizer exits with status 1 if anything secret-shaped survives. CI runs the same check on
every file in `workflows/`.
