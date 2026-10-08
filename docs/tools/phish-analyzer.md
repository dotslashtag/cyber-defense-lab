# Phishing Analyzer

!!! note "Coming in Week 5"

**Why:** the lab's operations start after initial access, so phishing (the most
common way in) wasn't covered. This tool closes that gap.

**Planned features**

- Parse a `.eml`: sender path, `Received` chain, reply-to mismatches
- Check SPF, DKIM and DMARC results and display-name spoofing
- Extract and defang URLs, domains, IPs and attachment hashes
- Send IOCs to the lab's existing n8n enrichment workflows (MISP, VirusTotal)
- Verdict report in Markdown/HTML
- **Browser demo:** drop an email on this page and analyze it locally; nothing is uploaded
