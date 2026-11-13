# 🛡️ VT IOC Triage

A lightweight command-line tool for SOC analysts to enrich and triage Indicators of Compromise (IPs, domains, URLs and file hashes) using the **VirusTotal API v3**.

Paste in a list of IOCs from an alert, phishing report or threat feed and get a clear verdict, detection ratio, context and a pivot link for each one, ready to drop into a ticket.

## Features

- **Auto-detects IOC type**: IPv4/IPv6, domain, URL, MD5/SHA-1/SHA-256
- **Handles defanged IOCs**: `hxxps://evil[.]com` works as-is
- **Verdicts**: `MALICIOUS`, `SUSPICIOUS`, `CLEAN`, `NO DATA`, `NOT FOUND`
- **Rate-limit aware**: defaults to the free-tier limit (4 requests/min), with automatic back-off on HTTP 429
- **Skips private IPs** (RFC1918, loopback, link-local) so you don't waste quota
- **Exports** to CSV and JSON for case notes or SIEM/SOAR ingestion
- **Pipeline friendly**: exit code `2` when any IOC is malicious
- Deduplicates input and ignores `#` comments in IOC files

## Requirements

- Python 3.8+
- A VirusTotal API key (free at <https://www.virustotal.com/gui/join-us>)

## Installation

```bash
git clone https://github.com/<your-username>/vt-ioc-triage.git
cd vt-ioc-triage
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

The API key is read from an environment variable so it never lands in your code or shell history of scripts:

```bash
# Linux / macOS
export VT_API_KEY='your_api_key_here'

# Windows PowerShell
$env:VT_API_KEY = 'your_api_key_here'
```

> ⚠️ Never hard-code or commit your API key. `.env` is already in `.gitignore`.

## Usage

```bash
# Single or multiple IOCs
python vt_triage.py 8.8.8.8 example.com

# Defanged indicators straight from a report
python vt_triage.py "hxxps://bad-site[.]com/login" "185.220.101[.]5"

# From a file, exporting results
python vt_triage.py -f sample_iocs.txt --csv results.csv --json results.json

# Piped input
cat iocs.txt | python vt_triage.py

# Premium API key (higher quota): shorten the delay
python vt_triage.py -f iocs.txt --rate 0.25
```

### Options

| Flag | Description |
|------|-------------|
| `iocs` | One or more IOCs as arguments |
| `-f, --file` | File containing one IOC per line |
| `--csv PATH` | Save results as CSV |
| `--json PATH` | Save results as JSON |
| `--rate SECONDS` | Delay between API calls (default `15`) |
| `--no-colour` | Disable coloured terminal output |

### Example output

```
[*] Triage started: 2 unique IOC(s)

[MALICIOUS] 44d88612fea8a8f36de82e1278abb02f (hash)  detections: 62/75
    context  : eicar.com | EICAR virus test file
    last scan: 2026-11-10 08:14 UTC
    link     : https://www.virustotal.com/gui/file/44d88612...

[CLEAN] example.com (domain)  detections: 0/94
    context  : registrar: RESERVED-Internet Assigned Numbers Authority | categories: n/a
    link     : https://www.virustotal.com/gui/domain/example.com

[*] Summary: CLEAN=1, MALICIOUS=1
```
*(Illustrative output; real numbers vary.)*

## Tuning verdicts

Thresholds live at the top of `vt_triage.py`:

```python
MALICIOUS_THRESHOLD = 5    # engines flagging malicious -> MALICIOUS
SUSPICIOUS_THRESHOLD = 1   # >=1 malicious (or >=3 suspicious) -> SUSPICIOUS
```

Adjust them to match your organisation's risk appetite and false-positive tolerance.

## Analyst notes & limitations

- A `CLEAN` verdict means **no engine flagged it right now**, not that it is safe. Always combine with internal telemetry, sandboxing and other intel sources.
- `NOT FOUND` means the IOC has never been seen by VirusTotal. That can itself be interesting for targeted threats.
- **Privacy:** querying VirusTotal sends the IOC to a third party. Do not submit confidential internal hostnames, URLs containing tokens/PII, or files hashes from sensitive documents without checking your policy. This tool only looks up existing reports; it never uploads files.
- Free API keys are for non-commercial use and limited to 4 requests/min and 500/day. Check VirusTotal's terms for your use case.

## Ideas for extension

- Add AbuseIPDB / URLhaus / AlienVault OTX lookups for a second opinion
- Push results to a SIEM (Splunk HEC, Elastic) or ticketing system
- Add on-disk caching to save quota on repeat IOCs
- Wrap it in a Slack/Teams bot for ad-hoc analyst lookups

## License

MIT. Use it, improve it, share it.
