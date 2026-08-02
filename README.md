# Detection-as-Code — Automated Threat Detection Pipeline

A detection engineering pipeline that treats security detections as version-controlled
code: rules are written in a vendor-neutral format, automatically tested and validated
through CI/CD on every change, enriched with threat intelligence, and wired to an
automated (SOAR-style) response workflow. Built to demonstrate how a modern security
team engineers and operates detections — not just clicks through a dashboard.

> Companion to my [Cloud SOC Detection Lab](https://github.com/Tejakarthik200212/cloud-soc-detection-lab):
> that project *operates* a SIEM; this one *engineers and automates the detections themselves*.

## What this demonstrates

- **Detection-as-Code** — detections written as version-controlled Sigma rules (YAML),
  each mapped to MITRE ATT&CK, reviewed and versioned like software
- **CI/CD for detections (GitHub Actions)** — every push automatically validates each
  rule's structure, severity, syntax, and ATT&CK mapping; a broken rule fails the build
  and can't be merged
- **Threat intelligence enrichment** — a Python module that scores a source IP against
  AbuseIPDB and returns an actionable verdict
- **Automated response (mini-SOAR)** — a Python workflow that, on a fired detection,
  enriches the IP, decides an action based on the threat-intel verdict, notifies a
  Slack/Teams channel, and writes a structured incident record
- **Security-as-software practices** — automated testing, version control, CI gates,
  and documentation applied to security operations (DevSecOps)

## Repository structure

```
detections/    Sigma detection rules (YAML), one per technique
tests/         Automated validation run locally and in CI
response/      Threat-intel enrichment + automated response (mini-SOAR)
.github/       GitHub Actions CI/CD workflow
docs/          Build guide and architecture notes
```

## Detections included

| Rule | MITRE ATT&CK | Severity |
|------|--------------|----------|
| SSH Brute Force Attempt | T1110 (Brute Force) | High |
| Cloud Storage Made Publicly Accessible | T1530 (Data from Cloud Storage) | High |
| Port Scan / Network Reconnaissance | T1046 (Network Service Discovery) | Medium |

## How the pipeline works

1. A detection is written or edited as a Sigma rule in `detections/`.
2. On push, **GitHub Actions** runs `tests/test_rules.py`, which fails the build if any
   rule is missing required fields, has an invalid severity, isn't valid YAML, or lacks
   a MITRE ATT&CK mapping.
3. When a detection fires (in a real deployment, from the SIEM), `response/respond.py`
   enriches the source IP via `response/enrich_ip.py`, decides an action, notifies the
   team, and records the incident.

## Running it locally

```bash
pip install -r requirements.txt

# Validate all detection rules (same check CI runs)
python -m pytest tests/ -v

# Enrich an IP with threat intelligence
export ABUSEIPDB_API_KEY="your_free_key"   # optional; runs in demo mode without it
python response/enrich_ip.py 74.96.216.30

# Simulate an automated response to a fired detection
export SLACK_WEBHOOK_URL="your_webhook"     # optional; prints to console without it
python response/respond.py --rule "SSH Brute Force Attempt" --src-ip 74.96.216.30
```

## Tech stack

Sigma · Python · GitHub Actions (CI/CD) · pytest · MITRE ATT&CK · AbuseIPDB API ·
Slack/Teams webhooks · YAML · Git

## Notes

- Enrichment and response scripts run in a safe **demo mode** when no API key / webhook
  is configured, so the whole pipeline works end-to-end without any secrets.
- No secrets are committed; see `.gitignore`. In a real deployment, API keys and webhook
  URLs would be injected as CI/CD secrets or environment variables.
