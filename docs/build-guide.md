# Build & Publish Guide

This project is already fully built. This guide walks you through understanding each
piece, running it locally, and publishing it to a new GitHub repository — following the
same rhythm as your Cloud SOC Detection Lab.

## Prerequisites (you already have these from the SOC lab)
- Python 3.9+ installed  (check: `python --version`)
- Git installed  (check: `git --version`)
- A GitHub account

## Step 1 — Understand the four pieces (read the files, in this order)
1. `detections/ssh_brute_force.yml` — a detection written as code. Notice it's just
   structured YAML: what to look for, over what timeframe, mapped to MITRE ATT&CK.
2. `tests/test_rules.py` — the automated quality gate. It loads every rule and fails if
   any is malformed or unmapped. This is what makes it "detection-as-code."
3. `response/enrich_ip.py` — takes an IP, returns a threat-intel verdict.
4. `response/respond.py` — the mini-SOAR: on a fired detection, enrich → decide → notify → record.

## Step 2 — Run it locally
```bash
pip install -r requirements.txt
python -m pytest tests/ -v
python response/enrich_ip.py 8.8.8.8
python response/respond.py --rule "SSH Brute Force Attempt" --src-ip 74.96.216.30
```
Everything runs in demo mode with no API keys required.

## Step 3 — (Optional) go live with real threat intel
1. Create a free account at https://www.abuseipdb.com and copy your API key.
2. `set ABUSEIPDB_API_KEY=your_key`  (Windows)  /  `export ABUSEIPDB_API_KEY=your_key` (Mac/Linux)
3. Re-run `enrich_ip.py` against a known-bad IP and see a real reputation score.

## Step 4 — Publish to a new GitHub repo
1. On GitHub: **New repository** → name it `detection-as-code-pipeline` → Public →
   do NOT add README/gitignore/license (this project already has them).
2. In this project folder:
   ```bash
   git init
   git add .
   git status          # confirm no .env or secrets are listed
   git commit -m "Detection-as-Code pipeline: Sigma rules, CI/CD validation, threat-intel enrichment, mini-SOAR"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/detection-as-code-pipeline.git
   git push -u origin main
   ```
3. On the repo page, watch the **Actions** tab — your CI workflow runs automatically and
   should show a green check. That green check *is* the demo: it proves your detections
   passed automated validation.

## Step 5 — Prove the CI gate works (great for interviews / screenshots)
1. Edit a rule and deliberately break it (e.g. delete its `level:` line).
2. Commit and push.
3. Watch the Actions tab show a **red X** — the pipeline caught the bad rule and blocked it.
4. Fix it, push again, watch it go green.
5. Screenshot both — the red failure and the green pass. This is the single most
   compelling artifact of the whole project, because it visibly demonstrates the
   automated quality gate working.

## Resume bullets
- Built a Detection-as-Code pipeline managing security detections as version-controlled
  Sigma rules mapped to MITRE ATT&CK, with automated CI/CD validation via GitHub Actions.
- Implemented an automated quality gate that validates rule structure, severity, syntax,
  and ATT&CK mapping on every commit, preventing malformed detections from being deployed.
- Developed Python-based threat-intelligence enrichment (AbuseIPDB) and a SOAR-style
  automated response workflow (verdict-based actioning, Slack/Teams alerting, structured
  incident records).
