#!/usr/bin/env python3
"""
Mini-SOAR automated response — Wazuh Active Response version.

Unlike respond.py (which takes --rule / --src-ip as command-line arguments
for manual/demo use), this script is designed to be registered as a Wazuh
Active Response command. Wazuh invokes it directly and sends the full alert
as JSON through stdin the moment the configured rule fires — no manual
input required.

Deployment (on the Wazuh manager):
    sudo cp respond_auto.py /var/ossec/active-response/bin/respond_auto.py
    sudo cp enrich_ip.py /var/ossec/active-response/bin/enrich_ip.py
    sudo chmod +x /var/ossec/active-response/bin/respond_auto.py

Then register it in /var/ossec/etc/ossec.conf:
    <command>
      <name>respond_auto</name>
      <executable>respond_auto.py</executable>
      <timeout_allowed>no</timeout_allowed>
    </command>
    <active-response>
      <command>respond_auto</command>
      <location>local</location>
      <rules_id>100010</rules_id>
    </active-response>

See docs/active-response-proof.md for a real, live-triggered example of
this script running end-to-end, and an honest note on a reliability quirk
observed with frequency/correlation-based rules.
"""
import sys
import json
import os
import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enrich_ip import enrich, verdict


def decide_action(v: str) -> str:
    if v.startswith("MALICIOUS"):
        return "AUTO-BLOCK source IP at firewall/NSG + page on-call"
    if v.startswith("SUSPICIOUS"):
        return "Open ticket for analyst review"
    return "Log only — no action required"


def notify(message: str) -> None:
    print("---- NOTIFICATION ----")
    print(message)
    print("-----------------------")


def main():
    # Wazuh Active Response sends the full alert as JSON through stdin the
    # instant it starts this script — read it directly from that channel.
    raw_data = sys.stdin.read()

    # Keep a copy for debugging / evidence
    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "last_alert_raw.log")
    try:
        with open(log_path, "a") as f:
            f.write(raw_data + "\n")
    except Exception:
        pass  # non-fatal if the log path isn't writable in this environment

    alert = json.loads(raw_data)
    src_ip = alert.get("parameters", {}).get("alert", {}).get("data", {}).get("srcip", "UNKNOWN")
    rule_desc = alert.get("parameters", {}).get("alert", {}).get("rule", {}).get("description", "Unknown rule")

    enrichment = enrich(src_ip)
    v = verdict(enrichment.get("abuse_confidence_score"))
    action = decide_action(v)

    incident = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
        "rule": rule_desc,
        "src_ip": src_ip,
        "enrichment": enrichment,
        "verdict": v,
        "action_taken": action,
    }

    incidents_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "incidents")
    os.makedirs(incidents_dir, exist_ok=True)
    fname = os.path.join(
        incidents_dir,
        f"incident_{src_ip.replace('.', '_')}_{int(datetime.datetime.now(datetime.timezone.utc).timestamp())}.json",
    )
    with open(fname, "w") as f:
        json.dump(incident, f, indent=2)

    message = (
        f"Detection fired: {rule_desc}\n"
        f"Source IP: {src_ip}\n"
        f"Threat-intel verdict: {v}\n"
        f"Automated action: {action}"
    )
    notify(message)


if __name__ == "__main__":
    main()
