"""
Mini-SOAR automated response.

Simulates what a SOAR platform does when a detection fires: enrich the source IP,
decide on an action based on threat-intel verdict, notify a channel (Slack/Teams
webhook), and write a structured incident record to disk.

Usage:
    python response/respond.py --rule "SSH Brute Force Attempt" --src-ip 74.96.216.30

If SLACK_WEBHOOK_URL is set, a real notification is sent; otherwise the payload
is printed so the workflow still demonstrates end-to-end without any secrets.
"""
import argparse
import json
import os
import datetime

from enrich_ip import enrich, verdict

try:
    import requests
except ImportError:
    requests = None


def decide_action(v: str) -> str:
    if v.startswith("MALICIOUS"):
        return "AUTO-BLOCK source IP at firewall/NSG + page on-call"
    if v.startswith("SUSPICIOUS"):
        return "Open ticket for analyst review"
    return "Log only — no action required"


def notify(message: str) -> None:
    webhook = os.environ.get("SLACK_WEBHOOK_URL")
    if webhook and requests is not None:
        try:
            requests.post(webhook, json={"text": message}, timeout=10)
            print("Notification sent to Slack webhook.")
            return
        except Exception as e:
            print(f"Notification failed ({e}); falling back to console.")
    print("---- NOTIFICATION (console fallback) ----")
    print(message)
    print("-----------------------------------------")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rule", required=True, help="Name of the detection that fired")
    parser.add_argument("--src-ip", required=True, help="Source IP from the alert")
    args = parser.parse_args()

    enrichment = enrich(args.src_ip)
    v = verdict(enrichment.get("abuse_confidence_score"))
    action = decide_action(v)

    incident = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
        "rule": args.rule,
        "src_ip": args.src_ip,
        "enrichment": enrichment,
        "verdict": v,
        "action_taken": action,
    }

    # Write a structured incident record (what a real SOAR would push to a case system)
    os.makedirs("incidents", exist_ok=True)
    fname = f"incidents/incident_{args.src_ip.replace('.', '_')}_{int(datetime.datetime.now(datetime.timezone.utc).timestamp())}.json"
    with open(fname, "w") as f:
        json.dump(incident, f, indent=2)

    message = (
        f":rotating_light: *Detection fired:* {args.rule}\n"
        f"*Source IP:* {args.src_ip}\n"
        f"*Threat-intel verdict:* {v}\n"
        f"*Automated action:* {action}"
    )
    notify(message)
    print(f"\nIncident record written to {fname}")


if __name__ == "__main__":
    main()
