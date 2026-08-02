"""
Threat intelligence enrichment.

Given an IP address (e.g. one pulled from a fired alert), query AbuseIPDB's
free API and return a reputation summary an analyst can act on immediately.

Usage:
    export ABUSEIPDB_API_KEY="your_free_key_here"
    python response/enrich_ip.py 8.8.8.8

Get a free API key at https://www.abuseipdb.com (free tier is enough for a lab).
If no API key is set, the script runs in demo mode with mocked data so the
pipeline still works end-to-end without a key.
"""
import os
import sys
import json

try:
    import requests
except ImportError:
    requests = None


def enrich(ip: str) -> dict:
    api_key = os.environ.get("ABUSEIPDB_API_KEY")

    # Demo mode: no key or no requests library available
    if not api_key or requests is None:
        return {
            "ip": ip,
            "mode": "demo",
            "abuse_confidence_score": 0,
            "note": "No ABUSEIPDB_API_KEY set — returning mocked data. "
                    "Set the env var for live enrichment.",
        }

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "ip": ip,
            "mode": "live",
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "country": data.get("countryCode"),
            "total_reports": data.get("totalReports"),
            "is_public": data.get("isPublic"),
        }
    except Exception as e:
        return {"ip": ip, "mode": "error", "error": str(e)}


def verdict(score) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 75:
        return "MALICIOUS — recommend immediate block"
    if score >= 25:
        return "SUSPICIOUS — investigate further"
    return "LIKELY BENIGN"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python response/enrich_ip.py <ip_address>")
        sys.exit(1)

    result = enrich(sys.argv[1])
    result["verdict"] = verdict(result.get("abuse_confidence_score"))
    print(json.dumps(result, indent=2))
