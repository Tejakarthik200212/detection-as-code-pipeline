"""
Validates every Sigma detection rule in ../detections/.
Run locally with:  python -m pytest tests/ -v
This same test runs automatically in CI (see .github/workflows/validate.yml),
so a broken rule can never be merged.
"""
import glob
import os
import yaml
import pytest

DETECTIONS_DIR = os.path.join(os.path.dirname(__file__), "..", "detections")

# Fields every well-formed Sigma rule in this repo must contain
REQUIRED_FIELDS = ["title", "id", "description", "logsource", "detection", "level"]
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}

rule_files = glob.glob(os.path.join(DETECTIONS_DIR, "*.yml"))


def test_at_least_one_rule_exists():
    assert len(rule_files) > 0, "No detection rules found in detections/"


@pytest.mark.parametrize("path", rule_files, ids=[os.path.basename(p) for p in rule_files])
def test_rule_is_valid(path):
    with open(path, "r") as f:
        rule = yaml.safe_load(f)

    # 1. Must be valid YAML that parses to a dict
    assert isinstance(rule, dict), f"{path} did not parse to a mapping"

    # 2. Must contain all required fields
    for field in REQUIRED_FIELDS:
        assert field in rule, f"{path} is missing required field: '{field}'"

    # 3. Severity level must be a recognised value
    assert rule["level"] in VALID_LEVELS, (
        f"{path} has invalid level '{rule['level']}'. Must be one of {VALID_LEVELS}"
    )

    # 4. detection block must contain a condition
    assert "condition" in rule["detection"], f"{path} detection block has no 'condition'"

    # 5. Encourage MITRE ATT&CK mapping (tags starting with attack.t)
    tags = rule.get("tags", [])
    assert any(str(t).startswith("attack.t") for t in tags), (
        f"{path} is not mapped to a MITRE ATT&CK technique (add an 'attack.tXXXX' tag)"
    )
