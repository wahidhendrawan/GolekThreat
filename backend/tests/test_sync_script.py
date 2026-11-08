"""scripts/sync_detection_rules.py must produce bodies the API accepts."""

import importlib.util
from pathlib import Path

import pytest
from pydantic import ValidationError

from golekthreat.schemas import PlaybookCreate

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "sync_detection_rules.py"
spec = importlib.util.spec_from_file_location("sync_detection_rules", SCRIPT)
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)

RULE = {
    "title": "Suspicious Encoded PowerShell",
    "id": "aa7262cf-72f2-44ad-978b-291567be38ba",
    "description": "Detects -enc usage.",
    "level": "high",
    "logsource": {"product": "windows", "category": "process_creation"},
    "detection": {"selection": {"CommandLine|contains": "-enc"}, "condition": "selection"},
    "falsepositives": ["Admin scripts"],
    "tags": ["attack.t1059.001", "attack.execution"],
}


def test_rule_maps_to_a_valid_playbook_body() -> None:
    body = sync.map_sigma_to_playbook(RULE, Path("win_enc_ps.yml"))
    playbook = PlaybookCreate(**body)
    assert playbook.slug == "dr-aa7262cf-72f2-44ad-978b-291567be38ba"
    assert (playbook.tactic, playbook.technique_id, playbook.severity.value) == (
        "Execution",
        "T1059.001",
        "high",
    )
    assert playbook.queries[0].platform == "Sigma" and "-enc" in playbook.queries[0].query
    assert len(playbook.steps) == 2


def test_minimal_rule_still_validates() -> None:
    body = sync.map_sigma_to_playbook({"title": "Bare"}, Path("bare.yml"))
    playbook = PlaybookCreate(**body)
    assert (
        playbook.slug == "dr-bare"
        and playbook.technique_id == "unmapped"
        and playbook.tactic == "Unknown"
    )
    with pytest.raises(ValidationError):
        PlaybookCreate(**{**body, "title": ""})
