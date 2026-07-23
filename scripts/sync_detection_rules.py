#!/usr/bin/env python3
"""Sync detection rules from Detection-Rules repo into GolekThreat playbooks.

Fetches Sigma detection rules from the Detection-Rules repository, parses them,
and maps the fields to GolekThreat playbook schema for import.

Usage:
    python scripts/sync_detection_rules.py                    # default repo
    python scripts/sync_detection_rules.py --repo-url https://github.com/wahidhendrawan/Detection-Rules
    python scripts/sync_detection_rules.py --output playbooks.json
    python scripts/sync_detection_rules.py --local /path/to/Detection-Rules

Output: JSON file ready for GolekThreat playbook import.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import yaml
from pathlib import Path
from typing import Any

DEFAULT_REPO = "https://github.com/wahidhendrawan/Detection-Rules.git"
SIGMA_DIR = "sigma"


def clone_or_use(repo_url: str | None, local_path: str | None) -> Path:
    """Return path to a local copy of the Detection-Rules repo."""
    if local_path:
        loc = Path(local_path).resolve()
        if not loc.exists():
            print(f"[-] Local path does not exist: {loc}", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Using local repo: {loc}")
        return loc

    tmpdir = Path(tempfile.mkdtemp(prefix="dr-sync-"))
    url = repo_url or DEFAULT_REPO
    print(f"[*] Cloning {url} ...")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, str(tmpdir)],
            check=True,
            capture_output=True,
            timeout=60,
        )
    except subprocess.CalledProcessError as exc:
        print(f"[-] Clone failed: {exc.stderr.decode()}", file=sys.stderr)
        sys.exit(1)
    return tmpdir


def parse_sigma_rule(path: Path) -> dict[str, Any] | None:
    """Parse a Sigma YAML rule file. Returns dict or None."""
    try:
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(rule, dict):
            return None
        if "title" not in rule:
            return None
        return rule
    except Exception:
        return None


def map_sigma_to_playbook(rule: dict[str, Any]) -> dict[str, Any]:
    """Map Sigma rule fields to GolekThreat playbook schema."""
    title = rule.get("title", "Untitled")
    description = rule.get("description", "")
    tags = rule.get("tags", [])
    level = rule.get("level", "medium")
    logsource = rule.get("logsource", {})
    detection = rule.get("detection", {})

    # Extract MITRE ATT&CK tags
    mitre_tags = [t for t in tags if t.startswith("attack.")]
    mitre_techs = [t.replace("attack.", "").upper() for t in mitre_tags]

    # Build playbook
    return {
        "title": f"[Detection Rule] {title}",
        "hypothesis": f"Detect {title} — {description[:200] if description else 'No description'}",
        "severity": map_sigma_level(level),
        "mitre_techniques": mitre_techs,
        "tags": [t for t in tags if not t.startswith("attack.")] + ["auto-sync", "detection-rules"],
        "data_sources": [logsource.get("product", "unknown")],
        "search_queries": extract_detection_queries(detection),
        "references": rule.get("references", []),
        "author": rule.get("author", "Detection-Rules Auto-Sync"),
        "expected_evidence": f"Events matching {title} conditions",
        "false_positives": rule.get("falsepositives", ["Unknown — review needed"]),
        "steps": [
            {
                "order": 1,
                "description": f"Deploy {title} detection rule",
                "query": generate_search_query(rule),
            }
        ],
    }


def map_sigma_level(level: str) -> str:
    return {"critical": "critical", "high": "high", "medium": "medium"}.get(level, "low")


def extract_detection_queries(detection: dict) -> list[str]:
    """Extract searchable patterns from Sigma detection block."""
    queries = []
    if isinstance(detection, dict):
        selection = detection.get("selection", {})
        if isinstance(selection, dict):
            for key, value in selection.items():
                if isinstance(value, str):
                    queries.append(f"{key}: {value}")
                elif isinstance(value, list):
                    queries.append(f"{key}: {', '.join(v for v in value if isinstance(v, str))}")
    return queries[:5]  # Limit to 5 queries


def generate_search_query(rule: dict) -> str:
    """Generate a basic search query from the Sigma rule."""
    logsource = rule.get("logsource", {})
    product = logsource.get("product", "")
    category = logsource.get("category", "")

    if product == "windows" and category == "process_creation":
        detection = rule.get("detection", {})
        selection = detection.get("selection", {})
        fields = " OR ".join(
            f"{k}=*{v}*" for k, v in selection.items()
            if isinstance(v, str)
        )
        return f"index=windows EventID=4688 ({fields})" if fields else f"index=windows EventID=4688"
    return f"Search for: {rule.get('title', 'unknown')}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync Detection-Rules → GolekThreat playbooks")
    parser.add_argument("--repo-url", help="Detection-Rules repo URL")
    parser.add_argument("--local", help="Path to local Detection-Rules clone")
    parser.add_argument("--output", default="playbooks_from_detection_rules.json", help="Output JSON file")
    parser.add_argument("--max", type=int, default=500, help="Max rules to sync")
    args = parser.parse_args()

    repo_path = clone_or_use(args.repo_url, args.local)
    sigma_path = repo_path / SIGMA_DIR
    if not sigma_path.exists():
        print(f"[-] Sigma directory not found at {sigma_path}", file=sys.stderr)
        sys.exit(1)

    rules = list(sigma_path.rglob("*.yml")) + list(sigma_path.rglob("*.yaml"))
    print(f"[*] Found {len(rules)} Sigma rule files")

    playbooks = []
    success = 0
    for rule_path in rules[:args.max]:
        rule = parse_sigma_rule(rule_path)
        if rule is None:
            continue
        try:
            playbook = map_sigma_to_playbook(rule)
            playbooks.append(playbook)
            success += 1
        except Exception as exc:
            print(f"  [!] Failed to map {rule_path.name}: {exc}")

    output = Path(args.output)
    output.write_text(
        json.dumps({"playbooks": playbooks, "source": str(repo_path), "count": success}, indent=2),
        encoding="utf-8",
    )

    print(f"\n✅ Synced {success} playbooks from Detection-Rules → {output}")
    print(f"   Import this file into GolekThreat via Admin → Import Playbooks.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
