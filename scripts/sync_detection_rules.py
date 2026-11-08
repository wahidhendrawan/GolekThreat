#!/usr/bin/env python3
"""Sync detection rules from Detection-Rules repo into GolekThreat playbooks.

Fetches Sigma detection rules from the Detection-Rules repository, parses them,
and maps the fields to GolekThreat playbook schema for import.

Usage:
    python scripts/sync_detection_rules.py                    # default repo
    python scripts/sync_detection_rules.py --repo-url https://github.com/wahidhendrawan/Detection-Rules
    python scripts/sync_detection_rules.py --output playbooks.json
    python scripts/sync_detection_rules.py --local /path/to/Detection-Rules
    python scripts/sync_detection_rules.py --push http://localhost:3000/api --token "$TOKEN"

Output: JSON file of `POST /playbooks` bodies; --push sends them to a running GolekThreat.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import yaml

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


ATTACK_TECHNIQUE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)$", re.I)
ATTACK_TACTIC = re.compile(r"attack\.([a-z][a-z-]+)$")


def map_sigma_to_playbook(rule: dict[str, Any], path: Path) -> dict[str, Any]:
    """A Sigma rule as a `PlaybookCreate` body for `POST /playbooks`."""
    tags = [str(t) for t in rule.get("tags") or []]
    technique_id = next((m.group(1).upper() for t in tags if (m := ATTACK_TECHNIQUE.match(t))), "")
    tactic = next(
        (m.group(1).replace("-", " ").title() for t in tags if (m := ATTACK_TACTIC.match(t))),
        "Unknown",
    )
    title = str(rule.get("title") or path.stem)
    false_positives = rule.get("falsepositives") or ["Unknown, review needed"]
    if not isinstance(false_positives, list):
        false_positives = [false_positives]
    logsource = rule.get("logsource") or {}
    return {
        "slug": f"dr-{rule.get('id') or path.stem}"[:120],
        "title": title[:200],
        "hypothesis": str(rule.get("description") or f"Activity matching {title}").strip()[:20_000],
        "severity": map_sigma_level(str(rule.get("level", "medium"))),
        "tactic": tactic[:120],
        "technique": (f"ATT&CK {technique_id}" if technique_id else "Unmapped technique")[:160],
        "technique_id": technique_id or "unmapped",
        "data_sources": ", ".join(f"{k}={v}" for k, v in logsource.items())[:20_000] or "unknown",
        "expected_evidence": f"Events matching the Sigma detection of '{title}'."[:20_000],
        "false_positives": "\n".join(str(fp) for fp in false_positives)[:20_000],
        "response": (
            "Validate the alert against the Sigma rule, scope the affected hosts and users, "
            "then follow the response plan for this technique."
        ),
        "steps": [
            {
                "title": "Run the detection query",
                "instruction": (
                    f"Execute the Sigma rule '{title[:150]}' over the hunt window "
                    "and review every hit."
                ),
            },
            {
                "title": "Triage the matches",
                "instruction": (
                    "Classify each hit as evidence, false positive or no finding, "
                    "and record notes per step."
                ),
            },
        ],
        "queries": [
            {
                "platform": "Sigma",
                "query": yaml.safe_dump(rule.get("detection") or {}, sort_keys=False)[:50_000],
            }
        ],
    }


def map_sigma_level(level: str) -> str:
    return {"critical": "critical", "high": "high", "medium": "medium"}.get(level, "low")


def push_playbooks(playbooks: list[dict[str, Any]], api_url: str, token: str) -> tuple[int, int]:
    """POST each playbook; an existing slug (409) is skipped. Returns (created, skipped)."""
    created = skipped = 0
    for playbook in playbooks:
        request = urllib.request.Request(
            f"{api_url.rstrip('/')}/playbooks",
            data=json.dumps(playbook).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30):
                created += 1
        except urllib.error.HTTPError as exc:
            if exc.code == 409:
                skipped += 1
            else:
                print(
                    f"  [!] {playbook['slug']}: HTTP {exc.code} {exc.read()[:200]!r}",
                    file=sys.stderr,
                )
    return created, skipped


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync Detection-Rules → GolekThreat playbooks")
    parser.add_argument("--repo-url", help="Detection-Rules repo URL")
    parser.add_argument("--local", help="Path to local Detection-Rules clone")
    parser.add_argument(
        "--output", default="playbooks_from_detection_rules.json", help="Output JSON file"
    )
    parser.add_argument("--max", type=int, default=500, help="Max rules to sync")
    parser.add_argument(
        "--push",
        metavar="API_URL",
        help="POST the playbooks to this GolekThreat API, e.g. http://localhost:3000/api",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("GOLEK_API_TOKEN", ""),
        help="Bearer token for --push (default: $GOLEK_API_TOKEN)",
    )
    args = parser.parse_args()
    if args.push and not args.token:
        parser.error("--push needs --token or GOLEK_API_TOKEN")

    repo_path = clone_or_use(args.repo_url, args.local)
    sigma_path = repo_path / SIGMA_DIR
    if not sigma_path.exists():
        print(f"[-] Sigma directory not found at {sigma_path}", file=sys.stderr)
        sys.exit(1)

    rules = list(sigma_path.rglob("*.yml")) + list(sigma_path.rglob("*.yaml"))
    print(f"[*] Found {len(rules)} Sigma rule files")

    playbooks = []
    for rule_path in rules[: args.max]:
        rule = parse_sigma_rule(rule_path)
        if rule is None:
            continue
        try:
            playbooks.append(map_sigma_to_playbook(rule, rule_path))
        except Exception as exc:
            print(f"  [!] Failed to map {rule_path.name}: {exc}")

    output = Path(args.output)
    output.write_text(
        json.dumps(
            {"playbooks": playbooks, "source": str(repo_path), "count": len(playbooks)}, indent=2
        ),
        encoding="utf-8",
    )
    print(f"\n✅ Mapped {len(playbooks)} playbooks from Detection-Rules → {output}")
    if args.push:
        created, skipped = push_playbooks(playbooks, args.push, args.token)
        print(f"   Pushed to {args.push}: {created} created, {skipped} already existed")
    else:
        print("   Push them with --push http://localhost:3000/api --token $GOLEK_API_TOKEN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
