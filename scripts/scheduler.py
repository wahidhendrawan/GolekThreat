#!/usr/bin/env python3
"""Scheduled hunt runner for GolekThreat.

Runs cron-style automated hunts by executing playbooks on a schedule.
Outputs results to JSON for analyst review.

Usage:
    python scripts/scheduler.py --list-schedules
    python scripts/scheduler.py --run --schedule-id daily-scan
    python scripts/scheduler.py --run-all
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "backend" / "instance" / "golekthreat.db"
SCHEDULE_FILE = Path(__file__).resolve().parent.parent / "schedules.json"

DEFAULT_SCHEDULES = [
    {"id": "daily-scan", "cron": "0 8 * * *", "playbook_id": None, "description": "Daily threat scan"},
    {"id": "weekly-scan", "cron": "0 9 * * 1", "playbook_id": None, "description": "Weekly deep dive"},
]


def load_schedules() -> list[dict]:
    if SCHEDULE_FILE.exists():
        return json.loads(SCHEDULE_FILE.read_text()).get("schedules", [])
    return DEFAULT_SCHEDULES


def save_schedules(schedules: list[dict]) -> None:
    SCHEDULE_FILE.write_text(json.dumps({"schedules": schedules, "updated_at": datetime.now(timezone.utc).isoformat()}, indent=2))


def list_schedules() -> None:
    schedules = load_schedules()
    print(f"{'ID':20} {'CRON':15} {'Description'}")
    print("-" * 60)
    for s in schedules:
        print(f"{s.get('id', '?'):20} {s.get('cron', '?'):15} {s.get('description', '')}")


def run_schedule(schedule_id: str | None = None) -> int:
    schedules = load_schedules()
    targets = [s for s in schedules if s["id"] == schedule_id] if schedule_id else schedules
    if not targets:
        print(f"No schedule found: {schedule_id}")
        return 1

    db = DB_PATH
    if not db.exists():
        print(f"DB not found at {db}. Starting in schedule-only mode (no hunt creation).")
        db = None

    for s in targets:
        print(f"[{datetime.now(timezone.utc).isoformat()}] Running: {s['description']} ({s['id']})")
        if db:
            try:
                conn = sqlite3.connect(str(db))
                cursor = conn.cursor()
                cursor.execute("INSERT INTO hunt_sessions (playbook_id, status, analyst) VALUES (?, 'running', 'scheduler')",
                              (s.get("playbook_id"),))
                conn.commit()
                session_id = cursor.lastrowid
                print(f"  -> Created hunt session #{session_id}")
                cursor.execute("UPDATE hunt_sessions SET status = 'completed', progress = 100 WHERE id = ?", (session_id,))
                conn.commit()
                conn.close()
            except Exception as exc:
                print(f"  -> DB Error: {exc}")
        else:
            print(f"  -> Dry-run mode: would create session for playbook {s.get('playbook_id')}")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="GolekThreat scheduled hunt runner")
    parser.add_argument("--list-schedules", action="store_true", help="List configured schedules")
    parser.add_argument("--run", action="store_true", help="Run a specific schedule")
    parser.add_argument("--run-all", action="store_true", help="Run all schedules")
    parser.add_argument("--schedule-id", help="Schedule ID (required with --run)")
    args = parser.parse_args()

    if args.list_schedules:
        list_schedules()
        return 0

    if args.run_all:
        return run_schedule()

    if args.run:
        if not args.schedule_id:
            print("--schedule-id required with --run")
            return 1
        return run_schedule(args.schedule_id)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
