# Changelog

All notable changes to GolekThreat are documented here.

## Unreleased

- Fixed: editing a playbook that already had hunt sessions failed on PostgreSQL (foreign key
  from `session_steps.playbook_step_id`); the column is dropped automatically at startup.
- Login is rate limited (10 failures lock a username for 15 minutes) and user tokens expire
  after 30 days. Request fields now have size limits matching the database columns, and
  steps, queries and evidence refuse empty titles and bodies.
- `scripts/sync_detection_rules.py` now emits valid `POST /playbooks` bodies and can push
  them with `--push`.
- Added user accounts with viewer, analyst and admin roles: `POST /auth/login` issues a
  bearer token, `POST /auth/logout` revokes it, admins manage users under `/users`, and
  the web UI signs in with a username and password. The first admin comes from
  `GOLEK_ADMIN_PASSWORD`; the shared `GOLEK_API_TOKEN` still works and acts as an admin.
- Added professional repository metadata, CI, docs, tests, and contribution guidance.

## 0.1.0

- Added Docker Compose stack for React, FastAPI, and PostgreSQL.
- Added threat hunt management console.
- Added playbook CRUD, session CRUD, evidence CRUD, and Markdown reports.
- Added generated MITRE ATT&CK Enterprise technique catalog for playbook mapping.
