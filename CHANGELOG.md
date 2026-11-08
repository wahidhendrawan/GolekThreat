# Changelog

All notable changes to GolekThreat are documented here.

## Unreleased

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
