# GolekThreat 🔍

[![CI](https://github.com/wahidhendrawan/GolekThreat/actions/workflows/ci.yml/badge.svg)](https://github.com/wahidhendrawan/GolekThreat/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/wahidhendrawan/GolekThreat?sort=semver)](https://github.com/wahidhendrawan/GolekThreat/releases/latest)
[![License](https://img.shields.io/github/license/wahidhendrawan/GolekThreat)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/wahidhendrawan/GolekThreat/badge)](https://scorecard.dev/viewer/?uri=github.com/wahidhendrawan/GolekThreat)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-compose%20ready-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![React](https://img.shields.io/badge/frontend-React%2018-61DAFB?logo=react)](frontend/)
[![FastAPI](https://img.shields.io/badge/backend-FastAPI-009688?logo=fastapi)](backend/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red)](docs/)
[![Pages](https://img.shields.io/badge/docs-🌐-orange.svg)](https://wahidhendrawan.github.io/GolekThreat/)
[![Last Commit](https://img.shields.io/github/last-commit/wahidhendrawan/GolekThreat)](https://github.com/wahidhendrawan/GolekThreat/commits/main)
[![GitHub stars](https://img.shields.io/github/stars/wahidhendrawan/GolekThreat?style=social)](https://github.com/wahidhendrawan/GolekThreat/stargazers)

GolekThreat is a threat hunting management console for building hunt playbooks,
mapping them to MITRE ATT&CK, running repeatable hunt sessions, tracking evidence,
and producing analyst-ready Markdown reports.

The name combines **Golek** (Javanese/Indonesian for "search") with threat hunting.

---

## ✨ Features

| Category | Features |
|---|---|
| **🎯 Playbook Engine** | Build structured hunt playbooks with hypothesis, severity, data sources, expected evidence, and response guidance |
| **📋 Step Management** | Ordered investigation steps with starter queries (Sigma, KQL, SPL, EQL, Wazuh) |
| **🔍 Hunt Sessions** | Execute playbooks as task-like work items with status, analyst, scope, and progress tracking |
| **📝 Evidence Tracking** | Record findings, artifacts, and analyst judgement per session step |
| **🗺️ MITRE ATT&CK** | Generated catalog from official STIX data — map playbooks to techniques and track coverage |
| **📊 ATT&CK Navigator Export** | Export coverage to MITRE ATT&CK Navigator JSON for visual gap analysis |
| **📄 Report Generation** | Markdown reports for analyst handoff with findings and evidence |
| **🐳 Docker Ready** | Full stack: React + FastAPI + Nginx + PostgreSQL 16 — one `docker compose up` |

---

## What It Does

- Manage threat hunting playbooks with hypothesis, severity, data sources, expected evidence, false positives, response guidance, steps, and starter queries.
- Map playbooks to MITRE ATT&CK Enterprise techniques using a generated catalog from official ATT&CK STIX data.
- Run hunt sessions as task-like work items with status, analyst, scope, progress, step notes, and evidence logs.
- Add, edit, and delete evidence tied to hunt sessions.
- Track ATT&CK coverage across the playbook library.
- Generate Markdown reports for analyst handoff.
- **Export ATT&CK Navigator JSON** for visual gap analysis and coverage review.
- Run as a Docker Compose stack with React, FastAPI, Nginx, and PostgreSQL.

## 📸 Screenshots

| Screen | Description |
|--------|-------------|
| **Playbook Management** | Create, edit, delete, and map hunt playbooks with ATT&CK techniques |
| **Hunt Tasks** | Start hunts from playbooks and manage running/completed/archived sessions |
| **Evidence Log** | Record findings, artifacts, and analyst judgement with severity scoring |
| **ATT&CK Coverage** | Visual coverage map of techniques covered by the hunt library |

---

## Architecture

```text
Browser
  -> frontend: React + Vite served by unprivileged Nginx (host port 3000)
  -> /api proxy: Nginx forwards API requests
  -> api: FastAPI + SQLAlchemy (internal port 8000, bearer token required)
  -> postgres: PostgreSQL 16 (internal only)
```

See [docs/architecture.md](docs/architecture.md) for more detail.

## Quick Start

```bash
cp .env.example .env
# Set GOLEK_API_TOKEN and POSTGRES_PASSWORD in .env, e.g. with openssl rand -hex 32
docker compose up --build
```

Open:

- Web UI: http://localhost:3000 (asks once per browser session for the API token)
- API health through frontend proxy: http://localhost:3000/api/health

The API seeds sample playbooks automatically when the database is empty.

## Configuration

Environment variables are documented in [.env.example](.env.example).

- `GOLEK_API_TOKEN` (required, at least 16 characters): shared bearer token for
  every API route except `/health`. The API refuses to start without it.
- `POSTGRES_PASSWORD` (required): database password. Compose builds the API's
  `DATABASE_URL` from `POSTGRES_USER`, `POSTGRES_PASSWORD` and `POSTGRES_DB`, so use
  URL-safe characters. PostgreSQL only applies it when the volume is first created;
  for an existing volume, keep the old password or change it with `ALTER USER`.
- `FRONTEND_PORT` (default `3000`): the only published host port. The API and
  PostgreSQL are reachable only on the Compose network.

The frontend uses a same-origin `/api` proxy in Docker so it works from
`localhost`, LAN IPs, and remote browser sessions without rebuilding for each host.

## Development

Backend:

```bash
cd backend
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
export GOLEK_API_TOKEN="$(openssl rand -hex 32)"
uvicorn golekthreat.main:app --reload
```

Docker and CI install the hash-pinned `backend/requirements.txt` /
`backend/requirements-dev.txt`, generated from `pyproject.toml` by `pip-compile`
on Python 3.12 (the exact command is in each file's header).

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Tests and build checks:

```bash
cd backend
pytest

cd ../frontend
npm run build
```

## 📡 API Overview

Every route except `/health` requires `Authorization: Bearer <GOLEK_API_TOKEN>`;
requests without a valid token get `401`. Through the Docker stack, prefix paths with `/api`.

```bash
curl -H "Authorization: Bearer $GOLEK_API_TOKEN" http://localhost:3000/api/playbooks
```

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/health` | No | API health check |
| GET | `/playbooks` | Yes | List all playbooks |
| POST | `/playbooks` | Yes | Create playbook |
| GET | `/playbooks/{id}` | Yes | Get playbook + steps + queries |
| PUT | `/playbooks/{id}` | Yes | Update playbook |
| DELETE | `/playbooks/{id}` | Yes | Delete playbook |
| GET | `/sessions` | Yes | List hunt sessions |
| POST | `/sessions` | Yes | Start hunt session from playbook |
| GET | `/sessions/{id}` | Yes | Get session with steps and evidence |
| PATCH | `/sessions/{id}` | Yes | Update session title/analyst/scope/status |
| DELETE | `/sessions/{id}` | Yes | Delete session |
| PATCH | `/session-steps/{id}` | Yes | Update step status and notes |
| POST | `/sessions/{id}/evidence` | Yes | Add evidence item |
| PATCH | `/evidence/{id}` | Yes | Update evidence |
| DELETE | `/evidence/{id}` | Yes | Delete evidence |
| GET | `/coverage` | Yes | ATT&CK coverage stats |
| GET | `/sessions/{id}/report.md` | Yes | Markdown report |

## MITRE ATT&CK Catalog

The frontend MITRE catalog is generated from official MITRE ATT&CK Enterprise
STIX data. The generated file is checked in so the app works offline and builds
without downloading ATT&CK data.

Regenerate it with:

```bash
python scripts/generate_mitre_catalog.py
```

Source: https://github.com/mitre-attack/attack-stix-data

## Core Data Model

- `playbooks`: hunt hypothesis, severity, ATT&CK mapping, data sources, expected evidence, false positives, response recommendations.
- `playbook_steps`: ordered investigation steps.
- `playbook_queries`: Sigma, KQL, SPL, EQL, Wazuh, or other query starters.
- `hunt_sessions`: execution instances created from playbooks.
- `session_steps`: per-step execution status and analyst notes.
- `evidence_items`: evidence notes and artifact references tied to sessions.

## Roadmap

- ✅ Docker Compose deployment with PostgreSQL.
- ✅ MITRE ATT&CK catalog with Navigator export.
- ✅ Hunt session management with evidence tracking.
- ✅ Markdown report generation.
- ✅ Shared API token authentication.
- ⬜ Per-user accounts and RBAC.
- ⬜ Playbook import/export as YAML.
- ⬜ Scheduled hunt automation with cron backend.
- ⬜ Report export to HTML/PDF.
- ⬜ Detection rule attachment and validation workflows.
- ⬜ Integrations with SIEM/EDR query APIs.
- ⬜ Multi-tenant/workspace support.
- ⬜ Velociraptor integration for live endpoint hunting.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting guidance.

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
