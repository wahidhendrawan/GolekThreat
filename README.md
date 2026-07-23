[![CI](https://github.com/wahidhendrawan/GolekThreat/actions/workflows/ci.yml/badge.svg)](https://github.com/wahidhendrawan/GolekThreat/actions/workflows/ci.yml)

# GolekThreat 🔍

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL-3.0-blue.svg)](https://github.com/wahidhendrawan/GolekThreat/blob/main/LICENSE)
[![Release](https://img.shields.io/badge/release-v1.0.0-green.svg)](https://github.com/wahidhendrawan/GolekThreat/releases)
[![CI](https://github.com/wahidhendrawan/GolekThreat/actions/workflows/ci.yml/badge.svg)](https://github.com/wahidhendrawan/GolekThreat/actions)
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
| **⏰ Scheduled Hunts** | Cron-style automation for recurring hunt jobs with configurable schedules |
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
- **Schedule recurring hunts** with cron-style automation.
- Run as a Docker Compose stack with React, FastAPI, Nginx, and PostgreSQL.

## 📸 Screenshots

| Screen | Description |
|--------|-------------|
| **Playbook Management** | Create, edit, delete, and map hunt playbooks with ATT&CK techniques |
| **Hunt Tasks** | Start hunts from playbooks and manage running/completed/archived sessions |
| **Evidence Log** | Record findings, artifacts, and analyst judgement with severity scoring |
| **ATT&CK Coverage** | Visual coverage map of techniques covered by the hunt library |
| **Scheduled Hunt Dashboard** | Manage recurring hunt schedules and view execution history |

---

## Architecture

```text
Browser
  -> frontend: React + Vite served by Nginx (Port 3000)
  -> /api proxy: Nginx forwards API requests
  -> api: FastAPI + SQLAlchemy (Port 8000)
  -> postgres: PostgreSQL 16 (Port 5433)
  -> scheduler: Cron-style hunt scheduler (built-in)
```

See [docs/architecture.md](docs/architecture.md) for more detail.

## Quick Start

```bash
cp .env.example .env
docker compose up --build
```

Open:

- Web UI: http://localhost:3000
- API docs: http://localhost:8000/docs
- API health through frontend proxy: http://localhost:3000/api/health

The API seeds sample playbooks automatically when the database is empty.

## Configuration

Environment variables are documented in [.env.example](.env.example).

Default ports:

- Frontend: `3000`
- API: `8000`
- PostgreSQL host port: `5433`

The frontend uses a same-origin `/api` proxy in Docker so it works from
`localhost`, LAN IPs, and remote browser sessions without rebuilding for each host.

## Development

Backend:

```bash
cd backend
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
uvicorn golekthreat.main:app --reload
```

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

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/health` | No | API health check |
| GET | `/api/playbooks` | No | List all playbooks |
| POST | `/api/playbooks` | Yes | Create playbook |
| GET | `/api/playbooks/:id` | No | Get playbook + steps + queries |
| PUT | `/api/playbooks/:id` | Yes | Update playbook |
| DELETE | `/api/playbooks/:id` | Yes | Delete playbook |
| GET | `/api/hunt-sessions` | No | List hunt sessions |
| POST | `/api/hunt-sessions` | Yes | Create hunt session from playbook |
| GET | `/api/hunt-sessions/:id` | No | Get session with evidence |
| PUT | `/api/hunt-sessions/:id` | Yes | Update session status/progress |
| POST | `/api/evidence` | Yes | Add evidence item |
| DELETE | `/api/evidence/:id` | Yes | Delete evidence |
| GET | `/api/coverage` | No | ATT&CK coverage stats |
| GET | `/api/coverage/navigator` | No | Export ATT&CK Navigator JSON |
| GET | `/api/reports/:id/markdown` | Yes | Generate Markdown report |

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
- ⬜ User authentication and RBAC.
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
