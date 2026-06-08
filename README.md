# GolekThreat

GolekThreat is a threat hunting management console for building hunt playbooks,
mapping them to MITRE ATT&CK, running repeatable hunt sessions, tracking evidence,
and producing analyst-ready Markdown reports.

The name combines **Golek** (Javanese/Indonesian for "search") with threat hunting.

## What It Does

- Manage threat hunting playbooks with hypothesis, severity, data sources, expected evidence, false positives, response guidance, steps, and starter queries.
- Map playbooks to MITRE ATT&CK Enterprise techniques using a generated catalog from official ATT&CK STIX data.
- Run hunt sessions as task-like work items with status, analyst, scope, progress, step notes, and evidence logs.
- Add, edit, and delete evidence tied to hunt sessions.
- Track ATT&CK coverage across the playbook library.
- Generate Markdown reports for analyst handoff.
- Run as a Docker Compose stack with React, FastAPI, Nginx, and PostgreSQL.

## Screens

- **Playbook Management**: create, edit, delete, and map hunt playbooks.
- **Hunt Tasks**: start hunts from playbooks and manage running/completed/archived sessions.
- **Evidence Log**: record findings, artifacts, and analyst judgement.
- **ATT&CK Coverage**: review techniques covered by the hunt library.

## Architecture

```text
Browser
  -> frontend: React + Vite served by Nginx
  -> /api proxy: Nginx forwards API requests
  -> api: FastAPI + SQLAlchemy
  -> postgres: PostgreSQL 16
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

- User authentication and RBAC.
- Playbook import/export as YAML.
- Organization/workspace support.
- Report export to HTML/PDF.
- Detection rule attachment and validation workflows.
- Integrations with SIEM/EDR query APIs.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting guidance.

## License

This project is licensed under the [MIT License](LICENSE).
