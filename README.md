# GolekThreat

GolekThreat is a threat hunting playbook engine for turning hypotheses into repeatable hunts, evidence trails, ATT&CK coverage, and analyst-ready reports.

The name combines **Golek** (Javanese/Indonesian for "search") with threat hunting.

## Features

- Playbook library for structured threat hunt hypotheses.
- Hunt session runner with step status tracking.
- Evidence notes tied to hunt sessions and playbook steps.
- MITRE ATT&CK tactic/technique coverage summary.
- Markdown report generation for analyst handoff.
- Docker Compose stack with React, FastAPI, and PostgreSQL.

## Architecture

```text
frontend/   React + Vite + TypeScript
backend/    FastAPI + SQLAlchemy + PostgreSQL
postgres    PostgreSQL 16 container
```

## Quick Start

```bash
cp .env.example .env
docker compose up --build
```

Open:

- Web UI: http://localhost:3000
- API docs: http://localhost:8000/docs

The API seeds sample playbooks automatically on startup.

## Local Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
uvicorn golekthreat.main:app --reload
```

## Local Frontend

```bash
cd frontend
npm install
npm run dev
```

## Core Data Model

- `playbooks`: hunt hypothesis, severity, tactic, technique, data sources, expected evidence, false positives, response recommendations.
- `playbook_steps`: ordered investigation steps.
- `playbook_queries`: Sigma, KQL, SPL, EQL, or Wazuh queries.
- `hunt_sessions`: execution instances created from playbooks.
- `session_steps`: per-step execution status.
- `evidence_items`: analyst evidence notes and artifact references.

## Roadmap

- User authentication and RBAC.
- Playbook import/export as YAML.
- Sigma skeleton generation from confirmed hunt findings.
- HTML/PDF report exports.
- Redis worker for long-running report and enrichment jobs.
- Integrations with Detection-Rules and ThreatDock.
