# Architecture

GolekThreat is a containerized web application for threat hunt playbook and
session management.

## Services

- `frontend`: React/Vite application served by Nginx.
- `api`: FastAPI application exposing REST endpoints.
- `postgres`: PostgreSQL 16 database.

## Request Flow

```text
Browser
  -> http://localhost:3000
  -> Nginx frontend
  -> /api/* proxy
  -> FastAPI api:8000
  -> PostgreSQL
```

The frontend defaults to `VITE_API_URL=/api`. In Docker Compose, Nginx proxies
`/api/*` to the `api` service over the Compose network. This avoids browser-side
CORS and host-name issues when the app is opened from a LAN IP.

Only the frontend is published on the host. The API and PostgreSQL are reachable
only on the Compose network, and every API route except `/health` requires
`Authorization: Bearer <GOLEK_API_TOKEN>`.

## Domain Model

```text
Playbook
  -> PlaybookStep[]
  -> PlaybookQuery[]
  -> HuntSession[]

HuntSession
  -> SessionStep[]
  -> EvidenceItem[]
```

Sessions copy playbook steps at creation time so analysts can update session
progress without mutating the original playbook.

## MITRE ATT&CK Data

The UI includes a generated Enterprise ATT&CK technique catalog in
`frontend/src/mitreCatalog.ts`. It is generated from official MITRE ATT&CK STIX
data and checked into the repo so builds do not need network access.

## Current Boundaries

- One shared API token; no per-user accounts or RBAC yet.
- No background workers.
- No migrations framework yet; SQLAlchemy creates tables at startup for the MVP.
- Reports are generated as Markdown over HTTP.
