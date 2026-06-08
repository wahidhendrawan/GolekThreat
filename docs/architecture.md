# Architecture

GolekThreat is designed as a containerized web application.

## Services

- `frontend`: React/Vite UI served by Nginx.
- `api`: FastAPI application exposing REST endpoints.
- `postgres`: PostgreSQL 16 database.

## Request Flow

```text
Browser -> Frontend -> FastAPI API -> PostgreSQL
```

The frontend reads `VITE_API_URL` at build time. In Docker Compose, the browser calls `http://localhost:8000`.

## MVP Boundaries

The MVP intentionally avoids background workers and authentication. The first useful workflow is:

1. Browse playbooks.
2. Start a hunt session.
3. Track session steps.
4. Add evidence.
5. Generate a Markdown report.
6. Review ATT&CK coverage.
