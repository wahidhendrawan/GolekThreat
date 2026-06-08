# Contributing

Thanks for improving GolekThreat.

## Development Setup

Use Docker Compose for the full stack:

```bash
cp .env.example .env
docker compose up --build
```

Backend-only setup:

```bash
cd backend
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Frontend-only setup:

```bash
cd frontend
npm install
npm run build
```

## Pull Request Checklist

- Keep changes scoped to one feature or fix.
- Update docs when behavior, setup, or user-facing workflows change.
- Add or update tests for backend behavior changes.
- Run backend tests and frontend build before submitting.
- Do not commit `.env`, database files, generated build output, or secrets.

## MITRE Catalog Updates

Regenerate the checked-in ATT&CK catalog with:

```bash
python scripts/generate_mitre_catalog.py
```

Review the generated diff before committing because ATT&CK releases can change
many techniques at once.
