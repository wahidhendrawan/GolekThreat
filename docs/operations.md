# Operations

## Start the Stack

```bash
cp .env.example .env  # then set GOLEK_API_TOKEN and POSTGRES_PASSWORD
docker compose up --build
```

## Useful Commands

```bash
docker compose ps
docker compose logs --tail=200 --no-color
docker compose logs --tail=200 --no-color api frontend
```

## Health Checks

```bash
curl http://localhost:3000/api/health
curl -H "Authorization: Bearer $GOLEK_API_TOKEN" http://localhost:3000/api/playbooks
```

## Database Access

```bash
docker compose exec postgres psql -U golek -d golekthreat
```

## Reset Local Data

This removes all local PostgreSQL data for the Compose project.

```bash
docker compose down -v
docker compose up --build
```

## Production Hardening Checklist

- Add per-user accounts and RBAC (the API uses one shared bearer token).
- Put the app behind TLS.
- Use managed PostgreSQL or persistent encrypted volumes.
- Rotate `GOLEK_API_TOKEN` and the database password.
- Configure backups and recovery testing.
- Add audit logging for playbook/session/evidence changes.
