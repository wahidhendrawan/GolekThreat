# Operations

## Start the Stack

```bash
cp .env.example .env
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
curl http://localhost:8000/health
curl http://localhost:3000/api/health
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

- Add authentication and RBAC.
- Put the app behind TLS.
- Use managed PostgreSQL or persistent encrypted volumes.
- Rotate database passwords and remove default credentials.
- Restrict API and database ports at the network layer.
- Configure backups and recovery testing.
- Add audit logging for playbook/session/evidence changes.
