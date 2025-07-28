# Chat Bot Pro V2

A production-grade micro-service SaaS platform featuring:

- **Rust** backend (Axum)
- **React TypeScript** frontend (Vite)
- **Python FastAPI** AI/Analytics worker
- **PostgreSQL**, **Redis** persistence & caching
- **Docker-Compose** powered infrastructure with Nginx reverse proxy & automatic Let’s Encrypt SSL
- **Prometheus + Grafana** observability
- CI/CD via **GitHub Actions** (lint → test → build → deploy)

---

## Quick Start (local)

```bash
cp .env.example .env   # adjust creds/secrets
docker compose up -d --build
```

| Service    | URL                                 |
|------------|-------------------------------------|
| Rust API   | http://localhost:8080/health        |
| Frontend   | http://localhost:3000               |
| AI Worker  | http://localhost:8000/health        |
| Prometheus | http://localhost:9090               |
| Grafana    | http://localhost:3001 (admin/admin) |

---

## Project Layout

```
backend/     # Rust micro-service
frontend/    # React SPA (Vite + TS)
ai_worker/   # Python FastAPI micro-service
docs/        # Architecture & ADRs
docker-compose.yml
```

---

## Developer Workflow

1. Write code & tests.
2. Run `docker compose exec backend cargo test` or similar.
3. Ensure `make ci` passes locally.
4. Open PR – GitHub Actions will lint, test, build images.

---

## Security & Compliance

See `docs/SECURITY.md` for threat model, hardening checklist, and compliance notes.

---

## License

MIT 