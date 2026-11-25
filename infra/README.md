# Infrastructure & Containerization Skeleton

Placeholder directory for Phase 1–4 Docker, PostgreSQL, Redis, and Celery deployment definitions.

## Planned Components
- `Dockerfile.api`: FastAPI REST API container
- `Dockerfile.worker`: Isolated Celery worker container for attack execution and evaluation
- `Dockerfile.sandbox`: Network-restricted sandbox container for Agent and Tool Security harnesses
- `docker-compose.yml`: Local development stack (PostgreSQL, Redis, API, Worker, Frontend)
