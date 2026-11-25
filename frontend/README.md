# Arbiter SecurityBench Frontend

React + TypeScript + Tailwind CSS + Recharts + React Router analytics dashboard connected directly to the FastAPI backend (`/api/v1/*` and `/health`).

## Running Locally

1. Start the FastAPI backend (with `Arbiter Security Benchmark v1.0` preloaded):

```powershell
$env:ASB_DATABASE_URL = "sqlite:///./securitybench.db"
uvicorn arbiter_securitybench.api.server:app --host 127.0.0.1 --port 8000 --reload
```

2. Install dependencies and start the Vite development server:

```powershell
cd frontend
npm install
npm run dev
```

Vite proxies `/api/*` and `/health` requests directly to `http://127.0.0.1:8000`.

## Build & Test

```powershell
cd frontend
npm run build
npm test
```
