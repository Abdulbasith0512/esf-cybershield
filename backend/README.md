# ESF CyberShield — Backend (FastAPI foundation)

Minimal API foundation. Only `GET /health` exists in this step.

## Install

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Requires Python 3.11+.

## Configure

Copy the repo env template (placeholders only, never commit real secrets):

```powershell
copy ..\.env.example ..\.env
```

`DATABASE_URL` must be set but is not queried by `/health` yet.

## Run

```powershell
cd backend
uvicorn app.main:app --reload --port 8000
```

## Test

```powershell
curl http://localhost:8000/health
# {"status":"healthy","service":"esf-cybershield-backend"}
```

Interactive docs: `http://localhost:8000/docs`
OpenAPI JSON: `http://localhost:8000/openapi.json`
