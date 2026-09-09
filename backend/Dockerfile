# ESF CyberShield backend — FastAPI + Uvicorn, SQLite-ready.
# Build context: repository root (docker-compose.yml sets context: .).
# The image carries app code + migrations, plus the minimal demo-seed assets
# under /srv/seed/ (seed script, 200-event demo dataset, tracked UEBA model).
# Benchmark datasets, .env files, and *.db files are excluded below.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_URL=sqlite:////data/esf.db \
    SEED_BACKEND_DIR=/srv/app \
    SEED_DATA_FILE=/srv/seed/data/sample_demo.jsonl \
    SEED_MODEL_FILE=/srv/seed/models/model.joblib

WORKDIR /srv/app

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
COPY backend/alembic ./alembic
COPY backend/alembic.ini ./alembic.ini

# Demo-seed assets ONLY (used by one-off `python /srv/seed/scripts/seed_demo.py`;
# never touched by the normal API runtime, which loads no model file).
COPY scripts/seed_demo.py /srv/seed/scripts/seed_demo.py
COPY data/synthetic/sample_demo.jsonl /srv/seed/data/sample_demo.jsonl
COPY models/ueba/model.joblib /srv/seed/models/model.joblib

EXPOSE 8000

# DB-free liveness probe (GET /health never touches the database) against the
# effective serving port (Render injects PORT; 8000 is the local fallback).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os,sys,urllib.request; p=os.environ.get('PORT','8000'); sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{p}/health', timeout=4).status == 200 else 1)"

# Exactly one worker: deployment uses SQLite. Honors Render's injected PORT
# with an 8000 fallback for local runs. No automatic migrations or seeding;
# initialize a fresh database once with:
#   docker compose run --rm backend alembic upgrade head
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
