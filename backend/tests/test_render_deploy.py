"""Render deployment configuration tests. Static only; no Render API, no Docker."""

import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent

if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

import yaml  # noqa: E402

DOCKERFILE = (REPO / "backend" / "Dockerfile").read_text(encoding="utf-8")
IGNORE = (REPO / ".dockerignore").read_text(encoding="utf-8")
RENDER = yaml.safe_load((REPO / "render.yaml").read_text(encoding="utf-8"))
COMPOSE = yaml.safe_load((REPO / "docker-compose.yml").read_text(encoding="utf-8"))

SEED_SOURCES = {
    "scripts/seed_demo.py",
    "data/synthetic/sample_demo.jsonl",
    "models/ueba/model.joblib",
}


def _copy_sources():
    sources = []
    for line in DOCKERFILE.splitlines():
        stripped = line.strip()
        if stripped.startswith("COPY "):
            parts = stripped.split()
            sources.extend(parts[1:-1])
    return sources


def test_backend_port_honors_render_env():
    assert "${PORT:-8000}" in DOCKERFILE
    assert "--host 0.0.0.0" in DOCKERFILE
    assert "--workers 1" in DOCKERFILE
    assert "uvicorn app.main:app" in DOCKERFILE
    assert "onrender" not in DOCKERFILE


def test_healthcheck_probes_effective_port():
    assert "HEALTHCHECK" in DOCKERFILE
    assert "/health" in DOCKERFILE
    assert 'os.environ.get(\'PORT\',\'8000\')' in DOCKERFILE.replace('"', "'").replace(" ", "")


def test_startup_runs_no_migrations_or_seeding():
    cmd = next(line for line in DOCKERFILE.splitlines()
               if line.strip().startswith("CMD ["))
    assert "uvicorn" in cmd
    assert "alembic" not in cmd and "seed_demo" not in cmd
    assert not any(line.strip().startswith("RUN")
                   and ("alembic" in line or "seed_demo" in line)
                   for line in DOCKERFILE.splitlines())


def test_seed_assets_exact_and_present():
    sources = _copy_sources()
    assert SEED_SOURCES <= set(sources)
    for source in SEED_SOURCES:
        assert (REPO / source).exists(), source
    blob = DOCKERFILE.lower()
    assert "data/public" not in blob
    assert not any(source.startswith(".env") or source.endswith(".db")
                   for source in sources)
    for line in DOCKERFILE.splitlines():
        if line.strip().startswith("COPY "):
            assert "cse" not in line.lower() and "cicids" not in line.lower()


def test_dockerignore_allowlists_only_seed_inputs():
    assert "data/public/" in IGNORE
    lines = [line.strip() for line in IGNORE.splitlines()
             if line.strip() and not line.strip().startswith("#")]
    for asset in ("sample_demo.jsonl", "model.joblib", "seed_demo.py"):
        hits = [line for line in lines if asset in line]
        assert hits and all(hit.startswith("!") for hit in hits), asset


def test_seed_assets_tracked_in_git():
    """Render builds from a fresh clone: every Dockerfile COPY source must be
    tracked. Regression test for the missing models/ueba/model.joblib build
    failure (the file existed locally but was git-ignored)."""
    import subprocess

    if not (REPO / ".git").exists():
        pytest.skip("not a git checkout")
    for source in ("backend/requirements.txt", "backend/alembic.ini",
                   "scripts/seed_demo.py", "data/synthetic/sample_demo.jsonl",
                   "models/ueba/model.joblib"):
        assert (REPO / source).exists(), source
        subprocess.run(["git", "ls-files", "--error-unmatch", source],
                       cwd=REPO, check=True, capture_output=True)


def _services():
    return {service["name"]: service for service in RENDER["services"]}


def test_render_services_present():
    services = _services()
    assert set(services) == {"esf-backend", "esf-frontend"}
    for service in services.values():
        assert service["type"] == "web" and service["runtime"] == "docker"


def test_render_backend_config():
    backend = _services()["esf-backend"]
    assert backend["dockerfilePath"] == "./backend/Dockerfile"
    assert backend["dockerContext"] == "."
    assert backend["healthCheckPath"] == "/health"
    assert backend["disk"]["mountPath"] == "/data"
    assert backend["disk"]["name"] == "esf-sqlite"
    env = {item["key"]: item["value"] for item in backend["envVars"]}
    assert env["DATABASE_URL"] == "sqlite:////data/esf.db"
    assert env["APP_ENV"] == "production"
    assert "*" not in env["CORS_ORIGINS"]
    assert "<frontend-render-url>" in env["CORS_ORIGINS"]


def test_render_frontend_config():
    frontend = _services()["esf-frontend"]
    assert frontend["dockerfilePath"] == "./frontend/Dockerfile"
    assert frontend["dockerContext"] == "./frontend"
    env = {item["key"]: item["value"] for item in frontend["envVars"]}
    assert "<backend-render-url>" in env["NEXT_PUBLIC_API_BASE_URL"]


def test_render_has_no_secrets_or_invented_fields():
    keys = [item["key"].lower()
            for service in RENDER["services"] for item in service.get("envVars", [])]
    for banned in ("password", "secret", "api_key", "api-key", "token"):
        assert not any(banned in key for key in keys), banned
    blob = (REPO / "render.yaml").read_text(encoding="utf-8").lower()
    assert "fromservice" not in blob
    assert "plan" not in RENDER["services"][0] and "plan" not in RENDER["services"][1]


def test_compose_matches_render_seed_path():
    backend = COMPOSE["services"]["backend"]
    assert backend["build"] == {"context": ".", "dockerfile": "./backend/Dockerfile"}
    seed = COMPOSE["services"]["seed"]
    assert seed["command"] == ["python", "/srv/seed/scripts/seed_demo.py"]
    assert seed["environment"]["DATABASE_URL"] == "sqlite:////data/esf.db"
    assert "esf-sqlite:/data" in seed["volumes"]
    assert not any(":/seed" in volume for volume in seed["volumes"])
