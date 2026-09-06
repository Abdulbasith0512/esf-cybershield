# ESF CyberShield

Independent prototype of a security operations platform inspired by capabilities such as Managed SOC, UEBA, threat hunting, incident response, digital forensics, and GRC.

## Purpose

Ingest security events, normalize them, detect suspicious behavior with rules and ML, correlate related events into incidents, model attack relationships, map activity to MITRE ATT&CK, score risk, and provide an evidence-grounded AI investigation assistant.

> Step 1 — foundation only. No application logic is implemented yet.

## Planned architecture

```
events → normalize → detect (rules + ML) → correlate → incidents
                                              ├── attack graph (Neo4j)
                                              ├── ATT&CK mapping + risk scoring
                                              └── RAG assistant (FastEmbed + ChromaDB + Ollama)
```

| Layer | Stack |
|---|---|
| Backend | Python 3.11+, FastAPI, Pydantic, SQLAlchemy, PostgreSQL |
| Frontend | React, TypeScript, Vite, Tailwind CSS |
| ML | Pandas, NumPy, Scikit-learn |
| Graph | Neo4j |
| AI/RAG | FastEmbed, ChromaDB, Ollama |
| Infra | Docker, Docker Compose |

## Structure

```
esf-cybershield/
├── backend/        # FastAPI service (planned)
├── frontend/       # React + Vite + Tailwind app (planned)
├── ml/             # Notebooks, training, inference helpers (planned)
├── data/
│   ├── raw/        # Immutable ingested events
│   ├── processed/  # Normalized / enriched events
│   └── synthetic/  # Generated fixtures for local dev
├── docs/           # Architecture, threat model, runbooks (planned)
├── scripts/        # Dev / ops helper scripts (planned)
├── tests/          # Cross-cutting tests (planned)
├── docker/         # Dockerfiles per service (planned)
├── docker-compose.yml
├── .env.example
├── .gitignore
└── README.md
```

## Getting started (foundation)

```powershell
copy .env.example .env
docker compose config   # validates compose file
docker compose up -d    # starts foundation infra (PostgreSQL)
```

## Explicitly out of scope for Step 1

Authentication, detection rules, ML models, RAG, Neo4j wiring, dashboards.
These will be built incrementally in later steps.
