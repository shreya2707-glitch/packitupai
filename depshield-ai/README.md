# DepShield AI

Finds vulnerable dependencies, shows the path each one takes into your app, and ranks what to fix first.

Demo flow: **repo or lockfile -> dependency graph -> OSV lookup -> blast radius across your apps -> risk ranking -> AI explanation -> preview the risk after upgrading.**

## Run it

Requirements: Docker with Compose.

```bash
cp .env.example .env        # set JWT_SECRET; OPENAI_API_KEY is optional
docker compose up --build
```

| Service | URL |
| --- | --- |
| App | http://localhost:8080 |
| API docs (Swagger) | http://localhost:8000/docs |
| Neo4j Browser | http://localhost:7474 (neo4j / depshield-pass) |
| Prometheus + Grafana | `docker compose --profile monitoring up` -> :9090 and :3000 |

Without `OPENAI_API_KEY` the app still works and writes template explanations instead of LLM ones.

### Local development (no Docker for app code)

```bash
# infra only (the dev file publishes Postgres and Redis on localhost)
docker compose -f docker-compose.yml -f docker-compose.dev.yml up postgres redis neo4j

# backend
cd backend && python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL=postgresql+psycopg2://depshield:depshield@localhost:5432/depshield
export REDIS_URL=redis://localhost:6379/0 NEO4J_URI=bolt://localhost:7687 NEO4J_PASSWORD=depshield-pass
uvicorn app.main:app --reload
# optional worker; without Redis the API runs scans in-process
rq worker --url $REDIS_URL

# frontend
cd frontend && npm install && npm run dev      # http://localhost:5173
```

The API needs Postgres. Redis and Neo4j are optional at runtime: scans fall back to in-process execution and single-app blast radius.

## Troubleshooting

- **`env file .env not found`**: run `cp .env.example .env` first (Windows: `copy .env.example .env`).
- **Port already in use** (8080, 8000, 7474, 7687): stop whatever uses it, or change the left side of the port mapping in `docker-compose.yml`. If you change the API port, also change `VITE_API_URL` in the `frontend` build args and `CORS_ORIGINS` in `.env`.
- **Blast radius shows only one app**: Neo4j takes about 30 seconds to start, and the worker gives up on it if the first scan runs earlier. Wait for `http://localhost:7474` to load, then `docker compose restart worker` and re-scan.
- **Scan stuck on "queued"**: check the worker with `docker compose logs -f worker`.
- **Scan fails with a GitHub error**: unauthenticated GitHub API calls are rate limited; set `GITHUB_TOKEN` in `.env` and `docker compose up -d`.
- **Changed `.env` or code**: `docker compose up --build -d`.
- **Start clean** (deletes all data): `docker compose down -v`.

## Demo script (2 minutes)

1. Create an account.
2. Upload `samples/admin-dashboard/package-lock.json` + `package.json`, name it `admin-dashboard`.
3. Upload `samples/payments-api/package-lock.json` + `package.json`, name it `payments-api`, and tick **Handles payments, auth or other sensitive data**.
4. Open `payments-api`. `lodash`, `express` and `qs` are also used by `admin-dashboard`, so their scores rise (blast radius), and the app is marked sensitive. Order matters: blast radius only counts apps that were scanned before. Re-scan an app after adding others to refresh its numbers.
5. Click the top finding: the graph traces `app > ... > package`, and the list shows why it scored what it did.
6. Tick "Preview upgrade" on a few findings, then **Preview updated risk** to show the score dropping.

Results come from the live OSV database, so exact findings change over time. The sample lockfiles are for scanning only, not for `npm install`.

## How the scoring works

Every point is traceable to a named signal, and the LLM only explains it. It never sets the score.

| Signal | Effect |
| --- | --- |
| CVSS (v3 vector from OSV, NVD or advisory label as fallbacks) | up to 60 points |
| Production and reachable from direct deps | +15 |
| Dev-only / not reachable | -20 / -10 |
| Direct dependency | +5 |
| Used by N of your apps (Neo4j) | +3 per app, max +10 |
| Used by an app marked sensitive | +10 |
| Structural anomaly (IsolationForest on fan-in, fan-out, depth, vuln count) | +5 |

Levels: 80+ critical, 60+ high, 35+ medium, below that low. Weights live in `backend/app/risk.py`.

## Layout

```
backend/app
  parsers.py      package-lock.json, package.json, requirements.txt, pom.xml -> graph
  osv_client.py   OSV querybatch + advisory details, NVD fallback, CVSS v3 calculator, Redis cache
  graph.py        reachability, paths, attack subgraph (pure Python) + Neo4j sync and queries
  risk.py         scoring + IsolationForest anomaly detection
  llm.py          OpenAI explanations with template fallback
  scanner.py      pipeline, RQ job entry point, what-if simulation
  routes.py       auth, scans, graph, simulate
frontend/src      React + TypeScript + Tailwind + React Flow dashboard
samples/          two deliberately vulnerable projects for the demo
.github/workflows CI (tests + build) and OSV-Scanner on this repo
```

## Tests

```bash
cd backend && pytest -q
```

Covers the parsers, CVSS maths, scoring, graph algorithms, and the full pipeline (with OSV and Neo4j mocked), including the what-if simulation.

## Known limits

Be upfront about these in a demo.

- **Reachability is approximate.** "Reachable" means "reachable through production dependency edges", not "your code calls the vulnerable function". True call-graph reachability needs per-language static analysis.
- **Anomaly detection is structural.** It flags unusual graph positions. It does not yet look at registry signals such as sudden maintainer or publish-frequency changes.
- **Python and Maven get direct dependencies only.** `requirements.txt` and `pom.xml` have no lockfile, so transitive dependencies are missing. Generate a full list (for example `pip freeze` output) for better coverage. Unpinned or parent-managed versions are skipped with a warning.
- **The what-if keeps an upgraded package's old sub-dependencies.** The real tree changes only after re-locking.
- **npm lockfile v1 is rejected.** Use npm 7+ (`lockfileVersion` 2 or 3).
- **GitHub scans read manifests via the GitHub API**, up to 12 files, four folders deep. Private repos need `GITHUB_TOKEN`.
- Tables are created on startup. Use Alembic before this holds real data.

## Not included, and how to add it

- **shadcn/ui**: the UI is plain Tailwind. Run `npx shadcn@latest init` in `frontend/` if you want its components.
- **OAuth 2.0 / GitHub login**: auth is email + password with JWT. Add an OAuth provider route beside `/auth/login`.
- **OSV-Scanner / Trivy as a backend engine**: the backend calls the OSV API directly. OSV-Scanner runs in CI against this repo (`.github/workflows/dependency-scan.yml`).
- **Cloud deployment**: the stack is containerised, so any of AWS ECS, Azure Container Apps or Cloud Run works. Swap the compose Postgres, Redis and Neo4j for managed services and set the env vars.
- **Grafana dashboards**: Prometheus scrapes `/metrics`. Add Prometheus as a Grafana data source and import a FastAPI dashboard.

## Security notes

- Set a long random `JWT_SECRET`.
- Never commit `.env`.
- Do not expose Postgres, Redis or Neo4j ports publicly. The compose file publishes the Neo4j ports for the demo only.
