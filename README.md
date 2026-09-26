# packitupai

Team repo for **PackitUp.AI** — built for the Open Innovation · AI + Cybersecurity hackathon track.

## 🛡️ PackitUp.AI

Finds vulnerable dependencies in your codebase, traces the path each one takes into your app, and ranks what to fix first — instead of dumping a flat list of CVEs and leaving you to guess what actually matters.

**Demo flow:**
`repo or lockfile → dependency graph → OSV lookup → blast radius across your apps → risk ranking → AI explanation → preview the risk after upgrading`

### Why

Most dependency scanners stop at "here are your CVEs." They don't tell you:
- whether the vulnerable code is even reachable from what you actually run
- how many of your other apps share the same risky package
- what your risk score looks like *after* you upgrade, before you commit to it

DepShield AI answers all three, and explains the score in plain language instead of a raw CVSS number.

### How scoring works

Every point is traceable to a named signal — the LLM only explains the score, it never sets it.

| Signal | Effect |
| --- | --- |
| CVSS (OSV / NVD / advisory fallback) | up to 60 points |
| Production and reachable from direct deps | +15 |
| Dev-only / not reachable | −20 / −10 |
| Direct dependency | +5 |
| Used by N of your apps (Neo4j) | +3 per app, max +10 |
| Used by an app marked sensitive | +10 |
| Structural anomaly (IsolationForest on graph shape) | +5 |

Levels: 80+ critical, 60+ high, 35+ medium, below that low.

### Tech stack

- **Backend:** FastAPI (Python) — parsers for `package-lock.json`, `package.json`, `requirements.txt`, `pom.xml`; OSV + NVD lookups; Neo4j for the dependency graph and blast-radius queries; IsolationForest for structural anomaly detection; OpenAI for explanations (falls back to templates if no key is set)
- **Frontend:** React + TypeScript + Tailwind + React Flow (for the dependency graph visualization)
- **Infra:** Docker Compose (Postgres, Redis, Neo4j), Prometheus + Grafana for monitoring, GitHub Actions CI with OSV-Scanner

### Quick start

```bash
cd depshield-ai
cp .env.example .env        # set JWT_SECRET; OPENAI_API_KEY is optional
docker compose up --build
```

| Service | URL |
| --- | --- |
| App | http://localhost:8080 |
| API docs (Swagger) | http://localhost:8000/docs |
| Neo4j Browser | http://localhost:7474 |
| Prometheus + Grafana | `--profile monitoring` → :9090 / :3000 |

Full setup, local-dev-without-Docker instructions, troubleshooting, a 2-minute demo script, known limitations, and security notes are all in [`depshield-ai/README.md`](./depshield-ai).

### Known limits (short version)

- Reachability is approximate — dependency-graph reachable, not call-graph verified
- Python/Maven manifests without lockfiles only get direct dependencies
- npm lockfile v1 isn't supported (need v2/v3, npm 7+)

See the [full README](./depshield-ai) for the complete list and how to work around each one.

## Repo layout

```
packitup-ai/
  backend/    FastAPI app — parsing, OSV/NVD lookups, graph, scoring, LLM explanations
  frontend/   React + TypeScript dashboard
  samples/    Two deliberately vulnerable sample projects for the demo
  monitoring/ Prometheus config
```

## Team

Built collaboratively for the hackathon. See [`depshield-ai/README.md`](./depshield-ai) for the technical deep-dive.
