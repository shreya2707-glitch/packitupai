from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import graph as G
from .auth import create_token, get_current_user, hash_password, verify_password
from .config import settings
from .db import get_db
from .models import Finding, Scan, User
from .parsers import is_manifest_path
from .scanner import nodes_from_graph, run_scan, simulate_fix
from .schemas import Credentials, FindingOut, ScanCreate, ScanOut, SimulateIn, TokenOut

auth_router = APIRouter(prefix="/auth", tags=["auth"])
scans_router = APIRouter(prefix="/scans", tags=["scans"])
packages_router = APIRouter(prefix="/packages", tags=["packages"])


# ----------------------------------------------------------------------------- auth

@auth_router.post("/register", response_model=TokenOut, status_code=201)
def register(body: Credentials, db: Session = Depends(get_db)):
    if db.scalar(select(User).where(User.email == body.email)):
        raise HTTPException(409, "An account with this email already exists")
    user = User(email=body.email, password_hash=hash_password(body.password))
    db.add(user)
    db.commit()
    return TokenOut(access_token=create_token(user.id))


@auth_router.post("/login", response_model=TokenOut)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == form.username.strip().lower()))
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(401, "Email or password is incorrect")
    return TokenOut(access_token=create_token(user.id))


# ---------------------------------------------------------------------------- scans

def _enqueue(scan_id: int, background: BackgroundTasks) -> None:
    """Use the Redis/RQ worker when available, otherwise run in-process."""
    try:
        from redis import Redis
        from rq import Queue

        Queue(connection=Redis.from_url(settings.redis_url, socket_connect_timeout=1)).enqueue(
            "app.scanner.run_scan", scan_id, job_timeout=900
        )
    except Exception:
        background.add_task(run_scan, scan_id)


def _own_scan(scan_id: int, user: User, db: Session) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan or scan.user_id != user.id:
        raise HTTPException(404, "Scan not found")
    return scan


@scans_router.post("", response_model=ScanOut, status_code=202)
def create_scan(body: ScanCreate, background: BackgroundTasks, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    url = body.repo_url.strip()
    if "github.com" not in url:
        raise HTTPException(422, "Enter a GitHub repository URL, like https://github.com/owner/repo")
    name = body.name or url.rstrip("/").removesuffix(".git").split("github.com/")[-1]
    scan = Scan(user_id=user.id, name=name, source_type="github", repo_url=url, sensitive=body.sensitive)
    db.add(scan)
    db.commit()
    _enqueue(scan.id, background)
    return scan


@scans_router.post("/upload", response_model=ScanOut, status_code=202)
async def upload_scan(
    background: BackgroundTasks,
    files: list[UploadFile] = File(...),
    name: str = Form("uploaded project"),
    sensitive: bool = Form(False),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    manifests: dict[str, str] = {}
    for f in files[:20]:
        if not is_manifest_path(f.filename or ""):
            continue
        data = await f.read()
        if len(data) > 8_000_000:
            raise HTTPException(413, f"{f.filename} is larger than 8 MB")
        manifests[f.filename] = data.decode("utf-8", errors="replace")
    if not manifests:
        raise HTTPException(422, "Upload package-lock.json, package.json, requirements.txt or pom.xml")
    scan = Scan(user_id=user.id, name=name, source_type="upload", manifests=manifests, sensitive=sensitive)
    db.add(scan)
    db.commit()
    _enqueue(scan.id, background)
    return scan


@scans_router.get("", response_model=list[ScanOut])
def list_scans(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.scalars(select(Scan).where(Scan.user_id == user.id).order_by(Scan.created_at.desc()).limit(50)).all()


@scans_router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _own_scan(scan_id, user, db)


@scans_router.get("/{scan_id}/findings", response_model=list[FindingOut])
def get_findings(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _own_scan(scan_id, user, db)
    return db.scalars(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.risk_score.desc())).all()


@scans_router.get("/{scan_id}/graph")
def get_graph(
    scan_id: int,
    focus: str = Query("attack", pattern="^(attack|full)$"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = _own_scan(scan_id, user, db)
    if not scan.graph:
        raise HTTPException(409, "Scan has not finished yet")
    nodes, roots = nodes_from_graph(scan.graph)
    meta = {n["key"]: n for n in scan.graph["nodes"]}
    truncated = False

    if focus == "full" and len(nodes) <= 400:
        keep = set(nodes)
        edges = [(G.APP_NODE, r) for r in sorted(roots)] + [(k, c) for k, d in nodes.items() for c in d.depends_on if c in nodes]
    else:
        truncated = focus == "full"
        vulnerable = {k for k, n in meta.items() if n["vuln_count"]}
        keep, edges = G.attack_subgraph(nodes, roots, vulnerable)

    return {
        "truncated": truncated,
        "nodes": [{k: v for k, v in meta[key].items() if k != "depends_on"} for key in keep],
        "edges": [{"source": a, "target": b} for a, b in edges],
    }


@scans_router.post("/{scan_id}/simulate")
def simulate(scan_id: int, body: SimulateIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = _own_scan(scan_id, user, db)
    if scan.status != "done":
        raise HTTPException(409, "Scan has not finished yet")
    return simulate_fix(scan, [u.model_dump() for u in body.upgrades])


@scans_router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db.delete(_own_scan(scan_id, user, db))
    db.commit()


# ------------------------------------------------------------------------- packages

@packages_router.get("/apps")
def package_apps(key: str, user: User = Depends(get_current_user)):
    """Which of your applications use this package version? (Neo4j)"""
    return {"key": key, "apps": G.apps_using(user.id, [key]).get(key, [])}
