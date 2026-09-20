"""Graph helpers.

Pure-Python algorithms (reachability, depth, attack paths) work on the in-memory
graph, so scans still work if Neo4j is down. Neo4j adds the cross-application
view: which of your apps share a vulnerable package (blast radius).
"""
from __future__ import annotations

import logging
from collections import deque

from .config import settings
from .parsers import Dep

log = logging.getLogger("depshield.graph")

APP_NODE = "app"


# ------------------------------------------------------------------ in-memory algorithms

def prod_reachable(nodes: dict[str, Dep], roots: set[str]) -> set[str]:
    """Packages reachable from the app through production (non-dev) dependencies."""
    seen: set[str] = set()
    queue = deque(k for k in roots if k in nodes and not nodes[k].dev)
    while queue:
        key = queue.popleft()
        if key in seen:
            continue
        seen.add(key)
        for child in nodes[key].depends_on:
            if child in nodes and not nodes[child].dev and child not in seen:
                queue.append(child)
    return seen


def bfs_paths(nodes: dict[str, Dep], roots: set[str]) -> tuple[dict[str, int], dict[str, str | None]]:
    """Shortest depth (direct deps = 1) and parent pointer for each node.

    Production dependencies are walked first so explanations show the path that
    actually ships; dev-only packages are filled in afterwards.
    """
    depth: dict[str, int] = {}
    parent: dict[str, str | None] = {}

    def walk(seeds: list[str], allow) -> None:
        queue = deque()
        for r in seeds:
            if r in nodes and r not in depth and allow(r):
                depth[r], parent[r] = 1, None
                queue.append(r)
        while queue:
            key = queue.popleft()
            for child in nodes[key].depends_on:
                if child in nodes and child not in depth and allow(child):
                    depth[child], parent[child] = depth[key] + 1, key
                    queue.append(child)

    ordered = sorted(roots)
    walk(ordered, lambda k: not nodes[k].dev)
    walk(ordered, lambda k: True)
    return depth, parent


def path_to(key: str, parent: dict[str, str | None]) -> list[str]:
    out, cur = [], key
    while cur is not None:
        out.append(cur)
        cur = parent.get(cur)
    return [APP_NODE, *reversed(out)]


def dependents_count(nodes: dict[str, Dep]) -> dict[str, int]:
    counts = {k: 0 for k in nodes}
    for dep in nodes.values():
        for child in dep.depends_on:
            if child in counts:
                counts[child] += 1
    return counts


def attack_subgraph(nodes: dict[str, Dep], roots: set[str], vulnerable: set[str]) -> tuple[set[str], list[tuple[str, str]]]:
    """Nodes and edges that lie on a path from the app to any vulnerable package."""
    reverse: dict[str, set[str]] = {}
    for k, dep in nodes.items():
        for c in dep.depends_on:
            reverse.setdefault(c, set()).add(k)

    keep: set[str] = set()
    queue = deque(v for v in vulnerable if v in nodes)
    while queue:
        k = queue.popleft()
        if k in keep:
            continue
        keep.add(k)
        queue.extend(reverse.get(k, ()))

    reachable_from_root: set[str] = set()
    queue = deque(r for r in roots if r in keep)
    while queue:
        k = queue.popleft()
        if k in reachable_from_root:
            continue
        reachable_from_root.add(k)
        queue.extend(c for c in nodes[k].depends_on if c in keep)

    edges = [(APP_NODE, r) for r in sorted(roots) if r in reachable_from_root]
    for k in reachable_from_root:
        for c in nodes[k].depends_on:
            if c in reachable_from_root:
                edges.append((k, c))
    return reachable_from_root, edges


# ------------------------------------------------------------------ Neo4j (optional)

_driver = None


def _get_driver():
    global _driver
    if _driver is None:
        try:
            from neo4j import GraphDatabase

            _driver = GraphDatabase.driver(
                settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password), connection_timeout=3
            )
            _driver.verify_connectivity()
        except Exception as exc:
            log.warning("Neo4j unavailable, blast-radius data limited to this scan: %s", exc)
            _driver = False
    return _driver or None


def _batches(items: list, size: int = 1000):
    for i in range(0, len(items), size):
        yield items[i : i + size]


def sync_app(user_id: int, app_name: str, sensitive: bool, nodes: dict[str, Dep]) -> bool:
    """Replace this app's dependency graph in Neo4j. Returns False if Neo4j is unavailable."""
    driver = _get_driver()
    if not driver:
        return False
    app_id = f"{user_id}:{app_name}"
    pkg_rows = [
        {"key": k, "name": d.name, "version": d.version, "eco": d.ecosystem, "direct": d.direct, "dev": d.dev}
        for k, d in nodes.items()
    ]
    edge_rows = [{"src": k, "dst": c} for k, d in nodes.items() for c in d.depends_on if c in nodes]
    try:
        with driver.session() as s:
            s.run("MERGE (a:App {id:$id}) SET a.name=$name, a.user_id=$uid, a.sensitive=$sens", id=app_id, name=app_name, uid=user_id, sens=sensitive)
            s.run("MATCH (:App {id:$id})-[r:USES]->() DELETE r", id=app_id)
            for batch in _batches(pkg_rows):
                s.run(
                    """
                    MATCH (a:App {id:$id})
                    UNWIND $rows AS n
                    MERGE (p:Package {key:n.key})
                    SET p.name=n.name, p.version=n.version, p.ecosystem=n.eco
                    MERGE (a)-[u:USES]->(p)
                    SET u.direct=n.direct, u.dev=n.dev
                    """,
                    id=app_id, rows=batch,
                )
            for batch in _batches(edge_rows):
                s.run(
                    """
                    UNWIND $rows AS e
                    MATCH (x:Package {key:e.src}), (y:Package {key:e.dst})
                    MERGE (x)-[:DEPENDS_ON]->(y)
                    """,
                    rows=batch,
                )
        return True
    except Exception as exc:
        log.warning("Neo4j sync failed: %s", exc)
        return False


def apps_using(user_id: int, keys: list[str]) -> dict[str, list[dict]]:
    """{package key: [{name, sensitive}]} across all of this user's apps."""
    driver = _get_driver()
    if not driver or not keys:
        return {}
    try:
        with driver.session() as s:
            rows = s.run(
                """
                MATCH (a:App {user_id:$uid})-[:USES]->(p:Package)
                WHERE p.key IN $keys
                RETURN p.key AS key, collect(DISTINCT {name:a.name, sensitive:coalesce(a.sensitive,false)}) AS apps
                """,
                uid=user_id, keys=keys,
            )
            return {r["key"]: r["apps"] for r in rows}
    except Exception as exc:
        log.warning("Neo4j query failed: %s", exc)
        return {}
