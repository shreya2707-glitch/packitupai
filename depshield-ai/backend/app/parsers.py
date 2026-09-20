"""Parse dependency manifests into one dependency graph.

Supported:
  - package-lock.json (npm 7+, lockfileVersion 2/3)  -> full transitive graph
  - package.json (no lockfile)                        -> direct deps only (versions approximated)
  - requirements.txt                                  -> direct deps only
  - pom.xml                                           -> direct deps only

Only the standard library is used here so the parsers are easy to test.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from posixpath import basename, dirname


@dataclass
class Dep:
    name: str
    version: str
    ecosystem: str  # npm | PyPI | Maven  (OSV ecosystem names)
    direct: bool = False
    dev: bool = False
    depends_on: set[str] = field(default_factory=set)
    approximate: bool = False  # version came from a range, not a lockfile

    @property
    def key(self) -> str:
        return make_key(self.ecosystem, self.name, self.version)


def make_key(ecosystem: str, name: str, version: str) -> str:
    return f"{ecosystem}:{name}@{version}"


@dataclass
class DepGraph:
    nodes: dict[str, Dep] = field(default_factory=dict)
    roots: set[str] = field(default_factory=set)  # keys of direct dependencies
    warnings: list[str] = field(default_factory=list)

    def add(self, dep: Dep) -> Dep:
        existing = self.nodes.get(dep.key)
        if existing is None:
            self.nodes[dep.key] = dep
            return dep
        existing.direct = existing.direct or dep.direct
        existing.dev = existing.dev and dep.dev
        existing.depends_on |= dep.depends_on
        return existing

    def merge(self, other: "DepGraph") -> None:
        for dep in other.nodes.values():
            self.add(dep)
        self.roots |= other.roots
        self.warnings += other.warnings


# --------------------------------------------------------------------------- npm

_RANGE_PREFIX = re.compile(r"^[\^~<>=v\s]+")
_VERSION_IN_SPEC = re.compile(r"\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z.\-]+)?")


def _npm_spec_to_version(spec: str) -> str | None:
    spec = spec.strip()
    if not spec or spec in {"*", "latest"} or "/" in spec or spec.startswith(("git", "http", "file:", "link:", "workspace:")):
        return None
    m = _VERSION_IN_SPEC.search(_RANGE_PREFIX.sub("", spec))
    return m.group(0) if m else None


def parse_package_json(text: str) -> DepGraph:
    """Direct dependencies only. Versions are the lower bound of each range."""
    g = DepGraph()
    data = json.loads(text)
    for section, dev in (("dependencies", False), ("optionalDependencies", False), ("devDependencies", True)):
        for name, spec in (data.get(section) or {}).items():
            version = _npm_spec_to_version(str(spec))
            if version is None:
                g.warnings.append(f"package.json: skipped {name}@{spec} (not a plain version range)")
                continue
            dep = g.add(Dep(name, version, "npm", direct=True, dev=dev, approximate=True))
            g.roots.add(dep.key)
    if g.nodes:
        g.warnings.append("package.json without a lockfile: transitive dependencies are not included. Commit package-lock.json for a full graph.")
    return g


def _resolve_npm(pkgs: dict, from_path: str, dep_name: str) -> str | None:
    """Node-style resolution: look in nested node_modules first, then walk up."""
    base = from_path
    while True:
        candidate = f"{base}/node_modules/{dep_name}" if base else f"node_modules/{dep_name}"
        if candidate in pkgs:
            return candidate
        if not base:
            return None
        idx = base.rfind("/node_modules/")
        base = base[:idx] if idx != -1 else ""


def parse_package_lock(text: str) -> DepGraph:
    lock = json.loads(text)
    pkgs: dict = lock.get("packages") or {}
    if not pkgs:
        raise ValueError("Unsupported package-lock.json: need lockfileVersion 2 or 3 (npm 7+).")

    g = DepGraph()
    root = pkgs.get("", {})
    root_prod = set((root.get("dependencies") or {})) | set((root.get("optionalDependencies") or {}))
    root_dev = set((root.get("devDependencies") or {}))

    path_to_key: dict[str, str] = {}
    for path, info in pkgs.items():
        if not path.startswith("node_modules/") or info.get("link"):
            continue
        version = info.get("version")
        if not version:
            continue
        name = info.get("name") or path.split("node_modules/")[-1]
        dep = Dep(name, version, "npm", dev=bool(info.get("dev")))
        path_to_key[path] = g.add(dep).key

    for path, key in path_to_key.items():
        info = pkgs[path]
        for section in ("dependencies", "optionalDependencies"):
            for dep_name in (info.get(section) or {}):
                target = _resolve_npm(pkgs, path, dep_name)
                if target and target in path_to_key:
                    g.nodes[key].depends_on.add(path_to_key[target])

    for name in root_prod | root_dev:
        target = _resolve_npm(pkgs, "", name)
        if target and target in path_to_key:
            key = path_to_key[target]
            g.nodes[key].direct = True
            if name in root_dev and name not in root_prod:
                g.nodes[key].dev = True
            g.roots.add(key)
    return g


# ------------------------------------------------------------------------ Python

_REQ_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._\-]*)\s*(?:\[[^\]]*\])?\s*(?P<op>==|===|~=|>=|<=|!=|>|<)?\s*(?P<ver>[A-Za-z0-9_.*+!\-]+)?"
)


def parse_requirements(text: str, filename: str = "requirements.txt") -> DepGraph:
    g = DepGraph()
    dev = any(x in filename.lower() for x in ("dev", "test"))
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http", ".", "/")):
            continue
        m = _REQ_LINE.match(line)
        if not m:
            continue
        name = m.group("name").lower().replace("_", "-")
        op, ver = m.group("op"), m.group("ver")
        if not ver or op in {"!=", "<", "<="} or "*" in ver:
            g.warnings.append(f"{filename}: skipped {line!r} (no usable version). Pin versions with == for accurate scanning.")
            continue
        dep = g.add(Dep(name, ver, "PyPI", direct=True, dev=dev, approximate=op not in {"==", "==="}))
        g.roots.add(dep.key)
    return g


# ------------------------------------------------------------------------ Maven

def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1]


def parse_pom(text: str) -> DepGraph:
    g = DepGraph()
    root = ET.fromstring(text)
    for el in root.iter():
        el.tag = _strip_ns(el.tag)

    props: dict[str, str] = {}
    for p in root.findall("properties/*"):
        props[p.tag] = (p.text or "").strip()
    for tag in ("version", "groupId"):
        el = root.find(tag) if root.find(tag) is not None else root.find(f"parent/{tag}")
        if el is not None and el.text:
            props[f"project.{tag}"] = el.text.strip()

    def sub(value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        for _ in range(5):
            new = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), value)
            if new == value:
                break
            value = new
        return None if "${" in value else value

    for d in root.findall("dependencies/dependency"):
        group, artifact = sub(d.findtext("groupId")), sub(d.findtext("artifactId"))
        version, scope = sub(d.findtext("version")), (d.findtext("scope") or "compile").strip()
        if not (group and artifact):
            continue
        if not version:
            g.warnings.append(f"pom.xml: skipped {group}:{artifact} (version managed elsewhere, e.g. a parent BOM)")
            continue
        dep = g.add(Dep(f"{group}:{artifact}", version, "Maven", direct=True, dev=scope in {"test", "provided"}, approximate=False))
        g.roots.add(dep.key)
    return g


# ----------------------------------------------------------------------- entry point

def parse_manifests(files: dict[str, str]) -> DepGraph:
    """files maps a repo-relative path to its text. Returns the merged graph."""
    result = DepGraph()
    lock_dirs = {dirname(p) for p in files if basename(p) == "package-lock.json"}

    for path, text in sorted(files.items()):
        name = basename(path)
        try:
            if name == "package-lock.json":
                result.merge(parse_package_lock(text))
            elif name == "package.json" and dirname(path) not in lock_dirs:
                result.merge(parse_package_json(text))
            elif re.fullmatch(r"requirements[\w.\-]*\.txt", name):
                result.merge(parse_requirements(text, name))
            elif name == "pom.xml":
                result.merge(parse_pom(text))
        except (ValueError, json.JSONDecodeError, ET.ParseError) as exc:
            result.warnings.append(f"{path}: could not parse ({exc})")

    if not result.nodes:
        result.warnings.append("No supported manifests found (package-lock.json, package.json, requirements.txt, pom.xml).")
    return result


MANIFEST_NAMES = {"package-lock.json", "package.json", "pom.xml"}


def is_manifest_path(path: str) -> bool:
    name = basename(path)
    return name in MANIFEST_NAMES or bool(re.fullmatch(r"requirements[\w.\-]*\.txt", name))
