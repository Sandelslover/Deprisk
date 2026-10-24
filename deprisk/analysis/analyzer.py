"""Analysis orchestrator: ties parsers, sources, graph and risk together."""

from __future__ import annotations

from typing import List, Optional

from ..models import (
    DepType,
    Dependency,
    Ecosystem,
    EOLStatus,
    ProjectAnalysis,
    RuntimeInfo,
    VulnStatus,
)
from ..parsers import detect_manifests, parse_manifest
from ..semver import minimum_version, satisfies, version_behind
from ..sources import eol as eol_source
from ..sources import osv as osv_source
from ..sources import registry
from .graph import resolve_graph
from .risk import estimate_risk


def _dedupe(deps: List[Dependency]) -> List[Dependency]:
    """Merge duplicate declarations, preferring entries with a resolved version."""
    by_key = {}
    order = []
    for d in deps:
        key = (d.ecosystem, d.name)
        if key in by_key:
            existing = by_key[key]
            if not existing.version and d.version:
                existing.version = d.version
                existing.version_source = d.version_source
            if not existing.spec and d.spec:
                existing.spec = d.spec
            continue
        by_key[key] = d
        order.append(d)
    return order


def _resolve_latest(dep: Dependency) -> None:
    latest, deprecated, err = registry.latest_info(dep.ecosystem, dep.name)
    if err is not None:
        dep.latest_known = False
        dep.latest_version = None
        return
    dep.latest_known = True
    dep.latest_version = latest
    if deprecated:
        dep.deprecated = deprecated
        dep.eol_status = EOLStatus.DEPRECATED
        dep.eol_reason = f"registry marks package deprecated: {deprecated}"
    if latest and dep.version:
        major, minor, patch = version_behind(dep.version, latest)
        dep.outdated = (major + minor + patch) > 0
        if dep.outdated:
            parts = []
            if major:
                parts.append(f"{major} major")
            if minor:
                parts.append(f"{minor} minor")
            if patch:
                parts.append(f"{patch} patch")
            dep.versions_behind = ", ".join(parts)


def _resolve_version(dep: Dependency) -> None:
    if dep.version:
        return
    minimum = minimum_version(dep.spec)
    if minimum:
        dep.version = minimum
        dep.version_source = "assumed-minimum (no lockfile)"


def analyze(
    root: str,
    ecosystems: Optional[List[Ecosystem]] = None,
    depth: int = 1,
    max_packages: int = 100,
    offline: bool = False,
) -> ProjectAnalysis:
    analysis = ProjectAnalysis(root=root)
    manifests = detect_manifests(root, ecosystems)
    analysis.manifests = manifests

    deps: List[Dependency] = []
    runtimes: List[RuntimeInfo] = []
    for path in manifests:
        try:
            pd, pr = parse_manifest(root, path)
        except Exception as e:  # noqa: BLE001
            analysis.errors.append(f"failed to parse {path}: {e}")
            continue
        deps.extend(pd)
        runtimes.extend(pr)

    analysis.dependencies = _dedupe(deps)
    analysis.runtimes = runtimes

    # 1. resolve installed versions where possible (local, no network needed)
    for d in analysis.dependencies:
        _resolve_version(d)

    if offline:
        for d in analysis.dependencies:
            d.vuln_status = VulnStatus.NO_DATA
            d.vuln_status_reason = "offline mode: databases not queried"
        return analysis

    # 2. latest version / deprecation for direct deps
    for d in analysis.dependencies:
        _resolve_latest(d)

    # 3. resolve transitive dependencies (relationships)
    def _fetch_deps(eco, name, version):
        children, _err = registry.get_dependencies(eco, name, version)
        return children

    all_deps, _edges = resolve_graph(
        analysis.dependencies, depth=depth, max_nodes=max_packages, fetch_deps=_fetch_deps
    )
    analysis.dependencies = all_deps

    # 4. resolve versions + latest for newly discovered transitive deps
    for d in analysis.dependencies:
        if d.dep_type is DepType.TRANSITIVE:
            _resolve_version(d)
            _resolve_latest(d)

    # 5. vulnerability batch query (only deps with a concrete version)
    query_items = []
    index_map = {}
    for i, d in enumerate(analysis.dependencies):
        if d.version:
            query_items.append((d.ecosystem, d.name, d.version))
            index_map[len(query_items) - 1] = d
        else:
            d.vuln_status = VulnStatus.NO_DATA
            d.vuln_status_reason = "no resolved version (no lockfile and no derivable lower bound)"

    results = osv_source.query_batch(query_items)
    for idx, (status, vulns, reason) in zip(index_map.keys(), results):
        d = index_map[idx]
        d.vuln_status = status
        d.vuln_status_reason = reason
        d.vulnerabilities = vulns

    # 6. runtime EOL
    for rt in analysis.runtimes:
        eol_source.check_runtime(rt)

    # 7. upgrade risk for direct deps
    for d in analysis.dependencies:
        if d.dep_type is DepType.DIRECT:
            d.risk = estimate_risk(d)

    return analysis
