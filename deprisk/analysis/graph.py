"""Dependency relationship graph (transitive resolution)."""

from __future__ import annotations

from typing import Callable, Dict, List, Tuple

from ..models import DepType, Dependency, Ecosystem

NodeKey = Tuple[Ecosystem, str]
Edge = Tuple[NodeKey, NodeKey]

FetchDeps = Callable[[Ecosystem, str, str], List[Tuple[str, str]]]


def resolve_graph(
    direct: List[Dependency],
    depth: int,
    max_nodes: int,
    fetch_deps: FetchDeps,
) -> Tuple[List[Dependency], List[Edge]]:
    """Breadth-first resolution of transitive dependencies.

    ``fetch_deps(ecosystem, name, version)`` returns the direct children of a
    package.  Newly discovered packages are added as TRANSITIVE nodes; edges are
    returned as ``(parent_key, child_key)`` pairs for rendering.
    """
    nodes: Dict[NodeKey, Dependency] = {}
    for d in direct:
        d.dependencies = []
        d.dependents = []
        nodes[(d.ecosystem, d.name)] = d

    edges: List[Edge] = []
    frontier = list(direct)

    for _ in range(depth):
        if len(nodes) >= max_nodes:
            break
        next_frontier: List[Dependency] = []
        for d in frontier:
            if len(nodes) >= max_nodes:
                break
            if not d.version:
                continue
            try:
                children = fetch_deps(d.ecosystem, d.name, d.version)
            except Exception:  # noqa: BLE001
                continue
            for cname, spec in children:
                if not cname:
                    continue
                key: NodeKey = (d.ecosystem, cname)
                parent_key: NodeKey = (d.ecosystem, d.name)
                edges.append((parent_key, key))
                child = nodes.get(key)
                if child is None:
                    if len(nodes) >= max_nodes:
                        break
                    child = Dependency(
                        ecosystem=d.ecosystem,
                        name=cname,
                        version="",
                        spec=spec or "",
                        dep_type=DepType.TRANSITIVE,
                        manifest=d.manifest,
                    )
                    nodes[key] = child
                    next_frontier.append(child)
                if d.name not in child.dependents:
                    child.dependents.append(d.name)
                if cname not in d.dependencies:
                    d.dependencies.append(cname)
        frontier = next_frontier

    return list(nodes.values()), edges
