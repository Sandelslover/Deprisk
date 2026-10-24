"""Parser for Node.js ``package.json`` (plus ``package-lock.json`` version resolution)."""

from __future__ import annotations

import json
import os
from typing import Dict, List, Optional, Tuple

from ..models import Dependency, Ecosystem, RuntimeInfo
from .base import ManifestParser, register


def _lock_versions(root: str) -> Dict[str, str]:
    """Extract resolved versions from package-lock.json (v2/v3)."""
    p = os.path.join(root, "package-lock.json")
    if not os.path.isfile(p):
        return {}
    try:
        with open(p, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}
    out: Dict[str, str] = {}
    packages = data.get("packages", {})
    for key, meta in packages.items():
        if key.startswith("node_modules/"):
            name = key[len("node_modules/"):]
            if isinstance(meta, dict) and "version" in meta:
                out[name] = meta["version"]
    # fallback to v1 "dependencies"
    for name, meta in (data.get("dependencies") or {}).items():
        if isinstance(meta, dict) and "version" in meta and name not in out:
            out[name] = meta["version"]
    return out


@register
class NpmParser(ManifestParser):
    ecosystem = Ecosystem.NPM
    filenames = ["package.json"]

    def parse(self, root: str, path: str) -> Tuple[List[Dependency], List[RuntimeInfo]]:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return [], []

        locks = _lock_versions(root)
        deps: List[Dependency] = []

        sections = [
            ("dependencies", False),
            ("devDependencies", False),
            ("optionalDependencies", True),
        ]
        for section, _optional in sections:
            for name, spec in (data.get(section) or {}).items():
                version = locks.get(name, "")
                deps.append(
                    Dependency(
                        ecosystem=self.ecosystem,
                        name=name,
                        version=version,
                        spec=str(spec),
                        manifest=os.path.basename(path),
                        version_source="lockfile" if version else "",
                    )
                )

        runtimes: List[RuntimeInfo] = []
        engines = data.get("engines") or {}
        if isinstance(engines, dict) and engines.get("node"):
            runtimes.append(RuntimeInfo(self.ecosystem, "node", str(engines["node"])))
        return deps, runtimes
