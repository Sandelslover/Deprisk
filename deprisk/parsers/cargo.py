"""Parser for Rust ``Cargo.toml`` (plus ``Cargo.lock`` version resolution)."""

from __future__ import annotations

import os
from typing import Dict, List, Tuple

from ..models import Dependency, Ecosystem, RuntimeInfo
from .base import ManifestParser, register

try:
    import tomllib  # py3.11+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]


def _lock_versions(root: str) -> Dict[str, str]:
    p = os.path.join(root, "Cargo.lock")
    if not os.path.isfile(p) or tomllib is None:
        return {}
    try:
        with open(p, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, Exception):  # noqa: BLE001
        return {}
    out: Dict[str, str] = {}
    for pkg in data.get("package", []) or []:
        if isinstance(pkg, dict) and "name" in pkg and "version" in pkg:
            out[pkg["name"]] = pkg["version"]
    return out


def _spec_from_value(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        if value.get("workspace") is True:
            return ""
        return str(value.get("version", "") or "")
    return ""


@register
class CargoParser(ManifestParser):
    ecosystem = Ecosystem.CARGO
    filenames = ["Cargo.toml"]

    def parse(self, root: str, path: str) -> Tuple[List[Dependency], List[RuntimeInfo]]:
        if tomllib is None:
            return [], []
        try:
            with open(path, "rb") as fh:
                data = tomllib.load(fh)
        except (OSError, Exception):  # noqa: BLE001
            return [], []

        locks = _lock_versions(root)
        deps: List[Dependency] = []

        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            table = data.get(section) or {}
            if not isinstance(table, dict):
                continue
            for name, value in table.items():
                spec = _spec_from_value(value)
                if not spec:
                    continue
                version = locks.get(name, "")
                deps.append(
                    Dependency(
                        ecosystem=self.ecosystem,
                        name=name,
                        version=version,
                        spec=spec,
                        manifest=os.path.basename(path),
                        version_source="lockfile" if version else "",
                    )
                )

        runtimes: List[RuntimeInfo] = []
        pkg = data.get("package") or {}
        if isinstance(pkg, dict) and pkg.get("rust-version"):
            runtimes.append(RuntimeInfo(self.ecosystem, "rust", str(pkg["rust-version"])))
        return deps, runtimes
