"""Parser for Python ``requirements.txt`` and ``pyproject.toml``."""

from __future__ import annotations

import os
import re
from typing import Dict, List, Tuple

from ..models import Dependency, Ecosystem, RuntimeInfo
from .base import ManifestParser, register

try:
    import tomllib  # py3.11+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

_NAME_RE = re.compile(r"^([A-Za-z0-9_.\-]+(?:\[[^\]]+\])?)\s*(.*)$")


def _split_name_spec(raw: str) -> Tuple[str, str]:
    raw = raw.strip()
    # strip environment markers
    if ";" in raw:
        raw = raw.split(";", 1)[0].strip()
    m = _NAME_RE.match(raw)
    if not m:
        return "", ""
    name = m.group(1)
    rest = m.group(2).strip()
    return name, rest


def _bare_name(name: str) -> str:
    return name.split("[", 1)[0]


def _parse_requirements_txt(path: str) -> Tuple[List[Dependency], List[RuntimeInfo]]:
    deps: List[Dependency] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return [], []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        name, rest = _split_name_spec(line)
        if not name:
            continue
        bare = _bare_name(name)
        version = ""
        if rest.startswith("=="):
            candidate = rest[2:].strip()
            if candidate and "*" not in candidate and "," not in candidate:
                version = candidate
        deps.append(
            Dependency(
                ecosystem=Ecosystem.PYPI,
                name=bare,
                version=version,
                spec=rest or "",
                manifest=os.path.basename(path),
                version_source="pinned" if version else "",
            )
        )
    return deps, []


def _iter_toml_deps(data) -> List[Tuple[str, str]]:
    """Yield (name, spec) from project/poetry style dependency tables."""
    out: List[Tuple[str, str]] = []
    project = data.get("project") or {}
    if isinstance(project, dict):
        for dep in project.get("dependencies") or []:
            if isinstance(dep, str):
                name, rest = _split_name_spec(dep)
                if name:
                    out.append((_bare_name(name), rest))
        for group in (project.get("optional-dependencies") or {}).values():
            for dep in group or []:
                if isinstance(dep, str):
                    name, rest = _split_name_spec(dep)
                    if name:
                        out.append((_bare_name(name), rest))
    # poetry
    poetry = data.get("tool", {}).get("poetry", {})
    if isinstance(poetry, dict):
        for name, val in (poetry.get("dependencies") or {}).items():
            if name.lower() == "python":
                continue
            spec = ""
            if isinstance(val, str):
                spec = val
            elif isinstance(val, dict) and "version" in val:
                spec = str(val["version"])
            out.append((_bare_name(name), spec))
        for group in (poetry.get("group", {}) or {}).values():
            if isinstance(group, dict):
                for name, val in (group.get("dependencies") or {}).items():
                    spec = val if isinstance(val, str) else (val.get("version", "") if isinstance(val, dict) else "")
                    out.append((_bare_name(name), str(spec)))
    return out


def _parse_pyproject_toml(path: str) -> Tuple[List[Dependency], List[RuntimeInfo]]:
    if tomllib is None:
        return [], []
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, Exception):  # noqa: BLE001
        return [], []

    deps: List[Dependency] = []
    for name, spec in _iter_toml_deps(data):
        version = ""
        if spec.startswith("==") and "," not in spec and "*" not in spec:
            version = spec[2:].strip()
        deps.append(
            Dependency(
                ecosystem=Ecosystem.PYPI,
                name=name,
                version=version,
                spec=spec,
                manifest=os.path.basename(path),
                version_source="pinned" if version else "",
            )
        )

    runtimes: List[RuntimeInfo] = []
    project = data.get("project") or {}
    if isinstance(project, dict) and project.get("requires-python"):
        runtimes.append(RuntimeInfo(Ecosystem.PYPI, "python", str(project["requires-python"])))
    poetry = data.get("tool", {}).get("poetry", {})
    if isinstance(poetry, dict) and poetry.get("dependencies", {}).get("python"):
        runtimes.append(RuntimeInfo(Ecosystem.PYPI, "python", str(poetry["dependencies"]["python"])))
    return deps, runtimes


@register
class PypiParser(ManifestParser):
    ecosystem = Ecosystem.PYPI
    filenames = ["requirements.txt", "pyproject.toml"]

    def parse(self, root: str, path: str) -> Tuple[List[Dependency], List[RuntimeInfo]]:
        if os.path.basename(path) == "requirements.txt":
            return _parse_requirements_txt(path)
        return _parse_pyproject_toml(path)
