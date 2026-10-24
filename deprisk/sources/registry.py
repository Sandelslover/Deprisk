"""Registry lookups: latest version, deprecation flags and direct dependencies.

Each ecosystem has its own registry endpoint:

* npm        -> https://registry.npmjs.org/
* PyPI       -> https://pypi.org/pypi/
* crates.io  -> https://crates.io/api/v1/

All lookups are best-effort: failures are returned to the caller (never raised)
so the dashboard can record "no data" instead of aborting.
"""

from __future__ import annotations

from typing import List, Optional, Tuple
from urllib.parse import quote

from ..httpclient import FetchError, get_json
from ..models import Ecosystem, normalize_name


class RegistryError(Exception):
    pass


def _npm_url(name: str) -> str:
    encoded = quote(name, safe="@")
    return f"https://registry.npmjs.org/{encoded}"


def _pypi_url(name: str) -> str:
    return f"https://pypi.org/pypi/{quote(name, safe='')}/json"


def _crates_url(name: str) -> str:
    return f"https://crates.io/api/v1/crates/{quote(name, safe='')}"


def latest_info(ecosystem: Ecosystem, name: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Return ``(latest_version, deprecated, error)``.

    ``deprecated`` is a message string when the package is marked deprecated,
    otherwise ``None``.  ``error`` is a human-readable string on failure.
    """
    norm = normalize_name(ecosystem, name)
    try:
        if ecosystem is Ecosystem.NPM:
            data = get_json(f"{_npm_url(norm)}/latest")
            if data is None:
                return None, None, f"package '{name}' not found on npm registry"
            version = data.get("version") if isinstance(data, dict) else None
            deprecated = data.get("deprecated") or None if isinstance(data, dict) else None
            if deprecated == "":
                deprecated = None
            return version, deprecated, None
        if ecosystem is Ecosystem.PYPI:
            data = get_json(_pypi_url(norm))
            if data is None:
                return None, None, f"package '{name}' not found on PyPI"
            info = data.get("info", {}) if isinstance(data, dict) else {}
            version = info.get("version")
            return version, None, None
        if ecosystem is Ecosystem.CARGO:
            data = get_json(_crates_url(norm))
            if data is None:
                return None, None, f"crate '{name}' not found on crates.io"
            crate = data.get("crate", {}) if isinstance(data, dict) else {}
            version = crate.get("max_stable_version") or crate.get("max_version")
            return version, None, None
        return None, None, f"unsupported ecosystem {ecosystem}"
    except FetchError as e:
        return None, None, f"registry error: {e.message}"


def get_dependencies(
    ecosystem: Ecosystem, name: str, version: str
) -> Tuple[List[Tuple[str, str]], Optional[str]]:
    """Return ``[(dep_name, spec), ...]`` and an optional error string."""
    norm = normalize_name(ecosystem, name)
    try:
        if ecosystem is Ecosystem.NPM:
            data = get_json(f"{_npm_url(norm)}/{quote(version, safe='')}")
            if data is None:
                return [], f"no metadata for {name}@{version}"
            deps = data.get("dependencies") or {}
            return [(str(k), str(v)) for k, v in deps.items()], None
        if ecosystem is Ecosystem.PYPI:
            data = get_json(f"https://pypi.org/pypi/{quote(norm, safe='')}/{quote(version, safe='')}/json")
            if data is None:
                return [], f"no metadata for {name}@{version}"
            info = data.get("info", {}) or {}
            reqs = info.get("requires_dist") or []
            out: List[Tuple[str, str]] = []
            for r in reqs:
                dep_name, spec = _parse_requires_dist(str(r))
                if dep_name:
                    out.append((dep_name, spec))
            return out, None
        if ecosystem is Ecosystem.CARGO:
            data = get_json(
                f"https://crates.io/api/v1/crates/{quote(norm, safe='')}/{quote(version, safe='')}/dependencies"
            )
            if data is None:
                return [], f"no metadata for {name}@{version}"
            out = []
            for d in data.get("dependencies") or []:
                if not isinstance(d, dict):
                    continue
                if d.get("optional"):
                    continue
                out.append((str(d.get("crate_id", "")), str(d.get("req", ""))))
            return out, None
        return [], f"unsupported ecosystem {ecosystem}"
    except FetchError as e:
        return [], f"registry error: {e.message}"


def _parse_requires_dist(req: str) -> Tuple[str, str]:
    """Parse a PyPI ``requires_dist`` entry like ``requests (>=2.0); extra == 'x'``."""
    if not req:
        return "", ""
    if ";" in req:
        req = req.split(";", 1)[0]
    req = req.strip()
    idx = None
    for i, ch in enumerate(req):
        if ch in " ([" and idx is None:
            idx = i
            break
    if idx is None:
        return req, ""
    name = req[:idx].strip()
    rest = req[idx:].strip()
    rest = rest.strip("()")
    return name, rest
