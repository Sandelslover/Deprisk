"""Runtime end-of-life checks via the endoflife.date API.

Package "end of life" is not a first-class concept on npm/PyPI/crates.io, so
the tool reports it in two forms:

1. *Runtime* EOL (this module): the Node/Python/Rust version the project
   declares.  If the minimum declared version is on an EOL cycle, we flag it.
2. *Package* deprecation/abandonment: reported through the ``deprecated`` flag
   discovered during registry lookups (see ``registry.py``).

Both are surfaced together in the report under "end of life".
"""

from __future__ import annotations

from typing import Optional

from ..httpclient import FetchError, get_json
from ..models import Ecosystem, RuntimeInfo
from ..semver import minimum_version, parse_version

_EOL_BASE = "https://endoflife.date/api"

_PRODUCT = {"node": "nodejs", "python": "python", "rust": "rust"}


def _cycle_key(name: str, minimum: str) -> Optional[str]:
    v = parse_version(minimum)
    if v is None:
        return None
    if name == "node":
        return str(v.major)
    return f"{v.major}.{v.minor}"


def check_runtime(rt: RuntimeInfo) -> RuntimeInfo:
    product = _PRODUCT.get(rt.name)
    if not product:
        rt.eol = None
        return rt
    minimum = minimum_version(rt.spec)
    if minimum is None:
        rt.eol = None
        return rt
    try:
        cycles = get_json(f"{_EOL_BASE}/{product}.json")
    except FetchError:
        rt.eol = None
        return rt
    if not isinstance(cycles, list):
        rt.eol = None
        return rt

    key = _cycle_key(rt.name, minimum)
    if key is None:
        rt.eol = None
        return rt

    for c in cycles:
        if not isinstance(c, dict):
            continue
        if str(c.get("cycle", "")) == key:
            latest = c.get("latest")
            eol = c.get("eol")
            rt.latest = str(latest) if latest else None
            if eol is True or (isinstance(eol, str) and eol.strip()):
                rt.eol = str(eol) if isinstance(eol, str) else "true"
            else:
                rt.eol = ""  # empty => supported
            return rt
    rt.eol = None  # cycle not found -> unknown
    return rt
