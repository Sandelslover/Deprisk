"""OSV (https://osv.dev) vulnerability lookups for npm, PyPI and crates.io.

OSV aggregates the GitHub Security Advisory database, PyPA advisories, RustSec,
and more.

Two endpoints are used together:

* ``/v1/querybatch``  - cheap, one request for every dependency; returns only
                        the advisory *ids* (or an empty object for "no match").
* ``/v1/query``       - full advisory details (summary, severity, aliases,
                        affected ranges, fixed versions); fetched only for the
                        packages the batch pass already flagged as vulnerable.

The return contract is explicit about *why* something is (or is not) reported:

* success + matches     -> ``VULNERABLE``
* success + no matches  -> ``NO_KNOWN_VULNS`` (with a caveat, never "safe")
* network/5xx/timeout   -> ``NO_DATA``
* malformed/ambiguous   -> ``UNCERTAIN``
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from ..httpclient import FetchError, post_json
from ..models import Ecosystem, VulnStatus, Vulnerability
from ..semver import parse_version

OSV_BASE = "https://api.osv.dev/v1"
OSV_QUERYBATCH_URL = f"{OSV_BASE}/querybatch"
OSV_QUERY_URL = f"{OSV_BASE}/query"


def _ecosystem_key(eco: Ecosystem) -> str:
    return eco.value


def _extract_severity(v: dict) -> Optional[str]:
    db = v.get("database_specific") or {}
    if isinstance(db, dict) and db.get("severity"):
        return str(db["severity"])
    sev = v.get("severity") or []
    if isinstance(sev, list) and sev:
        scores = []
        for s in sev:
            if isinstance(s, dict) and s.get("score"):
                scores.append(str(s["score"]))
        if scores:
            return " / ".join(scores)
    return None


def _extract_range_and_fixed(v: dict) -> Tuple[str, Optional[str]]:
    fixed_candidates: List[str] = []
    ranges: List[str] = []
    seen = set()
    for aff in v.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        for rng in aff.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            events = rng.get("events") or []
            introduced = None
            upper = None
            upper_op = "<"
            for ev in events:
                if "introduced" in ev:
                    introduced = ev["introduced"]
                if "fixed" in ev:
                    upper = ev["fixed"]
                    upper_op = "<"
                    fixed_candidates.append(str(upper))
                if "last_affected" in ev and upper is None:
                    upper = ev["last_affected"]
                    upper_op = "<="
                    fixed_candidates.append(str(upper))
            if introduced is not None:
                lo = "0" if introduced == "0" else str(introduced)
                text = f">= {lo} {upper_op} {upper or '?'}"
                if text not in seen:
                    seen.add(text)
                    ranges.append(text)
        if not ranges:
            for vv in (aff.get("versions") or [])[:3]:
                text = str(vv)
                if text not in seen:
                    seen.add(text)
                    ranges.append(text)

    # prefer a fixed version that looks like a release rather than a commit hash
    fixed: Optional[str] = None
    for f in fixed_candidates:
        if parse_version(f) is not None:
            fixed = f
            break
    if fixed is None and fixed_candidates:
        fixed = fixed_candidates[0]

    affected = ", ".join(ranges)
    if len(affected) > 160:
        affected = affected[:157] + "..."
    return affected, fixed


def _to_vuln(v: dict) -> Vulnerability:
    vid = v.get("id", "UNKNOWN")
    summary = v.get("summary") or v.get("details") or vid
    summary = summary.replace("\n", " ").strip()
    if len(summary) > 300:
        summary = summary[:297] + "..."
    affected_range, fixed = _extract_range_and_fixed(v)
    url = f"https://osv.dev/vulnerability/{vid}"
    for ref in v.get("references") or []:
        if isinstance(ref, dict) and ref.get("url"):
            url = ref["url"]
            break
    return Vulnerability(
        id=vid,
        summary=summary,
        severity=_extract_severity(v),
        aliases=[str(a) for a in (v.get("aliases") or [])],
        affected_range=affected_range,
        fixed_version=fixed,
        source="osv",
        url=url,
    )


def _batch_statuses(
    items: List[Tuple[Ecosystem, str, str]],
) -> List[Tuple[VulnStatus, List[str], str]]:
    """One querybatch call; returns ``(status, advisory_ids, reason)`` per item."""
    n = len(items)
    if n == 0:
        return []
    queries = [
        {"package": {"ecosystem": _ecosystem_key(eco), "name": name}, "version": version}
        for eco, name, version in items
    ]
    try:
        data = post_json(OSV_QUERYBATCH_URL, {"queries": queries})
    except FetchError as e:
        return [(VulnStatus.NO_DATA, [], f"OSV unavailable: {e.message}") for _ in items]

    if not isinstance(data, dict) or "results" not in data:
        reason = "OSV returned an unexpected response shape"
        return [(VulnStatus.UNCERTAIN, [], reason) for _ in items]

    results = data["results"]
    out: List[Tuple[VulnStatus, List[str], str]] = []
    for i, res in enumerate(results):
        _eco, _name, version = items[i] if i < len(items) else (None, None, "?")
        if not isinstance(res, dict):
            out.append((VulnStatus.UNCERTAIN, [], "OSV returned a non-object result"))
        elif "error" in res or "err" in res:
            err = res.get("error") or res.get("err")
            out.append((VulnStatus.NO_DATA, [], f"OSV query error: {err}"))
        elif "vulns" in res:
            ids = [str(v.get("id", "")) for v in (res.get("vulns") or []) if isinstance(v, dict)]
            ids = [i for i in ids if i]
            if ids:
                out.append((VulnStatus.VULNERABLE, ids, f"{len(ids)} advisory entries match version {version}"))
            else:
                out.append((VulnStatus.NO_KNOWN_VULNS, [], "no advisory in OSV for this exact version"))
        elif not res:
            # empty object => no advisories for this version
            out.append((VulnStatus.NO_KNOWN_VULNS, [], "no advisory in OSV for this exact version"))
        else:
            out.append((VulnStatus.UNCERTAIN, [], "OSV returned an unrecognized result shape"))
    return out


def _query_detail(ecosystem: Ecosystem, name: str, version: str) -> List[Vulnerability]:
    """Full advisory details for a single package version."""
    body = {
        "package": {"ecosystem": _ecosystem_key(ecosystem), "name": name},
        "version": version,
    }
    try:
        data = post_json(OSV_QUERY_URL, body)
    except FetchError:
        return []
    if not isinstance(data, dict) or "vulns" not in data:
        return []
    return [_to_vuln(v) for v in data.get("vulns") or [] if isinstance(v, dict)]


def analyze(
    items: List[Tuple[Ecosystem, str, str]],
) -> List[Tuple[VulnStatus, List[Vulnerability], str]]:
    """Look up vulnerabilities for ``(ecosystem, name, version)`` tuples.

    Returns a parallel list of ``(status, vulnerabilities, reason)``.  Full
    details are fetched only for packages the batch pass flagged as vulnerable.
    """
    statuses = _batch_statuses(items)
    out: List[Tuple[VulnStatus, List[Vulnerability], str]] = []
    for (eco, name, version), (status, ids, reason) in zip(items, statuses):
        if status is VulnStatus.VULNERABLE and ids:
            vulns = _query_detail(eco, name, version)
            if vulns:
                out.append((VulnStatus.VULNERABLE, vulns, reason))
            else:
                out.append(
                    (
                        VulnStatus.UNCERTAIN,
                        [],
                        f"{len(ids)} advisory ids returned by batch but details unavailable",
                    )
                )
        else:
            out.append((status, [], reason))
    return out


# Backwards-compatible alias
query_batch = analyze
