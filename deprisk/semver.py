"""Minimal semver / PEP 440-compatible version handling.

Implements enough of the Node.js semver range grammar and PEP 440 specifiers
to decide whether an installed version satisfies a declared constraint and to
compute major/minor/patch deltas between versions.  No third-party packages
are required.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

_PRERELEASE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$")
_PEP440_EPOCH = re.compile(r"^(\d+)!(.*)$")


class Version:
    __slots__ = ("major", "minor", "patch", "prerelease", "build")

    def __init__(
        self,
        major: int,
        minor: int = 0,
        patch: int = 0,
        prerelease: Tuple[str, ...] = (),
        build: str = "",
    ):
        self.major = major
        self.minor = minor
        self.patch = patch
        self.prerelease = prerelease
        self.build = build

    def __repr__(self) -> str:
        s = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            s += "-" + ".".join(self.prerelease)
        return s

    def key(self) -> Tuple[int, int, int, int, Tuple]:
        # 1.0.0-alpha < 1.0.0 ; numeric prerelease identifiers compare numerically
        if self.prerelease:
            pre: Tuple = tuple(
                int(p) if p.isdigit() else p for p in self.prerelease  # type: ignore[misc]
            )
            return (self.major, self.minor, self.patch, 0, pre)
        return (self.major, self.minor, self.patch, 1, ())


def _cmp_key(a: Version) -> tuple:
    return a.key()


def compare(a: Version, b: Version) -> int:
    ka, kb = a.key(), b.key()
    # Normalise prerelease tuples to a comparable form (int vs str mixing is
    # messy); use the sorted-array approach instead.
    return _compare_keys(ka, kb)


def _compare_keys(a: tuple, b: tuple) -> int:
    for x, y in zip(a, b):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return (x > y) - (x < y)
        # one is the "release vs prerelease" marker or mixed str/int
        return 1 if x > y else -1
    return 0


def _norm_pre(pre: tuple) -> tuple:
    return tuple(int(p) if str(p).isdigit() else p for p in pre)


def parse_version(raw: str) -> Optional[Version]:
    if raw is None:
        return None
    raw = str(raw).strip()
    if not raw:
        return None
    raw = raw.lstrip("vV")
    # PEP 440 epoch
    raw = _PEP440_EPOCH.sub(lambda m: m.group(2), raw)
    raw = raw.split("+", 1)[0]  # drop build metadata for comparison
    # strip leading zeros in each numeric component
    m = _PRERELEASE.match(raw)
    if m:
        return Version(
            int(m.group(1)),
            int(m.group(2)),
            int(m.group(3)),
            tuple(m.group(4).split(".")) if m.group(4) else (),
            m.group(5) or "",
        )
    # allow partial: "1", "1.2"
    parts = raw.split("-", 1)
    nums = parts[0].split(".")
    try:
        nums = [int(n) for n in nums if n != ""]
    except ValueError:
        return None
    if not nums:
        return None
    major = nums[0]
    minor = nums[1] if len(nums) > 1 else 0
    patch = nums[2] if len(nums) > 2 else 0
    pre = tuple(parts[1].split(".")) if len(parts) > 1 else ()
    return Version(major, minor, patch, pre)


def _is_wildcard(token: str) -> bool:
    return token in ("*", "x", "X") or ".*" in token or token == ""


class _Constraint:
    """A single lower/upper bound derived from a comparator."""

    def __init__(self):
        self.lower: Optional[Version] = None
        self.upper: Optional[Version] = None
        self.lower_inclusive = False
        self.upper_inclusive = False

    def matches(self, v: Version) -> bool:
        if self.lower is not None:
            c = compare(v, self.lower)
            if c < 0 or (c == 0 and not self.lower_inclusive):
                return False
        if self.upper is not None:
            c = compare(v, self.upper)
            if c > 0 or (c == 0 and not self.upper_inclusive):
                return False
        return True


def _constraint_from(op: str, version: Version, partial: bool) -> _Constraint:
    c = _Constraint()
    if op in ("=", "==", "===", ""):
        c.lower = version
        c.lower_inclusive = True
        c.upper = version
        c.upper_inclusive = True
    elif op == ">":
        c.lower = version
        c.lower_inclusive = False
    elif op == ">=":
        c.lower = version
        c.lower_inclusive = True
    elif op == "<":
        c.upper = version
        c.upper_inclusive = False
    elif op == "<=":
        c.upper = version
        c.upper_inclusive = True
    elif op == "~":
        # ~1.2.3 => >=1.2.3 <1.3.0 ; ~1.2 => >=1.2.0 <1.3.0 ; ~1 => >=1.0.0 <2.0.0
        c.lower = version
        c.lower_inclusive = True
        if partial >= 3:
            c.upper = Version(version.major, version.minor + 1, 0)
        elif partial >= 2:
            c.upper = Version(version.major, version.minor + 1, 0)
        else:
            c.upper = Version(version.major + 1, 0, 0)
        c.upper_inclusive = False
    elif op == "^":
        # ^1.2.3 => >=1.2.3 <2.0.0 ; ^0.2.3 => >=0.2.3 <0.3.0 ; ^0.0.3 => >=0.0.3 <0.0.4
        c.lower = version
        c.lower_inclusive = True
        if version.major > 0:
            c.upper = Version(version.major + 1, 0, 0)
        elif version.minor > 0:
            c.upper = Version(0, version.minor + 1, 0)
        else:
            c.upper = Version(0, 0, version.patch + 1)
        c.upper_inclusive = False
    elif op == "~=":
        # PEP 440 compatible release
        c.lower = version
        c.lower_inclusive = True
        if partial >= 3:
            c.upper = Version(version.major, version.minor + 1, 0)
        else:
            c.upper = Version(version.major + 1, 0, 0)
        c.upper_inclusive = False
    return c


def satisfies(version: str, spec: str) -> bool:
    """Return True if ``version`` satisfies the (npm/cargo or PEP 440) ``spec``."""
    if spec is None:
        return True
    spec = str(spec).strip()
    if spec == "" or spec == "*":
        return True
    v = parse_version(version)
    if v is None:
        return False
    return _satisfies_version(v, spec)


def _satisfies_version(v: Version, spec: str) -> bool:
    # OR groups (npm uses '||', PEP 440 uses ',' for AND which we handle below)
    or_groups = spec.split("||")
    for group in or_groups:
        group = group.strip()
        if not group:
            continue
        if _group_matches(v, group):
            return True
    return False


def _group_matches(v: Version, group: str) -> bool:
    constraints: List[_Constraint] = []
    # split into comparators on whitespace and commas (AND semantics)
    tokens = re.split(r"[\s,]+", group)
    i = 0
    # handle hyphen range "1.2.3 - 2.3.4"
    if " - " in group:
        lo, _, hi = group.partition(" - ")
        lo_v = parse_version(lo.strip())
        hi_v = parse_version(hi.strip())
        if lo_v and hi_v:
            c = _Constraint()
            c.lower = lo_v
            c.lower_inclusive = True
            c.upper = hi_v
            c.upper_inclusive = True
            constraints.append(c)
            tokens = []
    for tok in tokens:
        tok = tok.strip()
        if not tok:
            continue
        op_match = re.match(r"^(>=|<=|~=|===|==|!=|>|<|=|~|\^)?(.*)$", tok)
        op = op_match.group(1) or ""
        rest = op_match.group(2).strip()
        if op == "!=":
            # negative: treat as exclusion; skip for simplicity by ignoring
            continue
        if rest == "":
            continue
        if _is_wildcard(rest):
            # wildcard: expand lower bound
            base = rest.replace("*", "0").replace("x", "0").replace("X", "0")
            base = base.rstrip(".")
            base_v = parse_version(base) or Version(0, 0, 0)
            ncomp = len(rest.split("."))
            c = _Constraint()
            c.lower = base_v
            c.lower_inclusive = True
            if ncomp <= 1:
                c.upper = Version(base_v.major + 1, 0, 0)
            elif ncomp <= 2:
                c.upper = Version(base_v.major, base_v.minor + 1, 0)
            else:
                c.upper = Version(base_v.major, base_v.minor, base_v.patch + 1)
            c.upper_inclusive = False
            constraints.append(c)
            continue
        version = parse_version(rest)
        if version is None:
            # non-numeric prerelease / other; can't evaluate => ignore token
            continue
        partial = len(re.sub(r"[-+].*$", "", rest).split("."))
        c = _constraint_from(op, version, partial)
        constraints.append(c)
    if not constraints:
        return True
    return all(c.matches(v) for c in constraints)


def minimum_version(spec: Optional[str]) -> Optional[str]:
    """Return the lowest concrete version implied by a range spec.

    Used as a conservative stand-in for the installed version when no lockfile
    pins the dependency.  Returns ``None`` when no lower bound can be derived.
    """
    if spec is None:
        return None
    spec = str(spec).strip()
    if spec in ("", "*"):
        return None
    if "||" in spec:
        # OR ranges: take the minimum across alternatives
        best: Optional[Version] = None
        for grp in spec.split("||"):
            sub = minimum_version(grp)
            if sub is not None:
                sv = parse_version(sub)
                if best is None or (sv and compare(sv, best) < 0):
                    best = sv
        return repr(best) if best else None
    if " - " in spec:
        spec = spec.split(" - ", 1)[0].strip()
    best: Optional[Version] = None
    for tok in re.split(r"[\s,]+", spec):
        tok = tok.strip()
        if not tok:
            continue
        op_match = re.match(r"^(>=|<=|~=|==|!=|>|<|=|~|\^)?(.*)$", tok)
        op = op_match.group(1) or ""
        rest = op_match.group(2).strip()
        if not rest or _is_wildcard(rest) or op in ("<", "<=", "!="):
            continue
        v = parse_version(rest)
        if v is None:
            continue
        if best is None or compare(v, best) < 0:
            best = v
    return repr(best) if best else None


def version_behind(current: str, latest: str) -> Tuple[int, int, int]:
    """Return (major, minor, patch) difference of latest relative to current.

    A major-version jump dominates the result (minor/patch are reported as 0),
    since component-wise subtraction across a major boundary is meaningless.
    """
    c = parse_version(current)
    l = parse_version(latest)
    if c is None or l is None:
        return (0, 0, 0)
    if compare(l, c) <= 0:
        return (0, 0, 0)
    if l.major > c.major:
        return (l.major - c.major, 0, 0)
    if l.minor > c.minor:
        return (0, l.minor - c.minor, 0)
    return (0, 0, l.patch - c.patch)
