"""Upgrade-risk estimation.

Risk is scored per direct dependency and combines:

* how far behind the installed version is (major > minor > patch),
* whether a major-version jump implies breaking changes,
* whether the dependency itself has known vulnerabilities (an upgrade that
  closes a vulnerability is *urgent* even if the jump is small),
* whether the package is deprecated/abandoned, and
* the number of dependents (blast radius) in the resolved graph.

The output is a 0-100 score plus a categorical level.  The estimate is
heuristic and is always reported alongside its reasons so reviewers can judge
it rather than trusting a single number.
"""

from __future__ import annotations

from typing import List

from ..models import Dependency, RiskLevel, UpgradeRisk
from ..semver import version_behind


def _level(score: int) -> RiskLevel:
    if score <= 0:
        return RiskLevel.NONE
    if score < 30:
        return RiskLevel.LOW
    if score < 60:
        return RiskLevel.MEDIUM
    if score < 80:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def estimate_risk(dep: Dependency) -> UpgradeRisk:
    risk = UpgradeRisk()
    if not dep.outdated or not dep.latest_version or not dep.version:
        return risk

    major, minor, patch = version_behind(dep.version, dep.latest_version)
    risk.major_jumps = major
    risk.minor_jumps = minor
    risk.patch_jumps = patch

    score = 0
    reasons: List[str] = []

    if major > 0:
        risk.breaking = True
        contribution = min(major, 4) * 22
        score += contribution
        reasons.append(
            f"{major} major-version bump(s) {dep.version} -> {dep.latest_version} "
            f"(likely breaking changes; +{contribution})"
        )
    elif minor > 0:
        contribution = min(minor, 4) * 8
        score += contribution
        reasons.append(f"{minor} minor-version bump(s) (+{contribution})")
    elif patch > 0:
        contribution = min(patch, 10) * 2
        score += contribution
        reasons.append(f"{patch} patch-version bump(s) (+{contribution})")

    if dep.is_vulnerable:
        score += 25
        reasons.append(
            f"dependency has {len(dep.vulnerabilities)} known vulnerability entries; "
            "upgrading is security-critical (+25)"
        )

    if dep.deprecated:
        score += 15
        reasons.append("package is deprecated/abandoned (+15)")

    ndeps = len(dep.dependents)
    if ndeps > 0:
        contribution = min(ndeps, 10) * 2
        score += contribution
        reasons.append(
            f"{ndeps} dependent(s) must be re-validated after upgrade (blast radius; +{contribution})"
        )

    risk.score = min(score, 100)
    risk.level = _level(risk.score)
    risk.reasons = reasons
    return risk
