"""Core data models and the confidence model.

The confidence model is central to the tool: a dependency is *never* reported
as "safe" merely because no vulnerability was found.  Every vulnerability
assessment carries an explicit status:

* ``VULNERABLE``       - a public advisory matches the exact installed version.
* ``NO_KNOWN_VULNS``   - the databases were queried successfully and returned
                         nothing for this exact version.  This is *not* the same
                         as "safe": it only means "no entry in the queried
                         databases at this time".
* ``NO_DATA``          - the databases could not be reached (network error,
                         rate-limit, timeout).  Nothing can be concluded.
* ``UNCERTAIN``        - the databases responded but the result could not be
                         matched reliably (ambiguous version, malformed
                         advisory, partial response).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Ecosystem(str, Enum):
    NPM = "npm"
    PYPI = "PyPI"
    CARGO = "crates.io"


class DepType(str, Enum):
    DIRECT = "direct"
    TRANSITIVE = "transitive"


class VulnStatus(str, Enum):
    VULNERABLE = "vulnerable"
    NO_KNOWN_VULNS = "no_known_vulns"
    NO_DATA = "no_data"
    UNCERTAIN = "uncertain"


class EOLStatus(str, Enum):
    EOL = "eol"
    SUPPORTED = "supported"
    DEPRECATED = "deprecated"
    UNKNOWN = "unknown"


# Human-readable explanation of each vulnerability status, used in every
# report so a "clean" row can never be mistaken for a guarantee of safety.
VULN_STATUS_LABELS = {
    VulnStatus.VULNERABLE: "vulnerable (verified finding)",
    VulnStatus.NO_KNOWN_VULNS: "no advisory found in queried databases (not a guarantee of safety)",
    VulnStatus.NO_DATA: "no data (database unavailable - cannot conclude)",
    VulnStatus.UNCERTAIN: "uncertain (data returned but could not be verified)",
}


class RiskLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def normalize_name(ecosystem: Ecosystem, name: str) -> str:
    """Normalize a package name for registry/database lookups."""
    if ecosystem is Ecosystem.PYPI:
        import re as _re

        return _re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


@dataclass
class Vulnerability:
    id: str
    summary: str
    severity: Optional[str] = None
    aliases: List[str] = field(default_factory=list)
    affected_range: str = ""
    fixed_version: Optional[str] = None
    source: str = "osv"
    url: str = ""


@dataclass
class RuntimeInfo:
    """A language runtime detected from a manifest (node, python, rust)."""

    ecosystem: Ecosystem
    name: str  # e.g. "node", "python", "rust"
    spec: str  # declared version constraint, e.g. ">=16"
    latest: Optional[str] = None
    eol: Optional[str] = None  # date/true if the declared minimum is EOL


@dataclass
class Dependency:
    ecosystem: Ecosystem
    name: str
    version: str  # resolved/installed version
    spec: str = ""  # declared constraint, e.g. "^1.2.3"
    dep_type: DepType = DepType.DIRECT
    manifest: str = ""  # which manifest declared it
    version_source: str = ""  # how ``version`` was obtained (lockfile/registry/assumed)

    # populated by registry lookups
    latest_version: Optional[str] = None
    latest_known: bool = False  # False => we could not resolve the latest version
    outdated: bool = False
    versions_behind: str = ""
    deprecated: Optional[str] = None  # deprecation message ("" or None => not deprecated)

    # populated by vulnerability analysis
    vuln_status: VulnStatus = VulnStatus.NO_DATA
    vuln_status_reason: str = ""
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    # relationship graph
    dependencies: List[str] = field(default_factory=list)  # direct children
    dependents: List[str] = field(default_factory=list)  # reverse edges

    # eol
    eol_status: EOLStatus = EOLStatus.UNKNOWN
    eol_reason: str = ""

    # upgrade risk (populated for direct dependencies)
    risk: Optional["UpgradeRisk"] = None

    @property
    def is_vulnerable(self) -> bool:
        return self.vuln_status is VulnStatus.VULNERABLE

    @property
    def vuln_status_label(self) -> str:
        return VULN_STATUS_LABELS[self.vuln_status]


@dataclass
class UpgradeRisk:
    score: int = 0  # 0..100
    level: RiskLevel = RiskLevel.NONE
    major_jumps: int = 0
    minor_jumps: int = 0
    patch_jumps: int = 0
    breaking: bool = False
    reasons: List[str] = field(default_factory=list)


@dataclass
class ProjectAnalysis:
    root: str
    manifests: List[str] = field(default_factory=list)
    dependencies: List[Dependency] = field(default_factory=list)
    runtimes: List[RuntimeInfo] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def get(self, ecosystem: Ecosystem, name: str) -> Optional[Dependency]:
        for d in self.dependencies:
            if d.ecosystem is ecosystem and d.name == name:
                return d
        return None

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for d in self.dependencies if d.is_vulnerable)

    @property
    def outdated_count(self) -> int:
        return sum(1 for d in self.dependencies if d.outdated)

    @property
    def no_data_count(self) -> int:
        return sum(1 for d in self.dependencies if d.vuln_status is VulnStatus.NO_DATA)

    @property
    def uncertain_count(self) -> int:
        return sum(1 for d in self.dependencies if d.vuln_status is VulnStatus.UNCERTAIN)
