"""Markdown report generation (intended for use as a pull-request comment)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from ..models import (
    DepType,
    Dependency,
    EOLStatus,
    ProjectAnalysis,
    RiskLevel,
    RuntimeInfo,
    VulnStatus,
)


def _status_emoji(status: VulnStatus) -> str:
    return {
        VulnStatus.VULNERABLE: "!",
        VulnStatus.NO_KNOWN_VULNS: "-",
        VulnStatus.NO_DATA: "?",
        VulnStatus.UNCERTAIN: "~",
    }.get(status, "?")


def _vuln_cell(dep: Dependency) -> str:
    if dep.vuln_status is VulnStatus.VULNERABLE:
        return f"**vulnerable** ({len(dep.vulnerabilities)})"
    return dep.vuln_status.value.replace("_", " ")


def _eol_cell(dep: Dependency) -> str:
    if dep.eol_status is EOLStatus.DEPRECATED:
        return "deprecated"
    if dep.eol_status is EOLStatus.EOL:
        return "eol"
    return ""


def _render_runtime(rt: RuntimeInfo) -> str:
    if rt.eol is None:
        return f"- `{rt.name}` required `{rt.spec}` — EOL status **unknown** (no data)"
    if rt.eol == "":
        return f"- `{rt.name}` required `{rt.spec}` — supported (latest `{rt.latest}`)"
    return f"- `{rt.name}` required `{rt.spec}` — **END OF LIFE** since `{rt.eol}`"


def _risk_label(level: RiskLevel) -> str:
    return level.value.upper()


def render_markdown(analysis: ProjectAnalysis) -> str:
    lines: List[str] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines.append("# Dependency risk report")
    lines.append("")
    lines.append(f"> Generated {now} · analyzed `{analysis.root}`")
    lines.append("")
    if analysis.errors:
        lines.append("## Parsing warnings")
        for e in analysis.errors:
            lines.append(f"- {e}")
        lines.append("")

    # Summary
    vuln = analysis.vulnerable_count
    outdated = analysis.outdated_count
    no_data = analysis.no_data_count
    uncertain = analysis.uncertain_count
    deprecated = sum(1 for d in analysis.dependencies if d.eol_status is EOLStatus.DEPRECATED)
    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Metric | Count |")
    lines.append(f"|---|---|")
    lines.append(f"| Dependencies analyzed | {len(analysis.dependencies)} |")
    lines.append(f"| Known vulnerabilities | {vuln} |")
    lines.append(f"| Outdated | {outdated} |")
    lines.append(f"| Deprecated / abandoned | {deprecated} |")
    lines.append(f"| Vulnerability data unavailable | {no_data} |")
    lines.append(f"| Vulnerability data uncertain | {uncertain} |")
    lines.append("")

    # Confidence legend
    lines.append("## How to read this report")
    lines.append("")
    lines.append(
        "A dependency is **never** reported as \"safe\" just because no vulnerability was "
        "found. Each assessment falls into exactly one of four states:"
    )
    lines.append("")
    lines.append("- **vulnerable** — a public advisory matches the exact analyzed version (verified finding).")
    lines.append("- **no_known_vulns** — the queried databases (OSV: GitHub/PyPA/RustSec) returned no match "
                    "for this exact version. This is *not* a guarantee of safety; it only means nothing is "
                    "recorded today.")
    lines.append("- **no_data** — the databases could not be reached (network error / rate limit / timeout). "
                    "No conclusion is possible.")
    lines.append("- **uncertain** — the databases responded but the result could not be verified reliably.")
    lines.append("")
    lines.append(
        "> ⚠️ **Limitations**: vulnerability data is only as complete as the upstream databases. "
        "Versions marked `assumed-minimum` were not pinned by a lockfile and are a conservative "
        "lower bound. Absence of a finding is absence of *data*, not proof of safety."
    )
    lines.append("")

    # Runtime EOL
    if analysis.runtimes:
        lines.append("## Runtime end of life")
        lines.append("")
        for rt in analysis.runtimes:
            lines.append(_render_runtime(rt))
        lines.append("")

    # Dependency table
    lines.append("## Dependencies")
    lines.append("")
    lines.append("| # | Type | Package | Installed | Declared | Latest | Outdated | Vulns | EOL |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for i, d in enumerate(analysis.dependencies, 1):
        installed = d.version or "?"
        latest = d.latest_version or "?"
        outdated = "yes" if d.outdated else ("no" if d.latest_known else "?")
        vuln_cell = _vuln_cell(d)
        eol = _eol_cell(d)
        lines.append(
            f"| {i} | {d.dep_type.value} | `{d.name}` | {installed} | {d.spec or '*'}"
            f" | {latest} | {outdated} | {vuln_cell} | {eol} |"
        )
    lines.append("")

    # Vulnerability details
    vuln_deps = [d for d in analysis.dependencies if d.vulnerabilities]
    if vuln_deps:
        lines.append("## Known vulnerabilities")
        lines.append("")
        for d in vuln_deps:
            lines.append(f"### `{d.name}` `{d.version}` ({d.ecosystem.value})")
            lines.append("")
            for v in d.vulnerabilities:
                aliases = ", ".join(v.aliases) if v.aliases else "-"
                lines.append(f"- **{v.id}** — {v.summary}")
                lines.append(f"  - severity: `{v.severity or 'unspecified'}` · aliases: {aliases}")
                if v.affected_range:
                    lines.append(f"  - affected: `{v.affected_range}`")
                if v.fixed_version:
                    lines.append(f"  - fixed in: `{v.fixed_version}`")
                if v.url:
                    lines.append(f"  - reference: {v.url}")
            lines.append("")

    # Upgrade risk
    risky = [d for d in analysis.dependencies if d.risk and d.risk.score > 0]
    if risky:
        lines.append("## Upgrade risk")
        lines.append("")
        lines.append("| Package | From | To | Major | Minor | Patch | Score | Level |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for d in sorted(risky, key=lambda x: -x.risk.score):
            r = d.risk
            lines.append(
                f"| `{d.name}` | {d.version} | {d.latest_version} | {r.major_jumps} | {r.minor_jumps} | "
                f"{r.patch_jumps} | **{r.score}** | {_risk_label(r.level)} |"
            )
        lines.append("")
        lines.append("### Risk rationale")
        lines.append("")
        for d in sorted(risky, key=lambda x: -x.risk.score):
            lines.append(f"- `{d.name}` (score {d.risk.score}, {_risk_label(d.risk.level)}):")
            for reason in d.risk.reasons:
                lines.append(f"  - {reason}")
        lines.append("")

    # Relationships
    direct = [d for d in analysis.dependencies if d.dep_type is DepType.DIRECT]
    if direct:
        lines.append("## Dependency relationships")
        lines.append("")
        lines.append("Direct dependencies and their (depth-limited) children:")
        lines.append("")
        for d in direct:
            if d.dependencies:
                children = ", ".join(f"`{c}`" for c in d.dependencies)
                lines.append(f"- `{d.name}` → {children}")
            else:
                lines.append(f"- `{d.name}` (no direct children)")
        lines.append("")

    lines.append("---")
    lines.append(
        "_This report was generated automatically. Data sources: OSV.dev, npm registry, PyPI, "
        "crates.io, endoflife.date. Treat every \"no_known_vulns\" and \"no_data\" result as a "
        "call to verify, not as an assurance._"
    )
    lines.append("")
    return "\n".join(lines)
