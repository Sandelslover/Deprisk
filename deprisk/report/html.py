"""Self-contained HTML dashboard generation."""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Dict, List, Tuple

from ..models import (
    DepType,
    Dependency,
    Ecosystem,
    EOLStatus,
    ProjectAnalysis,
    RiskLevel,
    RuntimeInfo,
    VulnStatus,
)


def _esc(s) -> str:
    return html.escape(str(s)) if s is not None else ""


_VULN_CLASS = {
    VulnStatus.VULNERABLE: "vuln",
    VulnStatus.NO_KNOWN_VULNS: "ok",
    VulnStatus.NO_DATA: "nodata",
    VulnStatus.UNCERTAIN: "uncertain",
}

_VULN_LABEL = {
    VulnStatus.VULNERABLE: "vulnerable",
    VulnStatus.NO_KNOWN_VULNS: "no known vulns",
    VulnStatus.NO_DATA: "no data",
    VulnStatus.UNCERTAIN: "uncertain",
}

_RISK_CLASS = {
    RiskLevel.NONE: "risk-none",
    RiskLevel.LOW: "risk-low",
    RiskLevel.MEDIUM: "risk-med",
    RiskLevel.HIGH: "risk-high",
    RiskLevel.CRITICAL: "risk-crit",
}


def _badge(dep: Dependency) -> str:
    cls = _VULN_CLASS[dep.vuln_status]
    label = _VULN_LABEL[dep.vuln_status]
    return f'<span class="badge {cls}" title="{_esc(dep.vuln_status_reason)}">{label}</span>'


_CSS = """
:root{--bg:#0f1420;--panel:#171d2b;--border:#26304a;--text:#e6e9f0;--muted:#8b94ad;
--red:#ff5d5d;--green:#3ecf8e;--yellow:#f5c451;--orange:#ff9f43;--gray:#6b7280}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1200px;margin:0 auto;padding:24px}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:17px;margin:28px 0 10px;border-bottom:1px solid var(--border);padding-bottom:6px}
h3{font-size:15px;margin:16px 0 6px}
.meta{color:var(--muted);font-size:12px;margin-bottom:18px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px}
.card .num{font-size:28px;font-weight:700}
.card .lab{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.card.red .num{color:var(--red)}.card.green .num{color:var(--green)}
.card.yellow .num{color:var(--yellow)}.card.gray .num{color:var(--gray)}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px;margin-bottom:16px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.04em}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:600}
.badge.vuln{background:rgba(255,93,93,.15);color:var(--red)}
.badge.ok{background:rgba(62,207,142,.14);color:var(--green)}
.badge.nodata{background:rgba(107,114,128,.18);color:var(--gray)}
.badge.uncertain{background:rgba(255,159,67,.15);color:var(--orange)}
.badge.eol{background:rgba(245,196,81,.15);color:var(--yellow)}
.risk-none{color:var(--muted)}.risk-low{color:var(--green)}.risk-med{color:var(--yellow)}
.risk-high{color:var(--orange)}.risk-crit{color:var(--red);font-weight:700}
.note{background:rgba(245,196,81,.08);border:1px solid rgba(245,196,81,.3);border-radius:8px;padding:12px 14px;font-size:13px}
.note strong{color:var(--yellow)}
.small{color:var(--muted);font-size:12px}
ul.tight{margin:6px 0;padding-left:20px}
ul.tight li{margin:3px 0}
svg text{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px}
.legend{display:flex;gap:16px;flex-wrap:wrap;margin:8px 0}
.legend span{font-size:12px}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:5px}
"""


def _summary_cards(a: ProjectAnalysis) -> str:
    vuln = a.vulnerable_count
    outdated = a.outdated_count
    no_data = a.no_data_count
    uncertain = a.uncertain_count
    deprecated = sum(1 for d in a.dependencies if d.eol_status is EOLStatus.DEPRECATED)
    return f"""
<div class="cards">
  <div class="card {'red' if vuln else ''}"><div class="num">{vuln}</div><div class="lab">Vulnerable</div></div>
  <div class="card {'yellow' if outdated else ''}"><div class="num">{outdated}</div><div class="lab">Outdated</div></div>
  <div class="card {'yellow' if deprecated else ''}"><div class="num">{deprecated}</div><div class="lab">Deprecated</div></div>
  <div class="card gray"><div class="num">{no_data}</div><div class="lab">No data</div></div>
  <div class="card gray"><div class="num">{uncertain}</div><div class="lab">Uncertain</div></div>
  <div class="card"><div class="num">{len(a.dependencies)}</div><div class="lab">Total deps</div></div>
</div>
"""


def _confidence_legend() -> str:
    return """
<div class="note">
  <strong>Confidence model.</strong> A dependency is never reported as "safe" simply because no
  vulnerability was found. Every result is one of:
  <b style="color:var(--red)">vulnerable</b> (verified advisory match) ·
  <b style="color:var(--green)">no known vulns</b> (databases queried, nothing matched — <i>not</i> a guarantee of safety) ·
  <b style="color:var(--gray)">no data</b> (database unreachable — no conclusion possible) ·
  <b style="color:var(--orange)">uncertain</b> (response could not be verified).
  Versions marked <i>assumed-minimum</i> were not pinned by a lockfile and are a conservative lower bound.
</div>
"""


def _runtime_section(a: ProjectAnalysis) -> str:
    if not a.runtimes:
        return ""
    rows = []
    for rt in a.runtimes:
        if rt.eol is None:
            status = '<span class="badge nodata">unknown</span>'
        elif rt.eol == "":
            status = f'<span class="badge ok">supported</span> <span class="small">(latest {_esc(rt.latest)})</span>'
        else:
            status = f'<span class="badge eol">EOL {_esc(rt.eol)}</span>'
        rows.append(f"<tr><td><code>{_esc(rt.name)}</code></td><td><code>{_esc(rt.spec)}</code></td><td>{status}</td></tr>")
    return f"""
<h2>Runtime end of life</h2>
<div class="panel"><table>
<thead><tr><th>Runtime</th><th>Declared</th><th>Status</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table></div>
"""


def _deps_table(a: ProjectAnalysis) -> str:
    rows = []
    for d in a.dependencies:
        installed = d.version or "?"
        latest = d.latest_version or "?"
        if d.outdated:
            out = '<span class="badge eol">outdated</span>'
        elif d.latest_known:
            out = '<span class="small">current</span>'
        else:
            out = '<span class="small">?</span>'
        eol = ""
        if d.eol_status is EOLStatus.DEPRECATED:
            eol = f'<span class="badge eol" title="{_esc(d.eol_reason)}">deprecated</span>'
        vs = _badge(d)
        vcount = len(d.vulnerabilities)
        if vcount:
            vs += f' <span class="small">({vcount})</span>'
        type_label = "direct" if d.dep_type is DepType.DIRECT else "transitive"
        rows.append(
            f"<tr><td>{type_label}</td><td><code>{_esc(d.name)}</code></td>"
            f"<td><code>{_esc(installed)}</code></td><td><code>{_esc(d.spec or '*')}</code></td>"
            f"<td><code>{_esc(latest)}</code></td><td>{out}</td><td>{vs}</td><td>{eol}</td></tr>"
        )
    return f"""
<h2>Dependencies</h2>
<div class="panel"><table>
<thead><tr><th>Type</th><th>Package</th><th>Installed</th><th>Declared</th><th>Latest</th><th>Version</th><th>Vulns</th><th>EOL</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table></div>
"""


def _vuln_section(a: ProjectAnalysis) -> str:
    vuln_deps = [d for d in a.dependencies if d.vulnerabilities]
    if not vuln_deps:
        return ""
    blocks = []
    for d in vuln_deps:
        items = []
        for v in d.vulnerabilities:
            aliases = ", ".join(v.aliases) if v.aliases else "-"
            link = f'<a href="{_esc(v.url)}" style="color:var(--orange)">{_esc(v.id)}</a>' if v.url else _esc(v.id)
            items.append(
                f'<li><strong>{link}</strong> — {_esc(v.summary)}<br>'
                f'<span class="small">severity: <code>{_esc(v.severity or "unspecified")}</code> · '
                f'aliases: {_esc(aliases)}</span>'
                + (f'<br><span class="small">affected: <code>{_esc(v.affected_range)}</code></span>' if v.affected_range else "")
                + (f'<br><span class="small">fixed in: <code>{_esc(v.fixed_version)}</code></span>' if v.fixed_version else "")
                + "</li>"
            )
        blocks.append(
            f'<h3><code>{_esc(d.name)}</code> <code>{_esc(d.version)}</code> '
            f'<span class="small">({_esc(d.ecosystem.value)})</span></h3><ul class="tight">{"" .join(items)}</ul>'
        )
    return f'<h2>Known vulnerabilities</h2><div class="panel">{"".join(blocks)}</div>'


def _risk_section(a: ProjectAnalysis) -> str:
    risky = [d for d in a.dependencies if d.risk and d.risk.score > 0]
    if not risky:
        return ""
    risky.sort(key=lambda x: -x.risk.score)
    rows = []
    for d in risky:
        r = d.risk
        cls = _RISK_CLASS[r.level]
        rows.append(
            f"<tr><td><code>{_esc(d.name)}</code></td><td><code>{_esc(d.version)}</code></td>"
            f"<td><code>{_esc(d.latest_version)}</code></td><td>{r.major_jumps}</td><td>{r.minor_jumps}</td>"
            f"<td>{r.patch_jumps}</td><td><b>{r.score}</b></td>"
            f'<td><span class="{cls}">{r.level.value.upper()}</span></td></tr>'
        )
    detail = []
    for d in risky:
        r = d.risk
        reasons = "".join(f"<li>{_esc(x)}</li>" for x in r.reasons)
        detail.append(f'<li><code>{_esc(d.name)}</code> <span class="{_RISK_CLASS[r.level]}">{r.level.value.upper()}</span>'
                      f'<ul class="tight">{reasons}</ul></li>')
    return f"""
<h2>Upgrade risk</h2>
<div class="panel"><table>
<thead><tr><th>Package</th><th>From</th><th>To</th><th>Major</th><th>Minor</th><th>Patch</th><th>Score</th><th>Level</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
<h3>Rationale</h3>
<ul class="tight">{''.join(detail)}</ul>
</div>
"""


def _graph_svg(a: ProjectAnalysis) -> str:
    nodes: Dict[Tuple[Ecosystem, str], Dependency] = {}
    for d in a.dependencies:
        nodes[(d.ecosystem, d.name)] = d

    # assign levels via BFS from direct deps
    level: Dict[Tuple[Ecosystem, str], int] = {}
    frontier = [(d.ecosystem, d.name) for d in a.dependencies if d.dep_type is DepType.DIRECT]
    for k in frontier:
        level[k] = 0
    while frontier:
        nxt = []
        for k in frontier:
            d = nodes.get(k)
            if not d:
                continue
            for c in d.dependencies:
                ck = (d.ecosystem, c)
                if ck in nodes and ck not in level:
                    level[ck] = level[k] + 1
                    nxt.append(ck)
        frontier = nxt

    max_level = max(level.values()) if level else 0
    by_level: Dict[int, List[Tuple[Ecosystem, str]]] = {}
    for k, lv in level.items():
        by_level.setdefault(lv, []).append(k)

    W, H = 170, 46
    GAPX, GAPY = 24, 46
    total_h = (max_level + 1) * (H + GAPY)
    widths = {lv: len(keys) * (W + GAPX) + GAPX for lv, keys in by_level.items()}
    total_w = max(widths.values()) if widths else 400

    positions: Dict[Tuple[Ecosystem, str], Tuple[float, float]] = {}
    for lv, keys in by_level.items():
        row_w = len(keys) * (W + GAPX)
        start_x = (total_w - row_w) / 2 + W / 2
        for i, k in enumerate(keys):
            positions[k] = (start_x + i * (W + GAPX), lv * (H + GAPY) + H / 2)

    color = {
        VulnStatus.VULNERABLE: "#ff5d5d",
        VulnStatus.NO_KNOWN_VULNS: "#3ecf8e",
        VulnStatus.NO_DATA: "#6b7280",
        VulnStatus.UNCERTAIN: "#ff9f43",
    }
    edge_color = "#334066"

    parts = [
        f'<svg width="100%" viewBox="0 0 {int(total_w)} {int(total_h)}" '
        f'style="background:var(--bg);border:1px solid var(--border);border-radius:10px">'
    ]
    for lv, keys in by_level.items():
        for k in keys:
            d = nodes.get(k)
            if not d:
                continue
            for c in d.dependencies:
                ck = (d.ecosystem, c)
                if ck not in positions:
                    continue
                x1, y1 = positions[k]
                x2, y2 = positions[ck]
                parts.append(
                    f'<line x1="{x1:.1f}" y1="{y1 + H / 2:.1f}" x2="{x2:.1f}" y2="{y2 - H / 2:.1f}" '
                    f'stroke="{edge_color}" stroke-width="1"/>'
                )
    for k, (x, y) in positions.items():
        d = nodes[k]
        c = color.get(d.vuln_status, "#6b7280")
        rx, ry = x - W / 2, y - H / 2
        label = d.name
        if len(label) > 20:
            label = label[:18] + ".."
        version = d.version or "?"
        if d.eol_status is EOLStatus.DEPRECATED:
            stroke = "#f5c451"
        else:
            stroke = c
        parts.append(
            f'<rect x="{rx:.1f}" y="{ry:.1f}" width="{W}" height="{H}" rx="8" fill="#171d2b" '
            f'stroke="{stroke}" stroke-width="1.5"/>'
        )
        parts.append(
            f'<text x="{x:.1f}" y="{y - 2:.1f}" fill="#e6e9f0" text-anchor="middle" font-weight="700">{_esc(label)}</text>'
        )
        parts.append(
            f'<text x="{x:.1f}" y="{y + 14:.1f}" fill="#8b94ad" text-anchor="middle">{_esc(version)}</text>'
        )
    parts.append("</svg>")

    legend = """
<div class="legend">
  <span><span class="dot" style="background:#ff5d5d"></span>vulnerable</span>
  <span><span class="dot" style="background:#3ecf8e"></span>no known vulns</span>
  <span><span class="dot" style="background:#6b7280"></span>no data</span>
  <span><span class="dot" style="background:#ff9f43"></span>uncertain</span>
  <span><span class="dot" style="background:#171d2b;border:2px solid #f5c451"></span>deprecated</span>
</div>
"""
    return f'<h2>Dependency relationships</h2><div class="panel">{legend}{"".join(parts)}<p class="small">Edges point from a package to its direct dependencies (depth-limited).</p></div>'


def render_html(a: ProjectAnalysis) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sections = [
        _summary_cards(a),
        _confidence_legend(),
        _runtime_section(a),
        _deps_table(a),
        _vuln_section(a),
        _risk_section(a),
        _graph_svg(a),
    ]
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dependency risk dashboard</title>
<style>{_CSS}</style></head>
<body><div class="wrap">
<h1>Dependency risk dashboard</h1>
<div class="meta">Generated {now} · analyzed <code>{_esc(a.root)}</code> · manifests: {_esc(", ".join(a.manifests) or "none")}</div>
{''.join(sections)}
<div class="meta">Data sources: OSV.dev, npm registry, PyPI, crates.io, endoflife.date. "no known vulns" and "no data" are calls to verify, not assurances.</div>
</div></body></html>
"""
