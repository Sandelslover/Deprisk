"""Command-line interface for the dependency risk dashboard."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Optional

from . import __version__
from .analysis import analyze
from .models import Ecosystem, ProjectAnalysis, VulnStatus
from .report import render_html, render_markdown

_ECO_CHOICES = {"npm": Ecosystem.NPM, "pypi": Ecosystem.PYPI, "cargo": Ecosystem.CARGO}


def _json_default(o):
    if isinstance(o, Enum):
        return o.value
    if is_dataclass(o):
        return asdict(o)
    raise TypeError(f"not serializable: {type(o)}")


def _to_dict(a: ProjectAnalysis) -> dict:
    return json.loads(json.dumps(asdict(a), default=_json_default))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="deprisk",
        description="Dependency risk dashboard: outdated, vulnerable and EOL analysis "
        "with upgrade-risk estimation for npm, PyPI and Cargo projects.",
    )
    p.add_argument("path", nargs="?", default=".", help="project directory to analyze (default: .)")
    p.add_argument(
        "-e", "--ecosystem", action="append", choices=list(_ECO_CHOICES),
        help="restrict to an ecosystem (repeatable)",
    )
    p.add_argument("--depth", type=int, default=1, help="transitive dependency depth (default: 1)")
    p.add_argument("--max-packages", type=int, default=100, help="cap on packages resolved (default: 100)")
    p.add_argument("--offline", action="store_true", help="parse manifests only; skip all network lookups")
    p.add_argument(
        "-o", "--output-dir", default=None,
        help="directory to write reports into (default: project directory)",
    )
    p.add_argument(
        "--format", default="all", choices=["md", "html", "json", "all"],
        help="report format(s) to write (default: all)",
    )
    p.add_argument("--stdout", action="store_true", help="also print the markdown report to stdout")
    p.add_argument("--version", action="version", version=f"deprisk {__version__}")
    return p


def _print_summary(a: ProjectAnalysis) -> None:
    print(f"Analyzed {len(a.dependencies)} dependencies from {len(a.manifests)} manifest(s).")
    print(f"  vulnerable:  {a.vulnerable_count}")
    print(f"  outdated:    {a.outdated_count}")
    print(f"  deprecated:  {sum(1 for d in a.dependencies if d.eol_status.value == 'deprecated')}")
    print(f"  no data:     {a.no_data_count}")
    print(f"  uncertain:   {a.uncertain_count}")
    for d in a.dependencies:
        if d.vuln_status is VulnStatus.VULNERABLE:
            print(f"    [!] {d.ecosystem.value}:{d.name}@{d.version} -> {len(d.vulnerabilities)} advisory entries")


def main(argv: Optional[list] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    args = build_parser().parse_args(argv)

    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2

    ecosystems = [_ECO_CHOICES[e] for e in args.ecosystem] if args.ecosystem else None

    analysis = analyze(
        root,
        ecosystems=ecosystems,
        depth=args.depth,
        max_packages=args.max_packages,
        offline=args.offline,
    )

    _print_summary(analysis)
    print()

    out_dir = args.output_dir or root
    os.makedirs(out_dir, exist_ok=True)

    md = render_markdown(analysis)
    html = render_html(analysis)

    if args.format in ("md", "all"):
        p = os.path.join(out_dir, "dependency-report.md")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"wrote {p}")
    if args.format in ("html", "all"):
        p = os.path.join(out_dir, "dependency-dashboard.html")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"wrote {p}")
    if args.format == "json":
        p = os.path.join(out_dir, "dependency-report.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(_to_dict(analysis), fh, indent=2)
        print(f"wrote {p}")

    if args.stdout:
        print()
        print(md)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
