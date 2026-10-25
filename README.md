# deprisk — dependency risk dashboard

A dependency-free Python CLI that analyzes a software project's dependencies and
produces a risk dashboard for pull requests. It parses dependency manifests,
flags outdated packages, looks up known vulnerabilities against public
databases, surfaces end-of-life / deprecated dependencies, and estimates the
risk of upgrading each package.

Supported ecosystems:

- **npm** (`package.json` + `package-lock.json`)
- **Python** (`requirements.txt` + `pyproject.toml`)
- **Rust** (`Cargo.toml` + `Cargo.lock`)

No third-party Python packages are required (stdlib only; Python 3.9+).

## Install

```powershell
cd /deprisk
py -3 -m pip install -e .
deprisk --help
```

Or run directly without installing:

```powershell
py -3 -m deprisk <project-dir>
```

## Usage

```powershell
# Analyze the current directory, write markdown + HTML reports
py -3 -m deprisk .

# Restrict to one ecosystem
py -3 -m deprisk . -e npm

# Deeper transitive resolution and a higher package cap
py -3 -m deprisk . --depth 2 --max-packages 250

# Parse only (no network) — useful for a first sanity check
py -3 -m deprisk . --offline

# Emit machine-readable JSON
py -3 -m deprisk . --format json
```

Outputs (written next to the project by default):

- `dependency-report.md` — a markdown report ready to paste into a PR comment.
- `dependency-dashboard.html` — a self-contained HTML dashboard with an SVG
  dependency graph.
- `dependency-report.json` — machine-readable results (`--format json`).

## What it reports

1. **Outdated packages** — compares the installed (or conservatively assumed)
   version against the latest release in the registry.
2. **Known vulnerabilities** — via the [OSV.dev](https://osv.dev) API, which
   aggregates GitHub Security Advisory, PyPA, RustSec and other databases.
3. **End of life** — deprecated/abandoned packages (registry flags) plus the
   end-of-life status of the declared Node/Python/Rust runtime.
4. **Dependency relationships** — a depth-limited transitive graph with reverse
   (dependent) edges, rendered as a table and an SVG.
5. **Upgrade risk** — a 0–100 score combining major/minor/patch distance,
   breaking-change likelihood (major jumps), the presence of known
   vulnerabilities, deprecation, and the blast radius (number of dependents).

## Confidence model

A dependency is **never** reported as "safe" merely because no vulnerability was
found. Every assessment carries an explicit status:

| Status | Meaning |
|---|---|
| `vulnerable` | a public advisory matches the exact analyzed version (verified finding) |
| `no_known_vulns` | the queried databases returned nothing for this version — *not* a guarantee of safety |
| `no_data` | the databases could not be reached — no conclusion is possible |
| `uncertain` | the databases responded but the result could not be verified |

Versions shown as `assumed-minimum` were not pinned by a lockfile; the tool uses
the lowest version allowed by the declared range as a conservative lower bound
for vulnerability checks.

## Layout

```
deprisk/
  pyproject.toml
  deprisk/
    cli.py            # command-line interface
    models.py         # data model + confidence status
    semver.py         # dependency-free semver / PEP 440 parsing
    httpclient.py     # urllib-based HTTP client (retries, timeouts)
    parsers/          # npm, pypi, cargo manifest parsers
    sources/          # osv (vulns), registry (latest/deprecation), eol
    analysis/         # graph resolution + upgrade-risk estimation
    report/           # markdown + HTML generators
```

## Notes and limitations

- Vulnerability data is only as complete as the upstream databases queried.
- Lockfile-based resolution is preferred; without a lockfile, versions are
  conservative lower bounds of the declared range.
- EOL checks apply to *runtimes* (Node/Python/Rust); package "end of life" is
  reported via registry deprecation flags, since package registries do not
  generally track EOL.
- Rate limits and network failures degrade gracefully into `no_data`, never into
  a false "clean" result.
