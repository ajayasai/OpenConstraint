# CI integration

OpenConstraint writes a report before applying severity and coverage gates, so
a failing audit can still leave useful artifacts.

## Policy controls

- `--fail-on error` (default): fail on errors.
- `--fail-on warning`: fail on warnings or errors.
- `--fail-on never`: findings do not affect the exit code.
- `--min-coverage N`: fail when any mode is below `N`.

A policy failure returns exit code 1. Input or CLI errors return 2.

## GitHub Actions with SARIF

```yaml
name: Constraint audit

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.14"
          cache: pip
      - name: Install the protected beta release
        run: >-
          python -m pip install
          https://github.com/ajayasai/OpenConstraint/releases/download/v0.3.0-beta/openconstraint-0.3.0b0-py3-none-any.whl
      - name: Audit constraints
        id: constraint-audit
        continue-on-error: true
        run: >-
          openconstraint audit
          --verilog netlist/top.v
          --liberty liberty/cells.lib
          --sdc constraints/top.sdc
          --top top
          --format sarif
          --output openconstraint.sarif
          --fail-on warning
          --min-coverage 90
      - name: Upload SARIF
        if: always() && hashFiles('openconstraint.sarif') != ''
        uses: github/codeql-action/upload-sarif@cdf488f595d80d6e07e03d4674febd5ab45fa938 # v4.37.9
        with:
          sarif_file: openconstraint.sarif
      - name: Enforce audit policy
        if: steps.constraint-audit.outcome == 'failure'
        run: exit 1
```

For fork pull requests, GitHub may restrict `security-events: write`. Upload the
SARIF as a normal artifact or run code-scanning upload only for trusted events.
Never give an untrusted constraint job release credentials.

Do not enable `--opensta` for an untrusted pull request: OpenSTA evaluates SDC as
Tcl with the job's permissions. For a trusted internal flow, use a pinned
executable path, finite timeout, non-privileged runner, read-only inputs, and
resource/network restrictions. Archive the captured version and effective-SDC
hash with the report.

## Generic CI

```console
openconstraint audit \
  --verilog netlist/top.v \
  --liberty liberty/cells.lib \
  --sdc constraints/top.sdc \
  --format json \
  --output build/openconstraint.json \
  --fail-on warning \
  --min-coverage 90
```

Archive the JSON plus a human-readable HTML report when confidentiality policy
allows. The JSON schema can be checked into a consumer or exported at build
time with `openconstraint schema`.

## Adoption guidance

Start by running `--fail-on never`, reviewing rule evidence and component
denominators. Then gate errors, establish an evidence-backed coverage threshold,
and finally consider warnings. Existing designs can commit a reviewed
`--baseline`; intentional exceptions belong in exact-fingerprint `--waivers`
with a reason and optional expiry. Use `--strict-controls` to fail stale
baseline entries and unused waivers. See
[adoption controls](adoption-controls.md) instead of filtering report logs.

The default `--fail-on error` gate includes `OC0002`. A parser or elaboration
warning therefore fails the audit even when the partial structural model would
otherwise receive high coverage. The complete warning list remains in
`design.parser_warnings`; diagnostic evidence contains a bounded sample.
