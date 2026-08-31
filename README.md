# OpenConstraint

[![CI](https://github.com/ajayasai/OpenConstraint/actions/workflows/ci.yml/badge.svg)](https://github.com/ajayasai/OpenConstraint/actions/workflows/ci.yml)
[![CodeQL](https://github.com/ajayasai/OpenConstraint/actions/workflows/codeql.yml/badge.svg)](https://github.com/ajayasai/OpenConstraint/actions/workflows/codeql.yml)
[![Benchmarks](https://github.com/ajayasai/OpenConstraint/actions/workflows/benchmarks.yml/badge.svg)](https://github.com/ajayasai/OpenConstraint/actions/workflows/benchmarks.yml)
[![Parser fuzzing](https://github.com/ajayasai/OpenConstraint/actions/workflows/fuzz.yml/badge.svg)](https://github.com/ajayasai/OpenConstraint/actions/workflows/fuzz.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Status: beta](https://img.shields.io/badge/status-0.2.0--beta-orange.svg)](CHANGELOG.md)

OpenConstraint is an open-source, deterministic auditor for Synopsys Design
Constraints (SDC). It statically reads structural Verilog, relevant Liberty
metadata, and a deliberately non-executing Tcl/SDC subset to find constraint
queries that match nothing, risky wildcards, clock mistakes, unconstrained
sequential endpoints, missing I/O delays, overlapping exceptions, and
cross-mode drift.

The result is reviewable text, versioned JSON, SARIF 2.1.0, or a self-contained
HTML clock/exception dashboard. An explicit `--opensta` option can also run
trusted inputs through a separately installed OpenSTA executable. OpenConstraint
is built for early feedback and CI policy—not timing sign-off.

> **Beta scope:** v0.2.0-beta is a structural and semantic checker. It does not
> calculate delays, formally prove false paths, or certify that a design is
> correctly constrained for silicon sign-off. The default static backend never
> executes Tcl. `--opensta` is an explicit trusted-input execution boundary.

## See it in a minute

OpenConstraint requires Python 3.11 or newer. From a source checkout:

```console
python -m pip install -e .
openconstraint demo --output-dir openconstraint-demo-report
```

The demo writes synthetic inputs plus `openconstraint-report.txt`, `.json`,
`.sarif`, and `.html`. Open the HTML file locally to explore its offline clock
and exception graph; it loads no external assets and sends no telemetry.

Audit your own design:

```console
openconstraint audit \
  --verilog design.v \
  --liberty cells.lib \
  --sdc constraints.sdc \
  --top top \
  --format text \
  --output -
```

Each input option is repeatable. To compare named modes, use `--mode` instead of
`--sdc`:

```console
openconstraint audit \
  --verilog design.v \
  --liberty cells.lib \
  --mode functional=constraints/functional.sdc \
  --mode scan=constraints/scan.sdc \
  --format all \
  --output reports/openconstraint \
  --fail-on warning \
  --min-coverage 90
```

## What the beta checks

- Malformed Tcl grouping without evaluating the Tcl program.
- Static `get_ports`, `get_pins`, `get_cells`, `get_nets`, `get_clocks`, and
  register queries that match zero objects.
- Wildcard/regular-expression queries that match a risky share of a collection.
- Dynamic or unsupported query constructs that cannot be resolved safely.
- Missing or invalid clock periods, implicit waveforms, conflicting clock
  redefinitions, and multiple clocks reaching one sequential clock pin.
- Missing or unrelated generated-clock sources and masters.
- Sequential endpoints not reached by a modeled clock.
- Missing input/output delays on modeled interface ports.
- Intersections and redundancy among false-path, multicycle, min/max-delay, and
  clock-group exceptions.
- Clock-definition and exception-topology drift across named modes.
- Failure of an explicitly requested OpenSTA `check_setup`/effective-SDC
  validation, including timeout and nonzero exit.

Run `openconstraint rules` for the installed catalog or read the
[rule reference](docs/rules/index.md).

## Structural coverage, made explicit

OpenConstraint reports four per-mode components:

| Component | Base weight |
| --- | ---: |
| Clocked sequential endpoints | 50% |
| Input-delay coverage | 20% |
| Output-delay coverage | 20% |
| Resolvable static object queries | 10% |

Empty categories are omitted and the remaining weights are renormalized. This
score is useful for regression gating, but it does not measure exception
validity, analog timing accuracy, or functional intent. Read the exact
[coverage methodology](docs/coverage-methodology.md) before setting a threshold.

## CI-native output

```console
openconstraint audit \
  --verilog design.v --liberty cells.lib --sdc constraints.sdc \
  --format sarif --output openconstraint.sarif \
  --fail-on error --min-coverage 85
```

`--fail-on error` is the default. Use `warning` for a stricter gate or `never`
to produce a report without failing on findings. A quality-policy failure exits
with code 1; invalid CLI or input usage exits with code 2. See
[CI integration](docs/ci-integration.md) and [report formats](docs/report-formats.md).

## Real-design evidence and continuous parser testing

The public benchmark suite fetches checksum-pinned OpenROAD 26Q3 SKY130HD gate
netlists instead of committing third-party design data. AES, Ibex, and JPEG
together exercise 78,537 instances and 6,842 sequential endpoints. Every
source records its immutable URL, exact byte size, SHA-256, license URL, and
attribution notice. Exact structural-inventory fingerprints, clocks,
exceptions, coverage components, and normalized diagnostic evidence are gated
against a reviewed baseline; timing and traced memory remain observational
because shared runners are noisy.

The upstream SDC files call an OpenROAD Tcl helper that the safe static backend
does not execute. Each benchmark therefore records both the raw static result
and a transparent static-coverage reference. The reference is explicitly not
claimed to be collection-equivalent sign-off SDC; it makes the parser boundary
visible instead of mislabeling the upstream constraints as incomplete. See the
[benchmark method](benchmarks/README.md).

Parser robustness has two layers: Hypothesis properties and corpus replay run
in the ordinary cross-platform test suite, while Atheris/libFuzzer mutates
grammar-aware seed corpora on every relevant change and on a weekly extended
schedule. Crash reproducers are retained as CI artifacts. See the
[fuzzing guide](fuzz/README.md).

## Safety model

SDC files are Tcl programs, and evaluating an untrusted SDC file can execute
arbitrary logic in a full interpreter. By default, OpenConstraint's static
backend does not evaluate variables, nested commands, `source`, environment
access, or shell commands. Unsupported dynamic constructs produce diagnostics
instead.

`--opensta` deliberately changes that boundary: it executes the supplied SDC in
a separately installed `sta`/`opensta` process. Use it only for inputs you trust
with the runner's permissions. It is never enabled implicitly.

The beta does not impose hard input-size or runtime limits, so hostile files
should still be processed in an OS sandbox with resource quotas. Read the full
[security model](docs/security-model.md) and report vulnerabilities privately
according to [SECURITY.md](SECURITY.md).

## Supported subset and OpenSTA

The built-in parsers intentionally cover only the constructs needed by the
current rules. Unsupported syntax is not silently treated as sign-off-clean.
Review the [compatibility matrix](docs/compatibility.md).

OpenSTA is a separate GPL-3.0-or-later project. v0.2.0-beta can invoke an
installed executable only when `--opensta` is supplied; it does not link or
redistribute OpenSTA. Each mode runs in an isolated process with a default
120-second timeout, and the report records the OpenSTA version and SHA-256 of
the effective SDC. See [OpenSTA validation](docs/opensta-validation.md) and
[third-party notices](THIRD_PARTY_NOTICES.md).

## Why open

Every diagnostic has a stable ID, deterministic evidence, documented limits,
and small regression fixtures. The coverage equation and report schema are
public. These properties make the checker inspectable, extensible, and easy to
place in CI. They are not a claim that the beta is more accurate than a
commercial constraint or sign-off product.

## Project resources

- [Live interactive dashboard](https://ajayasai.github.io/OpenConstraint/)
  and [deliberately broken example](https://ajayasai.github.io/OpenConstraint/broken.html)
- [Documentation index](docs/index.md)
- [CLI reference](docs/cli.md)
- [Architecture](docs/architecture.md)
- [Public-design benchmarks](benchmarks/README.md)
- [Parser fuzzing](fuzz/README.md)
- [Compatibility and limitations](docs/compatibility.md)
- [Roadmap](ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [Governance](GOVERNANCE.md)
- [Support](SUPPORT.md)

OpenConstraint is independently developed and is not affiliated with or
endorsed by Synopsys, Cadence, Siemens EDA, Parallax Software, or the OpenROAD
Project. Product names are trademarks of their respective owners.

Licensed under [Apache-2.0](LICENSE).
