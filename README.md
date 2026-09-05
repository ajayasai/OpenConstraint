# OpenConstraint

[![CI](https://github.com/ajayasai/OpenConstraint/actions/workflows/ci.yml/badge.svg)](https://github.com/ajayasai/OpenConstraint/actions/workflows/ci.yml)
[![CodeQL](https://github.com/ajayasai/OpenConstraint/actions/workflows/codeql.yml/badge.svg)](https://github.com/ajayasai/OpenConstraint/actions/workflows/codeql.yml)
[![Benchmarks](https://github.com/ajayasai/OpenConstraint/actions/workflows/benchmarks.yml/badge.svg)](https://github.com/ajayasai/OpenConstraint/actions/workflows/benchmarks.yml)
[![Parser fuzzing](https://github.com/ajayasai/OpenConstraint/actions/workflows/fuzz.yml/badge.svg)](https://github.com/ajayasai/OpenConstraint/actions/workflows/fuzz.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Status: beta](https://img.shields.io/badge/status-0.3.0--beta-orange.svg)](CHANGELOG.md)

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

> **Beta scope:** v0.3.0-beta is a structural and semantic checker. It does not
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

## Replayable evidence beyond lint

`openconstraint-prove analyze` produces structural path witnesses and vacuity
certificates, with review-only repair proposals and independent replay. Clock
reachability is reused within each mode rather than recomputed for every
exception. Use `--fail-on inconclusive` to reject unresolved or resource-bounded
analysis, including an untrusted mode with no modeled exceptions.

The separate experimental `openconstraint-functional` command checks Boolean
influence on flat Yosys JSON using optional Z3 or a built-in exhaustive backend.
It emits concrete counterexamples, rejects contradictory assumptions, and
supports cross-backend replay. **Boolean independence is not delay-aware timing
false-path proof**, and this command never generates SDC exceptions.

See [structural evidence](docs/proof-carrying-analysis.md) and
[Boolean evidence, examples, and limits](docs/functional-analysis.md).

## What the beta checks

- Malformed Tcl grouping or modeled-command grammar without evaluating the Tcl
  program.
- A strict static allowlist of nine constraint commands plus a validated
  literal `current_design` context directive; dynamic dispatch and every other
  top-level command fail closed instead of being treated as inert.
- Incomplete structural models caused by ignored, inferred, malformed, or
  truncated Verilog/Liberty/elaboration input.
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
| Input-delay min/max × rise/fall slots per relationship | 20% |
| Output-delay min/max × rise/fall slots per relationship | 20% |
| Fully resolvable object queries | 10% |

Empty categories are omitted and the remaining weights are renormalized. This
score is useful for regression gating, but it does not measure exception
validity, analog timing accuracy, or functional intent. Read the exact
[coverage methodology](docs/coverage-methodology.md) before setting a threshold.
Invalid I/O relationships cover zero slots. `OC0001`, `OC0003`, `OC1003`, and
`OC1004` force the affected mode's trusted aggregate to 0/F; structural parser
or elaboration warning `OC0002` does the same in every mode. Component counts
remain visible for debugging rather than being presented as trusted coverage.

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

For an existing design, `--write-baseline FILE` snapshots current diagnostics
so new findings can be gated immediately. Exact-fingerprint `--waivers FILE`
entries require a review reason and may expire; `--strict-controls` rejects
stale baseline entries and unused waivers. Reports retain every controlled
finding plus the SHA-256 provenance of each policy file. See
[adoption controls](docs/adoption-controls.md).

## Real-design evidence and continuous parser testing

The public benchmark suite fetches checksum-pinned OpenROAD 26Q3 SKY130HD gate
netlists instead of committing third-party design data. AES, Ibex, and JPEG
together exercise 78,537 instances and 6,842 sequential endpoints. Every
source records its immutable URL, exact byte size, SHA-256, license URL, and
attribution notice. Exact structural-inventory fingerprints, clocks,
exceptions, coverage components, and normalized diagnostic evidence are gated
against a reviewed baseline; timing and traced memory remain observational
because shared runners are noisy.

The upstream SDC files call an OpenROAD Tcl helper that the non-executing static backend
does not execute. Each benchmark therefore records both the fail-closed raw
static result (`OC0003`, `0/F` trusted coverage) and a self-contained,
transparent static-coverage reference. The reference is explicitly not claimed
to be collection-equivalent sign-off SDC; it makes the parser boundary visible
instead of mislabeling the upstream constraints as incomplete. See the
[benchmark method](benchmarks/README.md).

Parser robustness has two layers: Hypothesis properties and corpus replay run
in the ordinary cross-platform test suite, while Atheris/libFuzzer mutates
grammar-aware seed corpora on every relevant change and on a weekly extended
schedule. Crash reproducers are retained as CI artifacts. See the
[fuzzing guide](fuzz/README.md).

## Safety model

SDC files are Tcl programs, and evaluating an untrusted SDC file can execute
arbitrary logic in a full interpreter. By default, OpenConstraint's static
backend recognizes only the nine documented constraint commands and does not
evaluate variables, general nested commands, `source`, environment access, or
shell commands. Any other top-level command, dynamic command name, or opaque
argument produces a fail-closed diagnostic instead.

`--opensta` deliberately changes that boundary: it executes the supplied SDC in
a separately installed `sta`/`opensta` process. Use it only for inputs you trust
with the runner's permissions. It is never enabled implicitly.

The beta accepts at most 16 MiB (16,777,216 bytes) of UTF-8 static SDC source
per logical mode, cumulatively across that mode's ordered files. A file that is
not valid UTF-8 or crosses the remaining budget rejects the entire mode as
`OC0001`; commands from earlier files are not retained as a trusted prefix.
Parser cardinalities, nesting depths, and supported glob/regular-expression
work are also bounded; raw Tcl command substitutions, selectors, and literal
lists stop at 64 grouping levels. Recursive selector parsing shares a document-wide
16,777,216-character work-and-retention budget and does not retain nested
source suffixes in a process-global cache. OpenConstraint does not impose a general file-size
limit on every input type or a complete memory, CPU, or wall-clock quota, so
hostile files should still be processed in an OS sandbox with resource quotas.
Read the full [security
model](docs/security-model.md) and report vulnerabilities privately according
to [SECURITY.md](SECURITY.md).

## Supported subset and OpenSTA

The built-in parsers intentionally cover only the constructs needed by the
current rules. Unsupported syntax is not silently treated as sign-off-clean.
Review the [compatibility matrix](docs/compatibility.md).

OpenSTA is a separate GPL-3.0-or-later project. v0.3.0-beta can invoke an
installed executable only when `--opensta` is supplied; it does not link or
redistribute OpenSTA. Each mode runs in a separate process with a default
120-second timeout. An effective SDC snapshot is accepted only when it is valid
UTF-8 and no larger than a separate 16 MiB limit; accepted snapshots receive a
SHA-256 and static re-audit. An oversized or invalidly encoded snapshot emits
`OC6001` and is not retained, hashed, or re-audited. See [OpenSTA
validation](docs/opensta-validation.md) and
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
- [Competitive position and evidence bar](docs/competitive-position.md)
- [Roadmap](ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [Governance](GOVERNANCE.md)
- [Support](SUPPORT.md)

OpenConstraint is independently developed and is not affiliated with or
endorsed by Synopsys, Cadence, Siemens EDA, Parallax Software, or the OpenROAD
Project. Product names are trademarks of their respective owners.

Licensed under [Apache-2.0](LICENSE).
