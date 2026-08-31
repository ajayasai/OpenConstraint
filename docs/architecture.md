# Architecture

OpenConstraint is intentionally small and layered so that a diagnostic can be
traced from source input to evidence and report output.

```text
Verilog files ──> structural reader ─┐
Liberty files ──> cell metadata ─────┼─> design index
                                    │
SDC files ──────> non-executing Tcl lexer ─> SDC command/query model
                                    │
                                    v
                           deterministic audit engine
                       ┌────────────┼──────────────┐
                       v            v              v
                  diagnostics    coverage      graph data
                       └────────────┼──────────────┘
                                    v
                    optional adoption-control policy
                    ├─> active diagnostics for gates
                    └─> reviewable dispositions + provenance
                                    v
                          text / JSON / SARIF / HTML
```

An explicit optional branch runs after the static audit:

```text
--opensta ─> one separate trusted-input OpenSTA process per mode
          └> check_setup + effective-SDC capture
                         ├─> failure ─> OC6001
                         └─> success ─> same static audit pipeline
                                        ├─> unique diagnostics merged
                                        └─> effective coverage + semantic digests
```

## Input layers

The Tcl lexer separates commands and words while tracking braces, quotes,
brackets, comments, continuations, and source locations. It does not evaluate
the tokens. The SDC layer has an exact allowlist of nine constraint commands
plus a literal `current_design` context directive, a distinct option/operand
grammar for each modeled command, and command-specific object-query grammars.
The context name must match the elaborated top. Every other top-level command
fails closed as `OC0003` rather than being assumed inert.

The Liberty reader extracts leaf-cell pin direction, sequential groups, data
pins, clock pins, and declared combinational dependencies from output
`function` and timing `related_pin` metadata. The Verilog reader builds module
hierarchy, leaf instances, pins, nets, drivers, loads, and instance-level
input/output arcs. This is a structural index, not a full simulator or
elaborator.

## Audit engine

Each named mode is analyzed independently:

1. Read its SDC documents in the supplied order.
2. Build primary and generated clock records, including waveform and transform
   validation. Retain invalid attempts as report evidence while exposing only
   proven-valid clocks to downstream semantic state.
3. Resolve supported object queries, including static `-of_objects`
   connectivity, work-bounded OpenSTA-compatible byte globs, complexity-bounded
   anchored common-subset regular expressions, current-scope/hierarchy naming,
   component-level regexp routing, and collection multiplicity, against the
   design index. Decode literal object lists separately and invalidate the
   dependent command if any leaf is malformed or unresolved.
4. Propagate clocks only through declared Liberty input/output dependencies;
   stop and invalidate incomplete structural models rather than assuming
   all-input-to-all-output connectivity.
5. Normalize I/O delay value/clock/direction/min-max/additive semantics and
   edge-qualified, ordered exception scopes.
6. Run query, clock, generated-clock, exception, multicycle, endpoint, and I/O
   checks.
7. Compute per-component structural coverage and graph data.

After every mode is complete, cross-mode rules compare clock definitions and
exception signatures. Findings have stable IDs, source locations, rationales,
remediation text, evidence objects, mode names, and deterministic fingerprints.

## Adoption-control layer

Diagnostic baselines and waivers are applied after the static audit and any
explicit OpenSTA result is merged, but before rendering and quality-policy exit
evaluation. This keeps rule generation independent from organizational policy.
The layer validates versioned control JSON, matches only exact fingerprints,
removes matches from active top-level and per-mode diagnostic arrays, and adds
complete disposition plus source-digest provenance to `summary.adoption`.
Coverage is not recalculated or waived. See
[adoption controls](adoption-controls.md).

## Optional OpenSTA adapter

Only `--opensta` crosses the execution boundary. The adapter discovers or uses
an explicit executable, queries its version, then creates a temporary fixed Tcl
driver for each mode. The driver reads the supplied libraries and netlists,
links the top, executes that mode's SDC files, runs `check_setup -verbose`, and
writes a timestamp-free effective SDC. OpenConstraint launches an argument
vector with `shell=False`, captures stdout/stderr, applies the configured
timeout, hashes the effective SDC with SHA-256, and deletes the temporary
directory. On success, the in-memory effective SDC is passed through the same
non-executing static audit. Diagnostics not already present by normalized rule,
message, and evidence are merged into the mode; the report also records the
effective audit's coverage and diagnostic count plus SHA-256 digests of modeled
static/effective clocks, exceptions, canonical active I/O-delay state, and
coverage. The effective model does not replace the original mode, and
cross-mode findings are not recomputed from it.
OpenSTA is not imported, linked, or redistributed.

## Determinism

Reports sort maps, findings, and matched evidence where practical. For the same
release, input contents, input order, top, options, and path strings, output is
designed to be repeatable. Source paths are part of locations and fingerprints,
so moving inputs can intentionally change those fields.

## Extension boundary

The public 0.x interface is the CLI and versioned report schema, not internal
Python classes. A custom-rule API is planned only after rule inputs, lifecycle,
and compatibility guarantees can be versioned safely.

## What is deliberately absent

- Implicit Tcl evaluation or a shell-command execution path. Explicit
  `--opensta` runs trusted SDC in OpenSTA without a shell.
- Delay calculation, parasitic analysis, setup/hold path search, or formal
  false-path proof.
- OpenSTA linking or redistribution.
- Hidden heuristics or a proprietary coverage denominator.

See [compatibility.md](compatibility.md) for the exact parser subset and
[security-model.md](security-model.md) for trust boundaries.

## Public-design benchmark boundary

The optional benchmark harness sits outside the audit report schema. It loads a
strict versioned manifest, verifies HTTPS artifacts and checked-in suite inputs
by exact byte size and SHA-256, safely materializes upstream data in a
content-addressed cache, and then invokes the same parser and audit layers as
`openconstraint audit`. Offline mode is a hard network prohibition.

Benchmark results keep deterministic semantic snapshots separate from noisy
wall-time and traced-memory observations. A semantic baseline is tied to the
canonical manifest digest and compares an exact structural-inventory digest,
clock definitions, exception topology, complete coverage components, and
normalized diagnostic evidence as well as aggregate counts. This makes subtle
compatibility drift fail CI without pretending that one shared-runner timing
sample is a reliable performance limit.
