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
                          text / JSON / SARIF / HTML
```

An explicit optional branch runs after the static audit:

```text
--opensta ─> one separate trusted-input OpenSTA process per mode
          └> check_setup + effective-SDC provenance + OC6001
```

## Input layers

The Tcl lexer separates commands and words while tracking braces, quotes,
brackets, comments, continuations, and source locations. It does not evaluate
the tokens. The SDC layer recognizes supported command and object-query shapes.

The Liberty reader extracts leaf-cell pin direction, sequential groups, data
pins, and clock pins. The Verilog reader builds module hierarchy, leaf
instances, pins, nets, drivers, and loads. This is a structural index, not a
full simulator or elaborator.

## Audit engine

Each named mode is analyzed independently:

1. Read its SDC documents in the supplied order.
2. Build primary and generated clock records.
3. Resolve supported object queries against the design index.
4. Propagate clocks structurally through modeled combinational leaf cells.
5. Collect I/O delays and exception scopes.
6. Run query, clock, exception, endpoint, and I/O checks.
7. Compute per-component structural coverage and graph data.

After every mode is complete, cross-mode rules compare clock definitions and
exception signatures. Findings have stable IDs, source locations, rationales,
remediation text, evidence objects, mode names, and deterministic fingerprints.

## Optional OpenSTA adapter

Only `--opensta` crosses the execution boundary. The adapter discovers or uses
an explicit executable, queries its version, then creates a temporary fixed Tcl
driver for each mode. The driver reads the supplied libraries and netlists,
links the top, executes that mode's SDC files, runs `check_setup -verbose`, and
writes a timestamp-free effective SDC. OpenConstraint launches an argument
vector with `shell=False`, captures stdout/stderr, applies the configured
timeout, hashes the effective SDC with SHA-256, and deletes the temporary
directory. OpenSTA is not imported, linked, or redistributed.

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
