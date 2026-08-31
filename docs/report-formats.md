# Report formats

All formats describe the same audit result. Select one with `--format`, or use
`--format all --output DIRECTORY` to write all four.

## Text

Designed for terminals and CI logs. It includes design inventory, per-mode
coverage components, ordered findings, remediation, and a summary. Text is a
human interface and may evolve before 1.0; scripts should consume JSON.

## JSON

The JSON report is the canonical machine-readable representation. Top-level
fields include:

- `schema_version` (currently `1.1.0`);
- tool name/version and design inventory;
- summary counts and per-mode coverage;
- optional adoption-control provenance and controlled-finding dispositions;
- per-mode clocks, exceptions, graph nodes/edges, and diagnostics;
- a flattened diagnostic list for simple consumers.

Every diagnostic includes rule ID, severity, message, location, rationale,
suggestion, mode, fingerprint, and rule-specific evidence. Export the bundled
JSON Schema with `openconstraint schema`.

Clock records include explicit-waveform state and normalized generated-clock
source/master, divide/multiply/duty, invert/combinational, edge, and edge-shift
fields. Exception records retain ordered through collections and a strict
qualifier object for transitions, setup/hold or start/end applicability,
multiplier/delay values, explicit-side/scope-resolution state, multicycle reset
markers, and clock-group relation where relevant.

Graph records include explicit generated-clock source-object edges. Exception
through edges carry their zero-based collection index and rise/fall transition,
so consumers can reconstruct ordered through scopes instead of flattening them.

When a diagnostic baseline or waiver file is loaded, active diagnostic arrays
contain only findings that still affect the severity gate.
`summary.adoption.dispositions` retains every baselined or waived diagnostic,
and records waiver rationale/expiry plus the schema version and SHA-256 of each
control source. This separation is part of the report contract; a controlled
finding is not erased evidence.

The schema validates the complete report structure, including nested coverage,
clock, exception, graph, and diagnostic records. Structural records reject
unknown fields so accidental producer changes fail early. The `design` inventory
and each diagnostic's `evidence` object intentionally allow additional fields;
those are the extension points for new inventory metrics and rule-specific proof
without weakening validation of the surrounding report.

When `--opensta` is enabled, `summary.opensta` records the executable version,
overall status, and per-mode return code, timeout status, duration,
effective-SDC SHA-256, stdout, and stderr. A successful mode also contains
`effective_audit`: effective coverage and diagnostic counts, the number of new
diagnostics merged into the active result, normalized static/effective semantic
SHA-256 values, and their equality flag. The digests cover modeled clocks,
ordered exception records, canonical active I/O-delay state, and coverage; they
are not a Tcl- or signoff-equivalence proof. This additional output may contain sensitive design or
environment details.

Schema compatibility is independent from the pre-1.0 CLI version. An
incompatible report shape requires a schema-version change and changelog entry.

## SARIF 2.1.0

SARIF output is intended for code-scanning systems. It includes rule metadata,
severity, locations, remediation, evidence, and an `openconstraint/v1` partial
fingerprint. Repository-relative inputs remain portable URI paths. Absolute
inputs inside the current workspace are relativized; external absolute inputs
use file URIs.

Moving an input file changes its location-derived fingerprint. Keep workspace
paths stable when using SARIF result baselines.

With adoption controls, SARIF also includes controlled results. Waivers use an
accepted external `suppressions` record with the review justification;
diagnostic-baseline matches use `baselineState: unchanged`, and active findings
use `baselineState: new` when a baseline was loaded.

## HTML

The HTML report is one offline file with embedded styles, scripts, and data. It
contains coverage cards, design inventory, finding filters, adoption-control
provenance and dispositions, remediation, and a mode-selectable clock/exception
graph. It loads no CDN and sends no telemetry.

HTML and machine reports can expose hierarchical names, source paths, raw SDC
exception text, and matched-object samples. Review them before sharing outside
the design's confidentiality boundary.

## Determinism

For the default static backend, a fixed release, input contents/order, options,
top module, and path strings are intended to produce reproducible reports. JSON
keys and evidence collections are sorted where the schema permits. Absolute
versus relative paths are observable and can affect SARIF URIs and
fingerprints. Opt-in OpenSTA fields include measured duration and captured
engine output, so an otherwise equivalent `--opensta` report is not guaranteed
to be byte-identical.
