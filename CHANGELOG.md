# Changelog

All notable changes to OpenConstraint are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) with pre-1.0
compatibility caveats documented in [GOVERNANCE.md](GOVERNANCE.md).

## [Unreleased]

### Planned

- Diagnostic baselines and reviewable suppressions for adoption in existing flows.
- Broader SDC preprocessing evidence and more public design families.

## [0.2.0-beta] - 2026-08-31

### Added

- A checksum-pinned, offline-reproducible public-design benchmark harness with
  strict manifests, content-addressed acquisition, safe archive extraction,
  semantic baselines, JSON Schemas, and CI evidence.
- OpenROAD 26Q3 SKY130HD AES, Ibex, and JPEG benchmark cases covering 78,537
  gate-level instances and 6,842 sequential endpoints without vendoring
  third-party design files.
- Transparent static-coverage overlays alongside the unexecuted upstream
  helper calls, making the Tcl boundary explicit without claiming collection
  equivalence or sign-off semantics.
- Hypothesis parser properties, Atheris/libFuzzer targets, grammar dictionaries,
  nine seed-corpus inputs, corpus replay tests, scheduled CI fuzzing, and crash
  reproducer artifacts.

### Security

- Tcl command/issue retention; Liberty token/node/warning retention; Verilog
  module, statement, connection, warning, bus, and name retention/expansion;
  Liberty/hierarchy depth; and total elaborated structural objects are bounded.
  Limits produce deterministic parser warnings, with an outer memory cap on
  native fuzzing jobs.
- Benchmark downloads require HTTPS plus exact byte-size and SHA-256 matches;
  blob and full materialization cache reuse are reverified, TAR extraction is
  streamed, and archive handling rejects traversal, links, special files,
  portable path aliases/device names, duplicate members, encrypted ZIP entries,
  and size or entry-count bombs.

### Validation

- Public benchmark semantic baselines cover upstream-static and
  coverage-reference modes on AES, Ibex, and JPEG.
- Property tests run on every supported operating system; coverage-guided
  mutation runs on relevant changes and weekly with bounded CI resources.

## [0.1.0-beta] - 2026-08-31

### Added

- Dependency-free static readers for a structural Verilog subset, relevant
  Liberty cell metadata, and a deliberately non-executing Tcl/SDC subset.
- Stable diagnostics for parse limitations, object-query quality, clocks,
  generated clocks, I/O delays, unconstrained endpoints, timing exceptions,
  mode differences, and structural coverage.
- Text, JSON, SARIF, and self-contained HTML reports.
- Clock and timing-exception graph data.
- Multi-mode comparison for functional, scan, test, and other named modes.
- CI controls for severity and minimum structural-coverage thresholds.
- Explicit, opt-in validation of trusted inputs with a separately installed
  OpenSTA executable, including per-mode process isolation, timeout, captured
  version/output, effective-SDC SHA-256, and OC6001 failure diagnostics.

### Security

- SDC input is tokenized but never evaluated as Tcl by the default static backend.
- Dynamic Tcl constructs are reported as unsupported instead of executed.
- OpenSTA execution requires `--opensta`, uses argument-vector process launch
  without a shell, disables user init loading, and applies a finite timeout.

### Known limitations

- This beta is a deterministic structural auditor, not a sign-off timing engine.
- It does not formally prove false paths or validate analog timing accuracy.
- The Verilog, Liberty, and SDC parsers intentionally support documented
  subsets; unsupported constructs must be reviewed rather than assumed safe.

[Unreleased]: https://github.com/ajayasai/OpenConstraint/compare/v0.2.0-beta...HEAD
[0.2.0-beta]: https://github.com/ajayasai/OpenConstraint/releases/tag/v0.2.0-beta
[0.1.0-beta]: https://github.com/ajayasai/OpenConstraint/releases/tag/v0.1.0-beta
