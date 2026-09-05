# Changelog

All notable changes to OpenConstraint are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) with pre-1.0
compatibility caveats documented in [GOVERNANCE.md](GOVERNANCE.md).

## [Unreleased]

### Added

- Replayable structural exception witnesses/vacuity analysis and inert,
  review-only repair plans through `openconstraint-prove`.
- Experimental Boolean source-to-target influence analysis on flat Yosys JSON,
  optional Z3, exhaustive cross-checking, independently evaluated counterexamples,
  strict schemas, provenance digests, and `openconstraint-functional` CLI.
- Dedicated CI synthesis of a real RTL example and cross-backend verification.
- Compound `inconclusive` and `any` structural proof gates; an untrusted mode
  cannot pass these gates merely because it contains no modeled exceptions.

### Fixed

- Direct unconnected clock-pin targets and direct combinational clock-pin
  propagation, sharing the audit implementation with structural proofs.
- Repeated clock reachability work, now memoized per mode within each proof run.
- Multicycle repair operand placement, implicit setup/hold replacement, quoted
  option operands, and conservative handling of `-reset_path` history.
- Exact multi-object Tcl collection templates, clock names containing spaces,
  and physical-line commenting of all untrusted repair metadata.

### Scope

- The Boolean backend models zero-delay logic and arbitrary DFF Q state, not
  delay-sensitive path sensitization, sequential proof, or timing signoff.
  Unsupported logic, contradictory assumptions, and resource limits never
  become successful independence decisions.

## [0.3.0-beta] - 2026-09-01

### Added

- Versioned diagnostic baselines and exact-fingerprint waiver files with
  mandatory review reasons, optional expiry, strict stale-control gates,
  SHA-256 report provenance, packaged JSON Schemas, and SARIF dispositions.
- Stable errors `OC2006` for malformed primary-clock identity/targets and
  `OC4002` for malformed exception or clock-group definitions, with dedicated
  rule documentation and reviewed semantic-accuracy cases.
- Stable error `OC0003` for dynamic command dispatch and every command outside
  the exact allowlist of nine constraint commands plus a validated literal
  `current_design` directive; affected modes now receive zero trusted coverage
  instead of a clean score.
- A versioned, occurrence-level accuracy corpus with closed JSON Schemas and a
  CI gate that reports true positives, false positives, false negatives,
  precision, and recall without inflating scores for unlabeled behavior.
- Source-pinned OpenSTA integration CI that builds the engine and rejects
  effective-SDC semantic divergence, newly introduced diagnostics, or coverage
  drift.
- New semantic checks for partially unmatched queries, invalid generated-clock
  transformations, malformed I/O-delay relationships, incomplete slot
  coverage, redundant exception definitions, ordered-through overlap, and
  exact generated-clock reference failures.
- Tcl/SDC fuzz seeds for literal `current_design` context and selector grammar
  boundaries, increasing the reviewed cross-parser seed corpus from nine to
  eleven inputs.

### Changed

- Verilog, Liberty, and elaboration warnings now emit design-level error
  `OC0002`, preventing truncated, inferred, or unsupported structural models
  from passing the default CI severity gate.
- Clock propagation now follows Liberty output `function` and timing
  `related_pin` dependencies instead of assuming every combinational input
  reaches every output. Missing instantiated dependencies stop propagation and
  invalidate the structural model through `OC0002`.
- Query-health coverage now counts dynamic, unsupported, and partially
  unmatched queries as unresolved instead of letting unknown scope improve the
  score. Graph output now retains generated-clock source edges and ordered,
  transition-qualified exception-through edges.
- I/O coverage now measures active min/max by rise/fall slots per clock,
  reference-pin, and edge relationship after deterministic OpenSTA-compatible
  replacement and `-add_delay` replay. Invalid attempted relationships add
  uncovered obligations instead of disappearing from the denominator.
- I/O overwrite diagnostics now follow that same active-state replay: a
  non-additive clock or clock-edge switch reports the relationships it removes,
  while superseded relationships no longer create stale completeness warnings.
- I/O-delay commands now require exactly one delay and one target collection,
  matching OpenSTA's positional arity and preventing rejected extra targets
  from satisfying missing-delay or coverage obligations.
- The nine modeled constraint commands and literal `current_design` context
  assertion now use separate source-pinned operand grammars. Foreign or missing
  options, malformed decoded words, and invalid positional shapes fail closed
  without mutating modeled state, while nested selectors remain available as
  diagnostic evidence.
- Tcl backslash-newline folding now consumes following spaces/tabs in every
  lexical context and preserves Tcl's odd/even comment-continuation behavior.
  Brackets inside `${...}` variable names remain inert during lexical grouping
  even though variable evaluation itself stays outside the static subset.
  Selector substitutions in scalar options or effective scalar positionals
  fail the outer command closed as `OC0003`, while documented collection-valued
  selector roles remain static;
  astral eight-digit escapes fail closed across Tcl 8.6 Unicode builds.
- Object-query parsing now distinguishes an omitted OpenSTA-compatible
  implicit wildcard from an explicitly empty Tcl pattern, rejects malformed
  option/positional arity instead of broadening it, and exempts intentional
  `all_*` collections from broad-wildcard warnings. It also preserves Tcl
  brace-suppressed substitutions, decodes non-evaluating Tcl word escapes in
  command and selector names plus nested list elements before wildcard/option
  classification, recognizes singular query aliases and modeled option
  abbreviations, implements literal `*`/`?` glob matching and anchored
  common-subset regular expressions, and applies OpenSTA's kind-specific
  hierarchy scope names and current-scope wildcard depth. Conservative regexp
  validation rejects backend-specific escapes, quantifiers, bracket classes,
  and case folding; OpenSTA's component-level regexp/exact-lookup routing and
  raw-anchor precedence are retained. Multiplicity is retained for singleton
  contracts even when duplicate patterns collapse to one object. Exact
  direction filters, literal exception scopes, excessive selector nesting,
  malformed Tcl lists, and invalid Unicode escapes now fail closed. Sequential
  truth filtering is limited to the explicit `get_registers` extension.
- Glob matching now follows pinned OpenSTA UTF-8 byte and adjacent-star
  semantics with stack-safe dynamic programming and a per-comparison limit.
  One aggregate budget now spans every pattern, hierarchy-routing scan,
  collection comparison, `*` fast path, aggregation, filter, and nested
  `-of_objects` source in a root selector resolution. Pattern Tcl lists share
  one aggregate 50,000-element/64-level bound per selector, including dynamic
  or otherwise invalid extra positional text; commands retain at most 50,000
  words before failing without a partial command. Raw Tcl command-substitution
  grouping is limited to 64 levels and rejects the complete document without a
  parsed prefix when crossed. Recursive selector parsing
  now has one 16,777,216-character document budget, command-local identity
  memoization, bounded error spellings, and no process-global suffix cache.
  Each top-level SDC command resolves its complete selector forest once under
  one aggregate work budget and reuses those results in semantic collectors and
  diagnostics. Base object universes are precharged and cached once per forest,
  all-object multiplicities and filter source text are precharged, and
  equal-text option/positional operands retain exact occurrence identity so a
  healthy sibling cannot mask a failed or literal effective operand. Semantic
  reuse no longer rebuilds literal candidate unions. Regular
  expressions have explicit length, nesting, quantifier,
  top-level-alternation/repetition, ambiguity, and aggregate-work limits.
  Escaped hierarchy dividers and bus-range-shaped patterns fail closed instead
  of being misresolved by the flattened structural model.
- Non-ANSI packed port declarations no longer leave aggregate-name ghost ports
  or nets. Named and positional hierarchical bus connections remain intact;
  escaped-identifier/hierarchy path collisions now produce a parser warning and
  therefore design-level `OC0002`.
- Literal target, reference, exception-scope, and clock-group collections use a
  bounded Tcl-list decoder and fail the whole modeled command when any member is
  malformed or unresolved. Singleton literal references count the complete
  list and preserve their original spelling. This intentionally prevents
  OpenSTA's warning-based partial-retention behavior from silently narrowing an
  audited constraint.
- Primary clocks now reject more than one positional target word, and generated
  clocks reject either missing or multiple positional target words, matching
  the source-pinned OpenSTA command arity.
- Invalid clock definition attempts remain visible with `valid: false`, but are
  excluded from active clock queries, I/O requirements, exceptions, graphs,
  coverage, cross-mode comparison, and semantic digests.
- Numeric operands are Tcl-decoded exactly once. Waveform, edge, and edge-shift
  values use the bounded Tcl-list decoder instead of comma/whitespace splitting;
  integer transforms and multicycle values are parsed exactly within the pinned
  Tcl `string is integer` range instead of round-tripping through binary floats.
- Exception selectors that cannot resolve remain inactive and are covered by
  the query diagnostics. Clock groups accept only fully resolved clock collections;
  `all_clocks` is valid at exception endpoints, and singleton `all_inputs` or
  `all_outputs` collections satisfy the I/O reference-pin contract.
- Benchmark manifests and baselines reject duplicate JSON keys, excessive
  size, excessive nesting, and excessive node counts before semantic traversal.
- Release builds pin the backend, bind wheel timestamps to the release commit,
  and refuse to replace assets on an existing GitHub release tag.
- OpenSTA semantic comparison now normalizes a valid implicit primary-clock
  waveform to its effective 50% duty cycle while preserving the raw waveform
  and explicitness fields in reports.
- Benchmark commands now validate fetch, result, and baseline outputs against
  the declared/resolved cache and fixed cache layers before manifest loading,
  then against exact selected blob, digest, and materialization paths before
  work. After selection, the cache root is materialized and identity is checked
  again before work, including for suite-only cases; a final check runs
  immediately before publication. Validation does not walk the cache tree and
  bounds same-entry disambiguation. CLI single-file output uses atomic
  replacement so an external hard-link alias cannot truncate a cached blob or
  materialization.

### Security

- Static SDC input now has an all-or-nothing 16 MiB UTF-8 budget shared by all
  ordered files in one logical mode. Exact-size input is accepted; an invalidly
  encoded file or a file exceeding the remaining budget emits `OC0001`,
  discards earlier documents, and leaves later files unopened so no parsed
  prefix survives. Direct in-memory parsing enforces the same source boundary.
- Tcl command-substitution grouping now fails closed at 64 levels in command
  chunking, word splitting, and whole-selector recognition, preventing an
  attacker-sized lexical context stack from preceding selector validation.
- OpenSTA effective snapshots have a separate all-or-nothing 16 MiB, strict
  UTF-8 boundary. Oversized or invalidly encoded output emits `OC6001` with a
  failure reason and is not retained, hashed, or statically re-audited.

### Validation

- The reviewed accuracy corpus contains 67 expected diagnostic occurrences
  across 35 cases and currently gates at 67 true positives, zero false
  positives, and zero false negatives for its explicitly scored rule set.
- The checksum-pinned OpenROAD AES, Ibex, and JPEG suite covers 78,537
  gate-level instances and 6,842 sequential endpoints; all refreshed semantic
  baselines replay without a regression, and the transparent static-reference
  modes reach 100% structural coverage.

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

[Unreleased]: https://github.com/ajayasai/OpenConstraint/compare/v0.3.0-beta...HEAD
[0.3.0-beta]: https://github.com/ajayasai/OpenConstraint/releases/tag/v0.3.0-beta
[0.2.0-beta]: https://github.com/ajayasai/OpenConstraint/releases/tag/v0.2.0-beta
[0.1.0-beta]: https://github.com/ajayasai/OpenConstraint/releases/tag/v0.1.0-beta
