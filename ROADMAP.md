# Roadmap

This roadmap is an evidence-driven engineering programme, not a delivery-date
promise. OpenConstraint will claim superiority only for capabilities that are
measured on the same inputs with a published oracle. The goal is broader:
build the most inspectable, reproducible, automation-friendly constraint
verification system, then earn any comparative claim with independent data.

## 0.1–0.3 beta — auditable static foundation

Delivered:

- Non-executing Tcl/SDC parsing with explicit unsupported-syntax findings.
- Structural Verilog and Liberty indexing.
- Query, clock, I/O-delay, endpoint, generated-clock, and exception checks.
- Named-mode comparison and a published structural-coverage formula.
- Text, JSON, SARIF, and HTML output suitable for local and CI use.
- Explicit trusted-input OpenSTA validation with per-mode subprocess isolation,
  finite timeout, effective-SDC provenance, and no bundled OpenSTA binary.
- Checksum-pinned public-design benchmarks, reviewed semantic baselines,
  occurrence-level accuracy truth sets, parser fuzzing, diagnostic baselines,
  expiring waivers, and strict stale-control gates.

## 0.4 beta — proof-carrying exception review

The first step beyond ordinary lint is replayable structural proof evidence:

- A canonical directed port/net/pin graph with explicit resource limits.
- Deterministic shortest witnesses for exception scopes that cover a real
  structural path.
- Exhaustive, replayable vacuity certificates when no path satisfies the
  resolved ordered `-from`/`-through`/`-to` scope.
- Clock-scope expansion to the launch and capture pins of clocked sequential
  instances without crossing sequential state.
- Certificate, graph, exception, and complete-pack SHA-256 identities.
- A verifier that rebuilds the graph and rejects altered or stale proof packs.
- Machine-readable, review-required repair plans that never guess timing
  values or edit SDC automatically.

This milestone proves structural reachability or structural vacuity only. It
never calls a structurally absent path *functionally false*.

## 0.5 — functional exception proof and counterexamples

Implemented first evidence layer (experimental): explicit zero-delay Boolean
influence on a fail-closed flat Yosys gate model, optional Z3, a separately
implemented exhaustive backend, concrete counterexample checking, and
cross-backend replay. See [the model boundary](docs/functional-analysis.md).
This does **not** complete the timing/temporal goals below.


- Extract bit-accurate combinational and bounded sequential cones from a
  synthesis-grade intermediate representation.
- Add pluggable SAT/SMT and sequential-property backends with versioned solver
  manifests and independently replayable proof or counterexample artifacts.
- Prove or refute false paths and multicycle assumptions under explicit reset,
  mode, clock, and environmental assumptions.
- Generate SVA/PSL-style review properties from each proof obligation and bind
  every accepted exception to the assumptions that make it valid.
- Distinguish proven, disproven, inconclusive, resource-bounded, and
  assumption-incomplete outcomes; never convert solver uncertainty into a pass.

## 0.6 — hierarchical constraint equivalence and transformation

- Compare block-level and top-level effective constraint semantics.
- Implement proof-carrying promotion and demotion proposals for clocks, I/O
  delays, and exceptions.
- Add timing-budget contracts with provenance, unit handling, corner/mode
  dimensions, and round-trip equivalence checks.
- Report hierarchy-boundary counterexamples when transformed constraints alter
  the set of timed or cut paths.
- Support reusable IP constraint packages with explicit assumptions and
  compatibility negotiation rather than opaque vendor databases.

## 0.7 — broad, safe Tcl/SDC compatibility

- Introduce a typed Tcl/SDC intermediate representation that separates data,
  control flow, collection queries, and side effects.
- Symbolically evaluate a documented, bounded Tcl subset with deterministic
  branch and loop limits.
- Define a sandbox protocol for trusted full-interpreter execution with
  filesystem, process, network, CPU, memory, and wall-clock restrictions.
- Add versioned Synopsys-, Cadence-, Siemens-, and OpenSTA-dialect compatibility
  profiles tested against legally redistributable conformance corpora.
- Preserve fail-closed behavior whenever semantics cannot be reproduced.

## 0.8 — automatic constraint synthesis with proof obligations

- Infer candidate primary/generated clocks and interface relationships from
  connectivity, protocol metadata, and user-supplied architecture contracts.
- Synthesize the smallest deterministic constraint set that satisfies explicit
  coverage and policy objectives.
- Attach provenance and proof obligations to every generated command.
- Require human approval for architectural timing values and functional
  assumptions; optimization may simplify evidence but may not invent intent.
- Compare generated and existing constraints and produce an auditable semantic
  patch instead of rewriting files opaquely.

## 0.9 — incremental, distributed, industrial-scale analysis

- Content-addressed parsing, elaboration, query, graph, and proof caches.
- Incremental invalidation by changed design, library, constraint, mode, and
  policy dependency.
- Deterministic parallel and distributed execution with mergeable proof packs.
- Public million-instance and thousand-clock scale suites with runtime, peak
  memory, cache-hit, and incremental-latency regression gates.
- Fault isolation and resumable analysis so one bounded cone does not erase
  completed evidence for unrelated scopes.

## 1.0 readiness criteria

- Stable CLI, configuration, diagnostic IDs, proof algorithms, exit codes, and
  versioned report schemas with documented migrations.
- Functional exception proof on an independently reviewed corpus containing
  clean controls, real defects, adversarial cases, hierarchy transformations,
  and multiple modes/corners.
- Published precision, recall, false-pass rate, runtime, memory, incremental
  latency, proof replay success, and human waiver burden.
- Legally shareable, same-input comparisons against licensed commercial tools,
  with vendor versions and settings recorded and results repeatable by an
  independent party where licence terms permit.
- Multiple active maintainers, external users, a security review, release
  succession, and no known critical correctness issue in the claimed scope.

## Claim policy

OpenConstraint may claim a measured advantage—such as more reproducible proof
artifacts, safer untrusted-input handling, lower deployment friction, or better
CI interoperability—when the supporting experiment is public. It must not say
"better than all closed-source alternatives" until an independent, same-input
comparison demonstrates overall superiority across correctness, coverage,
scale, usability, support burden, and total cost for a clearly defined target
workflow.
