# Roadmap

This roadmap communicates direction, not delivery dates or commitments. Work is
prioritized through public issues and the governance process.

## 0.1 beta — auditable static foundation

- Non-executing Tcl/SDC parsing with explicit unsupported-syntax findings.
- Structural Verilog and Liberty indexing.
- Query, clock, I/O-delay, endpoint, generated-clock, and exception checks.
- Named-mode comparison and a published structural-coverage formula.
- Text, JSON, SARIF, and HTML output suitable for local and CI use.
- Explicit trusted-input OpenSTA validation with per-mode subprocess isolation,
  finite timeout, effective-SDC provenance, and no bundled OpenSTA binary.

## 0.2 — compatibility and trust

- Expand documented SDC, structural-Verilog, and Liberty subsets from public
  fixtures.
- Publish a permissively licensed regression corpus and benchmark method.
- Improve source spans, suppressions with reason and expiry, and diagnostic
  baselines for adoption in existing designs.
- Add property-based and fuzz testing for parsers and report escaping.
- Expand regression validation against pinned OpenSTA revisions while keeping
  Tcl execution explicit and outside the default static backend.

## 0.3 — extension and flow integration

- Versioned custom-rule interface with deterministic inputs and outputs.
- Richer clock-domain and exception-relationship visualization.
- Mode-diff policies and reviewable waivers.
- Reusable GitHub Actions and documented integrations for other CI systems.
- Performance and memory regression dashboards on public designs.

## 1.0 readiness criteria

- Stable CLI, configuration, diagnostic IDs, exit codes, and report schemas.
- Published compatibility matrix and upgrade/deprecation policy.
- Reproducible benchmark evidence and a security review of parser boundaries.
- Multiple active maintainers and a documented release succession path.
- No known critical correctness issue in the supported static subset.

## Explicit non-goals

- Replacing STA sign-off or claiming equivalence to commercial constraint tools.
- Formally proving false paths in the 0.x line.
- Silently executing Tcl to increase apparent SDC compatibility.
- Treating a 100% structural-coverage score as proof that constraints are
  functionally correct or complete for silicon sign-off.
