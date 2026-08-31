# Competitive position and evidence bar

OpenConstraint is designed to be the strongest **open, reproducible,
CI-native** SDC quality auditor it can be. That is a narrower and testable goal
than claiming universal superiority over commercial constraint-signoff suites.
This page records the evidence boundary as of 2026-08-31.

## What is independently reproducible here

| Capability | Public evidence |
| --- | --- |
| Rule behavior | Tiny reviewed fixtures plus the versioned semantic accuracy truth set |
| Precision/recall on that truth set | Deterministic occurrence-level TP/FP/FN output and strict JSON Schema |
| Real-design compatibility | Checksum-pinned OpenROAD SKY130HD AES, Ibex, and JPEG netlists with reviewed semantic baselines |
| Parser resilience | Cross-platform properties, seed-corpus replay, and scheduled Atheris/libFuzzer mutation |
| OpenSTA alignment | Source-pinned semantic tests and a workflow that builds and exercises the pinned engine revision |
| CI adoption | Stable rule IDs, SARIF, JSON/HTML/text, exact diagnostic baselines, expiring waivers, and stale-control gates |
| Auditability | Apache-2.0 source, documented coverage equation, closed-shape schemas, immutable corpus digests, and no default Tcl execution |

The checked-in accuracy score measures only its labeled cases. The public
design run measures compatibility and scale on those designs. Neither is a
formal false-path proof, a silicon-signoff result, or a vendor head-to-head
benchmark.

## Where commercial suites remain ahead

Commercial vendors publicly describe capabilities outside OpenConstraint's
current scope:

- [Synopsys Timing Constraints Manager](https://www.synopsys.com/verification/static-and-formal-verification/timing-constraints-manager.html)
  advertises formal SDC verification, generation, management, hierarchy
  promotion/demotion, and large RTL/gate abstraction.
- [Cadence Conformal Constraint Designer](https://www.cadence.com/en_US/home/resources/datasheets/encounter-conformal-constraint-designer-ds.html)
  advertises formal false-path and multicycle validation, constraint/template
  generation, hierarchical checking, CDC analysis, counterexamples, and
  multi-mode comparison. Cadence's newer
  [TimeVision](https://www.cadence.com/en_US/home/resources/datasheets/cadence-timevision-solution-ds.html)
  comparison bar also advertises automatic generation, hierarchy propagation,
  distributed execution, and multi-billion-instance capacity.
- [Siemens Gencellicon Constraints Builder](https://www.siemens.com/en-us/products/ic/ic-design/gencellicon/constraints-builder/)
  advertises automatic hierarchical, multi-mode constraint generation and
  management from RTL or netlists. The companion
  [Constraints Certifier](https://www.siemens.com/en-gb/products/ic/ic-design/gencellicon/constraints-certifier/)
  adds formal exception verification, assertion generation, hierarchy
  demotion, budgeting, and timing-equivalence checking.

OpenConstraint does not currently provide formal exception proof, full Tcl/SDC
execution, mixed-language RTL elaboration, automatic signoff-quality constraint
generation, distributed formal solving, or vendor application-engineering
support. Those gaps prevent an honest claim that it is better overall.

## Where OpenConstraint can be better today

OpenConstraint has advantages that are directly inspectable rather than
marketing claims:

- no license server or per-seat feature tier;
- source-level rule and parser review;
- deterministic, diffable machine output and schemas;
- public accuracy labels, corpus provenance, fuzz harnesses, and regression
  baselines;
- safe static analysis by default, with Tcl execution isolated behind an
  explicit trusted-input OpenSTA option;
- ordinary pull-request, SARIF, waiver, and baseline workflows without a
  proprietary database.

These are meaningful advantages for open-source flows, CI policy, education,
research, and teams that need auditable automation. They are not a substitute
for formal signoff features when those features are required.

## Standard for a future overall superiority claim

An overall comparison requires, at minimum:

1. the same licensed tool versions, design snapshots, modes, libraries, and SDC
   inputs;
2. an independently reviewed defect oracle, including clean controls;
3. severity-normalized precision, recall, false-pass rate, runtime, memory, and
   waiver burden;
4. formal-exception and hierarchy cases, not only structural lint;
5. published methodology and raw, legally shareable outputs; and
6. repeat runs on multiple industrial-scale designs.

Until that evidence exists, project documentation and releases must describe
specific measured advantages and limitations instead of saying "better than
all closed-source alternatives."
