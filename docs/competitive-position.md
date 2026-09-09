# Competitive position and evidence bar

OpenConstraint is an **open, reproducible, CI-native** SDC quality auditor.
Its objective is to make each supported result inspectable and replayable. That
is a narrower and testable goal than claiming universal superiority over
commercial constraint-signoff suites.

## What is independently reproducible here

| Capability | Public evidence |
| --- | --- |
| Rule behavior | Tiny reviewed fixtures plus the versioned semantic accuracy truth set |
| Precision/recall on that truth set | Deterministic occurrence-level TP/FP/FN output and strict JSON Schema |
| Real-design compatibility | Checksum-pinned OpenROAD SKY130HD AES, Ibex, and JPEG netlists with reviewed semantic baselines |
| Parser resilience | Cross-platform properties, seed-corpus replay, and scheduled Atheris/libFuzzer mutation |
| OpenSTA alignment | Source-pinned semantic tests and a workflow that builds and exercises the pinned engine revision |
| CI adoption | Stable rule IDs, SARIF, JSON/HTML/text, exact diagnostic baselines, expiring waivers, and stale-control gates |
| Structural exception evidence | Canonical graph digests, deterministic path witnesses, replayable vacuity certificates, explicit search bounds, and a fresh deterministic replay command |
| Repair planning | Deterministic machine-readable proposals whose numeric timing intent remains an explicit human-reviewed placeholder |
| Auditability | Apache-2.0 source, documented coverage equation, strict schemas, immutable corpus digests, and no default Tcl execution |

The checked-in accuracy score measures only its labeled cases. Public-design
runs measure compatibility and scale only on those designs. Structural
exception certificates prove path existence or absence in the trusted modeled
graph; they are not functional false-path proofs, STA results, or vendor
head-to-head benchmarks.

## Where commercial suites remain ahead

Commercial vendors publicly describe capabilities outside OpenConstraint's
current scope:

- [Synopsys Timing Constraints Manager](https://www.synopsys.com/verification/static-and-formal-verification/timing-constraints-manager.html)
  advertises formal SDC verification, generation, management, hierarchy
  promotion/demotion, and large RTL/gate abstraction.
- [Cadence Conformal Constraint Designer](https://www.cadence.com/en_US/home/resources/datasheets/encounter-conformal-constraint-designer-ds.html)
  advertises functional false-path and multicycle validation, constraint and
  template generation, hierarchical checking, CDC analysis, counterexamples,
  and multi-mode comparison. Cadence's
  [TimeVision](https://www.cadence.com/en_US/home/resources/datasheets/cadence-timevision-solution-ds.html)
  positioning also advertises automatic generation, hierarchy propagation,
  distributed execution, and very large design capacity.
- [Siemens Gencellicon Constraints Builder](https://www.siemens.com/en-us/products/ic/ic-design/gencellicon/constraints-builder/)
  advertises automatic hierarchical, multi-mode constraint generation and
  management from RTL or netlists. The companion
  [Constraints Certifier](https://www.siemens.com/en-gb/products/ic/ic-design/gencellicon/constraints-certifier/)
  adds functional exception verification, assertion generation, hierarchy
  demotion, budgeting, and timing-equivalence checking.

OpenConstraint does not yet provide functional exception proof, broad
production Tcl/SDC execution, mixed-language RTL elaboration, automatic
signoff-quality constraint generation, hierarchy promotion/demotion and timing
budgeting, distributed formal solving, or vendor application-engineering
support. Those gaps prevent an honest overall-superiority claim.

## Where OpenConstraint can be better today

OpenConstraint has advantages that are directly inspectable rather than hidden
behind product claims:

- no licence server or per-seat feature tier;
- source-level rule, parser, graph, certificate, and repair-planner review;
- deterministic, diffable machine output and schemas;
- public accuracy labels, corpus provenance, fuzz harnesses, and regression
  baselines;
- replayable structural path evidence with explicit resource-bound outcomes;
- non-executing, fail-closed static analysis by default, with Tcl execution
  available only through an explicit trusted-input OpenSTA option;
- ordinary pull-request, SARIF, waiver, baseline, proof-pack, and repair-plan
  workflows without a proprietary database.

These are meaningful advantages for open-source flows, CI policy, education,
research, and teams that require auditable automation. They are not a
substitute for functional formal signoff features when those features are
required.

## Standard for a future overall-superiority claim

An overall comparison requires, at minimum:

1. the same licensed tool versions, design snapshots, modes, libraries, and SDC
   inputs;
2. an independently reviewed defect oracle, including clean controls;
3. severity-normalized precision, recall, false-pass rate, runtime, memory,
   incremental latency, proof replay, and human waiver burden;
4. functional-exception, hierarchy, generation, and mixed-language cases, not
   only structural lint;
5. published methodology and raw, legally shareable outputs; and
6. repeat runs on multiple industrial-scale designs by an independent party
   where licence terms permit.

Until that evidence exists, documentation and releases must describe specific,
measured advantages and limitations instead of saying "better than all
closed-source alternatives."
