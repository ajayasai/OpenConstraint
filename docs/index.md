# OpenConstraint documentation

OpenConstraint v0.3.0-beta performs deterministic, static checks over a
documented subset of structural Verilog, Liberty, and Tcl/SDC. It is intended
for lint, review, CI coverage feedback, and replayable structural path analysis.
It is not a static-timing sign-off engine and does not prove that an exception
is functionally valid.

## Start here

- [Getting started](getting-started.md)
- [CLI reference](cli.md)
- [Proof-carrying structural exception analysis](proof-carrying-analysis.md)
- [Experimental Boolean influence and counterexample replay](functional-analysis.md)
- [Reset-aware synchronous safety proofs and waveform replay](sequential-analysis.md)
- [Rule reference](rules/index.md)
- [Coverage methodology](coverage-methodology.md)
- [Report formats](report-formats.md)
- [CI integration](ci-integration.md)
- [Diagnostic baselines and reviewable waivers](adoption-controls.md)
- [Named-mode comparison](modes.md)
- [Opt-in OpenSTA validation](opensta-validation.md)
- [Public-design benchmark method](../benchmarks/README.md)
- [Parser fuzzing and seed corpora](../fuzz/README.md)

## Understand the boundary

- [Compatibility and parser subsets](compatibility.md)
- [Competitive position and evidence bar](competitive-position.md)
- [Security model](security-model.md)
- [Architecture](architecture.md)
- [Project roadmap](../ROADMAP.md)

## Project policies

- [Contributing](../CONTRIBUTING.md)
- [Governance](../GOVERNANCE.md)
- [Support](../SUPPORT.md)
- [Security reporting](../SECURITY.md)

Machine-readable schemas:

```console
openconstraint schema --output openconstraint-report.schema.json
openconstraint schema --kind waivers --output openconstraint-waivers.schema.json
openconstraint schema --kind baseline --output openconstraint-diagnostic-baseline.schema.json
```

Proof and repair schemas can also be exported directly:

```console
openconstraint-prove schema --kind proof --output openconstraint-proof.schema.json
openconstraint-prove schema --kind repair --output openconstraint-repair.schema.json
```
