# OpenConstraint documentation

OpenConstraint v0.2.0-beta performs deterministic, static checks over a
documented subset of structural Verilog, Liberty, and Tcl/SDC. It is intended
for lint, review, and CI coverage feedback. It is not a static-timing sign-off
engine and does not prove timing exceptions.

## Start here

- [Getting started](getting-started.md)
- [CLI reference](cli.md)
- [Rule reference](rules/index.md)
- [Coverage methodology](coverage-methodology.md)
- [Report formats](report-formats.md)
- [CI integration](ci-integration.md)
- [Named-mode comparison](modes.md)
- [Opt-in OpenSTA validation](opensta-validation.md)
- [Public-design benchmark method](../benchmarks/README.md)
- [Parser fuzzing and seed corpora](../fuzz/README.md)

## Understand the boundary

- [Compatibility and parser subsets](compatibility.md)
- [Security model](security-model.md)
- [Architecture](architecture.md)
- [Project roadmap](../ROADMAP.md)

## Project policies

- [Contributing](../CONTRIBUTING.md)
- [Governance](../GOVERNANCE.md)
- [Support](../SUPPORT.md)
- [Security reporting](../SECURITY.md)

Machine-readable report schema:

```console
openconstraint schema --output openconstraint-report.schema.json
```
