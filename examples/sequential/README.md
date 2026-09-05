# Synchronous safety conformance and synthesis controls

`netlist.json` is a **hand-written** gate-level representation of `design.v`.
`checks.json` asks for two-cycle event spacing, deliberately incorrect
three-cycle spacing, and captured-register coherence after one synchronous
reset tick. Expected outcomes: `proven`, `counterexample`, `proven`.

Run `python examples/sequential/validate.py --output NEW_DIRECTORY` with
`.[dev,formal]` installed. Add `--yosys` to require actual RTL synthesis and
three separate eight-step native Yosys SAT controls. The validation script
records the netlist's origin and the exact tool versions. It does not describe
the hand-written JSON as synthesis output or a bounded native SAT comparison
as an unbounded signoff result.

Both OpenConstraint backends, independent replay, synthetic VCD output, and
three synthetic sparse-state-bank sizes are included. The scale cases isolate
one relevant register from 1,005 / 10,005 / 50,005 total registers; they are not
industrial SoC benchmarks. See [the guide](../../docs/sequential-analysis.md).
