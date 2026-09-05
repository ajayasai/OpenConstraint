# Reset-aware synchronous safety verification

`openconstraint-sequential` checks state across logical clock ticks, rather than
regarding every register output as an unrelated arbitrary input. This is an
experimental verification layer for a **declared single-clock, two-state,
zero-delay synchronous model**. It is not physical timing signoff.

## What is implemented

The exhaustive backend computes a complete reachable-state fixed point and
exports a finite inductive invariant. The Z3 backend checks the initial/reset
base case and an arbitrary-state **k-induction** step. Neither backend reports
`proven` merely because a bounded search found no bug.

The front end supports the twelve Boolean primitives documented for the
[Boolean checker](functional-analysis.md), plus 46 synchronous primitive
variants: `$_DFF_[PN]_`, `$_DFFE_[PN][PN]_`,
`$_SDFF_[PN][PN][01]_`, `$_SDFFE_[PN][PN][01][PN]_`, and
`$_SDFFCE_[PN][PN][01][PN]_`. All polarity combinations and both reset/enable
priorities are tested against an independent procedural truth table.

The relevant property cone is closed under **next-state dependencies** before
search: a register that feeds a relevant register in a later cycle cannot be
removed as unrelated. Unrelated registers are excluded from enumeration and
SMT encoding, but unsupported design constructs still fail closed globally.

## Try the included controls

From a checkout containing these changes:

```console
python -m pip install -e '.[formal]'
openconstraint-sequential analyze \
  --netlist examples/sequential/netlist.json \
  --spec examples/sequential/checks.json \
  --backend z3 --output sequential-result.json
```

The example deliberately returns **1**, not 0: two properties are proven, but
the three-cycle event-spacing control has a concrete violation. The bundled
JSON is identified as a hand-written conformance fixture, not synthesis output.

```console
openconstraint-sequential verify \
  --netlist examples/sequential/netlist.json \
  --spec examples/sequential/checks.json \
  --report sequential-result.json --backend enumerate
openconstraint-sequential witness \
  --netlist examples/sequential/netlist.json \
  --spec examples/sequential/checks.json \
  --report sequential-result.json --check invalid-spacing-3 \
  --output counterexample.vcd
```

`verify` defaults to the solver-free backend. A verified counterexample returns
0 with `verified: true, passed: false`: **reproduced is not the same as passed**.
`witness` independently replays the selected violation before exporting it.
The VCD uses synthetic one-nanosecond sample units only for waveform viewers;
these samples do not represent physical gate delays or an SDC clock period.
Every output path must be fresh. Existing files, including links, are refused.

For actual synthesis and a separate native Yosys SAT comparison:

```console
python examples/sequential/validate.py --yosys --output build/sequential-validation
```

This requires a separately installed Yosys and the optional formal/development
Python dependencies. The script stages only the repository-owned fixture,
records versions, retains synthesis/native-SAT logs, runs both checker backends,
replays proof/counterexample artifacts, and measures synthetic cone scaling.
The native SAT controls are **eight-step bounded comparisons**, not a claim
that Yosys independently establishes the checker's unbounded induction proof.
The solver-free invariant checker supplies independent proof-search validation.

## Specification and sampling semantics

A specification explicitly selects `schema_version: "1.0.0"`,
`model: "single_clock_synchronous_v1"`, the top, a direct primary-input clock,
and either `posedge` or `negedge`. All flip-flops must use that same clock edge.

`initial` is a list of assignments to register Q bits **before** any prefix.
Omitted state bits are arbitrary; they are never silently initialized to zero.
`prefix` is a list of per-tick primary-input assignment lists. A synchronous
reset prefix is simulated as real state transitions. Unspecified prefix inputs
remain arbitrary. `assumptions` constrain primary inputs at every tick,
including the prefix; conflicts and aliases are checked before proving anything.

Properties begin at the state reached **after** the prefix. They observe the
settled combinational values and state **before** the next selected clock edge.
All registers update simultaneously from those pre-edge values. Inputs may
change arbitrarily between ticks subject to the declared assumptions. This
model says nothing about transitions or glitches between samples.

Two property kinds are available:

- `forbid`: a nonempty conjunction of signal assignments must never hold. This
  covers invariants, mutually exclusive enables, or explicit bad-state signals.
- `min_spacing`: assertions of an event must be at least `cycles` samples apart.
  An event high for two successive samples violates any spacing greater than
  one. The history is empty at the end of the prefix and is not silently reset
  by subsequent reset signals.

Signal references may be scalar net names, integer bit IDs, or objects such as
`{"net": "counter", "bit": 2}`. `bit` indexes the Yosys **bits array**, not the
source-language bus subscript. Resolve bus orientation explicitly.

## Proof and failure contracts

| Result | Meaning |
| --- | --- |
| `proven` | An invariant is closed, or both the base case and induction step are proven, under this model and contract. |
| `counterexample` | A concrete reachable trace violates the property and passes independent concrete replay. |
| `bounded` | Search depth, state count, aggregate work, or a solver budget prevents a complete decision. Never a pass. |
| `unsupported` | Inputs or requested semantics cannot be modeled safely, or a required solver is missing. |
| `inconsistent_assumptions` | Initial/prefix/assumption aliases conflict, or a forbidden predicate is syntactically impossible. |

Event-spacing proofs additionally report activation. A property with an event
that is unreachable or has not been witnessed does **not** produce `passed:
true`, even when the spacing proposition is mathematically true. This prevents
an inactive/reset-held block from masquerading as a useful successful check.

A finite-invariant verifier checks initiation from all allowed initial/prefix
states, property safety, and closure under every allowed input. A modified
state set is not accepted just because its SHA256 was recomputed. A Z3 proof
can instead be established independently by complete state enumeration. That
cross-backend replay establishes the proposition, not the authenticity of a
solver's historical log. Hashes are integrity/identity checks, not signatures.

Counterexamples retain state, input, and observed vectors in the deterministic
bit order recorded in `cone`. Replay checks all three, the initial state,
every prefix/assumption, every transition, and the final property violation.

## Binding evidence to actual SDC revisions

Generate an index without executing Tcl:

```console
openconstraint-sequential sdc-index --sdc constraints/top.sdc --source-id functional
```

Attach a binding to the relevant authored property, using the returned file
hash and **zero-based command index among all parsed commands**:

```json
"binding": {
  "source": "functional",
  "sha256": "<the actual 64-character file SHA256>",
  "command_index": 3
}
```

Supply that source explicitly during analysis, verification, and waveform export:

```console
openconstraint-sequential analyze --netlist top.json --spec properties.json \
  --sdc functional=constraints/top.sdc --output evidence.json
```

Changing even a comment in the bound SDC invalidates its existing binding.
Moving an identical file does not. The spec cannot cause the checker to open
arbitrary paths: only the caller's explicit `--sdc ID=PATH` inputs are read.
The file must parse as the supported static SDC subset.

**A binding is a review-property link, not automatic exception verification.**
It does not prove that the event is the correct capture enable, that a source
is stable, that all paths/edges are covered, or that a multicycle exception is
valid. Every binding states `exception_validated: false`. Unbound exceptions
are not inventoried or covered by this command; this is not a complete SDC
signoff report. Do not waive an exception merely because its linked property
was proven. Continue to use the structural auditor for SDC scope checks.

## Limits and reproducibility

All work bounds are reported and configurable. Defaults include 32 SMT search
steps, 64 prefix steps, 65,536 reachable states, 20 free enumeration variables,
5,000,000 aggregate transition/encoding work units and 128 total solver calls.
Each solver call also has time/resource limits. Raising a limit is explicit;
`unknown` never becomes UNSAT. JSON/SDC input and emitted evidence sizes are
bounded. The Z3 version is recorded; cross-version witness identity is not
promised. The exhaustive backend's ordering and reports are deterministic.

Export the closed Draft 2020-12 schemas:

```console
openconstraint-sequential schema --kind spec --output sequential-spec.schema.json
openconstraint-sequential schema --kind result --output sequential-result.schema.json
```

## Scope exclusions

Asynchronous resets, latches, derived/multiple/mixed-edge clocks, clock-as-data,
X/Z logic, memories, unlowered processes, unknown cell types, hidden Yosys
initialization attributes, multiply driven and used-undriven signals are not
silently approximated. The model excludes analog metastability, delay-sensitive
sensitization, CDC signoff, and automatic hierarchy/budget transformations.
A proof may be unbounded in time and still be narrow in its modeling scope.

References: [Yosys gate-level flip-flop semantics](https://yosyshq.readthedocs.io/projects/yosys/en/latest/cell/gate_reg_ff.html),
[Yosys SAT command](https://yosyshq.readthedocs.io/projects/yosys/en/v0.49/cmd/sat.html),
and [SBY bounded versus unbounded proof modes](https://symbiyosys.readthedocs.io/en/latest/reference.html).
