# Structural coverage methodology

OpenConstraint's coverage score measures modeled structural obligations in each
constraint mode. It is intentionally transparent and reproducible. It does not
measure path slack, prove exceptions, or certify sign-off completeness.

## Components

| Key | Base weight | Numerator | Denominator |
| --- | ---: | --- | --- |
| `sequential_endpoints` | 0.50 | Sequential data endpoints whose instance has a clock pin reached by a defined clock | All sequential data endpoints identified from Liberty or conservative cell-name/pin inference |
| `input_delays` | 0.20 | Covered min/max × rise/fall slots from active valid input delays | Four slots for every distinct active clock-set/reference-pin/clock-edge relationship on each required input/inout port; a port with no relationship has one default four-slot obligation |
| `output_delays` | 0.20 | Covered min/max × rise/fall slots from active valid output delays | Four slots for every distinct active clock-set/reference-pin/clock-edge relationship on each required output/inout port; a port with no relationship has one default four-slot obligation |
| `query_health` | 0.10 | Object queries that resolve without an error, match at least one object, and have no unmatched collection pattern | All object queries collected from supported constraints, including dynamic and unsupported queries |

Dynamic queries are reported by `OC1003` and count as unresolved in the
query-health denominator because unknown scope must not improve the coverage
score. Unsupported static filters and partially unmatched collections likewise
count as unresolved.

## Formula

For applicable components `i` with base weight `w`, covered count `c`, and total
count `t`:

```text
score = 100 × Σ(w_i × c_i / t_i) / Σ(w_i), for every component with t_i > 0
```

Components with a zero denominator are displayed as `n/a`, omitted from both
sums, and the remaining weights are renormalized. If every denominator is zero,
the implementation returns 100% by convention. Such a degenerate score has no
useful coverage evidence; always inspect component totals.

Each I/O relationship has exactly four normalized analysis slots: `min/rise`,
`min/fall`, `max/rise`, and `max/fall`. Multiple commands may collectively
cover those slots after non-additive overwrite and additive min/max history is
replayed with the modeled OpenSTA semantics. A malformed delay, unresolved clock/reference pin, wrong
direction, or otherwise invalid record covers none. An invalid record that can
still be associated with a required port establishes its attempted relationship
in the denominator, so invalid intent cannot disappear from the score.

If Verilog, Liberty, or elaboration warnings make the structural model
untrusted (`OC0002`), the final score is forced to `0.0` with grade `F` in every
mode. Component counts remain visible as debugging evidence, but they are not
promoted into a trustworthy aggregate score.

The score is rounded to two decimal places. Grades are display aids:

| Grade | Score |
| --- | ---: |
| A | at least 95 |
| B | at least 85 |
| C | at least 70 |
| D | at least 50 |
| F | below 50 |

## Clock reachability model

A clock starts at its resolved target port, pin, or net. The beta propagates the
clock along net loads and only across input-to-output dependencies extracted
from an output's Liberty `function` or `timing.related_pin` metadata.
Propagation stops at sequential cells. If an instantiated combinational output
has connected inputs but no usable dependency metadata, propagation stops at
that output and the incomplete model produces `OC0002`; it is never treated as
proof that every input reaches every output.

This is structural arc reachability, not case analysis or Boolean-condition
proof. Conditional timing senses, modes, and enable values are not evaluated,
so a declared dependency may still be inactive in a particular functional
state.

## What the score omits

- Whether a false path is functionally impossible.
- Whether warnings about multicycle setup/hold pairing are functionally
  justified or complete for all clock relationships.
- Clock uncertainty, latency, transition, derating, or propagated-clock quality.
- Liberty timing conditions and functional case analysis beyond declared
  input/output dependency extraction.
- Whether finite input/output delay values and interface protocol intent are
  physically correct. The score measures structural min/max and rise/fall slot
  presence, not whether the values or selected relationships are appropriate.
- Min/max path-delay completeness or physical timing accuracy.
- Unsupported or behaviorally elaborated RTL semantics.

Use diagnostic findings and engineering review alongside the score. Never use
coverage alone as a tapeout gate.

## CI policy

`--min-coverage N` fails with exit code 1 when any mode scores below `N`. Start
with a threshold supported by current evidence, review each component, and
increase it intentionally. A mode-specific breakdown is available in every
report format.

Any future change to a component, denominator, exclusion, weight, or formula is
a compatibility change requiring documentation and a changelog entry.
