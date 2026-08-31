# Structural coverage methodology

OpenConstraint's coverage score measures modeled structural obligations in each
constraint mode. It is intentionally transparent and reproducible. It does not
measure path slack, prove exceptions, or certify sign-off completeness.

## Components

| Key | Base weight | Numerator | Denominator |
| --- | ---: | --- | --- |
| `sequential_endpoints` | 0.50 | Sequential data endpoints whose instance has a clock pin reached by a defined clock | All sequential data endpoints identified from Liberty or conservative cell-name/pin inference |
| `input_delays` | 0.20 | Required input/inout ports matched by at least one `set_input_delay` | Input/inout ports, excluding ports targeted by a defined clock |
| `output_delays` | 0.20 | Required output/inout ports matched by at least one `set_output_delay` | All output/inout ports |
| `query_health` | 0.10 | Static object queries that resolve without an error and match at least one object | All non-dynamic object queries collected from supported constraints |

Dynamic queries are reported by `OC1003` but excluded from the query-health
denominator because their result is unknowable to the safe static backend.
Unsupported static filters are included and count as unresolved.

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
clock along net loads and conservatively from each input of a modeled
combinational leaf cell to its outputs. Propagation stops at sequential cells.
This is topology, not Liberty timing-arc or case-analysis evaluation, and may
over-approximate reachability through gated or conditional logic.

## What the score omits

- Whether a false path is functionally impossible.
- Whether multicycle setup and hold pairs are correct.
- Clock uncertainty, latency, transition, derating, or propagated-clock quality.
- Input/output delay values, edge selection, and interface protocol correctness.
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
