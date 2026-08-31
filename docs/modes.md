# Named-mode comparison

Functional, scan, test, and low-power constraints often share a netlist but
intentionally differ. OpenConstraint audits each named mode independently and
then reports structural drift that deserves review.

```console
openconstraint audit \
  --verilog top.v --liberty cells.lib \
  --mode functional=common.sdc \
  --mode functional=functional.sdc \
  --mode scan=common.sdc \
  --mode scan=scan.sdc \
  --format html --output mode-review.html
```

Repeating `--mode functional=...` appends files to that mode in CLI order. The
first supplied mode is the baseline for exception-topology comparisons.

## Cross-mode rules

- `OC5001` compares clock presence, period, targets, and primary/generated
  classification across every mode.
- `OC5002` compares each later mode's exception signatures with the first mode.
  A signature includes exception kind and resolved from/to objects.

Mode-specific constraints are normal. These diagnostics ask for an explicit
review; they do not assume every difference is a defect.

## Coverage gates

Coverage is computed independently for each mode. `--min-coverage N` fails when
any mode is below `N`. HTML and JSON preserve per-mode clocks, exceptions,
coverage, graph data, and diagnostics.

## Current limits

The beta does not understand mode activation logic, case analysis, power-state
tables, UPF, scenario inheritance, or waiver files. It compares the SDC files
exactly as grouped on the command line.
