# Parameterized SDC example

`main.sdc` selects a caller-declared `MODE` (`functional` or `slow`), imports an
explicitly supplied helper, creates a primary clock and expands I/O-delay loops.
It targets the existing [tiny design](../tiny/design.v).

See the [expansion guide](../../docs/sdc-expansion.md) for compile, audit and
source-replay commands. Both declared modes must be compiled/audited separately.
