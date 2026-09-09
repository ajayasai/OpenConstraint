# Boolean influence example

`netlist.json` is an explicitly hand-written Yosys-format conformance fixture.
`design.v` describes the same AND gate; the functional CI workflow independently
synthesizes it with the installed Yosys and records that version.

With `enable=0`, `out` is Boolean-independent of `a`. With `enable=1`, changing
`a` changes `out`; the checker produces two concrete assignments. Neither
conclusion establishes an SDC false path, glitch freedom, or timing signoff.

See [the functional-analysis guide](../../docs/functional-analysis.md) for
commands, result meanings, source-index conventions, and verification limits.
