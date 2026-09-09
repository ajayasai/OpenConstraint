# Parameterized SDC expansion (experimental)

`openconstraint-expand` interprets a bounded, documented Tcl subset and emits
static SDC that the existing OpenConstraint audit and structural proof commands
can consume. It does **not** invoke Tcl, execute host commands, access the
network, run Python `eval`, or load paths requested by an input script.

This closes an onboarding gap: projects may keep variables, helper procedures,
constant arithmetic, mode conditionals, literal-list loops and explicitly supplied
includes without manually flattening them before auditing. It is not full Tcl
compatibility, native design-query execution, or timing signoff.

## End-to-end example

From this branch, install with `python -m pip install -e .`, then run:

```console
openconstraint-expand compile \
  --source main=examples/expansion/main.sdc \
  --source clock_helpers.sdc=examples/expansion/clock_helpers.sdc \
  --entry main --define MODE=functional --output build/expanded-functional

openconstraint audit \
  --verilog examples/tiny/design.v --liberty examples/tiny/cells.lib \
  --sdc build/expanded-functional/normalized.sdc --top tiny_top \
  --min-coverage 100 --fail-on error --format all --output build/expanded-audit
```

Compile `MODE=slow` into a different directory to evaluate the other authored
mode. No reset values, clock periods, external delays or architectural intent
are inferred: all numerical values come from the source and explicit defines.

The fresh output directory contains `normalized.sdc` and `provenance.json`.
The latter records input SHA256 hashes, used/unused includes, caller defines,
entry order, limits, work counters, the emitted command sequence and its origin
stack. `enclosing_line` is the original **enclosing command's** line for nested
scripts, not a falsely precise token location within a loop/procedure body.
Origins include procedure definition/call sites and loop iteration numbers.

## Supported language

| Area | Supported subset |
| --- | --- |
| Variables | Simple local scalar names; `set`, `unset`, `incr`, `append`, `lappend`; explicit caller defines |
| Lists | `list`, list-only `concat`, `llength`, one-index `lindex`, integer / `end` / `end-N` indices |
| Expressions | Bounded integers and finite floats; `+ - * / %`, comparisons, `eq/ne`, `!`, lazy `&&/||`, lazy ternary `?:`, parentheses |
| Control | `if/elseif/else`, `foreach` including parallel lists and tuple destructuring, `for`, `while`, loop-body `break/continue` |
| Procedures | Local frames, fixed/default arguments, final simple `args`, return values and `return`; bounded calls |
| Includes | Exact logical names supplied by repeated `--source ID=PATH`; repeated `--entry ID` preserves entry order |
| Collections | Existing supported static selectors remain typed symbolic query expressions, including supported nesting |

Script bodies must be literal braced scripts. Variable-dependent conditions must
be braced expressions such as `if {$MODE eq "functional"}`; eager dynamic
condition substitution is deliberately rejected. `%` requires integers and
integer division follows Tcl's floor convention. Arrays, namespaces, argument
splicing (`{*}`), general `eval`, Tcl packages and arbitrary host commands are
not supported. Unsupported syntax fails the **whole expansion**, not just the
line that was unrecognized. Unselected literal branches are not executed;
this is configuration-specific coverage, not proof about all possible modes.

Generated lists remain a distinct type: list contents can enter list-valued SDC
fields, query pattern lists, loop/list operations, or `lindex`. Implicit conversion
of a generated list into a scalar name, string concatenation, numeric operand or
string comparison is rejected, as is nesting a generated list as a list element.
This avoids guessing Tcl's history-dependent list string representation. Literal
braced strings retain their original value. This is a deliberate compatibility
boundary, not silent string normalization.

## Collection correctness boundary

A value returned by `get_ports`, `get_clocks`, etc. is a **symbolic collection**,
not a list of matching objects. The expander preserves its type rather than
turning it into a guessed string. Use of its unknown contents/cardinality in
`foreach`, `llength`, string concatenation, arithmetic or list construction is
rejected. The downstream audit resolves the queries against the actual design.

Capturing a clock collection and then defining another clock before using that
collection changes when a deferred query would be evaluated. That is unsafe:

```tcl
set clocks [get_clocks *]
create_clock -name new_clock -period 10 [get_ports clk]
set_false_path -from $clocks -to [get_ports dout]
```

The compiler rejects this case instead of silently broadening the original
collection. All symbolic queries are also invalidated by intervening
`current_design` directives. Immutable design-object collections can otherwise
be reused across clock definitions. SDC side effects inside substitutions are
rejected. Scalar words are substitution-safe, including literal dollar signs,
semicolon characters, brackets, quotes, backslashes and line breaks.

## Verify an artifact against current source

```console
openconstraint-expand verify \
  --source main=examples/expansion/main.sdc \
  --source clock_helpers.sdc=examples/expansion/clock_helpers.sdc \
  --entry main --define MODE=functional --pack build/expanded-functional
```

Verification reads only caller-selected source paths and the selected pack,
re-expands the current inputs, and checks exact SDC bytes, provenance and hashes.
Moving byte-identical files to another checkout leaves replay unchanged.
Changing any supplied source (including comments and unused sources), mode
definition, source entry order or resource contract invalidates exact replay.
Rehashing fabricated metadata cannot make it equal the freshly rebuilt pack.
Hashes bind contents but do not authenticate an author or signer.

Exit codes are `0` for completed compilation / matching replay, `1` for replay
mismatch, and `2` for rejected inputs, resource bounds or operational errors.
**Successful compilation means expanded, not audited or proven.** Every pack
sets `timing_signoff: false` and `design_queries_executed: false`.
No outputs are created before successful expansion. Existing output directories,
files and symlinks are refused. A later disk/write failure may leave an incomplete
directory; it is never reported as a successful pack, and replay rejects it.

The bundled strict schema can be exported with:

```console
openconstraint-expand schema --output expansion.schema.json
```

## Limits and evidence

Default ceilings include 2 MiB aggregate source, 20,000 interpreted commands,
10,000 loop iterations, 10,000 emitted commands, 4 MiB emitted SDC, depth 32,
65,536 characters per value, 4,096 elements per list and 32 MiB charged character
work. Expressions are limited to 512 tokens, depth 64, 256-bit integer operands
and finite floating-point values. Limits can be reduced, not raised beyond
these implementation ceilings. These are algorithmic bounds, not an OS-level
CPU/RSS sandbox guarantee.

`tests/test_expand_reference.py` executes **repository-owned** test programs
with native Tcl and compares their final SDC command argument vectors with the
normalized program. Its query stubs test Tcl value/argument semantics, not
native STA object selection. Other tests feed expanded constraints through the
real OpenConstraint audit and structural proof layers, test clock-query mutation,
source tampering, resource limits, quoted names and rejection behavior. The
Linux expansion workflow explicitly installs/requires Tcl so this reference
suite cannot silently skip. No user-provided script is executed by this test
harness or native interpreter in production.
