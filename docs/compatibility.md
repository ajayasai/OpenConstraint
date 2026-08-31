# Compatibility and supported subsets

OpenConstraint v0.1.0-beta is intentionally not a complete Verilog, Liberty,
Tcl, or SDC implementation. This page defines what the static audit can model.
Unsupported syntax must be reviewed; it is not evidence of a valid constraint.

## Platforms

The package declares Python 3.11–3.14 and has no runtime Python dependencies.
CI exercises Linux, macOS, and Windows. File paths can affect source locations
and fingerprints, but parsing and rule semantics are intended to be portable.

## Tcl behavior

Supported lexical behavior includes command separation by newline/semicolon,
comments at word boundaries, continuations, braces, quotes, brackets, escapes,
and source-line tracking.

Not executed or interpreted:

- variables, `set`, procedures, loops, conditionals, arithmetic, or Tcl lists;
- `source`, `eval`, `exec`, environment access, file/network I/O;
- general nested command substitution;
- user-defined commands.

Malformed grouping produces `OC0001`. Dynamic or unsupported query expressions
produce `OC1003`/`OC1004` when they occur in modeled constraint positions.

## SDC commands modeled

| Command | Static semantics used by the beta |
| --- | --- |
| `create_clock` | Name, target, period, waveform, additive redefinition |
| `create_generated_clock` | Target, source, master, explicit or derived period using divide/multiply |
| `set_input_delay` | Matching input/inout ports for coverage |
| `set_output_delay` | Matching output/inout ports for coverage |
| `set_false_path` | From/to/through scope for overlap analysis |
| `set_multicycle_path` | From/to/through scope for overlap analysis |
| `set_max_delay`, `set_min_delay` | From/to/through scope for overlap analysis |
| `set_clock_groups` | Pairwise directional group cuts for overlap analysis |

Other commands may be tokenized, and their nested supported selectors may be
checked for query quality, but their timing semantics are not modeled.

## Object queries modeled

- `get_ports`, `get_pins`, `get_cells`, `get_nets`, `get_clocks`,
  `get_registers`.
- `all_inputs`, `all_outputs`, `all_clocks`, `all_registers`.
- Exact names, shell-style globs, `-regexp`, `-nocase`, and
  leaf-name matching with `-hierarchical`.
- Filters for object `direction` and sequential-cell truth in the documented
  simple forms.

General filter expressions, `-of_objects` semantics, Tcl-generated patterns,
and arbitrary collection algebra are not modeled.

## Structural Verilog modeled

- Modules, ANSI/non-ANSI port declarations, common net declarations, simple
  packed bit ranges, hierarchy, and leaf-cell instantiation.
- Named and positional port connections.
- Simple scalar/bit-select signals and constants at leaf pins.
- Backslash-escaped identifiers in common structural positions.

Behavioral blocks, generate semantics, parameters that require elaboration,
complex expressions, interfaces, SystemVerilog types, and continuous-assignment
connectivity are not fully modeled. Some unsupported statements are ignored
with parser warnings. Use a synthesized structural netlist and inspect the
reported design inventory.

## Liberty modeled

- `cell`, `pin`/`bus`, and pin `direction`.
- Clock pins marked by `clock : true`.
- `ff`, `ff_bank`, `latch`, and `latch_bank` groups.
- Identifiers referenced by `next_state`, `data_in`, `clocked_on`,
  `clocked_on_also`, and `enable` for data/clock classification.

Timing arcs, Boolean-function evaluation, operating conditions, units,
templates, tables, power, and delay values are not evaluated.

When Liberty metadata is absent, the beta can conservatively infer some
sequential cells and conventional pins from names. Treat inferred structure as
a warning to improve the library input, not as foundry-quality characterization.

## OpenSTA

OpenSTA is not bundled, imported, or linked. When `--opensta` is explicitly
supplied, OpenConstraint discovers `sta`/`opensta` or uses `--opensta-bin`,
queries its version, and runs one isolated process per mode. The generated
driver reads every supplied Liberty and Verilog file, links the selected top,
executes the mode's SDC files, runs `check_setup -verbose`, and writes a
timestamp-free effective SDC whose SHA-256 is recorded.

The default timeout is 120 seconds per version query/mode and can be changed
with `--opensta-timeout`. A failed mode emits OC6001. This validates that the
installed engine can load and normalize the trusted constraints; it does not
make OpenConstraint a delay-calculation or sign-off-equivalent product. Exact
behavior depends on the separately installed OpenSTA version, which is captured
in the report rather than hidden behind a compatibility badge.
