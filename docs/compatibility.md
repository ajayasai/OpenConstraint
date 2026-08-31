# Compatibility and supported subsets

OpenConstraint v0.3.0-beta is intentionally not a complete Verilog, Liberty,
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
One input retains at most 50,000 Tcl commands and 1,000 detailed lexer issues;
the lexer still scans the remaining text and adds one deterministic truncation
issue when either limit is crossed.

## SDC commands modeled

| Command | Static semantics used by the beta |
| --- | --- |
| `create_clock` | [Identity/target/additive shape](rules/OC2006.md), positive period, explicit waveform sanity, and redefinition |
| `create_generated_clock` | Target, source, master, divide/multiply/duty, three-edge/edge-shift, invert, combinational, and additive-transform validation |
| `set_input_delay` | Exact delay/target arity, finite value, singular clock/reference-pin resolution, input/inout direction, min/max and rise/fall slots, clock edge, and OpenSTA-compatible replacement/merge replay |
| `set_output_delay` | Exact delay/target arity, finite value, singular clock/reference-pin resolution, output/inout direction, min/max and rise/fall slots, clock edge, and OpenSTA-compatible replacement/merge replay |
| `set_false_path` | [Definition-shape validation](rules/OC4002.md), edge-qualified from/to plus ordered through scope, and setup/hold applicability |
| `set_multicycle_path` | Edge-qualified ordered scope, integer multiplier, setup/hold, start/end, reset marker, pairing, and conflict analysis |
| `set_max_delay`, `set_min_delay` | Definition/value validation, edge-qualified ordered scope, and normalized numeric value for overlap/mode comparison |
| `set_clock_groups` | Relationship/group validation plus pairwise directional cuts with `-allow_paths` retained as a qualifier |

Other commands may be tokenized, and their nested supported selectors may be
checked for query quality, but their timing semantics are not modeled.
`-reset_path` removes earlier modeled exceptions with the same normalized,
edge-qualified scope and overlapping setup/hold applicability before conflict
analysis. This is a deterministic exact-scope subset of full STA history; the
static model does not reproduce partial collection subtraction or every
tool-specific reset interaction.

I/O-delay analysis requires a supplied `-clock` to resolve to exactly one valid
clock and `-reference_pin` to resolve to exactly one port or pin. It preserves
source/network-latency inclusion flags and reports their OpenSTA-defined ignored
combination with `-reference_pin`; it does not evaluate reference-pin topology
or external interface protocol intent.

Reports retain every I/O-delay command. Semantic baselines and OpenSTA
static/effective digests separately replay the active state: a non-`-add_delay`
update removes competing clock-edge relationships for that port and overwrites
only its selected min/max × rise/fall cells; `-add_delay` merges minima downward
and maxima upward. The static model does not retain clock-object generations
across later clock redefinitions and does not yet model `unset_input_delay` or
`unset_output_delay`, so those histories remain outside the active-state
comparison contract.

## Object queries modeled

- `get_ports`, `get_pins`, `get_cells`, `get_nets`, `get_clocks`,
  `get_registers`.
- `all_inputs`, `all_outputs`, `all_clocks`, `all_registers`.
- Exact names, shell-style globs, `-regexp`, and leaf-name matching with
  `-hierarchical`. As in OpenSTA, `-nocase` affects only `-regexp`; it is
  ignored for exact and glob matching.
- Source-pinned OpenSTA omitted-pattern semantics: a bare `get_ports`,
  `get_pins`, `get_cells`, `get_nets`, or `get_clocks` query means `*`, while an
  explicitly empty Tcl pattern remains an empty collection. Broad implicit
  wildcards remain eligible for OC1002; intentional `all_*` selectors do not.
- Selector option spelling and positional arity are checked per command.
  Modeled unambiguous option prefixes follow OpenSTA; invalid options and valid
  qualifiers outside the documented static subset fail closed as OC1004
  instead of being reinterpreted as object patterns. Tcl braces suppress
  nested command substitution, including inside `-of_objects` operands.
- Filters for object `direction` and sequential-cell truth in the documented
  simple forms.
- Static nested `-of_objects` connectivity using OpenSTA's source-type matrix:
  `get_cells` accepts ports, pins, or nets; `get_nets` accepts cells or pins;
  `get_pins` accepts cells or nets; and `get_ports` accepts nets. Positional
  patterns supplied with `-of_objects` are retained for reporting but ignored
  during resolution, matching OpenSTA. The relation uses modeled
  port/net/pin/instance connectivity rather than timing arcs.
- Selector occurrences retain their command-argument role. A query evaluated
  inside `-source`, `-master_clock`, `-clock`, `-comment`, or another option is
  not mistaken for the command's positional target, even when its raw text is
  identical to that target.

General filter expressions, Tcl-generated patterns, arbitrary collection
algebra, `get_registers`/clock queries with `-of_objects`, and
property/timing-arc-based connectivity are not modeled. A nested `-of_objects`
source must itself be a supported static selector with an accepted collection
type.

## Structural Verilog modeled

- Modules, ANSI/non-ANSI port declarations, common net declarations, simple
  packed bit ranges, hierarchy, and leaf-cell instantiation.
- Named and positional port connections.
- Simple scalar/bit-select signals and constants at leaf pins.
- Backslash-escaped identifiers in common structural positions.

Packed buses are limited to 65,536 bits and 65,536 expanded names per
declaration, with 65,536 connections per instance, 131,072 expanded names,
200,000 structural statements, 10,000 module occurrences, and 1,000 detailed
parser warnings per parsed file. Structural hierarchy is limited to 256 module
levels and 262,144 elaborated nets, instances, and pins. Inputs beyond those
bounds produce parser warnings and are deterministically truncated. Any
Verilog, Liberty, or elaboration warning also produces design-level error
`OC0002`, so incomplete structural modeling participates in the normal CI
severity gate instead of coexisting with a clean result.

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
- Combinational input-to-output dependencies extracted from output Boolean
  `function` attributes and `timing` groups' `related_pin` attributes. Unknown
  instantiated dependencies stop clock propagation and produce `OC0002`.

Timing conditions, Boolean-function truth evaluation, operating conditions,
units, templates, tables, power, and delay values are not evaluated.

Liberty group nesting is limited to 256 levels. Each input retains at most
750,000 non-whitespace tokens, 120,000 parser nodes, and 1,000 detailed parser
warnings. Deeper or higher-cardinality content is deterministically truncated
with one summary warning. These bounds preserve the published SKY130HD corpus,
which uses 610,986 tokens and fewer than 100,000 total parsed nodes.

When Liberty metadata is absent, the beta can conservatively infer some
sequential cells and conventional pins from names. Inference produces a bounded,
aggregate parser warning and therefore `OC0002`; it is not foundry-quality
characterization.

## OpenSTA

OpenSTA is not bundled, imported, or linked. When `--opensta` is explicitly
supplied, OpenConstraint discovers `sta`/`opensta` or uses `--opensta-bin`,
queries its version, and runs one isolated process per mode. The generated
driver reads every supplied Liberty and Verilog file, links the selected top,
executes the mode's SDC files, runs `check_setup -verbose`, and writes a
timestamp-free effective SDC whose SHA-256 is recorded. A successful effective
SDC is then parsed by the same static subset: new semantic diagnostics are
merged into the active result, and separate normalized static/effective
semantic digests and effective coverage are reported. The digest includes the
canonical active I/O-delay state rather than raw I/O command history.

The default timeout is 120 seconds per version query/mode and can be changed
with `--opensta-timeout`. A failed mode emits OC6001. This validates that the
installed engine can load and normalize the trusted constraints; it does not
make OpenConstraint a delay-calculation or sign-off-equivalent product. The
semantic digest compares modeled clocks, exceptions, active I/O delays, and coverage, not arbitrary
Tcl behavior or formal equivalence. Exact behavior depends on the separately
installed OpenSTA version, which is captured in the report rather than hidden
behind a compatibility badge.
