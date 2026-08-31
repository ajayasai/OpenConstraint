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
and source-line tracking. Static selector words also receive non-evaluating Tcl
backslash substitution and Tcl-list element decoding before option and wildcard
classification. Collection-valued literal operands use a separate bounded,
non-evaluating Tcl-list decoder with Tcl whitespace, nested brace/quote, and
bare/quoted backslash behavior.
Backslash-newline plus its immediately following spaces/tabs collapses to one
space even inside quotes and braces; an odd backslash run before a comment
newline continues that comment. Eight-digit Unicode escapes above the BMP fail
closed so results do not depend on Tcl 8.6's build-time Unicode width.

Numeric command operands are Tcl-word decoded exactly once. Scalar values use
finite Tcl 8.6 integer spellings or decimal floating-point spellings with Tcl
whitespace; `NaN` and infinities fail closed. Integer-only operands retain exact
values and the pinned `string is integer` magnitude range instead of passing
through a binary float. Waveforms, generated edges, and edge shifts are decoded
as Tcl lists, so quoted list elements work while comma-separated values and an
extra brace/quote layer do not get silently normalized.

Not executed or interpreted:

- variables, `set`, procedures, loops, conditionals, arithmetic, or general Tcl
  list construction/operations outside static selector-pattern decoding;
- `source`, `eval`, `exec`, environment access, file/network I/O;
- general nested command substitution;
- user-defined commands.

Malformed grouping, malformed decoded words, and modeled-command grammar
errors produce `OC0001`. Dynamic command dispatch and every command outside
the exact allowlist below produce `OC0003`; this includes Tcl control/evaluation
commands and project-specific helpers. Either error forces the affected mode's
trusted coverage to `0.0/F`. Dynamic or unsupported query expressions similarly
produce error `OC1003`/`OC1004` and force `0.0/F` when they occur in modeled
constraint positions.
One input retains at most 50,000 Tcl commands and 1,000 detailed lexer issues;
the lexer still scans the remaining text and adds one deterministic truncation
issue when either limit is crossed. A literal Tcl list is limited to 50,000
elements and 64 grouping levels; selectors are separately limited to 64 nested
commands.

## SDC commands modeled

The following table is the complete top-level static allowlist—exactly nine
commands. Each has its own source-pinned option/operand grammar. Modeled
unambiguous option abbreviations follow OpenSTA's declaration-order matching;
repeatable `-through` and `-group` operands require their exact spelling.
Foreign options, missing operands, malformed Tcl words, and invalid positional
shapes produce `OC0001`, do not mutate modeled state, and force `0.0/F`.

| Command | Static semantics used by the beta |
| --- | --- |
| `create_clock` | [Identity/target/additive shape](rules/OC2006.md), zero-or-one positional target word, positive period, explicit waveform sanity, and redefinition |
| `create_generated_clock` | Exactly one positional target word plus source, master, divide/multiply/duty, three-edge/edge-shift, invert, combinational, and additive-transform validation |
| `set_input_delay` | Exact delay/target arity, finite value, singular clock/reference-pin resolution, input/inout direction, min/max and rise/fall slots, clock edge, and OpenSTA-compatible replacement/merge replay |
| `set_output_delay` | Exact delay/target arity, finite value, singular clock/reference-pin resolution, output/inout direction, min/max and rise/fall slots, clock edge, and OpenSTA-compatible replacement/merge replay |
| `set_false_path` | [Definition-shape validation](rules/OC4002.md), edge-qualified from/to plus ordered through scope, and setup/hold applicability |
| `set_multicycle_path` | Edge-qualified ordered scope, integer multiplier, setup/hold, start/end, reset marker, pairing, and conflict analysis |
| `set_max_delay`, `set_min_delay` | Definition/value validation, edge-qualified ordered scope, and normalized numeric value for overlap/mode comparison |
| `set_clock_groups` | Relationship/group validation plus pairwise directional cuts with `-allow_paths` retained as a qualifier |

Every other top-level command emits `OC0003` and forces `0.0/F`; no unknown
helper is silently assumed to be inert. Its nested supported selectors may
still be checked independently to preserve useful query evidence, but the
command never mutates modeled clocks, I/O delays, or exceptions. Flatten such
helpers to the documented subset or validate trusted source through OpenSTA.
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

Every static leaf of a collection-valued literal target, exception scope, or
clock group must be well formed and resolve. One malformed or unknown member
invalidates the entire modeled command; known siblings are retained only as
attempt evidence, never active state or coverage credit. This deliberately
fails closed more strictly than OpenSTA c821ad1 helpers that warn and retain the
resolved subset for some generated-clock, exception, and clock-group arguments.
Literal operands with a singleton contract (`-source`, `-master_clock`, I/O
`-clock`, and `-reference_pin`) count the complete Tcl list, require exactly one
known object occurrence, and look up the original singleton spelling rather
than flattening nested grouping. Selector collections retain their Tcl
multiplicity and are checked by occurrence count. Implicit wildcard expansion
is not applied to literal names; use an explicit supported `get_*` selector.
Clock-group selector operands must return clocks (`get_clocks` or `all_clocks`)
and every pattern must resolve before pairwise cuts become active. Exception
endpoints accept `all_clocks`, and a singleton `all_inputs`/`all_outputs`
collection is valid for the I/O-delay `-reference_pin` contract. Stray
positional operands on `set_false_path` or `set_clock_groups` fail closed as
`OC0001`; this is intentionally stricter than OpenSTA's warning-and-apply
behavior for those operands.

Invalid clock definition attempts remain in JSON/HTML provenance with
`valid: false`. Only clocks that pass definition, period, waveform, generated
source/master, and transform checks participate in later clock queries, I/O
requirements, exceptions, graph edges, coverage, cross-mode comparison, or
semantic digests.

Reports retain every I/O-delay command. Semantic baselines and OpenSTA
static/effective digests separately replay the active state: a non-`-add_delay`
update removes competing clock-edge relationships for that port and overwrites
only its selected min/max × rise/fall cells; `-add_delay` merges minima downward
and maxima upward. The static model does not retain clock-object generations
across later clock redefinitions and does not yet model `unset_input_delay` or
`unset_output_delay`, so those histories remain outside the active-state
comparison contract.

## Object queries modeled

- `get_ports`, `get_pins`, `get_cells`, `get_nets`, `get_clocks`, and the
  `get_registers` extension. Source-pinned singular aliases `get_port`,
  `get_pin`, `get_cell`, `get_net`, and `get_clock` canonicalize to their
  plural forms.
- `all_inputs`, `all_outputs`, `all_clocks`, `all_registers`.
- Exact names and a deliberately small non-regexp glob grammar: only `*` and
  `?` are wildcards; bracket expressions such as `[abc]` are literal text.
  Matching follows the pinned OpenSTA UTF-8 byte behavior, so `?` consumes one
  byte rather than one Unicode code point and adjacent stars retain their
  source behavior (`data**` does not match `data`). A single glob comparison is
  limited to 1,000,000 dynamic-programming states and a collection walk to
  10,000,000 estimated states; an exceeded limit fails closed as `OC1004`.
  `-regexp` is anchored to the full comparison name and accepts only the
  conservative subset proven consistent between Tcl ARE and Python regular
  expressions. `(?...)` forms, alphanumeric escapes such as `\b`/`\w` and
  backreferences, counted or modified/repeated quantifiers, advanced bracket
  classes, and non-ASCII `-nocase` evaluation fail closed as `OC1004`.
  Patterns are limited to 4,096 characters, 64 group levels, eight total
  quantifiers, and—per path component—one unbounded quantifier and one
  alternation; top-level alternation cannot share a component with a
  quantifier because OpenSTA's raw anchor injection leaves one alternative
  unanchored at one end. A regexp collection walk is limited to 10,000,000
  estimated states. These conservative availability limits intentionally
  reject some valid Tcl ARE expressions rather than risking backend-specific
  or pathologically expensive behavior. As in OpenSTA, `-nocase` affects only
  regexp matching; it is ignored for exact/glob matching and for regexp
  components routed through exact lookup.
- Without `-hierarchical`, exact cell, net, and pin paths compare their complete
  names relative to the linked top. Wildcard walks stay at the path depth
  addressed by the pattern: a separator-free wildcard sees the current linked
  top scope, while an explicit path such as `block/*` can address that deeper
  scope. OpenSTA's special `get_pins *` walk sees pins of direct child
  instances. With `-hierarchical`, cells and nets compare their local leaf name,
  while pins compare `local_instance/pin`—not the bare pin leaf or full
  top-relative path. Unsupported hierarchy options on other query kinds fail
  closed.
- For non-hierarchical cell/net/pin regexps, OpenSTA c821ad1 decides per path
  component whether to use a regexp walk or exact lookup based only on
  `.`/`+`/`*`/`?`/`[`/`]`. OpenConstraint preserves that routing, including raw
  `^pattern$` anchor injection and its alternation precedence. A regexp-looking
  component with no routing metacharacter can therefore be an exact literal
  lookup rather than a compiled expression.
- Source-pinned OpenSTA omitted-pattern semantics: a bare `get_ports`,
  `get_pins`, `get_cells`, `get_nets`, or `get_clocks` query means `*`, while an
  explicitly empty Tcl pattern remains an empty collection. Broad implicit
  wildcards remain eligible for OC1002; intentional `all_*` selectors do not.
  Effective wildcard/option classification happens after static Tcl word
  backslash substitution and nested Tcl-list quoting are decoded.
- Selector option spelling and positional arity are checked per command.
  Modeled unambiguous option prefixes follow OpenSTA; invalid options and valid
  qualifiers outside the documented static subset fail closed as OC1004
  instead of being reinterpreted as object patterns. Tcl braces suppress
  nested command substitution, including inside `-of_objects` operands.
- Query results retain Tcl collection multiplicity in addition to their stable
  object set. Duplicate or overlapping patterns therefore remain non-singleton
  for `-clock`, generated-clock `-source`/`-master_clock`, and I/O
  `-reference_pin` contracts even when they name one unique object.
- Simple equality filters use exact, case-sensitive OpenSTA direction
  properties (`direction`, `port_direction`, or `pin_direction`) on their valid
  port/pin query types and exact direction values (`input`, `output`,
  `tristate`, `bidirect`, `internal`, `ground`, `power`, `well`, or `unknown`).
  The structural model's `inout` direction is compared as OpenSTA's `bidirect`.
  Unsupported property/type/value combinations fail closed. Sequential-cell
  truth filtering is an OpenConstraint extension limited to `get_registers`.
- Static nested `-of_objects` connectivity using OpenSTA's source-type matrix:
  `get_cells` accepts ports, pins, or nets; `get_nets` accepts cells or pins;
  `get_pins` accepts cells or nets; and `get_ports` accepts nets. Positional
  patterns supplied with `-of_objects` are retained for reporting but ignored
  during resolution, matching OpenSTA. The relation uses modeled
  port/net/pin/instance connectivity rather than timing arcs.
- Selector occurrences retain their command-argument role. A query evaluated
  inside `-source`, `-master_clock`, `-clock`, another modeled collection
  option, or a positional collection is not mistaken for another occurrence,
  even when its raw text is identical. A selector used as a scalar value such
  as `-name`, `-comment`, or the effective delay/multiplier positional is still
  evaluated by Tcl but cannot be preserved as source text safely; the outer
  command therefore produces `OC0003`, does not mutate semantic state, and the
  selector remains available for independent query auditing.
- Escaped hierarchy dividers such as `\/` and bus-range-shaped object patterns
  such as `data[0:3]` fail closed as `OC1004`. The flattened structural model
  cannot disambiguate an escaped slash from a hierarchy path, and it does not
  retain enough declaration provenance to expand a range without guessing.
  Exact bit names such as `data[3]` remain supported.

One `get_*` positional word may be a Tcl pattern list. Static decoding is
bounded to 64 nested selectors; malformed list structure, invalid Unicode
escapes, or deeper nesting fails closed as `OC1004` rather than widening or
partially resolving the query. Malformed decoded words in one of the nine
modeled commands instead produce `OC0001`; a malformed/dynamic command name is
outside the allowlist and produces `OC0003`.

General filter expressions, Tcl-generated patterns, arbitrary collection
algebra, `get_registers`/clock queries with `-of_objects`, and
property/timing-arc-based connectivity are not modeled. A nested `-of_objects`
source must itself be a supported static selector with an accepted collection
type. The structural model flattens module instances and boundary pins, and the
static allowlist does not include `current_instance`; query scope is therefore
the linked top, module-instance cells/boundary pins cannot be returned, and
non-top current-instance state is outside the beta. Exact deep paths to modeled
leaf cells, nets, and pins remain supported.

Exception endpoints may also be exact literal object names from the documented
port, pin, cell, clock, and applicable net universes. A specified literal
`-from`, `-through`, or `-to` scope with any malformed or unresolved member is
an invalid definition (`OC4002`); it is never narrowed to the valid subset or
treated as an omitted/unrestricted scope.

## Structural Verilog modeled

- Modules, ANSI/non-ANSI port declarations, common net declarations, simple
  packed bit ranges, hierarchy, and leaf-cell instantiation.
- Named and positional port connections.
- Simple scalar/bit-select signals and constants at leaf pins.
- Backslash-escaped identifiers in common structural positions.

Non-ANSI packed declarations replace their header placeholders instead of
leaving ghost scalar ports or nets. If a flattened escaped identifier containing
`/` collides with an ordinary hierarchical path, the first structural object is
retained and the ambiguity is reported as a parser warning, which produces
design-level `OC0002` and zero trusted coverage.

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
queries its version, and runs one separate process per mode. The generated
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
