# Executed only by the source-pinned OpenSTA integration workflow.
read_liberty tests/fixtures/opensta/roundtrip.lib
read_verilog tests/fixtures/opensta/roundtrip.v
link_design opensta_roundtrip
create_clock -name core_clk -period 10 [get_ports clk]

proc assert_same_count {label actual expected} {
  set actual_count [llength $actual]
  set expected_count [llength $expected]
  if {$actual_count != $expected_count} {
    error "$label: expected $expected_count objects, got $actual_count"
  }
}

proc assert_empty {label collection} {
  set count [llength $collection]
  if {$count != 0} {
    error "$label: expected an empty collection, got $count objects"
  }
}

# OpenSTA c821ad1 defines an omitted get_* pattern as the implicit wildcard *.
assert_same_count get_ports-implicit-all [get_ports] [get_ports *]
assert_same_count get_pins-implicit-all [get_pins] [get_pins *]
assert_same_count get_cells-implicit-all [get_cells] [get_cells *]
assert_same_count get_nets-implicit-all [get_nets] [get_nets *]
assert_same_count get_clocks-implicit-all [get_clocks] [get_clocks *]
assert_same_count singular-get-port [get_port data] [get_ports data]
assert_same_count singular-get-pin [get_pin u_ff/D] [get_pins u_ff/D]
assert_same_count singular-get-cell [get_cell u_ff] [get_cells u_ff]
assert_same_count singular-get-net [get_net data] [get_nets data]
assert_same_count singular-get-clock [get_clock core_clk] [get_clocks core_clk]
assert_same_count braced-quiet-option [get_nets {-quiet}] [get_nets *]
assert_same_count abbreviated-quiet-option [get_ports -q data] [get_ports data]
assert_empty whitespace-preserved-pattern [get_ports -quiet { -quiet }]

# Tcl performs command-word backslash substitution before OpenSTA parses
# options/patterns, then OpenSTA iterates the one positional word as a Tcl list.
assert_same_count escaped-star-wildcard [get_ports \*] [get_ports *]
assert_same_count escaped-hex-star-wildcard [get_ports \x2a] [get_ports *]
assert_same_count escaped-quiet-option [get_ports \-quiet] [get_ports *]
assert_same_count nested-braced-wildcard [get_ports {{*}}] [get_ports *]
assert_same_count nested-braced-pattern-list [get_ports {{clk} data}] [get_ports {clk data}]
assert_same_count trailing-command-terminator [get_ports *;] [get_ports *]

# An explicitly supplied empty Tcl word is one pattern, not an omitted pattern.
assert_empty get_ports-explicit-empty [get_ports -quiet {}]
assert_empty get_pins-explicit-empty [get_pins -quiet {}]
assert_empty get_cells-explicit-empty [get_cells -quiet {}]
assert_empty get_nets-explicit-empty [get_nets -quiet {}]
assert_empty get_clocks-explicit-empty [get_clocks -quiet {}]

# Direction property names and values are exact, case-sensitive OpenSTA
# vocabulary. The round-trip fixture has two inputs, one output, and no
# bidirectional top-level port.
assert_same_count direction-input [get_ports -filter {direction == input} *] [get_ports {clk data}]
assert_same_count port-direction-output [get_ports -filter {port_direction == output} *] [get_ports -filter {direction == output} *]
assert_same_count pin-direction-input [get_pins -filter {pin_direction == input} *] [get_pins -filter {direction == input} *]
assert_empty direction-bidirect [get_ports -quiet -filter {direction == bidirect} *]
assert_empty direction-inout-not-vocabulary [get_ports -quiet -filter {direction == inout} *]
if {![catch {get_cells -filter {direction == unknown} *}]} {
  error "get_cells accepted the port/pin-only direction property"
}
if {![catch {get_ports -filter {pin_direction == input} *}]} {
  error "get_ports accepted the pin-only pin_direction property"
}
if {![catch {get_pins -filter {port_direction == input} *}]} {
  error "get_pins accepted the port-only port_direction property"
}
if {![catch {get_ports -filter {DIRECTION == input} *}]} {
  error "get_ports treated the direction property as case-insensitive"
}

# Patternless -of_objects is valid, while ordinary multiple positional words
# and options without operands are rejected by OpenSTA's argument parser.
assert_same_count get_cells-of-objects [get_cells -of_objects [get_nets data]] [get_cells u_ff]
assert_empty brace-suppressed-of-objects [get_cells -of_objects {[get_nets data]}]
assert_same_count all-register-cells [all_registers -cells] [get_cells u_ff]
assert_same_count all-inputs-without-clocks [all_inputs -no_clocks] [get_ports data]
assert_same_count all-inputs-ignored-positional [all_inputs ignored] [all_inputs]
if {![catch {get_ports data q}]} {
  error "get_ports accepted two positional Tcl arguments"
}
if {![catch {get_ports a" b"c}]} {
  error "get_ports treated a mid-word quote as Tcl grouping"
}
if {![catch {get_ports a{ b}c}]} {
  error "get_ports treated a mid-word brace as Tcl grouping"
}
if {![catch {get_ports {-q } data}]} {
  error "get_ports trimmed Tcl-significant option whitespace"
}
if {![catch {get_ports -filter}]} {
  error "get_ports accepted -filter without an operand"
}
if {![catch {get_ports -of_objects}]} {
  error "get_ports accepted -of_objects without an operand"
}
if {![catch {get_ports -filter {} *}]} {
  error "get_ports accepted an empty filter expression"
}
if {![catch {get_ports -hierarchical data}]} {
  error "get_ports accepted the get_cells/get_nets/get_pins-only -hierarchical option"
}
if {![catch {get_clocks -of_objects [get_ports clk]}]} {
  error "get_clocks accepted the get_cells/get_nets/get_pins/get_ports-only -of_objects option"
}
if {![catch {get_ports -regexp {(?P<x>data)}}]} {
  error "get_ports accepted a Python-only named regular-expression group"
}
if {![catch {get_ports -regexp {a++}}]} {
  error "get_ports accepted a Python-only possessive regular-expression quantifier"
}
assert_empty tcl-backspace-not-python-boundary [get_ports -quiet -regexp {\bdata\b}]
assert_empty pin-regexp-exact-routing [get_pins -quiet -regexp {^u_ff/D$}]
assert_empty hierarchical-pin-leaf [get_pins -quiet -hierarchical D]
assert_same_count hierarchical-pin-local-path [get_pins -hierarchical u_ff/D] [get_pins u_ff/D]

# create_clock accepts zero or one target word; create_generated_clock
# requires exactly one target word. A target word may itself be a collection.
create_clock -name virtual_arity_clock -period 20
assert_same_count create-clock-zero-target [get_clocks virtual_arity_clock] [get_clocks core_clk]
if {![catch {create_clock -name invalid_primary_arity -period 10 [get_ports clk] [get_ports data]}]} {
  error "create_clock accepted two positional target words"
}
if {![catch {create_clock -name invalid_primary_option -period 10 -rise [get_ports clk]}]} {
  error "create_clock accepted an option outside its command grammar"
}
if {![catch {create_generated_clock -name invalid_generated_missing_target -source [get_ports clk] -divide_by 2}]} {
  error "create_generated_clock accepted no positional target word"
}
if {![catch {create_generated_clock -name invalid_generated_arity -source [get_ports clk] -divide_by 2 [get_ports q] [get_ports data]}]} {
  error "create_generated_clock accepted two positional target words"
}
# get_clock_warn warns and returns NULL instead of throwing for a non-singleton
# or unknown -clock value. OpenConstraint intentionally treats both as invalid
# rather than silently installing a clockless delay.
if {[catch {set_input_delay 1 -clock [get_clocks {core_clk core_clk}] [get_ports data]}]} {
  error "set_input_delay unexpectedly rejected the warning-only duplicate clock collection"
}
if {[catch {set_input_delay 1 -clock {core_clk missing_clock} [get_ports data]}]} {
  error "set_input_delay unexpectedly rejected the warning-only literal clock list"
}
if {![catch {set_input_delay 1 -clock core_clk {data missing_port}}]} {
  error "set_input_delay accepted a partially unresolved literal target list"
}
if {![catch {set_input_delay 1 -clock core_clk -reference_pin {u_ff/Q missing_pin} [get_ports data]}]} {
  error "set_input_delay accepted a partially unresolved literal reference-pin list"
}
if {![catch {create_generated_clock -name invalid_duplicate_source -source [get_ports {clk clk}] -divide_by 2 [get_pins u_ff/CLK]}]} {
  error "create_generated_clock accepted a duplicate non-singleton source collection"
}
if {![catch {create_generated_clock -name invalid_literal_source -source {clk missing_port} -divide_by 2 [get_pins u_ff/CLK]}]} {
  error "create_generated_clock accepted a partially unresolved literal source list"
}
if {![catch {create_generated_clock -name invalid_literal_master -master_clock {core_clk missing_clock} -source [get_ports clk] -divide_by 2 [get_pins u_ff/CLK]}]} {
  error "create_generated_clock accepted a partially unresolved literal master-clock list"
}
if {![catch {set_multicycle_path 2 junk -to [get_ports q]}]} {
  error "set_multicycle_path accepted an extra positional operand"
}
# These two OpenSTA procedures warn about, then apply, stray positional words.
# The static auditor intentionally treats that ambiguous warning path as a
# grammar error and installs no exception state.
if {[catch {set_false_path junk -to [get_ports q]}]} {
  error "set_false_path unexpectedly rejected its warning-only positional operand"
}
if {[catch {set_clock_groups junk -asynchronous -group [get_clocks core_clk] -group [get_clocks virtual_arity_clock]}]} {
  error "set_clock_groups unexpectedly rejected its warning-only positional operand"
}

# Numeric operands are Tcl-decoded once. An extra grouping layer remains part
# of the scalar/list value and is rejected rather than stripped a second time.
if {![catch {create_clock -name invalid_nested_period -period {{10}}}]} {
  error "create_clock accepted a doubly grouped period"
}
if {![catch {create_clock -name invalid_nested_waveform -period 10 -waveform {{0 5}}}]} {
  error "create_clock accepted a doubly grouped waveform"
}
if {![catch {create_clock -name invalid_comma_waveform -period 10 -waveform {0,5}}]} {
  error "create_clock accepted a comma-separated waveform"
}
if {![catch {set_input_delay {{1}} [get_ports data]}]} {
  error "set_input_delay accepted a doubly grouped numeric value"
}
if {![catch {set_multicycle_path 9007199254740993 -to [get_ports q]}]} {
  error "set_multicycle_path accepted a value outside Tcl string-is-integer range"
}
puts "OPENCONSTRAINT_SELECTOR_SEMANTICS_OK"
