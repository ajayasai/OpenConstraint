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
assert_same_count braced-quiet-option [get_nets {-quiet}] [get_nets *]
assert_same_count abbreviated-quiet-option [get_ports -q data] [get_ports data]
assert_empty whitespace-preserved-pattern [get_ports -quiet { -quiet }]

# An explicitly supplied empty Tcl word is one pattern, not an omitted pattern.
assert_empty get_ports-explicit-empty [get_ports -quiet {}]
assert_empty get_pins-explicit-empty [get_pins -quiet {}]
assert_empty get_cells-explicit-empty [get_cells -quiet {}]
assert_empty get_nets-explicit-empty [get_nets -quiet {}]
assert_empty get_clocks-explicit-empty [get_clocks -quiet {}]

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
puts "OPENCONSTRAINT_SELECTOR_SEMANTICS_OK"
