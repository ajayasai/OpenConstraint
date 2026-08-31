from __future__ import annotations

import pytest

from openconstraint.model import Clock, Port, SourceLocation
from openconstraint.parsers.sdc import parse_sdc_text
from openconstraint.query import _glob_matches, resolve_selector


def _selector(query: str):
    return parse_sdc_text(f"set_false_path -to {query}\n").commands[0].selectors[0]


def test_non_regexp_patterns_do_not_treat_brackets_as_character_classes(design_factory) -> None:
    design = design_factory()
    selector = _selector("[get_ports {[cd]*}]")
    resolved = resolve_selector(selector, design, {})

    assert resolved.error is None
    assert resolved.matches == set()
    assert resolved.unmatched_patterns == ("[cd]*",)


def test_non_regexp_patterns_support_only_star_and_question_wildcards(design_factory) -> None:
    design = design_factory()

    assert resolve_selector(_selector("[get_ports {cl*}]"), design, {}).matches == {"clk", "clk2"}
    assert resolve_selector(_selector("[get_ports {cl?}]"), design, {}).matches == {"clk"}


def test_non_regexp_consecutive_stars_preserve_pinned_opensta_boundaries(design_factory) -> None:
    design = design_factory()
    resolved = resolve_selector(_selector("[get_ports {clk**}]"), design, {})

    assert resolved.matches == {"clk2"}
    assert _glob_matches("data**", "data") is False
    assert _glob_matches("data**", "data2") is True
    assert _glob_matches("**", "") is False
    assert _glob_matches("**", "x") is True


def test_non_regexp_pattern_with_long_star_run_is_stack_bounded(design_factory) -> None:
    design = design_factory()
    selector = _selector(f"[get_ports {{{'*' * 5_000}}}]")

    assert resolve_selector(selector, design, {}).matches == set(design.ports)


def test_non_regexp_glob_uses_opensta_utf8_byte_semantics(design_factory) -> None:
    design = design_factory()
    design.ports["é"] = Port("é", "input", "é")
    design.nets.add("é")

    one_byte = resolve_selector(_selector("[get_ports {?}]"), design, {})
    two_bytes = resolve_selector(_selector("[get_ports {??}]"), design, {})

    assert "é" not in one_byte.matches
    assert "é" in two_bytes.matches


def test_adversarial_glob_fails_closed_before_quadratic_work(design_factory) -> None:
    design = design_factory()
    candidate = "a" * 20_000
    design.ports[candidate] = Port(candidate, "input", candidate)
    design.nets.add(candidate)
    pattern = "*" + "a" * 10_000 + "b"

    resolved = resolve_selector(_selector(f"[get_ports {{{pattern}}}]"), design, {})

    assert resolved.matches == set()
    assert resolved.error is not None
    assert "deterministic" in resolved.error
    assert "limit" in resolved.error


@pytest.mark.parametrize(
    "query",
    [
        "[get_ports {" + "*" + "a" * 299 + "b}]",
        "[get_ports -regexp {" + "a" * 199 + ".*b}]",
    ],
)
def test_collection_match_work_is_bounded_across_many_candidates(design_factory, query: str) -> None:
    design = design_factory()
    for index in range(300):
        name = "a" * 200 + f"{index:03d}"
        design.ports[name] = Port(name, "input", name)
        design.nets.add(name)

    resolved = resolve_selector(_selector(query), design, {})

    assert resolved.matches == set()
    assert resolved.error is not None
    assert "collection comparison exceeds" in resolved.error


def test_regexp_patterns_are_anchored_to_the_full_object_name(design_factory) -> None:
    design = design_factory(verilog="module top(input data, input metadata, output result); endmodule")
    selector = _selector("[get_ports -regexp {data}]")
    resolved = resolve_selector(selector, design, {})

    assert resolved.error is None
    assert resolved.matches == {"data"}


def test_regexp_anchor_injection_matches_opensta_alternation_precedence(design_factory) -> None:
    design = design_factory(
        verilog="module top(input data, input database, input metadata, input premetadata, output result); endmodule"
    )
    resolved = resolve_selector(_selector("[get_ports -regexp {data|metadata}]"), design, {})

    # OpenSTA c821ad1 constructs ^data|metadata$, without adding a group.
    assert resolved.error is None
    assert resolved.matches == {"data", "database", "metadata", "premetadata"}


def test_nocase_applies_to_anchored_regexp_but_not_glob_patterns(design_factory) -> None:
    design = design_factory(verilog="module top(input data, input metadata, output result); endmodule")
    regexp = resolve_selector(_selector("[get_ports -regexp -nocase {DATA}]"), design, {})
    case_sensitive_regexp = resolve_selector(_selector("[get_ports -regexp {DATA}]"), design, {})
    glob = resolve_selector(_selector("[get_ports -nocase DATA]"), design, {})

    assert regexp.matches == {"data"}
    assert case_sensitive_regexp.matches == set()
    assert glob.matches == set()


def test_hierarchical_pin_matching_uses_local_instance_and_pin_name(design_factory) -> None:
    design = design_factory()

    assert resolve_selector(_selector("[get_pins -hierarchical {u_ff/D}]"), design, {}).matches == {"u_ff/D"}
    assert resolve_selector(_selector("[get_pins -hierarchical {D}]"), design, {}).matches == set()


def test_selector_result_retains_duplicate_pattern_cardinality(design_factory) -> None:
    design = design_factory()
    clock = Clock(
        name="core",
        targets={"clk"},
        period=10.0,
        waveform=(0.0, 5.0),
        waveform_explicit=True,
        location=SourceLocation("<test>"),
    )

    ports = resolve_selector(_selector("[get_ports {clk clk}]"), design, {})
    clocks = resolve_selector(_selector("[get_clocks {core core}]"), design, {"core": clock})

    assert ports.matches == {"clk"}
    assert ports.match_count == 2
    assert clocks.matches == {"core"}
    assert clocks.match_count == 2


def test_overlapping_patterns_contribute_each_collection_occurrence(design_factory) -> None:
    design = design_factory()
    resolved = resolve_selector(_selector("[get_ports {clk cl*}]"), design, {})

    assert resolved.matches == {"clk", "clk2"}
    assert resolved.match_count == 3


NESTED_VERILOG = """
module leaf(input clk, input data, output result);
  wire leaf_q;
  DFF u_ff (.CK(clk), .D(data), .Q(leaf_q));
  BUF u_buf (.A(leaf_q), .Y(result));
endmodule

module middle(input clk, input data, output result);
  wire middle_q;
  leaf u_leaf (.clk(clk), .data(data), .result(middle_q));
  BUF u_mid_buf (.A(middle_q), .Y(result));
endmodule

module top(input clk, input data, output result);
  wire top_q;
  DFF top_ff (.CK(clk), .D(data), .Q(top_q));
  middle u_mid (.clk(clk), .data(top_q), .result(result));
endmodule
"""


def test_nonhierarchical_queries_compare_names_relative_to_the_top_scope(design_factory) -> None:
    design = design_factory(verilog=NESTED_VERILOG)

    assert resolve_selector(_selector("[get_cells u_ff]"), design, {}).matches == set()
    assert resolve_selector(_selector("[get_cells u_mid/u_leaf/u_ff]"), design, {}).matches == {"u_mid/u_leaf/u_ff"}
    assert resolve_selector(_selector("[get_nets leaf_q]"), design, {}).matches == set()
    assert resolve_selector(_selector("[get_nets u_mid/u_leaf/leaf_q]"), design, {}).matches == {"u_mid/u_leaf/leaf_q"}
    assert resolve_selector(_selector("[get_pins D]"), design, {}).matches == set()
    assert resolve_selector(_selector("[get_pins u_mid/u_leaf/u_ff/D]"), design, {}).matches == {"u_mid/u_leaf/u_ff/D"}


def test_nonhierarchical_wildcards_stay_in_the_addressed_instance_scope(design_factory) -> None:
    design = design_factory(verilog=NESTED_VERILOG)

    cells = resolve_selector(_selector("[get_cells *]"), design, {})
    nets = resolve_selector(_selector("[get_nets *]"), design, {})
    pins = resolve_selector(_selector("[get_pins *]"), design, {})

    # The elaborated model contains leaf cells only; module instances and
    # their boundary pins are an explicitly documented flattened-model gap.
    assert cells.matches == {name for name in design.instances if "/" not in name}
    assert nets.matches == {name for name in design.nets if "/" not in name}
    assert pins.matches == {name for name in design.pins if name.count("/") == 1}
    assert cells.universe_size == len(cells.matches)
    assert nets.universe_size == len(nets.matches)
    assert pins.universe_size == len(pins.matches)


def test_nonhierarchical_wildcards_can_address_an_explicit_deep_scope(design_factory) -> None:
    design = design_factory(verilog=NESTED_VERILOG)

    assert resolve_selector(_selector("[get_cells {u_mid/u_leaf/u_*}]"), design, {}).matches == {
        "u_mid/u_leaf/u_buf",
        "u_mid/u_leaf/u_ff",
    }
    assert resolve_selector(_selector("[get_nets {u_mid/u_leaf/*}]"), design, {}).matches == {"u_mid/u_leaf/leaf_q"}
    assert resolve_selector(_selector("[get_pins {u_mid/u_leaf/u_ff/*}]"), design, {}).matches == {
        "u_mid/u_leaf/u_ff/CK",
        "u_mid/u_leaf/u_ff/D",
        "u_mid/u_leaf/u_ff/Q",
    }
    assert resolve_selector(_selector("[get_pins {*/D}]"), design, {}).matches == {"top_ff/D"}


def test_hierarchical_queries_use_kind_specific_local_names(design_factory) -> None:
    design = design_factory(verilog=NESTED_VERILOG)

    assert resolve_selector(_selector("[get_cells -hierarchical u_ff]"), design, {}).matches == {"u_mid/u_leaf/u_ff"}
    assert resolve_selector(_selector("[get_cells -hierarchical u_mid/u_leaf/u_ff]"), design, {}).matches == set()
    assert resolve_selector(_selector("[get_nets -hierarchical leaf_q]"), design, {}).matches == {"u_mid/u_leaf/leaf_q"}
    assert resolve_selector(_selector("[get_nets -hierarchical u_mid/u_leaf/leaf_q]"), design, {}).matches == set()
    assert resolve_selector(_selector("[get_pins -hierarchical u_ff/D]"), design, {}).matches == {"u_mid/u_leaf/u_ff/D"}
    assert resolve_selector(_selector("[get_pins -hierarchical D]"), design, {}).matches == set()
    assert resolve_selector(_selector("[get_pins -hierarchical u_mid/u_leaf/u_ff/D]"), design, {}).matches == set()


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("[get_cells -regexp {^top_ff$}]", set()),
        ("[get_nets -regexp {^(top_q)$}]", set()),
        ("[get_pins -regexp {(top_ff/D)}]", set()),
        ("[get_cells -regexp {top_ff}]", {"top_ff"}),
        ("[get_cells -regexp {top_.+}]", {"top_ff"}),
    ],
)
def test_nonhierarchical_no_meta_regexps_route_through_exact_lookup(
    design_factory, query: str, expected: set[str]
) -> None:
    design = design_factory(verilog=NESTED_VERILOG)
    resolved = resolve_selector(_selector(query), design, {})

    assert resolved.error is None
    assert resolved.matches == expected


def test_nonhierarchical_regexp_routes_each_path_component_independently(design_factory) -> None:
    design = design_factory(verilog=NESTED_VERILOG)

    exact_tail = resolve_selector(_selector("[get_pins -regexp {top_.+/^(D|Q)$}]"), design, {})
    wildcard_tail = resolve_selector(_selector("[get_pins -regexp {top_.+/(D|Q).?}]"), design, {})

    assert exact_tail.error is None
    assert exact_tail.matches == set()
    assert wildcard_tail.error is None
    assert wildcard_tail.matches == {"top_ff/D", "top_ff/Q"}


def test_exact_lookup_does_not_apply_nocase_regexp_semantics(design_factory) -> None:
    design = design_factory()
    design.nets.add("π")
    resolved = resolve_selector(_selector("[get_nets -regexp -nocase {q}]"), design, {})

    assert resolved.error is None
    assert resolved.matches == {"q"}


def test_hierarchical_regexp_walk_does_not_use_nonhierarchical_exact_lookup(design_factory) -> None:
    design = design_factory(verilog=NESTED_VERILOG)
    resolved = resolve_selector(_selector("[get_cells -hierarchical -regexp {^u_ff$}]"), design, {})

    assert resolved.error is None
    assert resolved.matches == {"u_mid/u_leaf/u_ff"}


@pytest.mark.parametrize(
    "pattern",
    [
        "(?P<x>data)",
        "(?s:data)",
        "(?<=meta)data",
        "(?(1)data|metadata)",
        r"(data)\1",
        "data++",
        "data+?",
        r"\bdata\b",
        r"\w+",
        "data{1,2}",
        "[[:alpha:]]+",
    ],
)
def test_python_only_regexp_extensions_fail_closed(design_factory, pattern: str) -> None:
    design = design_factory(verilog="module top(input data, input metadata, output result); endmodule")
    resolved = resolve_selector(_selector(f"[get_ports -regexp {{{pattern}}}]"), design, {})

    assert resolved.matches == set()
    assert resolved.match_count == 0
    assert resolved.error is not None
    assert "modeled Tcl ARE subset" in resolved.error


def test_common_tcl_are_and_python_regexp_subset_remains_supported(design_factory) -> None:
    design = design_factory(verilog="module top(input data, input metadata, input metadata2, output result); endmodule")
    resolved = resolve_selector(_selector("[get_ports -regexp {(data|metadata[0-9]*)}]"), design, {})

    assert resolved.error is None
    assert resolved.matches == {"data", "metadata", "metadata2"}
    assert resolved.match_count == 3


def test_deep_regexp_nesting_fails_closed_without_python_recursion_error(design_factory) -> None:
    design = design_factory(verilog="module top(input a, output result); endmodule")
    pattern = "(" * 1_000 + "a" + ")" * 1_000

    resolved = resolve_selector(_selector(f"[get_ports -regexp {{{pattern}}}]"), design, {})

    assert resolved.matches == set()
    assert resolved.error is not None
    assert "group nesting exceeds" in resolved.error


def test_nested_quantified_regexp_fails_before_catastrophic_backtracking(design_factory) -> None:
    design = design_factory()
    candidate = "a" * 36 + "!"
    design.ports[candidate] = Port(candidate, "input", candidate)
    design.nets.add(candidate)

    resolved = resolve_selector(_selector("[get_ports -regexp {(a+)+}]"), design, {})

    assert resolved.matches == set()
    assert resolved.error is not None
    assert "complexity-bounded subset" in resolved.error


def test_multiple_unbounded_quantifiers_fail_before_ambiguous_backtracking(design_factory) -> None:
    design = design_factory()
    candidate = "a" * 100 + "!"
    design.ports[candidate] = Port(candidate, "input", candidate)
    design.nets.add(candidate)
    pattern = "a*" * 8 + "b"

    resolved = resolve_selector(_selector(f"[get_ports -regexp {{{pattern}}}]"), design, {})

    assert resolved.matches == set()
    assert resolved.error is not None
    assert "multiple unbounded quantifiers" in resolved.error


def test_repeated_ambiguous_alternations_fail_before_exponential_backtracking(design_factory) -> None:
    design = design_factory()
    candidate = "a" * 60 + "!"
    design.ports[candidate] = Port(candidate, "input", candidate)
    design.nets.add(candidate)
    pattern = "(a|aa)" * 30 + "b"

    resolved = resolve_selector(_selector(f"[get_ports -regexp {{{pattern}}}]"), design, {})

    assert resolved.matches == set()
    assert resolved.error is not None
    assert "multiple alternations" in resolved.error


@pytest.mark.parametrize("pattern", ["x|.*b", ".*b|x", "x|a?b"])
def test_top_level_alternation_with_repetition_fails_before_unanchored_backtracking(
    design_factory, pattern: str
) -> None:
    design = design_factory()
    candidate = "c" * 100_000
    design.ports[candidate] = Port(candidate, "input", candidate)
    design.nets.add(candidate)

    resolved = resolve_selector(_selector(f"[get_ports -regexp {{{pattern}}}]"), design, {})

    assert resolved.matches == set()
    assert resolved.error is not None
    assert "top-level alternation with repetition" in resolved.error


def test_regexp_dot_and_end_anchor_match_tcl_newline_semantics(design_factory) -> None:
    design = design_factory()
    clocks = {
        name: Clock(
            name=name,
            targets=set(),
            period=10.0,
            waveform=(0.0, 5.0),
            waveform_explicit=True,
            location=SourceLocation("<test>"),
        )
        for name in ("\n", "a\n")
    }

    dot = resolve_selector(_selector("[get_clocks -regexp {.}]"), design, clocks)
    strict_end = resolve_selector(_selector("[get_clocks -regexp {a$}]"), design, clocks)

    assert dot.matches == {"\n"}
    assert strict_end.matches == set()


def test_of_objects_preserves_nested_source_occurrences(design_factory) -> None:
    design = design_factory()
    selector = _selector("[get_ports -of_objects [get_nets {clk clk}]]")

    resolved = resolve_selector(selector, design, {})

    assert resolved.matches == {"clk"}
    assert resolved.match_count == 2
    assert resolved.multiplicities == {"clk": 2}


def test_duplicate_nested_of_objects_source_is_rejected_by_singleton_contract(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 [get_ports clk]
create_generated_clock -name divided -source \
  [get_ports -of_objects [get_nets {clk clk}]] -divide_by 2 [get_pins u_ff/Q]
"""
    )

    invalid = [finding for finding in result.diagnostics if finding.rule_id == "OC2012"]
    assert any(
        "-source must resolve to exactly one port or pin" in problem
        for finding in invalid
        for problem in finding.evidence.get("problems", [])
    )
    assert result.modes[0].clocks["divided"].period is None


@pytest.mark.parametrize(
    "query",
    [
        r"[get_cells {foo\/bar}]",
        r"[get_nets {foo\/bar}]",
        r"[get_pins {foo\/bar}]",
        r"[get_ports {foo\/bar}]",
        r"[get_registers {foo\/bar}]",
    ],
)
def test_escaped_hierarchy_divider_fails_closed_in_flattened_model(design_factory, query: str) -> None:
    design = design_factory()
    resolved = resolve_selector(_selector(query), design, {})

    assert resolved.matches == set()
    assert resolved.error is not None
    assert "escaped hierarchy dividers" in resolved.error


def test_bus_range_shape_fails_closed_but_exact_bus_bit_remains_supported(design_factory) -> None:
    design = design_factory(verilog="module top(input [3:0] data, output result); endmodule")

    bus_range = resolve_selector(_selector("[get_ports {data[0:3]}]"), design, {})
    exact_bit = resolve_selector(_selector("[get_ports {data[0]}]"), design, {})

    assert bus_range.matches == set()
    assert bus_range.error is not None
    assert "bus-range-shaped" in bus_range.error
    assert exact_bit.error is None
    assert exact_bit.matches == {"data[0]"}


@pytest.mark.parametrize("query", [r"[get_pins {u_ff\/D}]", r"[get_ports {foo\/bar}]", r"[get_registers {foo\/bar}]"])
def test_ambiguous_escaped_divider_emits_oc1004(audit_factory, query: str) -> None:
    escaped = audit_factory(f"set_false_path -to {query}")

    assert any(finding.rule_id == "OC1004" for finding in escaped.diagnostics)


def test_bus_range_emits_oc1004(audit_factory) -> None:
    bus_range = audit_factory(
        "set_false_path -to [get_ports {data[0:3]}]",
        verilog="module top(input [3:0] data, output result); endmodule",
    )

    assert any(finding.rule_id == "OC1004" for finding in bus_range.diagnostics)


def test_unsupported_python_regexp_is_reported_as_oc1004(audit_factory) -> None:
    result = audit_factory("set_false_path -to [get_ports -regexp {(?P<x>data)}]")

    unsupported = [finding for finding in result.diagnostics if finding.rule_id == "OC1004"]
    assert len(unsupported) == 1
    assert "modeled Tcl ARE subset" in unsupported[0].evidence["reason"]


@pytest.mark.parametrize("clock_reference", ["[get_clocks {core core}]", "{core core}"])
def test_io_delay_clock_reference_rejects_duplicate_collection_occurrences(audit_factory, clock_reference: str) -> None:
    result = audit_factory(
        f"""
create_clock -name core -period 10 [get_ports clk]
set_input_delay 1 -clock {clock_reference} [get_ports data]
"""
    )

    invalid = [
        finding for finding in result.diagnostics if finding.rule_id == "OC3011" and "invalid -clock" in finding.message
    ]
    assert len(invalid) == 1
    assert result.modes[0].io_delays[0].valid is False


@pytest.mark.parametrize("source", ["[get_ports {clk clk}]", "{clk clk}"])
def test_generated_clock_source_rejects_duplicate_collection_occurrences(audit_factory, source: str) -> None:
    result = audit_factory(
        f"""
create_clock -name core -period 10 [get_ports clk]
create_generated_clock -name divided -source {source} -divide_by 2 [get_pins u_ff/Q]
"""
    )

    invalid = [finding for finding in result.diagnostics if finding.rule_id == "OC2012"]
    assert any(
        "-source must resolve to exactly one port or pin" in problem
        for finding in invalid
        for problem in finding.evidence.get("problems", [])
    )
    assert result.modes[0].clocks["divided"].period is None


@pytest.mark.parametrize("master", ["[get_clocks {core core}]", "{core core}"])
def test_generated_clock_master_rejects_duplicate_collection_occurrences(audit_factory, master: str) -> None:
    result = audit_factory(
        f"""
create_clock -name core -period 10 [get_ports clk]
create_generated_clock -name divided -master_clock {master} -source [get_ports clk] \
  -divide_by 2 [get_pins u_ff/Q]
"""
    )

    invalid = [
        finding
        for finding in result.diagnostics
        if finding.rule_id == "OC2012" and "invalid -master_clock collection" in finding.message
    ]
    assert len(invalid) == 1
    assert result.modes[0].clocks["divided"].master_clock is None
    assert result.modes[0].clocks["divided"].period is None


@pytest.mark.parametrize("reference", ["[get_pins {u_ff/Q u_ff/Q}]", "{u_ff/Q u_ff/Q}"])
def test_reference_pin_rejects_duplicate_collection_occurrences(audit_factory, reference: str) -> None:
    result = audit_factory(f"set_input_delay 1 -reference_pin {reference} [get_ports data]")

    invalid = [
        finding
        for finding in result.diagnostics
        if finding.rule_id == "OC3011" and "non-singleton -reference_pin" in finding.message
    ]
    assert len(invalid) == 1
    assert result.modes[0].io_delays[0].reference_pin is None
    assert result.modes[0].io_delays[0].valid is False
