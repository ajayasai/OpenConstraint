from __future__ import annotations

import pytest

from openconstraint.parsers import liberty as liberty_parser
from openconstraint.parsers import verilog as verilog_parser
from openconstraint.parsers.liberty import (
    LIBERTY_TRUNCATION_WARNING,
    MAX_GROUP_DEPTH,
    MAX_LIBERTY_NODES,
    MAX_LIBERTY_TOKENS,
    MAX_LIBERTY_WARNINGS,
    CellLibrary,
    parse_liberty_text,
)
from openconstraint.parsers.verilog import (
    MAX_EXPANDED_BUS_WIDTH,
    MAX_HIERARCHY_DEPTH,
    VERILOG_TRUNCATION_WARNING,
    elaborate,
    parse_verilog_text,
)

from .conftest import SYNTHETIC_LIBERTY


def test_liberty_extracts_combinational_flipflop_and_latch_metadata() -> None:
    library = parse_liberty_text(SYNTHETIC_LIBERTY)

    assert not library.warnings
    assert set(library.cells) == {"BUF", "INV", "DFF", "DFFR", "DLAT"}
    assert library.cells["BUF"].pin_directions == {"A": "input", "Y": "output"}
    assert library.cells["DFF"].sequential
    assert library.cells["DFF"].clock_pins == {"CK"}
    assert library.cells["DFF"].data_pins == {"D"}
    assert library.cells["DLAT"].sequential
    assert library.cells["DLAT"].clock_pins == {"G"}
    assert library.cells["DLAT"].data_pins == {"D"}


def test_liberty_ignores_comments_handles_quoted_names_and_bus_groups() -> None:
    library = parse_liberty_text(
        r"""
// line comment
library (x) {
  /* block comment */
  cell ("BUSCELL") {
    bus ("DATA") { direction : input; }
    pin ("Y") { direction : output; }
  }
}
"""
    )

    assert set(library.cells) == {"BUSCELL"}
    assert library.cells["BUSCELL"].pin_directions == {"DATA": "input", "Y": "output"}


def test_liberty_comment_scanner_preserves_comment_markers_inside_quoted_strings() -> None:
    library = parse_liberty_text(
        r"""
library (quoted_comments) {
  // This real comment is removed.
  cell ("CELL//retained") {
    /* This block comment is removed. */
    pin ("A/*retained*/") { direction : input; }
    pin ("Y//retained") { direction : output; }
  }
}
"""
    )

    assert set(library.cells) == {"CELL//retained"}
    assert library.cells["CELL//retained"].pin_directions == {
        "A/*retained*/": "input",
        "Y//retained": "output",
    }


def test_unterminated_comment_sequences_are_consumed_in_one_pass() -> None:
    verilog = parse_verilog_text("module top(); endmodule\n" + "/*a" * 12_000)
    liberty = parse_liberty_text("library(empty) {}\n" + "/*a;" * 12_000)

    assert set(verilog.modules) == {"top"}
    assert "no cell groups were found in the Liberty input" in liberty.warnings


def test_liberty_without_cells_is_nonfatal_but_records_warning() -> None:
    library = parse_liberty_text('library(empty) { time_unit : "1ns"; }')

    assert not library.cells
    assert "no cell groups were found in the Liberty input" in library.warnings


def test_liberty_bounds_pathological_group_nesting_without_recursion_failure() -> None:
    nesting = MAX_GROUP_DEPTH + 50
    source = "library (bounded) {" + " group (x) {" * nesting + "}" * (nesting + 1)

    library = parse_liberty_text(source)

    assert not library.cells
    assert any("nested beyond the parser limit" in warning for warning in library.warnings)


def test_liberty_caps_tokens_with_one_deterministic_truncation_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(liberty_parser, "MAX_LIBERTY_TOKENS", 12)

    library = parse_liberty_text("library(x) { cell(A) {} cell(B) {} cell(C) {} }")

    assert len(liberty_parser._tokens("a;" * 20)) == 12
    assert library.warnings.count(LIBERTY_TRUNCATION_WARNING) == 1


def test_liberty_caps_nodes_and_detailed_warnings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(liberty_parser, "MAX_LIBERTY_NODES", 3)
    node_limited = parse_liberty_text("a; b; c; d; e;")

    monkeypatch.setattr(liberty_parser, "MAX_LIBERTY_WARNINGS", 2)
    warning_limited = parse_liberty_text(";;;;;;")

    assert node_limited.warnings.count(LIBERTY_TRUNCATION_WARNING) == 1
    assert warning_limited.warnings[:2] == ["ignored unexpected token ';'"] * 2
    assert warning_limited.warnings.count(LIBERTY_TRUNCATION_WARNING) == 1
    assert len(warning_limited.warnings) == 4  # Two retained details, truncation, and the ordinary no-cell warning.


def test_liberty_default_cardinality_limits_cover_the_public_sky130_scale() -> None:
    assert MAX_LIBERTY_TOKENS >= 750_000
    assert MAX_LIBERTY_NODES >= 120_000
    assert MAX_LIBERTY_WARNINGS >= 1_000


def test_liberty_merge_is_deterministic_and_later_library_wins() -> None:
    first = parse_liberty_text("library(a) { cell(X) { pin(A) { direction : input; } } }")
    second = parse_liberty_text("library(b) { cell(X) { pin(Z) { direction : output; } } }")
    merged = CellLibrary()

    merged.merge(first)
    merged.merge(second)

    assert merged.cells["X"].pin_directions == {"Z": "output"}
    assert merged.warnings == first.warnings + second.warnings


def test_verilog_expands_ascending_and_descending_ansi_bus_ports() -> None:
    parsed = parse_verilog_text(
        """
module buses(input [3:1] down, output [0:2] up, inout scalar);
endmodule
"""
    )
    module = parsed.modules["buses"]

    assert [(port.name, port.direction) for port in module.ports] == [
        ("down[3]", "input"),
        ("down[2]", "input"),
        ("down[1]", "input"),
        ("up[0]", "output"),
        ("up[1]", "output"),
        ("up[2]", "output"),
        ("scalar", "inout"),
    ]


def test_verilog_applies_ansi_bus_range_to_comma_separated_names() -> None:
    parsed = parse_verilog_text("module buses(input [1:0] first, second, output scalar); endmodule")

    assert [(port.name, port.direction) for port in parsed.modules["buses"].ports] == [
        ("first[1]", "input"),
        ("first[0]", "input"),
        ("second[1]", "input"),
        ("second[0]", "input"),
        ("scalar", "output"),
    ]


def test_verilog_non_ansi_declarations_update_header_directions() -> None:
    parsed = parse_verilog_text(
        """
module legacy(clk, d, q);
  input clk, d;
  output q;
endmodule
"""
    )

    assert [(port.name, port.direction) for port in parsed.modules["legacy"].ports] == [
        ("clk", "input"),
        ("d", "input"),
        ("q", "output"),
    ]


def test_verilog_bounds_pathological_bus_expansion() -> None:
    parsed = parse_verilog_text(
        f"module bounded(input [{MAX_EXPANDED_BUS_WIDTH}:0] oversized, input scalar); endmodule"
    )

    assert [(port.name, port.direction) for port in parsed.modules["bounded"].ports] == [("scalar", "input")]
    assert any("the parser limit is" in warning for warning in parsed.warnings)


def test_verilog_bounds_indexes_beyond_integer_conversion_limits() -> None:
    huge_index = "9" * 5_000

    parsed = parse_verilog_text(f"module top(input [{huge_index}:0] data); endmodule")

    assert parsed.modules["top"].ports == []
    assert any("index wider than 64 decimal digits" in warning for warning in parsed.warnings)


def test_verilog_bounds_bus_width_times_declared_names() -> None:
    parsed = parse_verilog_text(f"module top(); wire [{MAX_EXPANDED_BUS_WIDTH - 1}:0] first, second; endmodule")

    assert parsed.modules["top"].nets == set()
    assert any("per-declaration limit" in warning for warning in parsed.warnings)


def test_verilog_bounds_total_expansion_across_declarations(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(verilog_parser, "MAX_EXPANDED_NAMES_PER_PARSE", 8)

    parsed = parse_verilog_text("module top(); wire [3:0] first; wire [3:0] second; wire [3:0] third; endmodule")

    assert {f"first[{index}]" for index in range(4)} <= parsed.modules["top"].nets
    assert {f"second[{index}]" for index in range(4)} <= parsed.modules["top"].nets
    assert not any(name.startswith("third[") for name in parsed.modules["top"].nets)
    assert any("parser-wide name expansion limit of 8" in warning for warning in parsed.warnings)


def test_verilog_bounds_duplicate_module_occurrences(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(verilog_parser, "MAX_VERILOG_MODULES", 3)

    parsed = parse_verilog_text("\n".join("module repeated(); endmodule" for _ in range(5)))

    assert set(parsed.modules) == {"repeated"}
    assert any("parser limit of 3" in warning for warning in parsed.warnings)


def test_verilog_bounds_port_entries_and_instance_connections(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(verilog_parser, "MAX_EXPANDED_NAMES_PER_DECLARATION", 3)
    monkeypatch.setattr(verilog_parser, "MAX_INSTANCE_CONNECTIONS", 2)

    parsed = parse_verilog_text("module top(input a, b, c, d); CELL leaf(.A(a), .B(b), .C(c)); endmodule")

    assert [port.name for port in parsed.modules["top"].ports] == ["a", "b", "c"]
    assert parsed.modules["top"].instances[0].named_connections == {"A": "a", "B": "b"}
    assert any("remaining port declarations" in warning for warning in parsed.warnings)
    assert any("remaining instance connections" in warning for warning in parsed.warnings)


def test_verilog_bounds_statements_and_detailed_warnings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(verilog_parser, "MAX_VERILOG_STATEMENTS_PER_PARSE", 4)
    monkeypatch.setattr(verilog_parser, "MAX_VERILOG_WARNINGS", 2)

    parsed = parse_verilog_text("module top(); a; b; c; d; e; f; endmodule")

    assert len(parsed.warnings) == 3
    assert any("parser-wide limit of 4" in warning for warning in parsed.warnings)
    assert parsed.warnings[-1] == VERILOG_TRUNCATION_WARNING


def test_hierarchical_elaboration_flattens_named_connections_and_preserves_top_nets() -> None:
    parsed = parse_verilog_text(
        """
module leaf(input clk, input d, output q);
  DFF state (.CK(clk), .D(d), .Q(q));
endmodule
module top(input clk, input data, output result);
  leaf block (.clk(clk), .d(data), .q(result));
endmodule
"""
    )
    design = elaborate(parsed, parse_liberty_text(SYNTHETIC_LIBERTY), "top")

    assert set(design.instances) == {"block/state"}
    assert design.instances["block/state"].sequential
    assert design.pins["block/state/CK"].net == "clk"
    assert design.pins["block/state/D"].net == "data"
    assert design.pins["block/state/Q"].net == "result"
    assert design.sequential_clock_pins == {"block/state/CK"}
    assert design.sequential_endpoints == {"block/state/D"}


def test_hierarchical_elaboration_supports_positional_module_and_cell_connections() -> None:
    parsed = parse_verilog_text(
        """
module leaf(input clk, input d, output q);
  DFF state (clk, d, q);
endmodule
module top(input clk, input data, output result);
  leaf block (clk, data, result);
endmodule
"""
    )
    design = elaborate(parsed, parse_liberty_text(SYNTHETIC_LIBERTY), "top")

    assert design.pins["block/state/CK"].net == "clk"
    assert design.pins["block/state/D"].net == "data"
    assert design.pins["block/state/Q"].net == "result"


def test_many_named_hierarchical_connections_use_indexed_port_lookup() -> None:
    port_count = 2_500
    leaf_ports = ", ".join(f"p{index}" for index in range(port_count))
    top_ports = ", ".join(f"n{index}" for index in range(port_count))
    connections = ", ".join(f".p{index}(n{index})" for index in range(port_count))
    source = (
        f"module leaf(input {leaf_ports}); BUF sink(.A(p{port_count - 1}), .Y()); endmodule "
        f"module top(input {top_ports}); leaf child({connections}); endmodule"
    )

    design = elaborate(parse_verilog_text(source), parse_liberty_text(SYNTHETIC_LIBERTY), "top")

    assert design.pins["child/sink/A"].net == f"n{port_count - 1}"


def test_long_scalar_alias_chains_are_resolved_without_repeated_net_rewrites() -> None:
    alias_count = 2_000
    declarations = ", ".join(f"n{index}" for index in range(alias_count))
    assignments = ["assign n0 = source;"]
    assignments.extend(f"assign n{index} = n{index - 1};" for index in range(1, alias_count))
    assignments.append(f"assign result = n{alias_count - 1};")
    source = (
        f"module top(input source, output result); wire {declarations}; "
        + " ".join(assignments)
        + f" BUF leaf(.A(n{alias_count - 1}), .Y(result)); endmodule"
    )

    design = elaborate(parse_verilog_text(source), parse_liberty_text(SYNTHETIC_LIBERTY), "top")

    assert design.pins["leaf/A"].net == "result"
    assert design.ports["source"].net == "result"


def test_elaboration_uses_safe_cell_inference_when_liberty_cell_is_absent() -> None:
    parsed = parse_verilog_text(
        """
module top(input clk, input data, output result);
  MYSTERY_DFF state (.CLK(clk), .D(data), .Q(result));
endmodule
"""
    )
    design = elaborate(parsed, CellLibrary(), "top")

    assert design.instances["state"].sequential
    assert design.sequential_clock_pins == {"state/CLK"}
    assert design.sequential_endpoints == {"state/D"}
    assert design.pins["state/Q"].direction == "output"


def test_constants_do_not_create_fake_nets_or_drivers() -> None:
    parsed = parse_verilog_text(
        """
module top(input clk, output result);
  DFF state (.CK(clk), .D(1'b0), .Q(result));
endmodule
"""
    )
    design = elaborate(parsed, parse_liberty_text(SYNTHETIC_LIBERTY), "top")

    assert design.pins["state/D"].net is None
    assert "1'b0" not in design.nets


def test_top_inference_and_explicit_missing_top_errors() -> None:
    parsed = parse_verilog_text(
        """
module leaf(input a); endmodule
module top(input a); leaf child(.a(a)); endmodule
"""
    )

    assert elaborate(parsed, CellLibrary()).top == "top"
    with pytest.raises(ValueError, match="top module 'missing' was not found"):
        elaborate(parsed, CellLibrary(), "missing")


def test_recursive_hierarchy_is_stopped_with_a_warning() -> None:
    parsed = parse_verilog_text(
        """
module recursive(input a);
  recursive again(.a(a));
endmodule
"""
    )
    design = elaborate(parsed, CellLibrary(), "recursive")

    assert any("recursive module instantiation stopped" in warning for warning in design.warnings)


def test_deep_acyclic_hierarchy_is_bounded_without_recursion_failure() -> None:
    modules = []
    for index in range(MAX_HIERARCHY_DEPTH + 20):
        child = f"m{index + 1} child(.a(a));" if index < MAX_HIERARCHY_DEPTH + 19 else "BUF leaf(.A(a), .Y());"
        modules.append(f"module m{index}(input a); {child} endmodule")

    design = elaborate(parse_verilog_text("\n".join(modules)), CellLibrary(), "m0")

    assert any("hierarchical elaboration stopped" in warning for warning in design.warnings)


def test_branching_hierarchy_is_bounded_by_total_objects(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(verilog_parser, "MAX_ELABORATION_OBJECTS", 40)
    modules = [
        f"module m{index}(input a); m{index + 1} left(.a(a)); m{index + 1} right(.a(a)); endmodule"
        for index in range(9)
    ]
    modules.append("module m9(input a); BUF leaf(.A(a), .Y()); endmodule")

    design = elaborate(parse_verilog_text("\n".join(modules)), CellLibrary(), "m0")

    assert len(design.instances) <= 40
    assert any("parser-wide object limit is 40" in warning for warning in design.warnings)


def test_missing_or_unterminated_modules_produce_actionable_parser_warnings() -> None:
    empty = parse_verilog_text("nonsense without any HDL construct")
    unterminated = parse_verilog_text("module top(input a);")

    assert empty.warnings == ["no modules were found in the Verilog input"]
    assert any("has no endmodule" in warning for warning in unterminated.warnings)
