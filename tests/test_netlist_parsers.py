from __future__ import annotations

import pytest

from openconstraint.parsers.liberty import CellLibrary, parse_liberty_text
from openconstraint.parsers.verilog import elaborate, parse_verilog_text

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


def test_liberty_without_cells_is_nonfatal_but_records_warning() -> None:
    library = parse_liberty_text('library(empty) { time_unit : "1ns"; }')

    assert not library.cells
    assert "no cell groups were found in the Liberty input" in library.warnings


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


def test_missing_or_unterminated_modules_produce_actionable_parser_warnings() -> None:
    empty = parse_verilog_text("nonsense without any HDL construct")
    unterminated = parse_verilog_text("module top(input a);")

    assert empty.warnings == ["no modules were found in the Verilog input"]
    assert any("has no endmodule" in warning for warning in unterminated.warnings)
