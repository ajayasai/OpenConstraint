from __future__ import annotations

import pytest

from openconstraint.parsers.sdc import parse_sdc_text
from openconstraint.query import resolve_selector


def _selector(query: str):
    return parse_sdc_text(f"set_false_path -to {query}\n").commands[0].selectors[0]


@pytest.mark.parametrize(
    ("property_name", "direction", "expected"),
    [
        ("direction", "input", {"a"}),
        ("direction", "output", {"y"}),
        ("direction", "bidirect", {"io"}),
        ("port_direction", "bidirect", {"io"}),
    ],
)
def test_port_direction_filter_uses_opensta_vocabulary(
    design_factory, property_name: str, direction: str, expected: set[str]
) -> None:
    design = design_factory(verilog="module top(input a, output y, inout io); endmodule")
    selector = _selector(f"[get_ports -filter {{{property_name} == {direction}}} *]")
    resolved = resolve_selector(selector, design, {})

    assert resolved.error is None
    assert resolved.matches == expected


def test_pin_direction_alias_is_limited_to_pin_queries(design_factory) -> None:
    design = design_factory()
    selector = _selector("[get_pins -filter {pin_direction == input} *]")
    resolved = resolve_selector(selector, design, {})

    assert resolved.error is None
    assert resolved.matches == {"u_ff/CK", "u_ff/D", "u_out/A"}


@pytest.mark.parametrize(
    "query",
    [
        "[get_ports -filter {DIRECTION == input} *]",
        "[get_ports -filter {direction == INPUT} *]",
        '[get_ports -filter {direction == "input"} *]',
        "[get_ports -filter {direction == 'input'} *]",
        "[get_ports -filter {direction == inout} *]",
        "[get_ports -filter {pin_direction == input} *]",
        "[get_pins -filter {port_direction == input} *]",
    ],
)
def test_direction_filter_rejects_non_opensta_spelling(audit_factory, query: str) -> None:
    result = audit_factory(f"set_false_path -to {query}")
    findings = [item for item in result.diagnostics if item.rule_id == "OC1004"]

    assert len(findings) == 1
    assert findings[0].evidence["query"] == query
    assert not any(item.rule_id in {"OC1001", "OC1002"} for item in result.diagnostics)


@pytest.mark.parametrize(
    "query",
    [
        "[get_cells -filter {direction == unknown} *]",
        "[get_nets -filter {direction == unknown} *]",
        "[get_clocks -filter {direction == unknown} *]",
        "[get_registers -filter {direction == unknown} *]",
    ],
)
def test_direction_filter_fails_closed_for_non_port_pin_queries(audit_factory, query: str) -> None:
    result = audit_factory(f"set_false_path -to {query}")
    findings = [item for item in result.diagnostics if item.rule_id == "OC1004"]

    assert len(findings) == 1
    assert findings[0].evidence["query"] == query
    assert "is not valid" in findings[0].evidence["reason"]
    assert not any(item.rule_id in {"OC1001", "OC1002"} for item in result.diagnostics)


@pytest.mark.parametrize("property_name", ["is_sequential", "is_sequential_cell"])
def test_get_registers_supports_exact_lowercase_sequential_filter(design_factory, property_name: str) -> None:
    design = design_factory()
    selector = _selector(f"[get_registers -filter {{{property_name} == true}} *]")
    resolved = resolve_selector(selector, design, {})

    assert resolved.error is None
    assert resolved.matches == {"u_ff"}


def test_get_cells_rejects_sequential_filter_extension(audit_factory) -> None:
    query = "[get_cells -filter {is_sequential == true} *]"
    result = audit_factory(f"set_false_path -to {query}")
    findings = [item for item in result.diagnostics if item.rule_id == "OC1004"]

    assert len(findings) == 1
    assert findings[0].evidence["query"] == query
    assert findings[0].evidence["reason"] == "sequential property is_sequential is only valid for get_registers queries"
    assert not any(item.rule_id in {"OC1001", "OC1002"} for item in result.diagnostics)


@pytest.mark.parametrize(
    "expression",
    [
        "IS_SEQUENTIAL == true",
        "is_sequential == TRUE",
        "IS_SEQUENTIAL_CELL == true",
        "is_sequential_cell == FALSE",
    ],
)
def test_get_registers_sequential_filter_is_case_sensitive(audit_factory, expression: str) -> None:
    query = f"[get_registers -filter {{{expression}}} *]"
    result = audit_factory(f"set_false_path -to {query}")
    findings = [item for item in result.diagnostics if item.rule_id == "OC1004"]

    assert len(findings) == 1
    assert findings[0].evidence["query"] == query
    assert "unsupported static filter expression" in findings[0].evidence["reason"]
    assert not any(item.rule_id in {"OC1001", "OC1002"} for item in result.diagnostics)
