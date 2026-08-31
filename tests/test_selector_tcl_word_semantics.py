from __future__ import annotations

import json

import pytest

from openconstraint.engine import AuditOptions
from openconstraint.parsers.sdc import parse_sdc_text
from openconstraint.query import resolve_selector


@pytest.mark.parametrize("escaped_wildcard", [r"\*", r"\x2a", r"\u002a", r"\052"])
def test_bare_tcl_backslash_substitution_can_produce_effective_wildcard(design_factory, escaped_wildcard: str) -> None:
    design = design_factory()
    selector = parse_sdc_text(f"set_false_path -to [get_ports {escaped_wildcard}]\n").commands[0].selectors[0]

    assert selector.patterns == ("*",)
    assert selector.parse_error is None
    assert selector.dynamic is False
    assert resolve_selector(selector, design, {}).matches == set(design.ports)


@pytest.mark.parametrize("escaped_option", [r"\-quiet", r"\x2dquiet", r"-\u0071"])
def test_bare_tcl_backslash_substitution_can_produce_effective_option(design_factory, escaped_option: str) -> None:
    design = design_factory()
    selector = parse_sdc_text(f"set_false_path -to [get_ports {escaped_option}]\n").commands[0].selectors[0]

    assert selector.patterns == ("*",)
    assert selector.parse_error is None
    assert resolve_selector(selector, design, {}).matches == set(design.ports)


def test_backslash_produced_wildcard_is_reported_as_broad_not_zero(audit_factory) -> None:
    result = audit_factory(
        r"set_false_path -to [get_ports \x2a]",
        options=AuditOptions(broad_match_count=1, broad_match_ratio=0.01, broad_match_min_universe=1),
    )
    ids = [finding.rule_id for finding in result.diagnostics]

    assert "OC1002" in ids
    assert "OC1001" not in ids


def test_escaped_trailing_space_preserves_effective_tcl_pattern_list(audit_factory) -> None:
    query = "[get_ports *\\ ]"
    selector = parse_sdc_text(f"set_false_path -to {query}\n").commands[0].selectors[0]

    assert selector.patterns == ("*",)
    result = audit_factory(
        f"set_false_path -to {query}\n",
        options=AuditOptions(broad_match_count=1, broad_match_ratio=0.01, broad_match_min_universe=1),
    )
    ids = [finding.rule_id for finding in result.diagnostics]
    assert "OC1002" in ids
    assert "OC1001" not in ids


@pytest.mark.parametrize(
    ("query", "expected_patterns"),
    [
        ("[get_ports {{*}}]", ("*",)),
        ("[get_ports {{*} data}]", ("*", "data")),
        ("[get_ports {{ data }}]", (" data ",)),
    ],
)
def test_nested_tcl_list_grouping_is_decoded_per_pattern(query: str, expected_patterns: tuple[str, ...]) -> None:
    selector = parse_sdc_text(f"set_false_path -to {query}\n").commands[0].selectors[0]

    assert selector.patterns == expected_patterns
    assert selector.parse_error is None
    assert selector.dynamic is False


def test_nested_tcl_list_wildcard_resolves_as_broad_collection(design_factory) -> None:
    design = design_factory()
    selector = parse_sdc_text("set_false_path -to [get_ports {{*}}]\n").commands[0].selectors[0]

    assert resolve_selector(selector, design, {}).matches == set(design.ports)


@pytest.mark.parametrize("separator", ["\u0085", "\u00a0", "\u1680", "\u2000", "\u2028", "\u2029"])
def test_unicode_whitespace_is_literal_inside_tcl_pattern_lists(separator: str) -> None:
    selector = parse_sdc_text(f"set_false_path -to [get_ports {{a{separator}b}}]\n").commands[0].selectors[0]

    assert selector.patterns == (f"a{separator}b",)


def test_braced_command_word_suppresses_backslash_substitution() -> None:
    literal = parse_sdc_text(r"set_false_path -to [get_ports {\x2a}]" + "\n").commands[0].selectors[0]
    nested = parse_sdc_text(r"set_false_path -to [get_ports {{\x2a}}]" + "\n").commands[0].selectors[0]

    assert literal.patterns == (r"\x2a",)
    # OpenSTA doubles backslashes before iterating a nested braced Tcl-list
    # element, where Tcl itself suppresses the second-stage substitution.
    assert nested.patterns == (r"\\x2a",)
    assert literal.parse_error is nested.parse_error is None


def test_braced_variable_and_command_text_stays_static_literal() -> None:
    variable = parse_sdc_text(r"set_false_path -to [get_ports {$name}]" + "\n").commands[0].selectors[0]
    command = parse_sdc_text(r"set_false_path -to [get_ports {[list *]}]" + "\n").commands[0].selectors[0]

    assert variable.patterns == ("$name",)
    assert variable.dynamic is False
    assert command.patterns == ("[list", "*]")
    assert command.dynamic is False


@pytest.mark.parametrize("variable", ["$1", "${}"])
def test_all_valid_tcl_variable_forms_make_selector_dynamic(variable: str) -> None:
    selector = parse_sdc_text(f"set_false_path -to [get_ports {variable}]\n").commands[0].selectors[0]

    assert selector.dynamic is True


def test_unpaired_unicode_escape_fails_closed_without_entering_report_text(audit_factory) -> None:
    query = r"[get_ports \uD800]"
    result = audit_factory(f"set_false_path -to {query}\n")
    findings = [finding for finding in result.diagnostics if finding.evidence.get("query") == query]

    assert [finding.rule_id for finding in findings] == ["OC1004"]
    assert "U+0000D800" in findings[0].evidence["reason"]
    json.dumps(result.to_dict(), ensure_ascii=False).encode("utf-8")


def test_astral_eight_digit_unicode_escape_fails_closed_for_tcl_86_portability(audit_factory) -> None:
    query = r"[get_ports \U0001F600]"
    selector = parse_sdc_text(f"set_false_path -to {query}\n").commands[0].selectors[0]
    result = audit_factory(f"set_false_path -to {query}\n")

    assert selector.patterns == ()
    assert selector.parse_error is not None
    assert "U+0001F600" in selector.parse_error
    findings = [finding for finding in result.diagnostics if finding.evidence.get("query") == query]
    assert [finding.rule_id for finding in findings] == ["OC1004"]


def test_unpaired_unicode_escape_in_command_name_fails_closed_without_crashing(audit_factory) -> None:
    result = audit_factory(r"\uD800 anything")

    assert any(finding.rule_id == "OC0003" for finding in result.diagnostics)
    assert result.modes[0].coverage.score == 0.0
    json.dumps(result.to_dict(), ensure_ascii=False).encode("utf-8")


@pytest.mark.parametrize(
    ("alias", "canonical", "pattern"),
    [
        ("get_cell", "get_cells", "u_ff"),
        ("get_clock", "get_clocks", "core"),
        ("get_net", "get_nets", "clk"),
        ("get_pin", "get_pins", "u_ff/D"),
        ("get_port", "get_ports", "data"),
    ],
)
def test_pinned_opensta_singular_query_aliases_are_canonicalized(alias: str, canonical: str, pattern: str) -> None:
    selector = parse_sdc_text(f"set_false_path -to [{alias} {pattern}]\n").commands[0].selectors[0]

    assert selector.command_name == canonical
    assert selector.patterns == (pattern,)
    assert selector.parse_error is None


@pytest.mark.parametrize(
    ("query", "message"),
    [
        ('[get_ports "{unterminated"]', "unmatched open brace"),
        ("[get_ports {{*}suffix}]", "extra characters after close-brace"),
        ('[get_ports {"unterminated}]', "unmatched quote"),
    ],
)
def test_malformed_effective_tcl_pattern_list_fails_closed(audit_factory, query: str, message: str) -> None:
    selector = parse_sdc_text(f"set_false_path -to {query}\n").commands[0].selectors[0]

    assert selector.patterns == ()
    assert selector.parse_error is not None
    assert message in selector.parse_error

    result = audit_factory(f"set_false_path -to {query}\n")
    matching = [finding for finding in result.diagnostics if finding.evidence.get("query") == query]
    assert [finding.rule_id for finding in matching] == ["OC1004"]


def test_dynamic_nested_selector_is_retained_for_independent_audit(audit_factory) -> None:
    query = "[get_ports [get_ports missing]]"
    selector = parse_sdc_text(f"set_false_path -to {query}\n").commands[0].selectors[0]

    assert selector.dynamic is True
    assert selector.patterns == ("[get_ports missing]",)
    assert [nested.raw for nested in selector.nested_selectors] == ["[get_ports missing]"]

    result = audit_factory(f"set_false_path -to {query}\n")
    assert any(finding.rule_id == "OC1003" and finding.evidence["query"] == query for finding in result.diagnostics)
    assert any(
        finding.rule_id == "OC1001" and finding.evidence["query"] == "[get_ports missing]"
        for finding in result.diagnostics
    )


def test_pathological_command_substitution_nesting_fails_closed_without_recursion_error(audit_factory) -> None:
    query = "leaf"
    for _ in range(1_000):
        query = f"[get_ports {query}]"

    result = audit_factory(f"set_false_path -to {query}\n")

    assert any(
        finding.rule_id == "OC0001" and "command substitution nesting exceeds" in finding.message
        for finding in result.diagnostics
    )
    assert result.modes[0].coverage.score == 0.0
