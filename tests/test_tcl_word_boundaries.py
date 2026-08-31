from __future__ import annotations

import pytest

import openconstraint.parsers.sdc as sdc_parser
from openconstraint.parsers.sdc import parse_sdc_text
from openconstraint.parsers.tcl import parse_tcl


@pytest.mark.parametrize(
    ("query", "expected_words", "expected_patterns"),
    [
        ('[get_ports a" b"c]', ("get_ports", 'a"', 'b"c'), ('a"', 'b"c')),
        ("[get_ports a{ b}c]", ("get_ports", "a{", "b}c"), ("a{", "b}c")),
    ],
)
def test_noninitial_quotes_and_braces_do_not_group_tcl_words(
    audit_factory,
    query: str,
    expected_words: tuple[str, ...],
    expected_patterns: tuple[str, ...],
) -> None:
    inner_commands, inner_issues = parse_tcl(query[1:-1], "inner.sdc")
    selector = parse_sdc_text(f"set_false_path -to {query}\n").commands[0].selectors[0]

    assert not inner_issues
    assert inner_commands[0].words == expected_words
    assert selector.patterns == expected_patterns
    assert selector.parse_error is not None
    assert "got 2" in selector.parse_error

    result = audit_factory(f"set_false_path -to {query}\n")
    assert any(finding.rule_id == "OC1004" and finding.evidence.get("query") == query for finding in result.diagnostics)


def test_selector_body_accepts_one_command_with_a_trailing_separator() -> None:
    selector = parse_sdc_text("set_false_path -to [get_ports *;]\n").commands[0].selectors[0]

    assert selector.patterns == ("*",)
    assert selector.parse_error is None
    assert selector.dynamic is False


@pytest.mark.parametrize(("backslash_count", "has_parse_error"), [(1, False), (2, True)])
def test_comment_continuation_inside_selector_body_uses_backslash_parity(
    backslash_count: int, has_parse_error: bool
) -> None:
    query = "[get_ports *; # continued comment " + "\\" * backslash_count + "\nget_ports data\n]"
    selector = parse_sdc_text(f"set_false_path -to {query}\n").commands[0].selectors[0]

    assert (selector.parse_error is not None) is has_parse_error
    if not has_parse_error:
        assert selector.patterns == ("*",)


def test_selector_body_with_multiple_commands_fails_closed(audit_factory) -> None:
    query = "[get_ports *; get_ports data]"
    selector = parse_sdc_text(f"set_false_path -to {query}\n").commands[0].selectors[0]

    assert selector.patterns == ()
    assert selector.parse_error is not None
    assert "exactly one Tcl command; got 2" in selector.parse_error

    result = audit_factory(f"set_false_path -to {query}\n")
    assert any(finding.rule_id == "OC1004" and finding.evidence.get("query") == query for finding in result.diagnostics)


def test_tcl_argument_expansion_in_selector_fails_closed(audit_factory) -> None:
    query = "[get_ports {*}$patterns]"
    selector = parse_sdc_text(f"set_false_path -to {query}\n").commands[0].selectors[0]

    assert selector.patterns == ()
    assert selector.parse_error is not None
    result = audit_factory(f"set_false_path -to {query}\n")
    assert any(finding.rule_id == "OC1004" and finding.evidence.get("query") == query for finding in result.diagnostics)


@pytest.mark.parametrize("word", [r'"$name\uD800"', r'"[list ok]\U00110000"'])
def test_opaque_substitution_scan_does_not_hide_later_invalid_unicode(word: str) -> None:
    command = parse_sdc_text(f"custom_command {word}\n").commands[0]

    assert command.opaque_substitutions == []
    assert len(command.parse_errors) == 1
    assert "invalid Tcl Unicode escape" in command.parse_errors[0]


@pytest.mark.parametrize(
    "sdc",
    [
        "create_clock -name ${foo -period 10 [get_ports clk]",
        "${command -to [get_ports data]",
        "set_false_path -to [get_ports ${port]",
    ],
)
def test_unterminated_tcl_variable_name_fails_closed(audit_factory, sdc: str) -> None:
    result = audit_factory(sdc)

    malformed = [finding for finding in result.diagnostics if finding.rule_id == "OC0001"]
    assert malformed
    assert any(
        "missing close-brace for Tcl variable name" in problem
        for finding in malformed
        for problem in finding.evidence.get("problems", [])
    )
    assert result.modes[0].coverage.score == 0.0
    assert result.modes[0].coverage.grade == "F"
    assert not result.modes[0].clocks


def test_selector_body_memo_is_command_local_without_process_global_retention(monkeypatch) -> None:
    body = "get_ports cache_probe_74839"
    parsed_bodies: list[str] = []
    original = sdc_parser._parse_selector_body

    def counted_parse(selector_body: str):
        parsed_bodies.append(selector_body)
        return original(selector_body)

    monkeypatch.setattr(sdc_parser, "_parse_selector_body", counted_parse)
    parse_sdc_text(f"set_false_path -to [{body}]\n")
    assert parsed_bodies == [body]

    parse_sdc_text(f"set_false_path -to [{body}]\n")
    assert parsed_bodies == [body, body]


def test_nested_selector_suffix_work_fails_closed_before_recursive_amplification(monkeypatch) -> None:
    payload = "x" * 2_048
    query = f"[get_cells {{{payload}}}]"
    for command_name in ("get_nets", "get_pins", "get_cells", "get_nets", "get_ports"):
        query = f"[{command_name} -of_objects {query}]"
    # The root is accepted, but reparsing its nearly identical child suffix
    # would exceed this document-wide budget.
    monkeypatch.setattr(sdc_parser, "MAX_SELECTOR_PARSE_WORK", len(query) + 8)
    parsed_body_lengths: list[int] = []
    original = sdc_parser._parse_selector_body

    def counted_parse(selector_body: str):
        parsed_body_lengths.append(len(selector_body))
        return original(selector_body)

    monkeypatch.setattr(sdc_parser, "_parse_selector_body", counted_parse)

    selector = parse_sdc_text(f"set_false_path -to {query}\n").commands[0].selectors[0]
    nested = selector.of_objects

    assert nested is not None
    assert nested.parse_error is not None
    assert "selector parsing exceeds the aggregate static work limit" in nested.parse_error
    assert len(nested.raw) <= sdc_parser._MAX_SELECTOR_ERROR_RAW_CHARACTERS
    assert selector.of_objects_raw == nested.raw
    assert parsed_body_lengths == [len(query) - 2]


def test_root_selector_parse_limit_uses_its_bounded_semantic_join_key(monkeypatch, audit_factory) -> None:
    query = f"[get_ports {{{'x' * 2_048}}}]"
    monkeypatch.setattr(sdc_parser, "MAX_SELECTOR_PARSE_WORK", 64)

    command = parse_sdc_text(f"set_false_path -to {query}\n").commands[0]
    selector = command.selectors[0]
    result = audit_factory(f"set_false_path -to {query}")

    assert selector.command_name == "<selector>"
    assert len(selector.raw) <= sdc_parser._MAX_SELECTOR_ERROR_RAW_CHARACTERS
    assert command.option("-to") == selector.raw
    assert any(finding.rule_id == "OC1004" for finding in result.diagnostics)
    assert result.modes[0].exceptions[0].to_objects == set()
    assert result.modes[0].exceptions[0].qualifiers["scope_resolvable"] is False
