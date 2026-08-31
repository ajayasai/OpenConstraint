from __future__ import annotations

import pytest

from openconstraint.parsers.sdc import _parse_selector_body, parse_sdc_text
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


def test_repeated_selector_bodies_reuse_the_bounded_parse_cache() -> None:
    body = "get_ports cache_probe_74839"
    before = _parse_selector_body.cache_info()

    parse_sdc_text(f"set_false_path -to [{body}]\n")
    parse_sdc_text(f"set_false_path -to [{body}]\n")

    after = _parse_selector_body.cache_info()
    assert after.maxsize == 4_096
    assert after.hits >= before.hits + 1
