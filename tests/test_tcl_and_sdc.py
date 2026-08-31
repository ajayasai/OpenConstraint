from __future__ import annotations

from openconstraint.engine import AuditOptions
from openconstraint.parsers import tcl as tcl_parser
from openconstraint.parsers.sdc import parse_sdc_text
from openconstraint.parsers.tcl import (
    MAX_TCL_COMMANDS,
    MAX_TCL_PARSE_ISSUES,
    bracket_body,
    parse_tcl,
    split_words,
    unquote,
)
from openconstraint.query import resolve_selector


def test_tcl_splits_newlines_and_semicolons_without_splitting_nested_groups() -> None:
    commands, issues = parse_tcl(
        "create_clock -period 10 [get_ports clk]; set x {alpha; beta\ngamma}\nset y [list one; two]\n",
        "constraints.sdc",
    )

    assert not issues
    assert [command.name for command in commands] == ["create_clock", "set", "set"]
    assert commands[0].location.line == 1
    assert commands[1].words[-1] == "{alpha; beta\ngamma}"
    assert commands[2].words[-1] == "[list one; two]"


def test_tcl_comments_are_ignored_only_outside_quotes_and_braces() -> None:
    commands, issues = parse_tcl(
        '# full-line comment\nset quoted "# retained"; # command-position comment\nset braced {# also retained}\n',
        "comments.sdc",
    )

    assert not issues
    assert [command.words for command in commands] == [
        ("set", "quoted", '"# retained"'),
        ("set", "braced", "{# also retained}"),
    ]
    assert [command.location.line for command in commands] == [2, 3]


def test_tcl_backslash_newline_continues_one_command_and_keeps_start_line() -> None:
    commands, issues = parse_tcl(
        "\ncreate_clock -name core \\\n  -period 10 \\\n  [get_ports clk]\n",
        "continued.sdc",
    )

    assert not issues
    assert len(commands) == 1
    assert commands[0].location.line == 2
    assert commands[0].words == (
        "create_clock",
        "-name",
        "core",
        "-period",
        "10",
        "[get_ports clk]",
    )


def test_tcl_reports_each_unbalanced_delimiter_without_throwing() -> None:
    _, brace_issues = parse_tcl("set x {unterminated\n", "brace.sdc")
    _, quote_issues = parse_tcl('set x "unterminated\n', "quote.sdc")
    _, bracket_issues = parse_tcl("set x [get_ports clk\n", "bracket.sdc")
    _, closing_issues = parse_tcl("set x value ]\n", "closing.sdc")

    assert [issue.message for issue in brace_issues] == ["unterminated brace group"]
    assert [issue.message for issue in quote_issues] == ["unterminated quoted word"]
    assert [issue.message for issue in bracket_issues] == ["unterminated command substitution"]
    assert [issue.message for issue in closing_issues] == ["unexpected closing bracket"]


def test_tcl_caps_retained_commands_but_scans_to_later_parse_issues() -> None:
    commands, issues = parse_tcl("a;" * (MAX_TCL_COMMANDS + 3) + "]\n", "many-commands.sdc")

    assert len(commands) == MAX_TCL_COMMANDS
    assert commands[0].words == commands[-1].words == ("a",)
    assert [issue.message for issue in issues] == [
        "unexpected closing bracket",
        "Tcl retention limit reached; additional commands or parse issues were omitted",
    ]
    assert issues[-1].location.line == 1


def test_tcl_caps_retained_parse_issues_and_adds_one_truncation_issue() -> None:
    commands, issues = parse_tcl("]\n" * (MAX_TCL_PARSE_ISSUES + 7), "many-issues.sdc")

    assert len(commands) == MAX_TCL_PARSE_ISSUES + 7
    assert len(issues) == MAX_TCL_PARSE_ISSUES + 1
    assert all(issue.message == "unexpected closing bracket" for issue in issues[:-1])
    assert issues[-1].message == "Tcl retention limit reached; additional commands or parse issues were omitted"
    assert issues[-1].location.line == MAX_TCL_PARSE_ISSUES + 1


def test_tcl_parses_each_retained_chunk_words_once(monkeypatch) -> None:
    original = tcl_parser.split_words
    calls: list[str] = []

    def counting_split_words(command: str) -> tuple[str, ...]:
        calls.append(command)
        return original(command)

    monkeypatch.setattr(tcl_parser, "split_words", counting_split_words)
    commands, issues = tcl_parser.parse_tcl("set a 1; set b 2\nset c 3\n", "once.sdc")

    assert not issues
    assert len(commands) == 3
    assert calls == [command.raw for command in commands]


def test_tcl_word_helpers_preserve_grouping_and_reject_partial_brackets() -> None:
    assert split_words('cmd {a b} "c d" [get_ports {x y}]') == (
        "cmd",
        "{a b}",
        '"c d"',
        "[get_ports {x y}]",
    )
    assert unquote("{a b}") == "a b"
    assert bracket_body("[get_ports clk]") == "get_ports clk"
    assert bracket_body("prefix[get_ports clk]") is None
    assert bracket_body("[get_ports clk]suffix") is None


def test_sdc_parser_extracts_repeated_options_and_nested_selectors() -> None:
    document = parse_sdc_text(
        "set_false_path -from [get_clocks a] -through [get_pins u0/A] -through [get_pins u1/Y] -to [get_clocks b]\n",
        "exception.sdc",
    )
    command = document.commands[0]

    assert command.name == "set_false_path"
    assert command.options["-through"] == ["[get_pins u0/A]", "[get_pins u1/Y]"]
    assert [(selector.kind, selector.patterns) for selector in command.selectors] == [
        ("clocks", ("a",)),
        ("pins", ("u0/A",)),
        ("pins", ("u1/Y",)),
        ("clocks", ("b",)),
    ]


def test_sdc_exact_bus_selectors_resolve_without_treating_brackets_as_wildcards(design_factory) -> None:
    design = design_factory(
        verilog="""
module top(input clk, input [3:0] data, output result);
  wire q;
  DFF u_ff (.CK(clk), .D(data[3]), .Q(q));
  BUF u_out (.A(q), .Y(result));
endmodule
"""
    )
    document = parse_sdc_text("set_input_delay 1 [get_ports {data[3] data[0]}]\n")
    selector = document.commands[0].selectors[0]
    resolved = resolve_selector(selector, design, {})

    assert selector.patterns == ("data[3]", "data[0]")
    assert resolved.error is None
    assert resolved.matches == {"data[3]", "data[0]"}


def test_sdc_hierarchical_leaf_matching_and_supported_filters(design_factory) -> None:
    design = design_factory()
    pin_selector = parse_sdc_text("set_false_path -to [get_pins -hierarchical D]\n").commands[0].selectors[0]
    port_selector = (
        parse_sdc_text("set_input_delay 1 [get_ports -filter {direction == input} *]\n").commands[0].selectors[0]
    )

    assert resolve_selector(pin_selector, design, {}).matches == {"u_ff/D"}
    assert resolve_selector(port_selector, design, {}).matches == {"clk", "clk2", "data", "spare"}


def test_zero_dynamic_unsupported_and_broad_query_diagnostics(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 [get_ports missing]
set_input_delay 1 [get_ports $input_name]
set_output_delay 1 [get_ports -filter {name == result} *]
set_false_path -to [get_ports *]
""",
        options=AuditOptions(broad_match_count=2, broad_match_ratio=0.5, broad_match_min_universe=2),
    )
    ids = [finding.rule_id for finding in result.diagnostics]

    assert "OC1001" in ids
    assert "OC1002" in ids
    assert "OC1003" in ids
    assert "OC1004" in ids
    zero = next(finding for finding in result.diagnostics if finding.rule_id == "OC1001")
    assert zero.evidence["universe_size"] == 5
    broad = next(finding for finding in result.diagnostics if finding.rule_id == "OC1002")
    assert broad.evidence["matched_count"] == 5


def test_all_inputs_and_outputs_are_not_reported_as_dangerous_broad_queries(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 -waveform {0 5} [get_ports clk]
set_input_delay 1 -clock core [all_inputs]
set_output_delay 1 -clock core [all_outputs]
""",
        options=AuditOptions(broad_match_count=1, broad_match_ratio=0.01, broad_match_min_universe=1),
    )

    assert "OC1002" not in [finding.rule_id for finding in result.diagnostics]


def test_invalid_regexp_is_an_unsupported_query_not_a_zero_match(audit_factory) -> None:
    result = audit_factory("set_input_delay 1 [get_ports -regexp {*+}]")
    ids = [finding.rule_id for finding in result.diagnostics]

    assert "OC1004" in ids
    assert "OC1001" not in ids
    finding = next(item for item in result.diagnostics if item.rule_id == "OC1004")
    assert "invalid regular expression" in finding.evidence["reason"]
