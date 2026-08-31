from __future__ import annotations

import pytest

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

PINNED_GET_COMMANDS = ("get_ports", "get_pins", "get_cells", "get_nets", "get_clocks")


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
    assert bracket_body('"[get_ports clk]"') == "get_ports clk"
    assert bracket_body("{[get_ports clk]}") is None
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


def test_io_delay_analysis_flags_are_not_misparsed_as_value_options() -> None:
    command = parse_sdc_text("set_input_delay -min -rise -add_delay 1.25 -clock core [get_ports data]\n").commands[0]

    assert command.has("-min")
    assert command.has("-rise")
    assert command.has("-add_delay")
    assert command.option("-clock") == "core"
    assert command.positionals == ["1.25", "[get_ports data]"]


def test_negative_numeric_arguments_remain_positionals() -> None:
    command = parse_sdc_text("set_output_delay -min -1.25 -clock core [get_ports result]\n").commands[0]

    assert command.options == {"-min": ["true"], "-clock": ["core"]}
    assert command.positionals == ["-1.25", "[get_ports result]"]


def test_min_max_delay_boolean_flags_do_not_consume_scope_options() -> None:
    command = parse_sdc_text(
        "set_max_delay -probe -ignore_clock_latency -from [get_ports data] -to [get_ports result] 2\n"
    ).commands[0]

    assert command.has("-probe")
    assert command.has("-ignore_clock_latency")
    assert command.option("-from") == "[get_ports data]"
    assert command.option("-to") == "[get_ports result]"
    assert command.positionals == ["2"]


@pytest.mark.parametrize("command_name", PINNED_GET_COMMANDS)
def test_omitted_get_patterns_use_the_sdc_implicit_wildcard(command_name: str) -> None:
    selector = parse_sdc_text(f"set_false_path -to [{command_name}]\n").commands[0].selectors[0]

    assert selector.command_name == command_name
    assert selector.patterns == ("*",)
    assert selector.parse_error is None


def test_omitted_get_patterns_resolve_as_all_objects(design_factory) -> None:
    design = design_factory()
    document = parse_sdc_text("set_false_path -from [get_cells] -to [get_ports]\n")
    from_selector, to_selector = document.commands[0].selectors

    assert from_selector.patterns == ("*",)
    assert to_selector.patterns == ("*",)
    assert resolve_selector(from_selector, design, {}).matches == {"u_ff", "u_out"}
    assert resolve_selector(to_selector, design, {}).matches == {"clk", "clk2", "data", "spare", "result"}


@pytest.mark.parametrize("command_name", PINNED_GET_COMMANDS)
def test_explicit_empty_get_pattern_remains_an_empty_collection(design_factory, command_name: str) -> None:
    design = design_factory()
    selector = parse_sdc_text(f"set_false_path -to [{command_name} {{}}]\n").commands[0].selectors[0]
    resolved = resolve_selector(selector, design, {})

    assert selector.patterns == ()
    assert selector.parse_error is None
    assert resolved.error is None
    assert resolved.matches == set()


def test_explicit_empty_get_pattern_is_a_zero_query_not_a_broad_query(audit_factory) -> None:
    result = audit_factory("set_input_delay 1 [get_ports {}]")
    ids = [finding.rule_id for finding in result.diagnostics]
    assert "OC1001" in ids
    assert "OC1002" not in ids


@pytest.mark.parametrize(
    ("command_name", "option"),
    [
        ("get_cells", "-filter"),
        ("get_cells", "-hsc"),
        ("get_cells", "-of_objects"),
        ("get_clocks", "-filter"),
        ("get_nets", "-filter"),
        ("get_nets", "-hsc"),
        ("get_nets", "-of_objects"),
        ("get_pins", "-filter"),
        ("get_pins", "-hsc"),
        ("get_pins", "-of_objects"),
        ("get_ports", "-filter"),
        ("get_ports", "-of_objects"),
    ],
)
def test_get_query_missing_option_operand_is_a_static_parse_error(
    audit_factory, command_name: str, option: str
) -> None:
    query = f"[{command_name} {option}]"
    selector = parse_sdc_text(f"set_false_path -to {query}\n").commands[0].selectors[0]

    assert selector.patterns == ()
    assert selector.parse_error == f"{command_name} {option} missing value"

    result = audit_factory(f"set_false_path -to {query}")
    findings = [finding for finding in result.diagnostics if finding.rule_id == "OC1004"]
    assert len(findings) == 1
    assert findings[0].evidence["query"] == query
    assert findings[0].evidence["reason"] == selector.parse_error
    assert not any(finding.rule_id in {"OC1001", "OC1002"} for finding in result.diagnostics)


@pytest.mark.parametrize("expression", ["{}", '""', "{   }"])
def test_empty_filter_expression_fails_closed(audit_factory, expression: str) -> None:
    query = f"[get_ports -filter {expression} *]"
    selector = parse_sdc_text(f"set_false_path -to {query}\n").commands[0].selectors[0]

    result = audit_factory(f"set_false_path -to {query}")
    finding = next(item for item in result.diagnostics if item.rule_id == "OC1004")
    assert selector.filter_expression is not None
    assert finding.evidence["reason"] == "empty filter expression"
    assert not any(item.rule_id in {"OC1001", "OC1002"} for item in result.diagnostics)


@pytest.mark.parametrize("command_name", ["get_cells", "get_nets", "get_pins"])
def test_hsc_operand_is_consumed_and_reported_as_unsupported(audit_factory, command_name: str) -> None:
    query = f"[{command_name} -hsc . target]"
    selector = parse_sdc_text(f"set_false_path -to {query}\n").commands[0].selectors[0]

    assert selector.patterns == ("target",)
    assert selector.parse_error == f"{command_name} -hsc is not modeled by the static backend"

    result = audit_factory(f"set_false_path -to {query}")
    finding = next(item for item in result.diagnostics if item.rule_id == "OC1004")
    assert finding.evidence["query"] == query
    assert finding.evidence["reason"] == selector.parse_error
    assert not any(item.rule_id in {"OC1001", "OC1002"} for item in result.diagnostics)


@pytest.mark.parametrize(
    ("query", "expected_reason"),
    [
        ("[get_ports -hierarchical data]", "get_ports does not support option -hierarchical"),
        ("[get_clocks -hierarchical core]", "get_clocks does not support option -hierarchical"),
        ("[get_ports -hsc . data]", "get_ports does not support option -hsc"),
        ("[get_clocks -of_objects [get_ports clk]]", "get_clocks does not support option -of_objects"),
        ("[get_cells -unknown target]", "get_cells does not support option -unknown"),
    ],
)
def test_command_specific_get_options_fail_closed(audit_factory, query: str, expected_reason: str) -> None:
    selector = parse_sdc_text(f"set_false_path -to {query}\n").commands[0].selectors[0]

    assert selector.parse_error == expected_reason

    result = audit_factory(f"set_false_path -to {query}")
    finding = next(item for item in result.diagnostics if item.rule_id == "OC1004")
    assert finding.evidence["query"] == query
    assert finding.evidence["reason"] == expected_reason
    assert not any(item.rule_id in {"OC1001", "OC1002"} for item in result.diagnostics)


@pytest.mark.parametrize(
    "query",
    [
        "[get_cells -hierarchical -quiet *]",
        "[get_clocks -regexp -nocase -quiet {^core$}]",
        "[get_nets -hierarchical -quiet *]",
        "[get_pins -hierarchical -quiet *]",
        "[get_ports -regexp -nocase -quiet {^data$}]",
        "[get_registers -filter {is_sequential == true} *]",
    ],
)
def test_command_specific_get_options_preserve_modeled_forms(query: str) -> None:
    selector = parse_sdc_text(f"set_false_path -to {query}\n").commands[0].selectors[0]

    assert selector.parse_error is None


def test_braced_option_token_is_parsed_after_tcl_quote_removal(design_factory) -> None:
    design = design_factory()
    selector = parse_sdc_text("set_false_path -to [get_nets {-quiet}]\n").commands[0].selectors[0]

    assert selector.patterns == ("*",)
    assert selector.parse_error is None
    assert resolve_selector(selector, design, {}).matches == set(design.nets)


@pytest.mark.parametrize("word", ["{ -quiet }", '" -quiet "'])
def test_option_like_word_with_preserved_tcl_whitespace_remains_a_pattern(design_factory, word: str) -> None:
    design = design_factory()
    selector = parse_sdc_text(f"set_false_path -to [get_ports {word}]\n").commands[0].selectors[0]

    assert selector.patterns == ("-quiet",)
    assert selector.parse_error is None
    assert resolve_selector(selector, design, {}).matches == set()


@pytest.mark.parametrize(
    ("word", "expected_patterns"),
    [("{-q }", ("data",)), ("{ -q}", ("-q", "data")), ('" -q "', ("-q", "data"))],
)
def test_option_like_word_with_tcl_whitespace_does_not_collapse_into_a_flag(
    word: str, expected_patterns: tuple[str, ...]
) -> None:
    selector = parse_sdc_text(f"set_false_path -to [get_ports {word} data]\n").commands[0].selectors[0]

    assert selector.parse_error is not None
    assert selector.patterns == expected_patterns


def test_braces_suppress_nested_of_objects_substitution(audit_factory) -> None:
    query = "[get_cells -of_objects {[get_nets q]}]"
    selector = parse_sdc_text(f"set_false_path -from {query} -to [get_ports result]\n").commands[0].selectors[0]

    assert selector.of_objects is None
    assert selector.nested_selectors == ()
    assert selector.dynamic is True

    result = audit_factory(f"set_false_path -from {query} -to [get_ports result]")
    assert any(item.rule_id == "OC1003" and item.evidence["query"] == query for item in result.diagnostics)
    assert result.modes[0].exceptions[0].from_objects == set()


def test_unsupported_of_objects_still_audits_evaluated_nested_query(audit_factory) -> None:
    query = "[get_clocks -of_objects [get_ports missing]]"
    selector = parse_sdc_text(f"set_false_path -from {query}\n").commands[0].selectors[0]

    assert selector.parse_error == "get_clocks does not support option -of_objects"
    assert selector.of_objects is not None
    assert [nested.raw for nested in selector.nested_selectors] == ["[get_ports missing]"]

    result = audit_factory(f"set_false_path -from {query}")
    assert any(item.rule_id == "OC1004" and item.evidence["query"] == query for item in result.diagnostics)
    assert any(
        item.rule_id == "OC1001" and item.evidence["query"] == "[get_ports missing]" for item in result.diagnostics
    )


@pytest.mark.parametrize(
    "query",
    [
        "[get_ports [get_ports missing]]",
        "[get_ports -hierarchical [get_ports missing]]",
        "[get_clocks -bogus [get_ports missing]]",
        "[all_inputs [get_ports missing]]",
    ],
)
def test_evaluated_nested_positional_query_is_audited_independently(audit_factory, query: str) -> None:
    selector = parse_sdc_text(f"set_false_path -from {query}\n").commands[0].selectors[0]

    assert [nested.raw for nested in selector.nested_selectors] == ["[get_ports missing]"]
    result = audit_factory(f"set_false_path -from {query}")
    assert any(item.rule_id == "OC1003" and item.evidence["query"] == query for item in result.diagnostics)
    assert any(
        item.rule_id == "OC1001" and item.evidence["query"] == "[get_ports missing]" for item in result.diagnostics
    )


def test_unmodeled_value_option_still_audits_evaluated_nested_query(audit_factory) -> None:
    query = "[all_registers -clock [get_clocks missing]]"
    selector = parse_sdc_text(f"set_false_path -from {query}\n").commands[0].selectors[0]

    assert [nested.raw for nested in selector.nested_selectors] == ["[get_clocks missing]"]
    result = audit_factory(f"set_false_path -from {query}")
    assert any(
        item.rule_id == "OC1001" and item.evidence["query"] == "[get_clocks missing]" for item in result.diagnostics
    )


def test_all_inputs_no_clocks_fails_closed_until_modeled(audit_factory) -> None:
    query = "[all_inputs -no_clocks]"
    selector = parse_sdc_text(f"set_false_path -from {query}\n").commands[0].selectors[0]

    assert selector.patterns == ()
    assert selector.parse_error == "all_inputs -no_clocks is not modeled by the static backend"

    result = audit_factory(f"set_false_path -from {query}")
    finding = next(item for item in result.diagnostics if item.rule_id == "OC1004")
    assert finding.evidence["reason"] == selector.parse_error
    assert not any(item.rule_id in {"OC1001", "OC1002"} for item in result.diagnostics)


def test_all_inputs_preserves_pinned_opensta_ignored_positional_arguments(design_factory) -> None:
    design = design_factory()
    selector = parse_sdc_text("set_false_path -from [all_inputs ignored extra]\n").commands[0].selectors[0]

    assert selector.parse_error is None
    assert selector.patterns == ("ignored", "extra")
    assert resolve_selector(selector, design, {}).matches == {"clk", "clk2", "data", "spare"}


@pytest.mark.parametrize(
    ("query", "expected_patterns"),
    [
        ("[get_ports -q data]", ("data",)),
        ("[get_ports -reg {^data$}]", ("^data$",)),
        ("[get_cells -hier *]", ("*",)),
    ],
)
def test_unambiguous_opensta_option_prefixes_are_accepted(query: str, expected_patterns: tuple[str, ...]) -> None:
    selector = parse_sdc_text(f"set_false_path -to {query}\n").commands[0].selectors[0]

    assert selector.patterns == expected_patterns
    assert selector.parse_error is None


@pytest.mark.parametrize(
    "option",
    sorted(
        ("-cells", "-data_pins", "-clock_pins", "-async_pins", "-output_pins", "-level_sensitive", "-edge_triggered")
    ),
)
def test_all_registers_flag_options_fail_closed(audit_factory, option: str) -> None:
    query = f"[all_registers {option}]"
    selector = parse_sdc_text(f"set_false_path -from {query}\n").commands[0].selectors[0]

    assert selector.patterns == ()
    assert selector.parse_error == f"all_registers {option} is not modeled by the static backend"

    result = audit_factory(f"set_false_path -from {query}")
    finding = next(item for item in result.diagnostics if item.rule_id == "OC1004")
    assert finding.evidence["reason"] == selector.parse_error


@pytest.mark.parametrize("option", ["-clock", "-rise_clock", "-fall_clock"])
def test_all_registers_value_options_consume_their_operand_and_fail_closed(audit_factory, option: str) -> None:
    query = f"[all_registers {option} core]"
    selector = parse_sdc_text(f"set_false_path -from {query}\n").commands[0].selectors[0]

    assert selector.patterns == ()
    assert selector.parse_error == f"all_registers {option} is not modeled by the static backend"

    result = audit_factory(f"set_false_path -from {query}")
    finding = next(item for item in result.diagnostics if item.rule_id == "OC1004")
    assert finding.evidence["reason"] == selector.parse_error


@pytest.mark.parametrize("command_name", ["all_inputs", "all_outputs", "all_clocks", "all_registers"])
def test_bare_all_selectors_remain_supported(command_name: str) -> None:
    selector = parse_sdc_text(f"set_false_path -to [{command_name}]\n").commands[0].selectors[0]

    assert selector.patterns == ("*",)
    assert selector.parse_error is None


@pytest.mark.parametrize(
    "command_name",
    ["get_cells", "get_clocks", "get_nets", "get_pins", "get_ports", "get_registers"],
)
def test_get_query_rejects_multiple_positional_tcl_arguments(audit_factory, command_name: str) -> None:
    query = f"[{command_name} first second]"
    selector = parse_sdc_text(f"set_false_path -to {query}\n").commands[0].selectors[0]

    assert selector.patterns == ("first", "second")
    assert selector.parse_error == f"{command_name} accepts at most one positional pattern-list argument; got 2"

    result = audit_factory(f"set_false_path -to {query}")
    finding = next(item for item in result.diagnostics if item.rule_id == "OC1004")
    assert finding.evidence["query"] == query
    assert finding.evidence["reason"] == selector.parse_error
    assert not any(item.rule_id in {"OC1001", "OC1002"} for item in result.diagnostics)


def test_one_positional_tcl_list_remains_a_valid_multi_pattern_query(design_factory) -> None:
    design = design_factory()
    selector = parse_sdc_text("set_false_path -to [get_ports {data result}]\n").commands[0].selectors[0]

    assert selector.patterns == ("data", "result")
    assert selector.parse_error is None
    assert resolve_selector(selector, design, {}).matches == {"data", "result"}


def test_of_objects_still_ignores_multiple_positional_tcl_arguments(design_factory) -> None:
    design = design_factory()
    selector = (
        parse_sdc_text("set_false_path -to [get_cells first second -of_objects [get_nets q]]\n")
        .commands[0]
        .selectors[0]
    )

    assert selector.patterns == ("first", "second")
    assert selector.parse_error is None
    assert resolve_selector(selector, design, {}).matches == {"u_ff", "u_out"}


def test_sdc_parser_preserves_cross_option_occurrence_order() -> None:
    command = parse_sdc_text(
        "set_false_path -through [get_pins u_ff/D] -rise_through [get_pins u_ff/Q] -through [get_pins u_ff/CK]\n"
    ).commands[0]

    assert command.option_occurrences == [
        ("-through", "[get_pins u_ff/D]"),
        ("-rise_through", "[get_pins u_ff/Q]"),
        ("-through", "[get_pins u_ff/CK]"),
    ]


def test_sdc_parser_records_selector_argument_roles() -> None:
    command = parse_sdc_text(
        "create_generated_clock -comment [get_ports data] -source [get_ports clk] -divide_by 2 [get_ports clk]\n"
    ).commands[0]

    assert [(selector.raw, selector.option) for selector in command.selectors] == [
        ("[get_ports data]", "-comment"),
        ("[get_ports clk]", "-source"),
        ("[get_ports clk]", None),
    ]


def test_of_objects_resolves_connectivity_for_cells_pins_nets_and_ports(design_factory) -> None:
    design = design_factory()
    cases = (
        ("[get_cells -of_objects [get_ports data]]", {"u_ff"}),
        ("[get_cells -of_objects [get_pins u_ff/D]]", {"u_ff"}),
        ("[get_cells -of_objects [get_nets q]]", {"u_ff", "u_out"}),
        ("[get_nets -of_objects [get_cells u_ff]]", {"clk", "data", "q"}),
        ("[get_nets -of_objects [get_pins u_ff/D]]", {"data"}),
        ("[get_pins -of_objects [get_cells u_ff]]", {"u_ff/CK", "u_ff/D", "u_ff/Q"}),
        ("[get_pins -of_objects [get_nets q]]", {"u_ff/Q", "u_out/A"}),
        ("[get_ports -of_objects [get_nets result]]", {"result"}),
    )

    for query, expected in cases:
        selector = parse_sdc_text(f"set_false_path -to {query}\n").commands[0].selectors[0]
        resolved = resolve_selector(selector, design, {})
        assert resolved.error is None
        assert resolved.matches == expected


def test_of_objects_rejects_source_types_opensta_does_not_accept(design_factory) -> None:
    design = design_factory()
    queries = (
        "[get_cells -of_objects [get_cells u_ff]]",
        "[get_nets -of_objects [get_nets q]]",
        "[get_nets -of_objects [get_ports data]]",
        "[get_pins -of_objects [get_pins u_ff/D]]",
        "[get_pins -of_objects [get_ports data]]",
        "[get_ports -of_objects [get_pins u_out/Y]]",
    )

    for query in queries:
        selector = parse_sdc_text(f"set_false_path -to {query}\n").commands[0].selectors[0]
        resolved = resolve_selector(selector, design, {})
        assert resolved.matches == set()
        assert resolved.error is not None
        assert "invalid -of_objects source kind" in resolved.error


def test_of_objects_ignores_positional_patterns_even_when_they_are_dynamic(design_factory) -> None:
    design = design_factory()
    selector = (
        parse_sdc_text("set_false_path -to [get_cells -of_objects [get_nets q] $ignored_pattern]\n")
        .commands[0]
        .selectors[0]
    )
    resolved = resolve_selector(selector, design, {})

    assert selector.patterns == ("$ignored_pattern",)
    assert selector.dynamic is False
    assert resolved.error is None
    assert resolved.matches == {"u_ff", "u_out"}
    assert resolved.unmatched_patterns == ()


def test_of_objects_ignored_wildcard_does_not_trigger_broad_query_diagnostic(audit_factory) -> None:
    result = audit_factory(
        "set_false_path -from [get_cells -of_objects [get_nets q] *] -to [get_ports result]",
        options=AuditOptions(broad_match_count=1, broad_match_ratio=0.01, broad_match_min_universe=1),
    )

    assert "OC1002" not in [finding.rule_id for finding in result.diagnostics]


def test_nocase_only_changes_regexp_matching(design_factory) -> None:
    design = design_factory()
    glob = parse_sdc_text("set_false_path -to [get_ports -nocase DATA]\n").commands[0].selectors[0]
    regexp = parse_sdc_text("set_false_path -to [get_ports -regexp -nocase {^DATA$}]\n").commands[0].selectors[0]

    assert resolve_selector(glob, design, {}).matches == set()
    assert resolve_selector(glob, design, {}).unmatched_patterns == ("DATA",)
    assert resolve_selector(regexp, design, {}).matches == {"data"}


def test_of_objects_query_participates_in_audit_without_unsupported_fallback(audit_factory) -> None:
    result = audit_factory("set_false_path -from [get_cells -of_objects [get_nets q]] -to [get_ports result]")

    assert not any(finding.rule_id in {"OC1001", "OC1004"} for finding in result.diagnostics)
    assert result.modes[0].exceptions[0].from_objects == {"u_ff", "u_out"}
