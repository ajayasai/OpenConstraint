from __future__ import annotations

import pytest

from openconstraint.engine import audit_sdc_text
from openconstraint.parsers.sdc import MODELED_SDC_COMMANDS, parse_sdc_text


def _ids(result) -> list[str]:
    return [finding.rule_id for finding in result.diagnostics]


def test_static_command_allowlist_is_exactly_nine_constraints_plus_context_directive() -> None:
    assert {
        "current_design",
        "create_clock",
        "create_generated_clock",
        "set_input_delay",
        "set_output_delay",
        "set_false_path",
        "set_multicycle_path",
        "set_max_delay",
        "set_min_delay",
        "set_clock_groups",
    } == MODELED_SDC_COMMANDS


def test_matching_literal_current_design_is_a_safe_context_directive(audit_factory) -> None:
    result = audit_factory(
        """
current_design top
create_clock -name core -period 10 -waveform {0 5} [get_ports clk]
set_input_delay 1 -clock core [get_ports {clk2 data spare}]
set_output_delay 2 -clock core [all_outputs]
"""
    )

    assert not {"OC0001", "OC0003"} & set(_ids(result))
    assert result.modes[0].coverage.score == 100.0


@pytest.mark.parametrize("constraint", ["current_design", "current_design top extra"])
def test_current_design_requires_exactly_one_literal_name(audit_factory, constraint: str) -> None:
    result = audit_factory(constraint)

    assert "OC0001" in _ids(result)
    assert result.modes[0].coverage.score == 0.0


@pytest.mark.parametrize(
    "constraint",
    [
        "current_design $top",
        'current_design "prefix$top"',
        "current_design [get_ports clk]",
        "current_design [list top]",
        "current_design {*}$tops",
    ],
)
def test_current_design_rejects_evaluated_names(audit_factory, constraint: str) -> None:
    result = audit_factory(constraint)

    assert "OC0003" in _ids(result)
    assert result.modes[0].coverage.score == 0.0


def test_current_design_accepts_a_literal_name_beginning_with_dash(design_factory) -> None:
    design = design_factory()
    design.top = "-top"

    result = audit_sdc_text(design, "default", "current_design {-top}\n")

    assert not {"OC0001", "OC0003"} & set(_ids(result))


def test_current_design_must_match_the_elaborated_top(audit_factory) -> None:
    result = audit_factory("current_design another_top")

    finding = next(item for item in result.diagnostics if item.rule_id == "OC0001")
    assert finding.evidence == {"selected_design": "another_top", "elaborated_top": "top"}
    assert result.modes[0].coverage.score == 0.0


@pytest.mark.parametrize("invalid_option", ["-rise", "-bogus"])
def test_create_clock_rejects_options_outside_its_opensta_grammar(audit_factory, invalid_option: str) -> None:
    result = audit_factory(f"create_clock {invalid_option} -period 10 -name core [get_ports clk]")

    assert "OC0001" in _ids(result)
    assert not result.modes[0].clocks
    assert result.modes[0].coverage.score == 0.0


def test_escaped_and_abbreviated_opensta_options_are_canonicalized(audit_factory) -> None:
    command = parse_sdc_text(r"create_clock \-per 10 \-n core [get_ports clk]" + "\n").commands[0]

    assert command.options == {"-period": ["10"], "-name": ["core"]}
    assert not command.parse_errors

    result = audit_factory(r"create_clock \-per 10 \-n core [get_ports clk]")
    assert "OC0001" not in _ids(result)
    assert "core" in result.modes[0].clocks


def test_generated_clock_rejects_primary_clock_only_option(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 [get_ports clk]
create_generated_clock -name divided -source [get_ports clk] -waveform {0 5} [get_ports clk2]
"""
    )

    assert "OC0001" in _ids(result)
    assert "divided" not in result.modes[0].clocks


@pytest.mark.parametrize(
    "constraint",
    [
        "set_input_delay -setup 1 [get_ports data]",
        "set_output_delay -hold 1 [get_ports result]",
        "set_false_path -min -from [get_ports data] -to [get_ports result]",
        "set_multicycle_path -max 2 -from [get_ports data] -to [get_ports result]",
        "set_max_delay -setup 2 -from [get_ports data] -to [get_ports result]",
        "set_min_delay -hold 1 -from [get_ports data] -to [get_ports result]",
        "set_clock_groups -setup -group [get_clocks core] -group [get_clocks aux]",
    ],
)
def test_every_other_modeled_command_rejects_foreign_options(audit_factory, constraint: str) -> None:
    result = audit_factory(constraint)

    assert "OC0001" in _ids(result)
    assert not result.modes[0].exceptions
    assert not result.modes[0].io_delays


@pytest.mark.parametrize(
    "constraint",
    [
        "set_false_path stray -from [get_ports data] -to [get_ports result]",
        """
create_clock -name core -period 10 [get_ports clk]
create_clock -name aux -period 20 [get_ports clk2]
set_clock_groups stray -asynchronous -group [get_clocks core] -group [get_clocks aux]
""",
    ],
)
def test_exception_commands_reject_stray_positional_operands_without_mutating_state(
    audit_factory, constraint: str
) -> None:
    result = audit_factory(constraint)

    assert "OC0001" in _ids(result)
    assert not result.modes[0].exceptions
    assert result.modes[0].coverage.score == 0.0
    assert result.modes[0].coverage.grade == "F"


def test_missing_value_option_is_a_command_grammar_error(audit_factory) -> None:
    command = parse_sdc_text("create_clock -name core -period\n").commands[0]

    assert command.parse_errors == ["create_clock -period missing value"]
    assert "OC0001" in _ids(audit_factory("create_clock -name core -period"))


def test_invalid_tcl_unicode_escape_fails_closed_without_crashing(audit_factory) -> None:
    source = r"create_clock -name \U00110000 -period 10 [get_ports clk]"
    command = parse_sdc_text(source + "\n").commands[0]

    assert any("invalid Tcl Unicode escape" in problem for problem in command.parse_errors)
    assert "OC0001" in _ids(audit_factory(source))


def test_repeatable_through_and_group_operands_preserve_occurrence_order() -> None:
    false_path = parse_sdc_text(
        "set_false_path -through [get_pins u_ff/D] -rise_through [get_pins u_ff/Q] -through [get_pins u_ff/CK]\n"
    ).commands[0]
    clock_groups = parse_sdc_text(
        "set_clock_groups -asynchronous -group [get_clocks core] -group [get_clocks aux]\n"
    ).commands[0]

    assert false_path.option_occurrences == [
        ("-through", "[get_pins u_ff/D]"),
        ("-rise_through", "[get_pins u_ff/Q]"),
        ("-through", "[get_pins u_ff/CK]"),
    ]
    assert clock_groups.options["-group"] == ["[get_clocks core]", "[get_clocks aux]"]
    assert not false_path.parse_errors
    assert not clock_groups.parse_errors


def test_quoted_selector_operand_remains_associated_with_io_target(audit_factory) -> None:
    result = audit_factory('set_input_delay 1 "[get_ports data]"')

    assert result.modes[0].io_delays[0].ports == frozenset({"data"})


def test_quoted_selector_operands_remain_associated_with_exception_scope(audit_factory) -> None:
    result = audit_factory('set_false_path -from "[get_ports data]" -to "[get_ports result]"')

    exception = result.modes[0].exceptions[0]
    assert exception.from_objects == {"data"}
    assert exception.to_objects == {"result"}


def test_quoted_selector_operands_remain_associated_with_clock_groups(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name a -period 10 [get_ports clk]
create_clock -name b -period 20 [get_ports clk2]
set_clock_groups -asynchronous -group "[get_clocks a]" -group "[get_clocks b]"
"""
    )

    groups = [item for item in result.modes[0].exceptions if item.kind == "clock_group"]
    assert len(groups) == 2


def test_invalid_command_still_audits_nested_selectors(audit_factory) -> None:
    result = audit_factory("set_false_path -bogus [get_ports absent] -to [get_ports result]")

    assert "OC0001" in _ids(result)
    assert any(
        finding.rule_id == "OC1001" and finding.evidence.get("query") == "[get_ports absent]"
        for finding in result.diagnostics
    )
    assert not result.modes[0].exceptions


@pytest.mark.parametrize(
    "constraint",
    [
        "create_clock -name $clock_name -period 10 [get_ports clk]",
        "set_false_path -from $objects -to [get_ports result]",
        "set_false_path -to foo[get_ports *]",
    ],
)
def test_modeled_commands_with_opaque_tcl_arguments_do_not_mutate_state(audit_factory, constraint: str) -> None:
    result = audit_factory(constraint)
    finding = next(item for item in result.diagnostics if item.rule_id == "OC0003")

    assert finding.evidence["opaque_argument_count"] == 1
    assert len(finding.evidence["opaque_arguments"]) == 1
    assert not result.modes[0].clocks
    assert not result.modes[0].exceptions
    assert result.modes[0].coverage.grade == "F"


def test_supported_selector_substitution_is_not_an_opaque_outer_argument(audit_factory) -> None:
    command = parse_sdc_text("set_false_path -from [get_ports $dynamic_name] -to [get_ports result]\n").commands[0]
    result = audit_factory("set_false_path -from [get_ports $dynamic_name] -to [get_ports result]")

    assert not command.opaque_substitutions
    assert "OC0003" not in _ids(result)
    assert "OC1003" in _ids(result)


def test_selector_substitution_in_scalar_option_fails_closed(audit_factory) -> None:
    source = "create_clock -name [get_ports clk] -period 10 [get_ports clk]"
    command = parse_sdc_text(source + "\n").commands[0]
    result = audit_factory(source)

    assert command.opaque_substitutions == ["[get_ports clk]"]
    assert [(selector.option, selector.raw) for selector in command.selectors] == [
        ("-name", "[get_ports clk]"),
        (None, "[get_ports clk]"),
    ]
    assert "OC0003" in _ids(result)
    assert not result.modes[0].clocks
    assert result.modes[0].coverage.score == 0.0
    assert result.modes[0].coverage.grade == "F"


@pytest.mark.parametrize(
    "constraint",
    [
        "set_input_delay [get_ports data] [get_ports data]",
        "set_output_delay [get_ports result] [get_ports result]",
        "set_multicycle_path [get_ports data] -to [get_ports result]",
        "set_max_delay [get_ports data] -to [get_ports result]",
        "set_min_delay [get_ports data] -to [get_ports result]",
    ],
)
def test_selector_substitution_in_scalar_positional_fails_closed(audit_factory, constraint: str) -> None:
    command = parse_sdc_text(constraint + "\n").commands[0]
    result = audit_factory(constraint)

    assert command.opaque_substitutions == [command.positionals[0]]
    assert "OC0003" in _ids(result)
    assert not result.modes[0].io_delays
    assert not result.modes[0].exceptions
    assert result.modes[0].coverage.score == 0.0
    assert result.modes[0].coverage.grade == "F"


@pytest.mark.parametrize(
    "constraint",
    [
        "create_generated_clock -source [get_ports clk] -master_clock [get_clocks core] [get_ports clk2]",
        "set_input_delay 1 -clock [get_clocks core] -reference_pin [get_pins u_ff/Q] [get_ports data]",
        "set_output_delay 1 -clock [get_clocks core] -reference_pin [get_pins u_ff/Q] [get_ports result]",
        "set_false_path -from [get_ports data] -through [get_pins u_ff/D] -to [get_ports result]",
        "set_multicycle_path -from [get_ports data] -to [get_ports result] 2",
        "set_max_delay -from [get_ports data] -to [get_ports result] 2",
        "set_min_delay -from [get_ports data] -to [get_ports result] 1",
        "set_clock_groups -asynchronous -group [get_clocks core] -group [get_clocks aux]",
        "set_input_delay 1 [get_ports data] [get_ports spare]",
        "set_max_delay 2 [get_ports data]",
    ],
)
def test_selector_substitutions_in_collection_options_remain_static(constraint: str) -> None:
    command = parse_sdc_text(constraint + "\n").commands[0]

    assert not command.opaque_substitutions


@pytest.mark.parametrize("word", [r"{$objects}", r"\$objects"])
def test_braced_or_escaped_substitution_text_remains_static(word: str) -> None:
    command = parse_sdc_text(f"set_false_path -from {word} -to [get_ports result]\n").commands[0]

    assert not command.opaque_substitutions


@pytest.mark.parametrize(
    "constraint, command_name",
    [
        ("set hidden [eval {set_false_path -to [all_outputs]}]", "set"),
        ("return", "return"),
        ("project_constraint_helper -mode functional", "project_constraint_helper"),
    ],
)
def test_every_command_outside_the_nine_command_allowlist_fails_closed(
    audit_factory, constraint: str, command_name: str
) -> None:
    result = audit_factory(constraint)
    finding = next(item for item in result.diagnostics if item.rule_id == "OC0003")

    assert finding.evidence["command"] == command_name
    assert result.modes[0].coverage.score == 0.0


def test_opaque_argument_evidence_is_bounded(audit_factory) -> None:
    result = audit_factory("set hidden " + " ".join(f"$value{index}" for index in range(12)))
    finding = next(item for item in result.diagnostics if item.rule_id == "OC0003")

    assert finding.evidence["opaque_argument_count"] == 12
    assert len(finding.evidence["opaque_arguments"]) == 8
