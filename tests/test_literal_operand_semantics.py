from __future__ import annotations

import json

import pytest


def _find(result, rule_id: str):
    return [finding for finding in result.diagnostics if finding.rule_id == rule_id]


@pytest.mark.parametrize("clock", ["{core absent}", "{{core absent}}", '"core {"'])
def test_literal_io_clock_requires_one_well_formed_known_list_element(audit_factory, clock: str) -> None:
    result = audit_factory(
        f"""
create_clock -name core -period 10 [get_ports clk]
set_input_delay 1 -clock {clock} [get_ports data]
"""
    )

    assert any("invalid -clock" in finding.message for finding in _find(result, "OC3011"))
    assert result.modes[0].io_delays[0].valid is False
    assert "data" in _find(result, "OC3001")[0].evidence["ports"]


def test_nested_literal_io_clock_singleton_is_rejected_without_coverage(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 [get_ports clk]
set_input_delay 1 -clock {{core}} [get_ports data]
"""
    )

    assert result.modes[0].io_delays[0].valid is False
    assert any("invalid -clock" in finding.message for finding in _find(result, "OC3011"))
    assert "data" in _find(result, "OC3001")[0].evidence["ports"]


@pytest.mark.parametrize("source", ["{clk absent}", "{{clk absent}}", "{{clk}}", '"clk {"'])
def test_literal_generated_source_requires_one_well_formed_known_list_element(audit_factory, source: str) -> None:
    result = audit_factory(
        f"""
create_clock -name core -period 10 [get_ports clk]
create_generated_clock -name divided -source {source} -divide_by 2 [get_pins u_ff/Q]
"""
    )

    generated = result.modes[0].clocks["divided"]
    assert generated.period is None
    assert any(
        "-source must resolve to exactly one port or pin" in problem
        for finding in _find(result, "OC2012")
        for problem in finding.evidence.get("problems", [])
    )


@pytest.mark.parametrize("master", ["{core absent}", "{{core absent}}", "{{core}}", '"core {"'])
def test_literal_generated_master_requires_one_well_formed_known_list_element(audit_factory, master: str) -> None:
    result = audit_factory(
        f"""
create_clock -name core -period 10 [get_ports clk]
create_generated_clock -name divided -master_clock {master} -source [get_ports clk] \
  -divide_by 2 [get_pins u_ff/Q]
"""
    )

    generated = result.modes[0].clocks["divided"]
    assert generated.master_clock is None
    assert generated.period is None
    assert any("invalid -master_clock collection" in finding.message for finding in _find(result, "OC2012"))


@pytest.mark.parametrize("reference", ["{u_ff/Q absent}", "{{u_ff/Q absent}}", "{{u_ff/Q}}", '"u_ff/Q {"'])
def test_literal_reference_pin_requires_one_well_formed_known_list_element(audit_factory, reference: str) -> None:
    result = audit_factory(f"set_input_delay 1 -reference_pin {reference} [get_ports data]")

    item = result.modes[0].io_delays[0]
    assert item.reference_pin is None
    assert item.valid is False
    assert any("non-singleton -reference_pin" in finding.message for finding in _find(result, "OC3011"))
    assert "data" in _find(result, "OC3001")[0].evidence["ports"]


@pytest.mark.parametrize(
    ("command", "missing_rule", "target"),
    [
        ("set_input_delay", "OC3001", "data"),
        ("set_output_delay", "OC3002", "result"),
    ],
)
@pytest.mark.parametrize("collection", ["{TARGET absent}", "{{TARGET absent}}", '"TARGET {"'])
def test_unresolved_or_malformed_literal_io_target_invalidates_whole_command_and_coverage(
    audit_factory,
    command: str,
    missing_rule: str,
    target: str,
    collection: str,
) -> None:
    result = audit_factory(f"{command} 1 {collection.replace('TARGET', target)}")

    item = result.modes[0].io_delays[0]
    finding = next(finding for finding in _find(result, "OC3010") if "literal target collection" in finding.message)
    assert finding.severity.value == "error"
    assert item.valid is False
    assert target in _find(result, missing_rule)[0].evidence["ports"]


def test_nested_singleton_literal_io_target_is_accepted(audit_factory) -> None:
    result = audit_factory("set_input_delay 1 {{data}}")

    assert not _find(result, "OC3010")
    assert result.modes[0].io_delays[0].ports == frozenset({"data"})
    assert result.modes[0].io_delays[0].valid is True


def test_recursive_literal_io_target_list_is_accepted_when_every_leaf_resolves(audit_factory) -> None:
    result = audit_factory("set_input_delay 1 {{data spare}}")

    assert not _find(result, "OC3010")
    assert result.modes[0].io_delays[0].ports == frozenset({"data", "spare"})
    assert result.modes[0].io_delays[0].valid is True


@pytest.mark.parametrize("target", ["{clk absent}", "{{clk absent}}", '"clk {"'])
def test_primary_clock_literal_target_is_all_or_nothing_for_trusted_state(audit_factory, target: str) -> None:
    result = audit_factory(
        f"""
create_clock -name core -period 10 {target}
set_input_delay 1 -clock core [get_ports data]
"""
    )

    assert any(
        "target literal" in problem for finding in _find(result, "OC2006") for problem in finding.evidence["problems"]
    )
    assert result.modes[0].io_delays[0].valid is False
    assert "data" in _find(result, "OC3001")[0].evidence["ports"]


def test_invalid_clock_attempt_is_retained_but_cannot_leak_into_active_semantics(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 {clk absent}
create_clock -name aux -period 20 [get_ports clk2]
set_false_path -from [get_clocks core] -to [get_ports result]
set_multicycle_path 2 -from [get_clocks core] -to [get_ports result]
set_false_path -from [get_clocks aux] -to [get_ports result]
"""
    )

    mode = result.modes[0]
    assert set(mode.clocks) == {"aux", "core"}
    assert mode.valid_clocks == frozenset({"aux"})
    graph_node_ids = {item["id"] for item in mode.graph["nodes"]}
    assert "clock:core" not in graph_node_ids
    assert "clock:aux" in graph_node_ids
    invalid_scopes = [item for item in mode.exceptions if "[get_clocks core]" in item.raw]
    assert invalid_scopes
    assert all(not item.from_objects for item in invalid_scopes)
    assert all(item.qualifiers["scope_resolvable"] is False for item in invalid_scopes)
    assert not _find(result, "OC4001")
    assert "clk" in _find(result, "OC3001")[0].evidence["ports"]

    clocks = {item["name"]: item for item in result.to_dict()["modes"][0]["clocks"]}
    assert clocks["core"]["valid"] is False
    assert clocks["aux"]["valid"] is True


@pytest.mark.parametrize("target", ["{u_ff/Q absent}", "{{u_ff/Q absent}}", '"u_ff/Q {"'])
def test_generated_clock_literal_target_is_strictly_fail_closed(audit_factory, target: str) -> None:
    result = audit_factory(
        f"""
create_clock -name core -period 10 [get_ports clk]
create_generated_clock -name divided -source [get_ports clk] -divide_by 2 {target}
"""
    )

    divided = result.modes[0].clocks["divided"]
    assert divided.period is None
    assert any(
        "target literal" in problem for finding in _find(result, "OC2012") for problem in finding.evidence["problems"]
    )


def test_partial_literal_exception_scope_is_reported_and_cannot_overlap(audit_factory) -> None:
    # OpenSTA c821ad1 tcl/CmdArgs.tcl::get_object_args lines 79-168 warns
    # and retains u_ff here. The auditor intentionally rejects the partial
    # scope so that a warning cannot silently establish trusted exception state.
    result = audit_factory(
        """
set_false_path -from [get_cells u_ff] -to [get_ports result]
set_multicycle_path 2 -from {u_ff absent} -to result
"""
    )

    multicycle = next(item for item in result.modes[0].exceptions if item.kind == "multicycle_path")
    assert multicycle.from_objects == {"u_ff"}
    assert multicycle.qualifiers["definition_valid"] is False
    assert multicycle.qualifiers["scope_resolvable"] is False
    assert any(
        "from scope literal collection contains unresolved object" in problem
        for finding in _find(result, "OC4002")
        for problem in finding.evidence["problems"]
    )
    assert not _find(result, "OC4001")


def test_partial_literal_clock_group_creates_no_clock_group_exceptions(audit_factory) -> None:
    # OpenSTA c821ad1 get_clocks_warn retains known clocks after warning; the
    # deterministic audit intentionally requires every literal member to resolve.
    result = audit_factory(
        """
create_clock -name core -period 10 [get_ports clk]
create_clock -name aux -period 20 [get_ports clk2]
set_clock_groups -asynchronous -group {core absent} -group aux
"""
    )

    finding = next(finding for finding in _find(result, "OC4002") if "Clock-group" in finding.message)
    assert any("unresolved clock" in problem for problem in finding.evidence["problems"])
    assert not [item for item in result.modes[0].exceptions if item.kind == "clock_group"]


def test_extra_multicycle_multiplier_is_definition_invalid_and_cannot_reset_or_overlap(
    audit_factory,
) -> None:
    result = audit_factory(
        """
set_false_path -from [get_cells u_ff] -to [get_ports result]
set_multicycle_path 2 3 -reset_path -from [get_cells u_ff] -to [get_ports result]
"""
    )

    multicycle = next(item for item in result.modes[0].exceptions if item.kind == "multicycle_path")
    assert multicycle.qualifiers["multiplier"] is None
    assert multicycle.qualifiers["definition_valid"] is False
    assert multicycle.qualifiers["scope_resolvable"] is False
    assert len([item for item in result.modes[0].exceptions if item.kind == "false_path"]) == 1
    assert "exactly one positional path multiplier" in _find(result, "OC4010")[0].message
    assert _find(result, "OC4002")
    assert not _find(result, "OC4001")


def test_extra_hold_multiplier_cannot_satisfy_multicycle_pairing(audit_factory) -> None:
    result = audit_factory(
        """
set_multicycle_path 3 -setup -from [get_cells u_ff] -to [get_ports result]
set_multicycle_path 2 extra -hold -from [get_cells u_ff] -to [get_ports result]
"""
    )

    assert _find(result, "OC4010")
    assert any("no matching hold" in finding.message for finding in _find(result, "OC4011"))


@pytest.mark.parametrize(
    ("sdc", "rule_id"),
    [
        ("create_clock -name core -period {{10}} [get_ports clk]", "OC2001"),
        ("create_clock -name core -period 10 -waveform {{0 5}} [get_ports clk]", "OC2005"),
        ("create_clock -name core -period 10 -waveform {0,5} [get_ports clk]", "OC2005"),
        ("set_input_delay {{1}} [get_ports data]", "OC3010"),
        ("set_multicycle_path {{2}} -from [get_cells u_ff] -to [get_ports result]", "OC4010"),
        ("set_max_delay {{2}} -from [get_cells u_ff] -to [get_ports result]", "OC4002"),
    ],
)
def test_numeric_operands_are_tcl_decoded_exactly_once(audit_factory, sdc: str, rule_id: str) -> None:
    result = audit_factory(sdc)

    assert _find(result, rule_id)


def test_clock_name_is_tcl_decoded_exactly_once(audit_factory) -> None:
    result = audit_factory("create_clock -name {{core}} -period 10 [get_ports clk]")

    assert set(result.modes[0].clocks) == {"{core}"}
    assert result.modes[0].valid_clocks == frozenset({"{core}"})


def test_numeric_lists_use_tcl_list_rules_and_accept_quoted_elements(audit_factory) -> None:
    result = audit_factory('create_clock -name core -period { 10 } -waveform {"0" "5"} [get_ports clk]')

    clock = result.modes[0].clocks["core"]
    assert clock.period == 10.0
    assert clock.waveform == (0.0, 5.0)
    assert result.modes[0].valid_clocks == frozenset({"core"})
    assert not _find(result, "OC2001")
    assert not _find(result, "OC2005")


def test_opensta_integer_range_is_rejected_without_float_rounding(audit_factory) -> None:
    result = audit_factory("set_multicycle_path 9007199254740993 -from [get_cells u_ff] -to [get_ports result]")

    item = result.modes[0].exceptions[0]
    assert item.qualifiers["multiplier"] is None
    assert _find(result, "OC4010")
    assert "9007199254740992" not in json.dumps(result.to_dict(), sort_keys=True)
