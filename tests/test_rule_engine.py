from __future__ import annotations

import pytest

from openconstraint.engine import AuditOptions
from openconstraint.model import Severity
from openconstraint.rules import RULES

from .conftest import COMPLETE_SDC

EXPECTED_RULES = {
    "OC0001",
    "OC0002",
    "OC0003",
    "OC1001",
    "OC1002",
    "OC1003",
    "OC1004",
    "OC2001",
    "OC2002",
    "OC2003",
    "OC2004",
    "OC2005",
    "OC2006",
    "OC2010",
    "OC2011",
    "OC2012",
    "OC2101",
    "OC3001",
    "OC3002",
    "OC3010",
    "OC3011",
    "OC3012",
    "OC3013",
    "OC3014",
    "OC4001",
    "OC4002",
    "OC4010",
    "OC4011",
    "OC4012",
    "OC5001",
    "OC5002",
    "OC6001",
}


def _find(result, rule_id: str):
    return [finding for finding in result.diagnostics if finding.rule_id == rule_id]


def test_rule_catalog_is_stable_complete_and_unique() -> None:
    assert set(RULES) == EXPECTED_RULES
    assert all(rule.rule_id == key for key, rule in RULES.items())
    assert len({rule.name for rule in RULES.values()}) == len(RULES)
    assert {rule.default_severity for rule in RULES.values()} == {
        Severity.ERROR,
        Severity.WARNING,
        Severity.NOTE,
    }


def test_oc0001_malformed_sdc_is_reported_with_source_location(audit_factory) -> None:
    result = audit_factory("create_clock -name core -period 10 [get_ports clk\n")
    finding = _find(result, "OC0001")[0]

    assert finding.severity == Severity.ERROR
    assert finding.location.line == 2
    assert finding.location.path.endswith(".sdc")
    assert "unterminated command substitution" in finding.message
    assert result.modes[0].coverage.score == 0.0
    assert result.modes[0].coverage.grade == "F"


@pytest.mark.parametrize("command_name", ["if", "foreach", "proc", "source", "eval"])
def test_oc0003_unevaluated_tcl_control_fails_closed(audit_factory, command_name: str) -> None:
    bodies = {
        "if": "if {1} { set_false_path -from [get_ports missing] -to [get_ports result] }",
        "foreach": "foreach item {missing} { set_false_path -from [get_ports $item] -to [get_ports result] }",
        "proc": "proc apply_constraints {} { set_false_path -from [get_ports missing] -to [get_ports result] }",
        "source": "source generated-constraints.sdc",
        "eval": "eval {set_false_path -from [get_ports missing] -to [get_ports result]}",
    }
    result = audit_factory(COMPLETE_SDC + "\n" + bodies[command_name])
    finding = _find(result, "OC0003")[0]

    assert finding.severity == Severity.ERROR
    assert finding.evidence == {"command": command_name}
    assert result.modes[0].coverage.score == 0.0
    assert result.modes[0].coverage.grade == "F"


def test_oc0003_dynamic_command_dispatch_fails_closed(audit_factory) -> None:
    result = audit_factory(COMPLETE_SDC + "\n$constraint_command -from [get_ports missing]")
    finding = _find(result, "OC0003")[0]

    assert finding.evidence == {"command": "<dynamic>"}
    assert result.modes[0].coverage.score == 0.0
    assert result.modes[0].coverage.grade == "F"


def test_oc0003_tcl_argument_expansion_command_dispatch_fails_closed(audit_factory) -> None:
    result = audit_factory(COMPLETE_SDC + "\n{*}if {1} {set_false_path -to [all_outputs]}")
    finding = _find(result, "OC0003")[0]

    assert finding.evidence == {"command": "<dynamic>"}
    assert result.modes[0].coverage.score == 0.0


def test_backslash_substitution_canonicalizes_top_level_sdc_command(audit_factory) -> None:
    result = audit_factory(COMPLETE_SDC + "\n" + r"\set_false_path -from [get_ports missing] -to [get_ports result]")

    assert any(
        finding.rule_id == "OC1001" and finding.evidence["query"] == "[get_ports missing]"
        for finding in result.diagnostics
    )


def test_oc1001_zero_query_has_kind_and_universe_evidence(audit_factory) -> None:
    result = audit_factory("create_clock -name core -period 10 [get_ports absent]")
    finding = _find(result, "OC1001")[0]

    assert finding.severity == Severity.ERROR
    assert finding.evidence == {
        "query": "[get_ports absent]",
        "object_kind": "ports",
        "universe_size": 5,
        "matched_count": 0,
        "unmatched_patterns": ["absent"],
    }


def test_oc1001_reports_each_missed_pattern_even_when_the_collection_is_nonempty(audit_factory) -> None:
    result = audit_factory("set_false_path -from [get_ports {data miss_a miss_b}] -to [get_ports result]")
    finding = _find(result, "OC1001")[0]

    assert finding.message.startswith("Object query has 2 unmatched ports pattern(s)")
    assert finding.evidence == {
        "query": "[get_ports {data miss_a miss_b}]",
        "object_kind": "ports",
        "universe_size": 5,
        "matched_count": 1,
        "unmatched_patterns": ["miss_a", "miss_b"],
    }
    assert result.modes[0].exceptions[0].from_objects == {"data"}


def test_oc1001_audits_partial_misses_in_nested_of_objects_sources(audit_factory) -> None:
    result = audit_factory("set_false_path -from [get_cells -of_objects [get_nets {q absent}]] -to [get_ports result]")
    finding = _find(result, "OC1001")[0]

    assert finding.evidence["query"] == "[get_nets {q absent}]"
    assert finding.evidence["matched_count"] == 1
    assert finding.evidence["unmatched_patterns"] == ["absent"]
    assert result.modes[0].exceptions[0].from_objects == {"u_ff", "u_out"}
    query_health = next(
        component for component in result.modes[0].coverage.components if component.key == "query_health"
    )
    assert (query_health.covered, query_health.total) == (2, 3)


def test_oc1002_broad_query_threshold_is_configurable(audit_factory) -> None:
    sdc = "set_false_path -to [get_ports *]"
    permissive = audit_factory(
        sdc,
        options=AuditOptions(broad_match_count=100, broad_match_ratio=1.1, broad_match_min_universe=2),
    )
    strict = audit_factory(
        sdc,
        options=AuditOptions(broad_match_count=2, broad_match_ratio=0.5, broad_match_min_universe=2),
    )

    assert not _find(permissive, "OC1002")
    finding = _find(strict, "OC1002")[0]
    assert finding.severity == Severity.WARNING
    assert finding.evidence["matched_count"] == 5
    assert finding.evidence["sample"] == ["clk", "clk2", "data", "result", "spare"]


@pytest.mark.parametrize(
    ("selector", "expected_id", "reason_fragment"),
    [
        ("[get_ports $port_name]", "OC1003", "Tcl variable"),
        ("[get_ports -filter {name == data} *]", "OC1004", "unsupported static filter"),
    ],
)
def test_oc1003_and_oc1004_distinguish_dynamic_from_unsupported_queries(
    audit_factory, selector: str, expected_id: str, reason_fragment: str
) -> None:
    result = audit_factory(f"set_input_delay 1 {selector}")
    finding = _find(result, expected_id)[0]

    assert finding.severity == Severity.ERROR
    assert reason_fragment in finding.evidence["reason"]
    assert result.modes[0].coverage.score == 0.0
    assert result.modes[0].coverage.grade == "F"


def test_all_registers_selects_sequential_instances_without_false_zero_query(audit_factory) -> None:
    result = audit_factory(
        "set_false_path -from [all_registers] -to [get_ports result]",
        options=AuditOptions(broad_match_count=1, broad_match_ratio=0.01, broad_match_min_universe=1),
    )

    assert not _find(result, "OC1001")
    assert not _find(result, "OC1002")
    assert result.modes[0].exceptions[0].from_objects == {"u_ff"}


@pytest.mark.parametrize("period", ["0", "-1", "NaN", "not-a-number"])
def test_oc2001_rejects_each_nonpositive_or_nonfinite_clock_period(audit_factory, period: str) -> None:
    result = audit_factory(f"create_clock -name core -period {period} [get_ports clk]")
    finding = _find(result, "OC2001")[0]

    assert finding.severity == Severity.ERROR
    assert finding.evidence["period"] in {None, 0.0, -1.0}
    endpoint_coverage = next(
        component for component in result.modes[0].coverage.components if component.key == "sequential_endpoints"
    )
    assert endpoint_coverage.covered == 0
    assert _find(result, "OC2101")


def test_oc2002_records_valid_implicit_waveform_and_can_be_suppressed(audit_factory) -> None:
    sdc = "create_clock -name core -period 10 [get_ports clk]"
    reported = audit_factory(sdc)
    suppressed = audit_factory(sdc, options=AuditOptions(report_implicit_waveform=False))
    finding = _find(reported, "OC2002")[0]

    assert finding.severity == Severity.NOTE
    assert finding.evidence["implicit_waveform"] == [0.0, 5.0]
    assert not _find(suppressed, "OC2002")


def test_oc2006_rejects_multiple_primary_clock_target_arguments(audit_factory) -> None:
    result = audit_factory("create_clock -name core -period 10 [get_ports clk] [get_ports clk2]")
    finding = _find(result, "OC2006")[0]

    assert any(
        "accepts at most one positional target collection; got 2" in problem for problem in finding.evidence["problems"]
    )
    assert _find(result, "OC2101")


def test_primary_clock_allows_multiple_objects_in_one_collection(audit_factory) -> None:
    result = audit_factory("create_clock -name core -period 10 [get_ports {clk clk2}]")

    assert not _find(result, "OC2006")
    assert result.modes[0].clocks["core"].targets == {"clk", "clk2"}
    assert not _find(result, "OC2101")


def test_oc2003_conflicting_clock_redefinition_reports_previous_location(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 [get_ports clk]
create_clock -name core -period 20 [get_ports clk2]
"""
    )
    finding = _find(result, "OC2003")[0]

    assert finding.severity == Severity.ERROR
    assert finding.evidence["clock"] == "core"
    assert finding.evidence["previous_location"]["line"] == 1
    assert result.modes[0].clocks["core"].period == 20.0
    assert result.modes[0].clocks["core"].targets == {"clk2"}


def test_clean_additive_clock_merge_does_not_report_oc2003(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 [get_ports clk]
create_clock -add -name core -period 10 [get_ports clk2]
"""
    )

    assert not _find(result, "OC2003")
    assert result.modes[0].clocks["core"].targets == {"clk", "clk2"}


def test_oc2003_treats_any_semantic_clock_redefinition_as_error(audit_factory) -> None:
    changed = audit_factory(
        """
create_clock -name core -period 10 -waveform {0 5} [get_ports clk]
create_clock -name core -period 10 -waveform {1 6} [get_ports clk]
"""
    )
    identical = audit_factory(
        """
create_clock -name core -period 10 -waveform {0 5} [get_ports clk]
create_clock -name core -period 10 -waveform {0 5} [get_ports clk]
"""
    )

    assert _find(changed, "OC2003")[0].severity == Severity.ERROR
    assert _find(identical, "OC2003")[0].severity == Severity.WARNING


def test_oc2004_multiple_clocks_at_one_sequential_pin_reports_clock_map(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name first -period 10 -waveform {0 5} [get_ports clk]
create_clock -name second -period 20 -waveform {0 10} [get_ports clk]
"""
    )
    finding = _find(result, "OC2004")[0]

    assert finding.severity == Severity.WARNING
    assert finding.evidence["pins"] == {"u_ff/CK": ["first", "second"]}


@pytest.mark.parametrize("waveform", ["{0 5 8}", "{0 5 4 9}", "{0 25}", "{0 NaN}"])
def test_oc2005_rejects_invalid_explicit_clock_waveforms(audit_factory, waveform: str) -> None:
    result = audit_factory(f"create_clock -name core -period 10 -waveform {waveform} [get_ports clk]")
    finding = _find(result, "OC2005")[0]

    assert finding.severity == Severity.ERROR
    assert finding.evidence["problems"]
    assert not _find(result, "OC2002")
    endpoint_coverage = next(
        component for component in result.modes[0].coverage.components if component.key == "sequential_endpoints"
    )
    assert endpoint_coverage.covered == 0


def test_oc2010_generated_clock_missing_source_is_not_hidden_by_query_error(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 [get_ports clk]
create_generated_clock -name divided -divide_by 2 -source [get_pins absent] [get_pins u_ff/Q]
"""
    )
    finding = _find(result, "OC2010")[0]

    assert finding.severity == Severity.ERROR
    assert finding.evidence == {"clock": "divided"}
    assert _find(result, "OC1001")


def test_oc2011_generated_clock_master_must_reach_source(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 [get_ports clk]
create_generated_clock -name divided -master_clock core -divide_by 2 \
  -source [get_ports clk2] [get_pins u_ff/Q]
"""
    )
    finding = _find(result, "OC2011")[0]

    assert finding.severity == Severity.ERROR
    assert finding.evidence == {
        "clock": "divided",
        "source_targets": ["clk2"],
        "master": "core",
    }


@pytest.mark.parametrize("master", ["absent", "[get_ports clk]"])
def test_explicit_invalid_generated_master_is_not_replaced_by_inference(audit_factory, master: str) -> None:
    result = audit_factory(
        f"""
create_clock -name core -period 10 [get_ports clk]
create_generated_clock -name divided -master_clock {master} -divide_by 2 \
  -source [get_ports clk] [get_pins u_ff/Q]
"""
    )
    clock = result.modes[0].clocks["divided"]

    assert _find(result, "OC2012")
    assert clock.master_clock is None
    assert clock.period is None


def test_valid_generated_clock_derives_period_and_master_without_generated_clock_errors(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 -waveform {0 5} [get_ports clk]
create_generated_clock -name divided -divide_by 2 -source [get_ports clk] [get_pins u_ff/Q]
"""
    )
    clock = result.modes[0].clocks["divided"]

    assert not _find(result, "OC2010")
    assert not _find(result, "OC2011")
    assert clock.master_clock == "core"
    assert clock.period == 20.0


def test_oc2012_rejects_multiple_generated_clock_target_arguments(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 [get_ports clk]
create_generated_clock -name divided -divide_by 2 -source [get_ports clk] \
  [get_pins u_ff/Q] [get_ports result]
"""
    )
    finding = _find(result, "OC2012")[0]

    assert any(
        "requires exactly one positional target collection; got 2" in problem
        for problem in finding.evidence["problems"]
    )
    assert result.modes[0].clocks["divided"].period is None


@pytest.mark.parametrize(
    "transform",
    [
        "",
        "-divide_by 1.5",
        "-divide_by 2 -multiply_by 3",
        "-combinational -divide_by 2",
        "-edges {0 2 4}",
        "-edges {1 1 3}",
        "-edges {1 3 5} -edge_shift {0 1}",
        "-invert -edges {1 3 5}",
        "-duty_cycle 40 -divide_by 2",
    ],
)
def test_oc2012_rejects_invalid_generated_clock_transforms(audit_factory, transform: str) -> None:
    result = audit_factory(
        f"""
create_clock -name core -period 10 [get_ports clk]
create_generated_clock -name generated -source [get_ports clk] {transform} [get_pins u_ff/Q]
"""
    )

    assert _find(result, "OC2012")[0].severity == Severity.ERROR


def test_generated_clock_records_multiply_duty_cycle_and_derived_waveform(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 [get_ports clk]
create_generated_clock -name fast -source [get_ports clk] -multiply_by 2 -duty_cycle 40 [get_pins u_ff/Q]
"""
    )
    clock = result.modes[0].clocks["fast"]

    assert not _find(result, "OC2012")
    assert clock.period == 5.0
    assert clock.waveform == (0.0, 2.0)
    assert clock.multiply_by == 2
    assert clock.duty_cycle == 40.0


def test_generated_clock_edges_and_shifts_are_validated_and_derived(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 [get_ports clk]
create_generated_clock -name shaped -source [get_ports clk] -edges {1 3 5} \
  -edge_shift {0 1 2} [get_pins u_ff/Q]
"""
    )
    clock = result.modes[0].clocks["shaped"]

    assert not _find(result, "OC2012")
    assert clock.edges == (1, 3, 5)
    assert clock.edge_shift == (0.0, 1.0, 2.0)
    assert clock.waveform == (0.0, 11.0)
    assert clock.period == 22.0


def test_generated_clock_edges_index_full_master_waveform_and_preserve_phase(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 -waveform {2 4 7 9} [get_ports clk]
create_generated_clock -name shaped -source [get_ports clk] -edges {5 6 9} \
  -edge_shift {1 -0.5 2} [get_pins u_ff/Q]
"""
    )
    clock = result.modes[0].clocks["shaped"]

    assert not _find(result, "OC2012")
    assert clock.waveform == (13.0, 13.5)
    assert clock.period == 11.0


@pytest.mark.parametrize(
    ("transform", "period", "waveform"),
    [
        ("-divide_by 1", 10.0, (1.0, 3.0)),
        ("-divide_by 2", 20.0, (1.0, 11.0)),
        ("-divide_by 3", 30.0, (3.0, 9.0, 18.0, 24.0)),
        ("-multiply_by 2", 5.0, (0.5, 1.5, 3.0, 4.0)),
        ("-multiply_by 1", 10.0, (1.0, 3.0, 6.0, 8.0)),
    ],
)
def test_generated_clock_divide_multiply_waveforms_match_opensta(
    audit_factory, transform: str, period: float, waveform: tuple[float, ...]
) -> None:
    result = audit_factory(
        f"""
create_clock -name core -period 10 -waveform {{1 3 6 8}} [get_ports clk]
create_generated_clock -name derived -source [get_ports clk] {transform} [get_pins u_ff/Q]
"""
    )
    clock = result.modes[0].clocks["derived"]

    assert not _find(result, "OC2012")
    assert clock.period == period
    assert clock.waveform == waveform


def test_generated_combinational_clock_uses_opensta_divide_by_one_semantics(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 -waveform {1 3 6 8} [get_ports clk]
create_generated_clock -name gated -source [get_ports clk] -combinational [get_pins u_ff/Q]
"""
    )
    clock = result.modes[0].clocks["gated"]

    assert not _find(result, "OC2012")
    assert clock.divide_by == 1
    assert clock.period == 10.0
    assert clock.waveform == (1.0, 3.0)


@pytest.mark.parametrize(
    ("duty_cycle", "waveform"),
    [(0, (1.0, 2.5, 3.5, 4.5)), (40, (1.0, 3.0)), (100, (1.0, 6.0))],
)
def test_generated_clock_duty_cycle_boundaries_preserve_opensta_behavior(
    audit_factory, duty_cycle: int, waveform: tuple[float, ...]
) -> None:
    result = audit_factory(
        f"""
create_clock -name core -period 10 -waveform {{2 5 7 9}} [get_ports clk]
create_generated_clock -name fast -source [get_ports clk] -multiply_by 2 \
  -duty_cycle {duty_cycle} [get_pins u_ff/Q]
"""
    )
    clock = result.modes[0].clocks["fast"]

    assert not _find(result, "OC2012")
    assert clock.period == 5.0
    assert clock.waveform == waveform


@pytest.mark.parametrize(
    ("master_waveform", "waveform"),
    [("{2 5 7 9}", (2.5, 3.5, 4.5, 6.0)), ("{12 15}", (2.5, 6.0))],
)
def test_generated_clock_invert_rotates_edges_with_opensta_phase_offset(
    audit_factory, master_waveform: str, waveform: tuple[float, ...]
) -> None:
    result = audit_factory(
        f"""
create_clock -name core -period 10 -waveform {master_waveform} [get_ports clk]
create_generated_clock -name fast -source [get_ports clk] -multiply_by 2 -invert [get_pins u_ff/Q]
"""
    )
    clock = result.modes[0].clocks["fast"]

    assert not _find(result, "OC2012")
    assert clock.period == 5.0
    assert clock.waveform == waveform


def test_invalid_generated_values_are_not_retained_as_validated_clock_fields(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 [get_ports clk]
create_generated_clock -name bad -source [get_ports clk] -divide_by 0 [get_pins u_ff/Q]
"""
    )
    clock = result.modes[0].clocks["bad"]

    assert _find(result, "OC2012")
    assert clock.divide_by is None


def test_clock_comment_selector_fails_the_scalar_outer_command_closed(audit_factory) -> None:
    result = audit_factory("create_clock -name core -period 10 -comment [get_ports data] [get_ports clk]")

    assert "OC0003" in [finding.rule_id for finding in result.diagnostics]
    assert not result.modes[0].clocks
    assert result.modes[0].coverage.score == 0.0


def test_generated_clock_keeps_identical_source_and_target_selector_occurrences(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 [get_ports clk]
create_generated_clock -name divided -source [get_ports clk] -divide_by 2 [get_ports clk]
"""
    )

    divided = result.modes[0].clocks["divided"]
    assert divided.source_targets == {"clk"}
    assert divided.targets == {"clk"}
    assert not _find(result, "OC2012")


def test_oc2101_lists_every_unconstrained_endpoint(audit_factory) -> None:
    verilog = """
module top(input clk, input clk2, input data, input spare, output result);
  wire q0;
  wire q1;
  DFF first (.CK(clk), .D(data), .Q(q0));
  DFF second (.CK(clk2), .D(q0), .Q(q1));
  BUF out (.A(q1), .Y(result));
endmodule
"""
    result = audit_factory("create_clock -name only -period 10 [get_ports clk]", verilog=verilog)
    finding = _find(result, "OC2101")[0]

    assert finding.severity == Severity.ERROR
    assert finding.evidence["unconstrained_endpoints"] == ["second/D"]
    assert "1 of 2" in finding.message


def test_oc3001_and_oc3002_report_exact_missing_port_sets(audit_factory) -> None:
    result = audit_factory("create_clock -name core -period 10 -waveform {0 5} [get_ports clk]")
    input_finding = _find(result, "OC3001")[0]
    output_finding = _find(result, "OC3002")[0]

    assert input_finding.severity == Severity.WARNING
    assert input_finding.evidence["ports"] == ["clk2", "data", "spare"]
    assert output_finding.evidence["ports"] == ["result"]


def test_complete_io_delays_remove_oc3001_and_oc3002(audit_factory) -> None:
    result = audit_factory(COMPLETE_SDC)

    assert not _find(result, "OC3001")
    assert not _find(result, "OC3002")


@pytest.mark.parametrize(
    ("delay", "severity"),
    [("not-a-number", Severity.ERROR), ("[expr {$period / 4}]", Severity.WARNING)],
)
def test_oc3010_rejects_invalid_or_unresolved_io_delay_values(audit_factory, delay: str, severity: Severity) -> None:
    result = audit_factory(
        f"""
create_clock -name core -period 10 [get_ports clk]
set_input_delay {delay} -clock core [get_ports data]
"""
    )
    finding = _find(result, "OC3010")[0]

    assert finding.severity == severity
    assert "delay" in finding.evidence
    assert _find(result, "OC3001")


@pytest.mark.parametrize(
    ("command", "kind", "missing_rule", "missing_ports", "coverage_key", "coverage_total"),
    [
        (
            "set_input_delay 1 -clock core [get_ports data] [get_ports spare]",
            "input",
            "OC3001",
            {"data", "spare"},
            "input_delays",
            12,
        ),
        (
            "set_output_delay 2 -clock core [get_ports result] [all_outputs]",
            "output",
            "OC3002",
            {"result"},
            "output_delays",
            4,
        ),
    ],
)
def test_oc3010_rejects_extra_io_delay_target_argument_without_coverage(
    audit_factory,
    command: str,
    kind: str,
    missing_rule: str,
    missing_ports: set[str],
    coverage_key: str,
    coverage_total: int,
) -> None:
    result = audit_factory(
        f"""
create_clock -name core -period 10 [get_ports clk]
{command}
"""
    )

    finding = _find(result, "OC3010")[0]
    io_delay = result.modes[0].io_delays[0]
    component = next(item for item in result.modes[0].coverage.components if item.key == coverage_key)

    assert finding.severity == Severity.ERROR
    assert "positional-operand count" in finding.message
    assert len(finding.evidence["positionals"]) == 3
    assert finding.evidence["expected_positional_count"] == 2
    assert finding.evidence["actual_positional_count"] == 3
    assert io_delay.kind == kind
    assert io_delay.valid is False
    assert missing_ports <= set(_find(result, missing_rule)[0].evidence["ports"])
    assert (component.covered, component.total) == (0, coverage_total)


def test_io_delay_accepts_one_collection_containing_multiple_ports(audit_factory) -> None:
    result = audit_factory("set_input_delay 1 [get_ports {data spare}]")

    assert not _find(result, "OC3010")
    assert result.modes[0].io_delays[0].ports == frozenset({"data", "spare"})
    assert result.modes[0].io_delays[0].valid is True


def test_negative_io_delay_is_a_valid_finite_value(audit_factory) -> None:
    result = audit_factory("set_input_delay -min -1.25 [get_ports data]")

    assert not _find(result, "OC3010")
    assert "data" not in _find(result, "OC3001")[0].evidence["ports"]
    assert _find(result, "OC3013")


def test_oc3011_distinguishes_legal_clockless_delay_from_unknown_clock(audit_factory) -> None:
    clockless = audit_factory("set_input_delay 1 [get_ports data]")
    unknown = audit_factory("set_input_delay 1 -clock absent [get_ports data]")

    assert _find(clockless, "OC3011")[0].severity == Severity.NOTE
    assert _find(unknown, "OC3011")[0].severity == Severity.ERROR
    assert _find(clockless, "OC3001")[0].evidence["ports"] != ["data"]
    assert "data" in _find(unknown, "OC3001")[0].evidence["ports"]


def test_io_delay_referencing_an_invalid_clock_does_not_inflate_coverage(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name broken -period 0 [get_ports clk]
set_input_delay 1 -clock broken [get_ports data]
"""
    )

    assert _find(result, "OC3011")[0].severity == Severity.ERROR
    assert "data" in _find(result, "OC3001")[0].evidence["ports"]


def test_same_port_clock_relation_is_rejected_per_target_and_does_not_count(audit_factory) -> None:
    mixed = audit_factory(
        """
create_clock -name core -period 10 [get_ports clk]
set_input_delay 1 -clock core [get_ports {clk data}]
"""
    )
    rejected = audit_factory(
        """
create_clock -name output_clock -period 10 [get_ports result]
set_output_delay 1 -clock output_clock [get_ports result]
"""
    )

    finding = next(item for item in _find(mixed, "OC3011") if "same port" in item.message)
    assert finding.severity == Severity.ERROR
    assert finding.evidence == {"command": "set_input_delay", "ports": ["clk"], "clocks": ["core"]}
    assert mixed.modes[0].io_delays[0].ports == frozenset({"data"})
    assert mixed.modes[0].io_delays[0].valid is True
    assert rejected.modes[0].io_delays[0].ports == frozenset()
    assert rejected.modes[0].io_delays[0].valid is False
    assert "result" in _find(rejected, "OC3002")[0].evidence["ports"]


def test_reference_pin_must_resolve_to_exactly_one_port_or_pin(audit_factory) -> None:
    valid = audit_factory("set_input_delay 1 -reference_pin [get_pins u_ff/Q] [get_ports data]")
    item = valid.modes[0].io_delays[0]

    assert item.reference_pin == "u_ff/Q"
    assert item.valid is True
    assert "data" not in _find(valid, "OC3001")[0].evidence["ports"]

    for reference in ("[get_pins u_ff/*]", "[get_nets q]"):
        invalid = audit_factory(f"set_input_delay 1 -reference_pin {reference} [get_ports data]")
        finding = next(item for item in _find(invalid, "OC3011") if "-reference_pin" in item.message)

        assert finding.severity == Severity.ERROR
        assert invalid.modes[0].io_delays[0].reference_pin is None
        assert invalid.modes[0].io_delays[0].valid is False
        assert "data" in _find(invalid, "OC3001")[0].evidence["ports"]

    dynamic = audit_factory("set_input_delay 1 -reference_pin $reference_pin [get_ports data]")
    assert _find(dynamic, "OC0003")
    assert any("-reference_pin" in item.message for item in _find(dynamic, "OC3011"))
    assert not dynamic.modes[0].io_delays


@pytest.mark.parametrize(
    ("constraint", "reference_pin"),
    [
        ("set_output_delay 1 -reference_pin [all_inputs] [all_outputs]", "data"),
        ("set_input_delay 1 -reference_pin [all_outputs] [all_inputs]", "result"),
    ],
)
def test_reference_pin_accepts_singleton_all_input_and_output_collections(
    audit_factory, constraint: str, reference_pin: str
) -> None:
    verilog = """
module top(input data, output result);
  BUF u_buf (.A(data), .Y(result));
endmodule
"""
    result = audit_factory(constraint, verilog=verilog)
    item = result.modes[0].io_delays[0]

    assert item.reference_pin == reference_pin
    assert item.valid is True
    assert not [finding for finding in _find(result, "OC3011") if "-reference_pin" in finding.message]


def test_reference_pin_ignores_but_records_latency_inclusion_flags(audit_factory) -> None:
    result = audit_factory(
        "set_input_delay 1 -reference_pin u_ff/Q -source_latency_included -network_latency_included [get_ports data]"
    )
    item = result.modes[0].io_delays[0]
    finding = next(item for item in _find(result, "OC3011") if "ignored" in item.message)

    assert finding.severity == Severity.WARNING
    assert finding.evidence == {
        "command": "set_input_delay",
        "reference_pin": "u_ff/Q",
        "ignored_flags": ["-source_latency_included", "-network_latency_included"],
    }
    assert item.reference_pin == "u_ff/Q"
    assert item.source_latency_included is True
    assert item.network_latency_included is True
    assert item.valid is True


def test_oc3012_rejects_io_delay_on_wrong_port_direction(audit_factory) -> None:
    result = audit_factory("set_input_delay 1 [get_ports result]")
    finding = _find(result, "OC3012")[0]

    assert finding.severity == Severity.ERROR
    assert finding.evidence["ports"] == ["result"]
    assert "result" in _find(result, "OC3002")[0].evidence["ports"]


def test_oc3013_requires_min_and_max_when_one_analysis_sense_is_selected(audit_factory) -> None:
    incomplete = audit_factory("set_input_delay -max 1 [get_ports data]")
    complete = audit_factory(
        """
set_input_delay -max 1 [get_ports data]
set_input_delay -min 0 [get_ports data]
"""
    )

    finding = _find(incomplete, "OC3013")[0]
    assert finding.evidence == {
        "port": "data",
        "clock": [],
        "present": ["max"],
        "missing": ["min"],
        "missing_by_transition": {"fall": ["min"], "rise": ["min"]},
    }
    assert not _find(complete, "OC3013")
    assert not _find(complete, "OC3014")


def test_oc3013_combines_min_max_coverage_per_transition_slot(audit_factory) -> None:
    result = audit_factory(
        """
set_input_delay -min 0 [get_ports data]
set_input_delay -max -rise 1 [get_ports data]
set_input_delay -max -fall 2 [get_ports data]
"""
    )

    assert not _find(result, "OC3013")


def test_oc3014_detects_overwrite_but_honors_add_delay(audit_factory) -> None:
    overwritten = audit_factory(
        """
set_input_delay 1 [get_ports data]
set_input_delay 2 [get_ports data]
"""
    )
    additive = audit_factory(
        """
set_input_delay 1 [get_ports data]
set_input_delay -add_delay 2 [get_ports data]
"""
    )

    finding = _find(overwritten, "OC3014")[0]
    assert finding.evidence["min_max"] == ["max", "min"]
    assert finding.evidence["transitions"] == ["fall", "rise"]
    assert not _find(additive, "OC3014")


def test_oc3014_detects_clock_and_edge_relationship_replacement(audit_factory) -> None:
    switched_clock = audit_factory(
        """
create_clock -name core -period 10 -waveform {0 5} [get_ports clk]
create_clock -name aux -period 12 -waveform {0 6}
set_input_delay -min 1 -clock core [get_ports data]
set_input_delay 2 -clock aux [get_ports data]
"""
    )
    switched_edge = audit_factory(
        """
create_clock -name core -period 10 -waveform {0 5} [get_ports clk]
set_input_delay 1 -clock core [get_ports data]
set_input_delay -clock_fall 2 -clock core [get_ports data]
"""
    )

    clock_findings = _find(switched_clock, "OC3014")
    assert len(clock_findings) == 1
    clock_finding = clock_findings[0]
    assert clock_finding.evidence["clock"] == ["aux"]
    assert clock_finding.evidence["clock_edge"] == "rise"
    assert clock_finding.evidence["overwritten_relationships"] == [
        {
            "clock": ["core"],
            "clock_edge": "rise",
            "min_max": ["min"],
            "transitions": ["fall", "rise"],
            "locations": [{"path": clock_finding.location.path, "line": 3, "column": 1}],
            "reason": "relationship_removed",
            "slots": [
                {
                    "transition": "fall",
                    "min_max": "min",
                    "value": 1.0,
                    "location": {"path": clock_finding.location.path, "line": 3, "column": 1},
                },
                {
                    "transition": "rise",
                    "min_max": "min",
                    "value": 1.0,
                    "location": {"path": clock_finding.location.path, "line": 3, "column": 1},
                },
            ],
        }
    ]
    assert not _find(switched_clock, "OC3013")

    edge_findings = _find(switched_edge, "OC3014")
    assert len(edge_findings) == 1
    edge_finding = edge_findings[0]
    assert edge_finding.evidence["clock"] == ["core"]
    assert edge_finding.evidence["clock_edge"] == "fall"
    assert edge_finding.evidence["overwritten_relationships"][0]["clock_edge"] == "rise"
    assert edge_finding.evidence["overwritten_relationships"][0]["reason"] == "relationship_removed"
    assert not _find(switched_edge, "OC3013")


def test_oc3014_add_delay_retains_competing_incomplete_relationship(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 -waveform {0 5} [get_ports clk]
create_clock -name aux -period 12 -waveform {0 6}
set_input_delay -max 1 -clock core [get_ports data]
set_input_delay -add_delay 2 -clock aux [get_ports data]
"""
    )

    assert not _find(result, "OC3014")
    incomplete = _find(result, "OC3013")
    assert len(incomplete) == 1
    assert incomplete[0].evidence == {
        "port": "data",
        "clock": ["core"],
        "present": ["max"],
        "missing": ["min"],
        "missing_by_transition": {"fall": ["min"], "rise": ["min"]},
    }


def test_oc3014_reports_the_active_relationship_not_stale_history(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 -waveform {0 5} [get_ports clk]
create_clock -name aux -period 12 -waveform {0 6}
set_input_delay 1 -clock core [get_ports data]
set_input_delay 2 -clock aux [get_ports data]
set_input_delay 3 -clock core [get_ports data]
"""
    )

    findings = _find(result, "OC3014")
    assert len(findings) == 2
    second = findings[1]
    assert second.evidence["clock"] == ["core"]
    assert second.evidence["previous_location"]["line"] == 4
    assert second.evidence["overwritten_relationships"][0]["clock"] == ["aux"]
    assert second.evidence["overwritten_relationships"][0]["locations"][0]["line"] == 4


def test_oc4001_false_path_shadowing_multicycle_is_error_with_intersections(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 -waveform {0 5} [get_ports clk]
set_false_path -from [get_cells u_ff] -to [get_ports result]
set_multicycle_path 2 -from [get_cells u_ff] -to [get_ports result]
"""
    )
    finding = _find(result, "OC4001")[0]

    assert finding.severity == Severity.ERROR
    assert finding.evidence["from_intersection"] == ["u_ff"]
    assert finding.evidence["to_intersection"] == ["result"]
    assert finding.evidence["first"]["line"] == 2
    assert finding.evidence["second"]["line"] == 3


def test_oc4001_redundant_false_path_and_clock_group_is_note(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name a -period 10 -waveform {0 5} [get_ports clk]
create_clock -name b -period 20 -waveform {0 10} [get_ports clk2]
set_clock_groups -asynchronous -group [get_clocks a] -group [get_clocks b]
set_false_path -from [get_clocks a] -to [get_clocks b]
"""
    )
    findings = _find(result, "OC4001")

    assert any(finding.severity == Severity.NOTE for finding in findings)
    assert any("redundant" in finding.message for finding in findings)


def test_disjoint_exceptions_do_not_report_oc4001(audit_factory) -> None:
    result = audit_factory(
        """
set_false_path -from [get_ports data] -to [get_ports result]
set_multicycle_path 2 -from [get_ports spare] -to [get_pins u_ff/D]
"""
    )

    assert not _find(result, "OC4001")


def test_exception_overlap_respects_analysis_and_edge_qualifiers(audit_factory) -> None:
    result = audit_factory(
        """
set_false_path -setup -rise_from [get_cells u_ff] -to [get_ports result]
set_multicycle_path 2 -hold -fall_from [get_cells u_ff] -to [get_ports result]
"""
    )

    assert not _find(result, "OC4001")


def test_exception_overlap_respects_ordered_through_scopes(audit_factory) -> None:
    result = audit_factory(
        """
set_false_path -through [get_pins u_ff/D] -through [get_pins u_ff/Q] -to [get_ports result]
set_multicycle_path 2 -through [get_pins u_ff/Q] -through [get_pins u_ff/D] -to [get_ports result]
"""
    )

    assert not _find(result, "OC4001")


def test_clock_groups_allow_paths_does_not_act_like_a_path_cut(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 [get_ports clk]
create_clock -name aux -period 20 [get_ports clk2]
set_clock_groups -asynchronous -allow_paths -group [get_clocks core] -group [get_clocks aux]
set_multicycle_path 2 -from [get_clocks core] -to [get_clocks aux]
"""
    )

    assert not _find(result, "OC4001")


@pytest.mark.parametrize(
    ("constraint", "problem_fragment"),
    [
        (
            "set_false_path -from [get_nets q] -to [get_ports result]",
            "from-scope selectors",
        ),
        (
            "set_false_path -through [get_clocks core] -to [get_ports result]",
            "through-scope selectors",
        ),
    ],
)
def test_oc4002_rejects_selector_kinds_that_opensta_disallows_by_scope_role(
    audit_factory, constraint: str, problem_fragment: str
) -> None:
    result = audit_factory("create_clock -name core -period 10 [get_ports clk]\n" + constraint)
    finding = _find(result, "OC4002")[0]
    exception = result.modes[0].exceptions[0]

    assert any(problem_fragment in problem for problem in finding.evidence["problems"])
    assert exception.qualifiers["scope_resolvable"] is False


def test_exception_endpoint_accepts_all_clocks_selector(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 [get_ports clk]
set_false_path -from [all_clocks] -to [get_ports result]
"""
    )
    exception = result.modes[0].exceptions[0]

    assert not _find(result, "OC4002")
    assert exception.from_objects == {"core"}
    assert exception.qualifiers["definition_valid"] is True
    assert exception.qualifiers["scope_resolvable"] is True


@pytest.mark.parametrize(
    ("group_one", "problem_fragment"),
    [
        ("[get_ports clk]", "selectors must return clocks, not ports"),
        ("[get_clocks {core absent}]", "selector contains 1 unmatched clock pattern"),
    ],
)
def test_clock_groups_require_clock_typed_fully_resolved_selectors(
    audit_factory, group_one: str, problem_fragment: str
) -> None:
    result = audit_factory(
        f"""
create_clock -name core -period 10 [get_ports clk]
create_clock -name aux -period 20 [get_ports clk2]
set_clock_groups -asynchronous -group {group_one} -group [get_clocks aux]
"""
    )
    finding = next(item for item in _find(result, "OC4002") if "Clock-group" in item.message)

    assert any(problem_fragment in problem for problem in finding.evidence["problems"])
    assert not [item for item in result.modes[0].exceptions if item.kind == "clock_group"]


@pytest.mark.parametrize(
    "command",
    [
        "set_false_path -from missing -to result",
        "set_multicycle_path 2 -from missing -to result",
        "set_max_delay 5 -from missing -to result",
    ],
)
def test_oc4002_rejects_literal_exception_scopes_that_resolve_to_nothing(audit_factory, command: str) -> None:
    result = audit_factory(COMPLETE_SDC + "\n" + command)
    findings = _find(result, "OC4002")

    assert len(findings) == 1
    assert "the specified from scope resolves to no objects" in findings[0].evidence["problems"]


def test_oc4002_rejects_non_opensta_exclusive_clock_group_alias(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name a -period 10 [get_ports clk]
create_clock -name b -period 20 [get_ports clk2]
set_clock_groups -exclusive -group [get_clocks a] -group [get_clocks b]
"""
    )

    finding = _find(result, "OC4002")[0]
    assert "-exclusive is not an OpenSTA" in " ".join(finding.evidence["problems"])
    assert not result.modes[0].exceptions


@pytest.mark.parametrize("definition", ["1.5 -setup", "0 -setup", "-1 -hold", "2 -start -end"])
def test_oc4010_rejects_invalid_multicycle_semantics(audit_factory, definition: str) -> None:
    result = audit_factory(f"set_multicycle_path {definition} -from [get_cells u_ff] -to [get_ports result]")

    assert _find(result, "OC4010")[0].severity == Severity.ERROR


def test_oc4011_requires_reviewable_setup_hold_pairing(audit_factory) -> None:
    unpaired = audit_factory("set_multicycle_path 3 -setup -from [get_cells u_ff] -to [get_ports result]")
    paired = audit_factory(
        """
set_multicycle_path 3 -setup -from [get_cells u_ff] -to [get_ports result]
set_multicycle_path 2 -hold -from [get_cells u_ff] -to [get_ports result]
"""
    )
    implicit_both = audit_factory("set_multicycle_path 3 -from [get_cells u_ff] -to [get_ports result]")

    assert _find(unpaired, "OC4011")[0].evidence["expected_hold_multiplier"] == 2
    assert not _find(paired, "OC4011")
    assert "both setup and hold" in _find(implicit_both, "OC4011")[0].message


def test_oc4011_pairs_edge_qualified_setup_and_hold_across_reference_flags(audit_factory) -> None:
    result = audit_factory(
        """
set_multicycle_path 3 -setup -end -rise_from [get_cells u_ff] -fall_to [get_ports result]
set_multicycle_path 2 -hold -start -rise_from [get_cells u_ff] -fall_to [get_ports result]
"""
    )

    assert not _find(result, "OC4011")


def test_oc4012_detects_conflicting_multiplier_on_exact_qualified_scope(audit_factory) -> None:
    result = audit_factory(
        """
set_multicycle_path 2 -setup -rise_from [get_cells u_ff] -fall_to [get_ports result]
set_multicycle_path 3 -setup -rise_from [get_cells u_ff] -fall_to [get_ports result]
"""
    )
    finding = _find(result, "OC4012")[0]
    exception = result.modes[0].exceptions[0]

    assert finding.evidence["first_multiplier"] == 2
    assert finding.evidence["second_multiplier"] == 3
    assert exception.from_objects == {"u_ff"}
    assert exception.to_objects == {"result"}
    assert exception.qualifiers["from_transition"] == "rise"
    assert exception.qualifiers["to_transition"] == "fall"


@pytest.mark.parametrize(
    ("phase", "explicit_reference"),
    [("setup", "end"), ("hold", "start")],
)
def test_oc4012_normalizes_default_multicycle_clock_reference(
    audit_factory, phase: str, explicit_reference: str
) -> None:
    result = audit_factory(
        f"""
set_multicycle_path 2 -{phase} -from [get_cells u_ff] -to [get_ports result]
set_multicycle_path 3 -{phase} -{explicit_reference} -from [get_cells u_ff] -to [get_ports result]
"""
    )

    finding = _find(result, "OC4012")[0]
    assert finding.evidence["phase"] == phase
    assert finding.evidence["first_multiplier"] == 2
    assert finding.evidence["second_multiplier"] == 3


def test_edge_qualified_multicycle_scopes_do_not_conflate_rise_and_fall(audit_factory) -> None:
    result = audit_factory(
        """
set_multicycle_path 2 -setup -rise_from [get_cells u_ff] -to [get_ports result]
set_multicycle_path 3 -setup -fall_from [get_cells u_ff] -to [get_ports result]
"""
    )

    assert not _find(result, "OC4012")


def test_exception_through_groups_keep_lexical_order_across_edge_qualifiers(audit_factory) -> None:
    result = audit_factory(
        "set_false_path -fall -through [get_pins u_ff/D] -rise_through [get_pins u_ff/Q] "
        "-through [get_pins u_ff/CK] -to [get_ports result]"
    )
    exception = result.modes[0].exceptions[0]

    assert exception.through_objects == (
        frozenset({"u_ff/D"}),
        frozenset({"u_ff/Q"}),
        frozenset({"u_ff/CK"}),
    )
    assert exception.qualifiers["through_transitions"] == ["rise_fall", "rise", "rise_fall"]
    assert exception.qualifiers["end_transition"] == "fall"


def test_min_max_delay_flags_are_preserved_as_exception_qualifiers(audit_factory) -> None:
    result = audit_factory("set_max_delay -probe -ignore_clock_latency -from [get_ports data] -to [get_ports result] 2")
    exception = result.modes[0].exceptions[0]

    assert exception.from_objects == {"data"}
    assert exception.to_objects == {"result"}
    assert exception.qualifiers["delay"] == 2.0
    assert exception.qualifiers["probe"] is True
    assert exception.qualifiers["ignore_clock_latency"] is True


def test_zero_object_exception_scope_is_not_treated_as_unrestricted_overlap(audit_factory) -> None:
    result = audit_factory(
        """
set_false_path -from [get_cells absent] -to [get_ports result]
set_multicycle_path 2 -from [get_cells absent] -to [get_ports result]
"""
    )

    assert _find(result, "OC1001")
    assert not _find(result, "OC4001")
    assert not _find(result, "OC4012")


def test_oc5002_compares_through_order_and_exception_qualifiers(audit_factory) -> None:
    result = audit_factory(
        [
            (
                "functional",
                "set_multicycle_path 2 -setup -through [get_pins u_ff/D] -to [get_ports result]",
            ),
            (
                "scan",
                "set_multicycle_path 3 -setup -through [get_pins u_ff/D] -to [get_ports result]",
            ),
        ]
    )

    assert _find(result, "OC5002")[0].evidence["added_count"] == 1


def test_oc5001_clock_drift_compares_period_target_presence_and_mode(audit_factory) -> None:
    result = audit_factory(
        [
            ("functional", "create_clock -name core -period 10 [get_ports clk]"),
            ("scan", "create_clock -name core -period 100 [get_ports clk2]"),
        ]
    )
    finding = _find(result, "OC5001")[0]

    assert finding.mode == "cross-mode"
    assert finding.evidence["clock"] == "core"
    assert finding.evidence["definitions"] == {
        "functional": {
            "period": 10.0,
            "targets": ["clk"],
            "generated": False,
            "waveform": None,
            "waveform_explicit": False,
            "source_targets": [],
            "master_clock": None,
            "divide_by": None,
            "multiply_by": None,
            "duty_cycle": None,
            "invert": False,
            "combinational": False,
            "edges": None,
            "edge_shift": None,
        },
        "scan": {
            "period": 100.0,
            "targets": ["clk2"],
            "generated": False,
            "waveform": None,
            "waveform_explicit": False,
            "source_targets": [],
            "master_clock": None,
            "divide_by": None,
            "multiply_by": None,
            "duty_cycle": None,
            "invert": False,
            "combinational": False,
            "edges": None,
            "edge_shift": None,
        },
    }
    assert finding.evidence["missing_modes"] == []


def test_oc5001_reports_clock_missing_from_one_mode(audit_factory) -> None:
    result = audit_factory(
        [
            ("functional", "create_clock -name core -period 10 [get_ports clk]"),
            ("scan", "create_clock -name scan -period 100 [get_ports clk2]"),
        ]
    )

    drift = {finding.evidence["clock"]: finding for finding in _find(result, "OC5001")}
    assert drift["core"].evidence["missing_modes"] == ["scan"]
    assert drift["scan"].evidence["missing_modes"] == ["functional"]


def test_oc5002_exception_topology_drift_is_note_with_counts(audit_factory) -> None:
    result = audit_factory(
        [
            (
                "functional",
                "set_false_path -from [get_cells u_ff] -to [get_ports result]",
            ),
            (
                "scan",
                "set_multicycle_path 2 -from [get_cells u_ff] -to [get_ports result]",
            ),
        ]
    )
    finding = _find(result, "OC5002")[0]

    assert finding.severity == Severity.NOTE
    assert finding.mode == "cross-mode"
    assert finding.evidence == {
        "baseline": "functional",
        "compared": "scan",
        "added_count": 1,
        "removed_count": 1,
    }


def test_identical_modes_have_no_cross_mode_diagnostics(audit_factory) -> None:
    result = audit_factory([("functional", COMPLETE_SDC), ("scan", COMPLETE_SDC)])

    assert not _find(result, "OC5001")
    assert not _find(result, "OC5002")


def test_clock_propagation_follows_liberty_dependencies_without_cross_output_leakage(audit_factory) -> None:
    liberty = """
library (dependency) {
  cell (SPLIT) {
    pin (A)  { direction : input; }
    pin (B)  { direction : input; }
    pin (YA) { direction : output; function : "A"; }
    pin (YB) { direction : output; function : "B"; }
  }
  cell (DFF) {
    ff (IQ, IQN) { clocked_on : "CK"; next_state : "D"; }
    pin (CK) { direction : input; clock : true; }
    pin (D)  { direction : input; }
    pin (Q)  { direction : output; }
  }
}
"""
    verilog = """
module top(input clk, input spare, input d, output qa, output qb);
  wire ca, cb;
  SPLIT split (.A(clk), .B(spare), .YA(ca), .YB(cb));
  DFF a (.CK(ca), .D(d), .Q(qa));
  DFF b (.CK(cb), .D(d), .Q(qb));
endmodule
"""
    result = audit_factory(
        "create_clock -name core -period 10 [get_ports clk]",
        verilog=verilog,
        liberty=liberty,
    )

    endpoint_coverage = next(
        component for component in result.modes[0].coverage.components if component.key == "sequential_endpoints"
    )
    assert (endpoint_coverage.covered, endpoint_coverage.total) == (1, 2)
    assert _find(result, "OC2101")[0].evidence["unconstrained_endpoints"] == ["b/D"]


def test_unknown_liberty_dependencies_stop_propagation_and_invalidate_model(audit_factory) -> None:
    liberty = """
library (unknown_arc) {
  cell (OPAQUE) {
    pin (A) { direction : input; }
    pin (Y) { direction : output; }
  }
  cell (DFF) {
    ff (IQ, IQN) { clocked_on : "CK"; next_state : "D"; }
    pin (CK) { direction : input; clock : true; }
    pin (D)  { direction : input; }
    pin (Q)  { direction : output; }
  }
}
"""
    verilog = """
module top(input clk, input d, output q);
  wire gated;
  OPAQUE opaque (.A(clk), .Y(gated));
  DFF state (.CK(gated), .D(d), .Q(q));
endmodule
"""
    result = audit_factory(
        "create_clock -name core -period 10 [get_ports clk]",
        verilog=verilog,
        liberty=liberty,
    )

    assert _find(result, "OC0002")
    assert _find(result, "OC2101")[0].evidence["unconstrained_endpoints"] == ["state/D"]
