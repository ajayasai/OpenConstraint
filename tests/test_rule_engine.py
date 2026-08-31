from __future__ import annotations

import pytest

from openconstraint.engine import AuditOptions
from openconstraint.model import Severity
from openconstraint.rules import RULES

from .conftest import COMPLETE_SDC

EXPECTED_RULES = {
    "OC0001",
    "OC1001",
    "OC1002",
    "OC1003",
    "OC1004",
    "OC2001",
    "OC2002",
    "OC2003",
    "OC2004",
    "OC2010",
    "OC2011",
    "OC2101",
    "OC3001",
    "OC3002",
    "OC4001",
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


def test_oc1001_zero_query_has_kind_and_universe_evidence(audit_factory) -> None:
    result = audit_factory("create_clock -name core -period 10 [get_ports absent]")
    finding = _find(result, "OC1001")[0]

    assert finding.severity == Severity.ERROR
    assert finding.evidence == {
        "query": "[get_ports absent]",
        "object_kind": "ports",
        "universe_size": 5,
    }


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

    assert finding.severity == Severity.WARNING
    assert reason_fragment in finding.evidence["reason"]


def test_all_registers_selects_sequential_instances_without_false_zero_query(audit_factory) -> None:
    result = audit_factory("set_false_path -from [all_registers] -to [get_ports result]")

    assert not _find(result, "OC1001")
    assert result.modes[0].exceptions[0].from_objects == {"u_ff"}


@pytest.mark.parametrize("period", ["0", "-1", "NaN", "not-a-number"])
def test_oc2001_rejects_each_nonpositive_or_nonfinite_clock_period(audit_factory, period: str) -> None:
    result = audit_factory(f"create_clock -name core -period {period} [get_ports clk]")
    finding = _find(result, "OC2001")[0]

    assert finding.severity == Severity.ERROR
    assert finding.evidence["period"] in {None, 0.0, -1.0}


def test_oc2002_records_valid_implicit_waveform_and_can_be_suppressed(audit_factory) -> None:
    sdc = "create_clock -name core -period 10 [get_ports clk]"
    reported = audit_factory(sdc)
    suppressed = audit_factory(sdc, options=AuditOptions(report_implicit_waveform=False))
    finding = _find(reported, "OC2002")[0]

    assert finding.severity == Severity.NOTE
    assert finding.evidence["implicit_waveform"] == [0.0, 5.0]
    assert not _find(suppressed, "OC2002")


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
        "functional": (10.0, ("clk",), False),
        "scan": (100.0, ("clk2",), False),
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
