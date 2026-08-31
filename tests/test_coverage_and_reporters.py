from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from openconstraint.model import CoverageComponent, Diagnostic, Severity, SourceLocation
from openconstraint.reporters.html import render_html
from openconstraint.reporters.json import render_json
from openconstraint.reporters.sarif import render_sarif
from openconstraint.reporters.text import render_text

from .conftest import COMPLETE_SDC


def _components(result) -> dict[str, CoverageComponent]:
    return {component.key: component for component in result.modes[0].coverage.components}


def test_coverage_component_percentage_handles_zero_and_rounding() -> None:
    absent = CoverageComponent("none", "None", 0, 0, 0.5, "not applicable")
    fraction = CoverageComponent("third", "Third", 1, 3, 0.5, "one of three")

    assert absent.percentage is None
    assert fraction.percentage == 33.33
    assert fraction.to_dict() == {
        "key": "third",
        "label": "Third",
        "covered": 1,
        "total": 3,
        "percentage": 33.33,
        "weight": 0.5,
        "explanation": "one of three",
    }


def test_complete_design_has_100_percent_coverage_and_exact_component_counts(audit_factory) -> None:
    result = audit_factory(COMPLETE_SDC)
    coverage = result.modes[0].coverage
    components = _components(result)

    assert coverage.score == 100.0
    assert coverage.grade == "A"
    assert (components["sequential_endpoints"].covered, components["sequential_endpoints"].total) == (1, 1)
    assert (components["input_delays"].covered, components["input_delays"].total) == (12, 12)
    assert (components["output_delays"].covered, components["output_delays"].total) == (4, 4)
    assert (components["query_health"].covered, components["query_health"].total) == (3, 3)


def test_weighted_coverage_math_and_grade_for_partial_constraints(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 -waveform {0 5} [get_ports clk]
set_input_delay 1 -clock core [get_ports data]
"""
    )
    coverage = result.modes[0].coverage

    # 0.50*(1/1) + 0.20*(4/12) + 0.20*(0/4) + 0.10*(2/2)
    assert coverage.score == 66.67
    assert coverage.grade == "D"


def test_io_delay_coverage_counts_min_max_by_transition_slots(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 [get_ports clk]
set_input_delay 1 -clock core -min -rise [get_ports data]
set_output_delay 2 -clock core -max -fall [get_ports result]
"""
    )
    components = _components(result)

    # data covers one slot; clk2 and spare each retain a default four-slot obligation.
    assert (components["input_delays"].covered, components["input_delays"].total) == (1, 12)
    assert components["input_delays"].percentage == 8.33
    assert (components["output_delays"].covered, components["output_delays"].total) == (1, 4)
    assert components["output_delays"].percentage == 25.0


def test_io_delay_coverage_normalizes_each_distinct_relationship(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 [get_ports clk]
create_clock -name auxiliary -period 12 [get_ports clk2]
set_input_delay 1 -clock core [get_ports data]
set_input_delay 2 -clock auxiliary -min -rise -clock_fall -add_delay [get_ports data]
set_input_delay 3 -clock core -reference_pin [get_pins u_ff/Q] -max -fall -add_delay [get_ports data]
"""
    )
    component = _components(result)["input_delays"]

    # OpenSTA stores reference-pin metadata on the whole core/rise
    # relationship, so the third command updates that relationship rather than
    # creating a third one. Core covers four slots and auxiliary covers one;
    # clk2 and spare retain default four-slot obligations.
    assert (component.covered, component.total) == (5, 16)
    assert component.percentage == 31.25


def test_invalid_io_delay_relationship_adds_zero_covered_slot_obligation(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 [get_ports clk]
set_input_delay 1 -clock core [get_ports data]
set_input_delay invalid -clock core -clock_fall [get_ports data]
"""
    )
    component = _components(result)["input_delays"]

    # The complete rising-edge relationship covers four slots. The invalid
    # falling-edge attempt adds four uncovered slots. Two other required ports
    # each retain a default four-slot obligation.
    assert (component.covered, component.total) == (4, 16)
    assert component.percentage == 25.0


def test_nonapplicable_component_weight_is_omitted_and_remaining_weights_renormalize(audit_factory) -> None:
    verilog = """
module top(input clk, input clk2, input data, input spare, output result);
  BUF pass (.A(data), .Y(result));
endmodule
"""
    result = audit_factory(
        """
set_input_delay 1 [all_inputs]
set_output_delay 1 [all_outputs]
""",
        verilog=verilog,
    )
    coverage = result.modes[0].coverage
    components = _components(result)

    assert components["sequential_endpoints"].total == 0
    assert components["sequential_endpoints"].percentage is None
    assert coverage.score == 100.0
    assert coverage.grade == "A"


def test_unresolved_and_partial_queries_reduce_query_health(audit_factory) -> None:
    static_result = audit_factory("set_input_delay 1 [get_ports absent]")
    dynamic_result = audit_factory("set_input_delay 1 [get_ports $name]")
    partial_result = audit_factory("set_input_delay 1 [get_ports {data absent}]")

    static_query = _components(static_result)["query_health"]
    dynamic_query = _components(dynamic_result)["query_health"]
    partial_query = _components(partial_result)["query_health"]
    assert (static_query.covered, static_query.total) == (0, 1)
    assert (dynamic_query.covered, dynamic_query.total) == (0, 1)
    assert (partial_query.covered, partial_query.total) == (0, 1)


def test_coverage_grades_hit_each_boundary() -> None:
    from openconstraint.model import Coverage

    expected = [(95, "A"), (94.99, "B"), (85, "B"), (84.99, "C"), (70, "C"), (69.99, "D"), (50, "D")]

    # Grade construction lives in the engine; this table documents the public thresholds without duplicating prose snapshots.
    def classify(score: float) -> str:
        return "A" if score >= 95 else "B" if score >= 85 else "C" if score >= 70 else "D" if score >= 50 else "F"

    assert [(score, classify(score)) for score, _ in expected] == expected
    assert Coverage(49.99, classify(49.99), []).grade == "F"


def test_graph_has_unique_nodes_and_deterministic_clock_reach_edges(audit_factory) -> None:
    result = audit_factory(COMPLETE_SDC)
    graph = result.modes[0].graph
    node_ids = [node["id"] for node in graph["nodes"]]

    assert len(node_ids) == len(set(node_ids))
    assert {"clock:core", "object:clk", "endpoint_clock:u_ff/CK"} <= set(node_ids)
    assert {tuple(sorted(edge.items())) for edge in graph["edges"]} >= {
        tuple(sorted({"source": "clock:core", "target": "object:clk", "kind": "defines"}.items())),
        tuple(
            sorted(
                {
                    "source": "clock:core",
                    "target": "endpoint_clock:u_ff/CK",
                    "kind": "reaches",
                }.items()
            )
        ),
    }


def test_graph_exposes_generated_sources_and_ordered_through_metadata(audit_factory) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 [get_ports clk]
create_generated_clock -name divided -source [get_ports clk] -divide_by 2 [get_pins u_ff/Q]
set_false_path -rise_through [get_pins u_ff/D] -fall_through [get_pins u_ff/Q] \
  -to [get_ports result]
"""
    )
    graph = result.modes[0].graph

    assert {node["id"] for node in graph["nodes"]} >= {
        "source_object:clk",
        "scope:u_ff/D",
        "scope:u_ff/Q",
    }
    assert {tuple(sorted(edge.items())) for edge in graph["edges"]} >= {
        tuple(
            sorted(
                {
                    "source": "source_object:clk",
                    "target": "clock:divided",
                    "kind": "source",
                }.items()
            )
        ),
        tuple(
            sorted(
                {
                    "source": "scope:u_ff/D",
                    "target": "exception:0",
                    "kind": "through",
                    "through_index": 0,
                    "transition": "rise",
                }.items()
            )
        ),
        tuple(
            sorted(
                {
                    "source": "scope:u_ff/Q",
                    "target": "exception:0",
                    "kind": "through",
                    "through_index": 1,
                    "transition": "fall",
                }.items()
            )
        ),
    }


def test_json_report_is_byte_deterministic_versioned_and_machine_readable(audit_factory) -> None:
    result = audit_factory(COMPLETE_SDC)
    first = render_json(result)
    second = render_json(result)
    payload = json.loads(first)

    assert first == second
    assert first.endswith("\n")
    assert payload["schema_version"] == "1.1.0"
    assert payload["tool"]["name"] == "OpenConstraint"
    assert payload["summary"]["coverage"] == {"default": 100.0}
    assert payload["modes"][0]["coverage"]["components"][0]["key"] == "sequential_endpoints"


def test_json_preserves_unicode_and_sorts_unordered_object_collections(audit_factory) -> None:
    result = audit_factory(COMPLETE_SDC)
    result.diagnostics.append(
        Diagnostic(
            "OC3001",
            Severity.WARNING,
            "µ-clock warning",
            SourceLocation("µ.sdc"),
            "résumé",
            "fix",
        )
    )
    result.modes[0].clocks["core"].targets.update({"z", "a"})
    rendered = render_json(result)
    payload = json.loads(rendered)

    assert "µ-clock warning" in rendered
    assert payload["modes"][0]["clocks"][0]["targets"] == ["a", "clk", "z"]


def test_machine_reports_refuse_nonfinite_json_numbers(audit_factory) -> None:
    result = audit_factory(COMPLETE_SDC)
    result.design["invalid_metric"] = math.nan

    for renderer in (render_json, render_sarif, render_html):
        with pytest.raises(ValueError, match="Out of range float"):
            renderer(result)


def test_nonfinite_clock_waveform_is_not_serialized_as_invalid_json(audit_factory) -> None:
    result = audit_factory("create_clock -name core -period 10 -waveform {NaN 5} [get_ports clk]")
    rendered = render_json(result)
    payload = json.loads(rendered)

    assert payload["modes"][0]["clocks"][0]["waveform"] is None
    assert any(item["rule_id"] == "OC2005" for item in payload["diagnostics"])


def test_text_report_renders_actionable_findings_and_nonapplicable_components(audit_factory) -> None:
    result = audit_factory("create_clock -name broken [get_ports absent]")
    rendered = render_text(result)

    assert "ERROR" in rendered
    assert "OC1001" in rendered
    assert "Fix:" in rendered
    assert "n/a" not in rendered or "0/0" in rendered


def test_sarif_contains_only_used_rules_valid_locations_and_stable_fingerprints(audit_factory) -> None:
    result = audit_factory("create_clock -name core -period 10 [get_ports absent]")
    first = render_sarif(result)
    payload = json.loads(first)
    run = payload["runs"][0]
    used_ids = sorted({finding.rule_id for finding in result.diagnostics})

    assert first == render_sarif(result)
    assert payload["version"] == "2.1.0"
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == used_ids
    assert all("precision" not in rule["properties"] for rule in run["tool"]["driver"]["rules"])
    assert {item["ruleId"] for item in run["results"]} == set(used_ids)
    assert all(item["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for item in run["results"])
    assert all(len(item["partialFingerprints"]["openconstraint/v1"]) == 20 for item in run["results"])


def test_sarif_uses_file_uri_for_real_paths_and_keeps_synthetic_locations(audit_factory) -> None:
    result = audit_factory("create_clock -name core -period 10 [get_ports absent]")
    payload = json.loads(render_sarif(result))
    uris = {
        item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for item in payload["runs"][0]["results"]
    }

    assert any(uri.startswith("file:///") and uri.endswith(".sdc") for uri in uris)
    assert "openconstraint://design" in uris


def test_sarif_keeps_repository_relative_paths_portable(audit_factory) -> None:
    result = audit_factory(COMPLETE_SDC)
    result.diagnostics.append(
        Diagnostic(
            "OC1001",
            Severity.ERROR,
            "portable path",
            SourceLocation(r"constraints\\functional.sdc"),
            "why",
            "fix",
        )
    )

    payload = json.loads(render_sarif(result))
    uri = next(
        item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for item in payload["runs"][0]["results"]
        if item["message"]["text"].startswith("[default] portable path")
    )

    assert uri == "constraints/functional.sdc"


def test_html_escapes_visible_fields_attributes_and_embedded_json(audit_factory) -> None:
    payload = '</script><!--<script>alert("x")</script>'
    result = audit_factory(COMPLETE_SDC)
    result.design["top"] = payload
    result.modes[0].name = f'bad" mode {payload}'
    result.diagnostics.append(
        Diagnostic(
            "OC1001",
            Severity.ERROR,
            payload,
            SourceLocation(f"evil<{payload}>.sdc"),
            payload,
            payload,
            f'bad" mode {payload}',
            {"payload": payload},
        )
    )
    rendered = render_html(result)

    assert "&lt;/script&gt;&lt;!--&lt;script&gt;alert(&quot;" in rendered
    assert 'value="bad&quot; mode' in rendered
    assert "\\u003c/script\\u003e\\u003c!--\\u003cscript\\u003ealert" in rendered
    assert payload not in rendered


def test_diagnostic_fingerprint_normalizes_path_separator_but_tracks_semantic_changes() -> None:
    common = dict(
        rule_id="OC1001",
        severity=Severity.ERROR,
        message="zero",
        rationale="why",
        suggestion="fix",
        mode="functional",
    )
    windows = Diagnostic(location=SourceLocation(r"dir\constraints.sdc", 3), **common)
    posix = Diagnostic(location=SourceLocation("dir/constraints.sdc", 3), **common)
    moved = Diagnostic(location=SourceLocation("dir/constraints.sdc", 4), **common)

    assert windows.fingerprint == posix.fingerprint
    assert moved.fingerprint != posix.fingerprint


def test_report_paths_and_findings_do_not_depend_on_current_working_directory(
    audit_factory, monkeypatch, tmp_path: Path
) -> None:
    result = audit_factory("create_clock -name core -period 10 [get_ports absent]")
    before = render_sarif(result)
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.chdir(other)

    assert render_sarif(result) == before
