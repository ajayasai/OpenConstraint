from __future__ import annotations

import copy
import json
from collections.abc import Callable
from importlib import resources
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from openconstraint.reporters.json import render_json


def _schema() -> dict[str, Any]:
    text = (
        resources.files("openconstraint.schemas")
        .joinpath("openconstraint-report.schema.json")
        .read_text(encoding="utf-8")
    )
    return json.loads(text)


def _report(audit_factory: Callable[..., object]) -> dict[str, Any]:
    result = audit_factory(
        """
create_clock -name core -period 10 -waveform {0 5} [get_ports clk]
set_input_delay 1 -clock core [all_inputs]
set_output_delay 2 -clock core [all_outputs]
set_false_path -from [get_ports data] -to [get_ports result]
set_input_delay 1 -clock core [get_ports absent]
"""
    )
    return json.loads(render_json(result))


@pytest.fixture
def report_validator() -> Draft202012Validator:
    schema = _schema()
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def test_schema_validates_every_static_report_section(
    audit_factory: Callable[..., object], report_validator: Draft202012Validator
) -> None:
    report = _report(audit_factory)

    report_validator.validate(report)
    assert report["modes"][0]["coverage"]["components"]
    assert report["modes"][0]["clocks"]
    assert report["modes"][0]["exceptions"]
    assert report["modes"][0]["graph"]["nodes"]
    assert report["modes"][0]["graph"]["edges"]
    assert report["diagnostics"]


def test_schema_validates_optional_opensta_summary(
    audit_factory: Callable[..., object], report_validator: Draft202012Validator
) -> None:
    report = _report(audit_factory)
    report["summary"]["opensta"] = {
        "version": "OpenSTA 2.7.0",
        "succeeded": False,
        "modes": [
            {
                "mode": "default",
                "succeeded": False,
                "return_code": None,
                "timed_out": True,
                "duration_seconds": 120.0,
                "effective_sdc_sha256": None,
                "stdout": "partial output",
                "stderr": "timed out",
            },
            {
                "mode": "scan",
                "succeeded": True,
                "return_code": 0,
                "timed_out": False,
                "duration_seconds": 0.125,
                "effective_sdc_sha256": "a" * 64,
                "stdout": "",
                "stderr": "",
            },
        ],
    }

    report_validator.validate(report)


def test_schema_keeps_design_and_evidence_as_forward_compatible_extension_points(
    audit_factory: Callable[..., object], report_validator: Draft202012Validator
) -> None:
    report = _report(audit_factory)
    report["design"]["hierarchy_depth"] = 3
    report["diagnostics"][0]["evidence"]["future_proof"] = {
        "objects": ["top/u_ff/D"],
        "confidence": 0.9,
    }

    report_validator.validate(report)


def _missing_mode_coverage_score(report: dict[str, Any]) -> None:
    del report["modes"][0]["coverage"]["score"]


def _invalid_clock_period(report: dict[str, Any]) -> None:
    report["modes"][0]["clocks"][0]["period"] = "10ns"


def _invalid_exception_through(report: dict[str, Any]) -> None:
    report["modes"][0]["exceptions"][0]["through"] = ["top/u_buf/A"]


def _missing_graph_edge_kind(report: dict[str, Any]) -> None:
    del report["modes"][0]["graph"]["edges"][0]["kind"]


def _invalid_diagnostic_fingerprint(report: dict[str, Any]) -> None:
    report["diagnostics"][0]["fingerprint"] = "unstable"


def _invalid_summary_coverage(report: dict[str, Any]) -> None:
    report["summary"]["coverage"]["default"] = "100%"


def _negative_design_inventory(report: dict[str, Any]) -> None:
    report["design"]["ports"] = -1


def _unexpected_structural_field(report: dict[str, Any]) -> None:
    report["modes"][0]["coverage"]["producer_typo"] = True


@pytest.mark.parametrize(
    "mutate",
    [
        _missing_mode_coverage_score,
        _invalid_clock_period,
        _invalid_exception_through,
        _missing_graph_edge_kind,
        _invalid_diagnostic_fingerprint,
        _invalid_summary_coverage,
        _negative_design_inventory,
        _unexpected_structural_field,
    ],
    ids=[
        "coverage-shape",
        "clock-shape",
        "exception-shape",
        "graph-shape",
        "diagnostic-shape",
        "summary-shape",
        "design-value",
        "unknown-structural-field",
    ],
)
def test_schema_rejects_malformed_nested_report_data(
    audit_factory: Callable[..., object],
    report_validator: Draft202012Validator,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    report = copy.deepcopy(_report(audit_factory))
    mutate(report)

    with pytest.raises(ValidationError):
        report_validator.validate(report)


def test_schema_rejects_incomplete_opensta_mode(
    audit_factory: Callable[..., object], report_validator: Draft202012Validator
) -> None:
    report = _report(audit_factory)
    report["summary"]["opensta"] = {
        "version": "OpenSTA 2.7.0",
        "succeeded": False,
        "modes": [
            {
                "mode": "default",
                "succeeded": False,
                "return_code": 1,
                "timed_out": False,
                "duration_seconds": 0.2,
                "effective_sdc_sha256": None,
                "stdout": "",
            }
        ],
    }

    with pytest.raises(ValidationError, match="stderr"):
        report_validator.validate(report)
