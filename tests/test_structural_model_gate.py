from __future__ import annotations

import json

from openconstraint.cli import main
from openconstraint.engine import ModeInput, audit
from openconstraint.model import Severity

from .conftest import COMPLETE_SDC, SYNTHETIC_VERILOG, write_text


def test_oc0002_is_one_design_error_with_bounded_evidence(tmp_path, design_factory) -> None:
    design = design_factory()
    design.warnings = [f"model warning {index:02d}" for index in range(55)]
    sdc = write_text(tmp_path / "complete.sdc", COMPLETE_SDC)

    result = audit(
        design,
        [ModeInput("functional", [str(sdc)]), ModeInput("scan", [str(sdc)])],
    )
    findings = [finding for finding in result.diagnostics if finding.rule_id == "OC0002"]

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.ERROR
    assert finding.mode == "design"
    assert finding.location.path == "<design>"
    assert finding.evidence == {
        "warning_count": 55,
        "warning_sample": design.warnings[:50],
        "omitted_warning_count": 5,
    }
    assert result.summary["errors"] == 1
    assert result.design["parser_warnings"] == design.warnings
    assert result.summary["coverage"] == {"functional": 0.0, "scan": 0.0}
    assert all(mode.coverage.score == 0.0 and mode.coverage.grade == "F" for mode in result.modes)


def test_default_cli_gate_fails_unsupported_structural_modeling(project_files, capsys) -> None:
    incomplete_verilog = SYNTHETIC_VERILOG.replace(
        "endmodule",
        "assign result = data & spare;\nendmodule",
    )
    verilog, liberty, sdc = project_files(verilog=incomplete_verilog)

    exit_code = main(
        [
            "audit",
            "--verilog",
            str(verilog),
            "--liberty",
            str(liberty),
            "--sdc",
            str(sdc),
            "--top",
            "top",
            "--format",
            "json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    finding = next(item for item in payload["diagnostics"] if item["rule_id"] == "OC0002")
    assert finding["severity"] == "error"
    assert finding["mode"] == "design"
    assert finding["evidence"]["warning_count"] == 1
    assert "ignored non-scalar assign" in finding["evidence"]["warning_sample"][0]
    assert payload["design"]["parser_warnings"] == finding["evidence"]["warning_sample"]
