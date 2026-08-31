from __future__ import annotations

import copy
import json
from datetime import date
from hashlib import sha256
from importlib import resources
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import openconstraint.adoption as adoption_module
from openconstraint.adoption import (
    FINGERPRINT_ALGORITHM,
    apply_adoption_controls,
    baseline_from_result,
    load_diagnostic_baseline,
    load_waivers,
    render_baseline,
)
from openconstraint.cli import main
from openconstraint.reporters.html import render_html
from openconstraint.reporters.json import render_json
from openconstraint.reporters.sarif import render_sarif
from openconstraint.reporters.text import render_text


def _json_file(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return path


def _waiver_payload(finding, **updates: object) -> dict[str, object]:
    entry: dict[str, object] = {
        "id": "reviewed-clock-query",
        "fingerprint": finding.fingerprint,
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "mode": finding.mode,
        "reason": "Reviewed against the integration specification in TICKET-123.",
        "expires": "2999-12-31",
    }
    entry.update(updates)
    return {"schema_version": "1.0.0", "kind": "openconstraint-waivers", "waivers": [entry]}


def test_exact_waiver_filters_quality_findings_but_preserves_review_provenance(audit_factory, tmp_path: Path) -> None:
    result = audit_factory("create_clock -name broken [get_ports absent]")
    raw_count = len(result.diagnostics)
    coverage_before = result.modes[0].coverage.to_dict()
    finding = result.modes[0].diagnostics[0]
    waiver_path = _json_file(tmp_path / "waivers.json", _waiver_payload(finding))
    waivers = load_waivers([waiver_path], today=date(2026, 8, 31))

    apply_adoption_controls(result, waivers=waivers)

    adoption = result.summary["adoption"]
    assert len(result.diagnostics) == raw_count - 1
    assert finding not in result.modes[0].diagnostics
    assert adoption["raw_diagnostic_count"] == raw_count
    assert adoption["waived_count"] == 1
    assert adoption["unused_waiver_count"] == 0
    assert adoption["waiver_sources"][0]["sha256"] == sha256(waiver_path.read_bytes()).hexdigest()
    assert adoption["dispositions"][0]["reason"].startswith("Reviewed")
    assert adoption["dispositions"][0]["diagnostic"]["fingerprint"] == finding.fingerprint
    assert result.modes[0].coverage.to_dict() == coverage_before
    assert render_json(result) == render_json(result)

    assert finding.fingerprint in render_text(result)
    assert "TICKET-123" in render_html(result)
    sarif = json.loads(render_sarif(result))
    controlled = next(
        item
        for item in sarif["runs"][0]["results"]
        if item["partialFingerprints"][FINGERPRINT_ALGORITHM] == finding.fingerprint
    )
    assert controlled["suppressions"][0]["status"] == "accepted"


def test_waiver_expiry_is_optional(audit_factory, tmp_path: Path) -> None:
    finding = audit_factory("create_clock -name broken [get_ports absent]").diagnostics[0]
    payload = _waiver_payload(finding)
    del payload["waivers"][0]["expires"]
    waiver = next(iter(load_waivers([_json_file(tmp_path / "permanent.json", payload)]).entries.values()))

    assert waiver.expires is None


def test_baseline_is_deterministic_validated_and_marks_matching_sarif_unchanged(audit_factory, tmp_path: Path) -> None:
    original = audit_factory("create_clock -name broken [get_ports absent]")
    payload = baseline_from_result(original)
    baseline_text = render_baseline(payload)
    assert baseline_text == render_baseline(baseline_from_result(original))
    fingerprints = [item["fingerprint"] for item in payload["diagnostics"]]
    assert fingerprints == sorted(fingerprints)
    baseline_path = tmp_path / "diagnostic-baseline.json"
    baseline_path.write_text(baseline_text, encoding="utf-8", newline="\n")

    result = copy.deepcopy(original)
    apply_adoption_controls(result, baseline=load_diagnostic_baseline(baseline_path), strict=True)

    assert result.diagnostics == []
    adoption = result.summary["adoption"]
    assert adoption["baselined_count"] == len(original.diagnostics)
    assert adoption["stale_baseline_count"] == 0
    assert adoption["strict_failure"] is False
    sarif_results = json.loads(render_sarif(result))["runs"][0]["results"]
    assert sarif_results
    assert {item["baselineState"] for item in sarif_results} == {"unchanged"}


def test_strict_controls_detect_stale_baseline_and_unused_waiver(audit_factory, tmp_path: Path) -> None:
    original = audit_factory("create_clock -name broken [get_ports absent]")
    payload = baseline_from_result(original)
    baseline_path = _json_file(tmp_path / "baseline.json", payload)
    reduced = copy.deepcopy(original)
    removed = reduced.diagnostics.pop()
    for mode in reduced.modes:
        mode.diagnostics = [finding for finding in mode.diagnostics if finding.fingerprint != removed.fingerprint]

    apply_adoption_controls(reduced, baseline=load_diagnostic_baseline(baseline_path), strict=True)

    adoption = reduced.summary["adoption"]
    assert adoption["stale_baseline_count"] == 1
    assert adoption["strict_failure"] is True

    unused_payload = _waiver_payload(original.diagnostics[0], fingerprint="0" * 20)
    unused_path = _json_file(tmp_path / "unused.json", unused_payload)
    unused_result = copy.deepcopy(original)
    apply_adoption_controls(
        unused_result,
        waivers=load_waivers([unused_path], today=date(2026, 8, 31)),
        strict=True,
    )
    assert unused_result.summary["adoption"]["unused_waiver_count"] == 1
    assert unused_result.summary["adoption"]["strict_failure"] is True


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"reason": "  "}, "reason"),
        ({"expires": None}, "expires"),
        ({"expires": "2025-01-01"}, "expired"),
        ({"expires": "2026-02-30"}, "calendar date"),
        ({"fingerprint": "ABC"}, "lowercase hexadecimal"),
        ({"rule_id": "bad"}, "OCdddd"),
        ({"severity": "fatal"}, "error, warning, or note"),
    ],
)
def test_waiver_validation_rejects_unreviewable_or_expired_entries(
    audit_factory, tmp_path: Path, updates: dict[str, object], message: str
) -> None:
    finding = audit_factory("create_clock -name broken [get_ports absent]").diagnostics[0]
    path = _json_file(tmp_path / "invalid.json", _waiver_payload(finding, **updates))

    with pytest.raises(ValueError, match=message):
        load_waivers([path], today=date(2026, 8, 31))


def test_control_loaders_reject_duplicate_keys_entries_and_unknown_fields(audit_factory, tmp_path: Path) -> None:
    finding = audit_factory("create_clock -name broken [get_ports absent]").diagnostics[0]
    duplicate_key = tmp_path / "duplicate-key.json"
    duplicate_key.write_text(
        '{"schema_version":"1.0.0","schema_version":"1.0.0","kind":"openconstraint-waivers","waivers":[]}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_waivers([duplicate_key])

    payload = _waiver_payload(finding)
    payload["waivers"].append(copy.deepcopy(payload["waivers"][0]))
    duplicate_entry = _json_file(tmp_path / "duplicate-entry.json", payload)
    with pytest.raises(ValueError, match="duplicate waiver id"):
        load_waivers([duplicate_entry])

    unknown = _waiver_payload(finding)
    unknown["unreviewed_escape_hatch"] = True
    unknown_path = _json_file(tmp_path / "unknown.json", unknown)
    with pytest.raises(ValueError, match="unknown field"):
        load_waivers([unknown_path])


def test_waiver_merge_rejects_duplicate_identity_across_files(audit_factory, tmp_path: Path) -> None:
    finding = audit_factory("create_clock -name broken [get_ports absent]").diagnostics[0]
    first = _json_file(tmp_path / "first.json", _waiver_payload(finding))
    second = _json_file(tmp_path / "second.json", _waiver_payload(finding, id="second-review"))

    with pytest.raises(ValueError, match="duplicate waiver fingerprint"):
        load_waivers([first, second], today=date(2026, 8, 31))


def test_control_loader_bounds_bytes_and_converts_recursion_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(adoption_module, "MAX_CONTROL_BYTES", 64)
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + b" " * 64 + b"}")
    with pytest.raises(ValueError, match="control-file limit"):
        load_waivers([oversized])

    monkeypatch.setattr(adoption_module, "MAX_CONTROL_BYTES", 100_000)
    nested = tmp_path / "nested.json"
    nested.write_text("{}", encoding="utf-8")

    def recurse(*_args: object, **_kwargs: object) -> object:
        raise RecursionError("maximum nesting")

    monkeypatch.setattr(adoption_module.json, "loads", recurse)
    with pytest.raises(ValueError, match="invalid waiver file JSON"):
        load_waivers([nested])


def test_metadata_mismatch_and_waiver_baseline_overlap_are_rejected(audit_factory, tmp_path: Path) -> None:
    original = audit_factory("create_clock -name broken [get_ports absent]")
    finding = original.diagnostics[0]
    mismatch_path = _json_file(tmp_path / "mismatch.json", _waiver_payload(finding, severity="note"))

    with pytest.raises(ValueError, match="metadata does not match"):
        apply_adoption_controls(
            copy.deepcopy(original),
            waivers=load_waivers([mismatch_path], today=date(2026, 8, 31)),
        )

    baseline_path = _json_file(tmp_path / "baseline.json", baseline_from_result(original))
    waiver_path = _json_file(tmp_path / "waiver.json", _waiver_payload(finding))
    with pytest.raises(ValueError, match="both waived and baselined"):
        apply_adoption_controls(
            copy.deepcopy(original),
            waivers=load_waivers([waiver_path], today=date(2026, 8, 31)),
            baseline=load_diagnostic_baseline(baseline_path),
        )


def test_control_application_and_baseline_generation_reject_already_controlled_results(
    audit_factory, tmp_path: Path
) -> None:
    result = audit_factory("create_clock -name broken [get_ports absent]")
    waiver_path = _json_file(tmp_path / "waiver.json", _waiver_payload(result.diagnostics[0]))
    waivers = load_waivers([waiver_path], today=date(2026, 8, 31))
    apply_adoption_controls(result, waivers=waivers)

    with pytest.raises(ValueError, match="already been applied"):
        apply_adoption_controls(result, waivers=waivers)
    with pytest.raises(ValueError, match="already controlled"):
        baseline_from_result(result)


def test_baseline_rejects_wrong_top_tampered_identity_and_duplicate_fingerprint(audit_factory, tmp_path: Path) -> None:
    original = audit_factory("create_clock -name broken [get_ports absent]")
    payload = baseline_from_result(original)
    wrong_top = copy.deepcopy(payload)
    wrong_top["design"]["top"] = "other"
    wrong_top_path = _json_file(tmp_path / "wrong-top.json", wrong_top)
    with pytest.raises(ValueError, match="does not match audited top"):
        apply_adoption_controls(copy.deepcopy(original), baseline=load_diagnostic_baseline(wrong_top_path))

    tampered = copy.deepcopy(payload)
    tampered["diagnostics"][0]["message"] += " changed"
    tampered_path = _json_file(tmp_path / "tampered.json", tampered)
    with pytest.raises(ValueError, match="does not match its diagnostic identity"):
        load_diagnostic_baseline(tampered_path)

    severity_changed = copy.deepcopy(payload)
    current_severity = severity_changed["diagnostics"][0]["severity"]
    severity_changed["diagnostics"][0]["severity"] = "note" if current_severity != "note" else "warning"
    severity_path = _json_file(tmp_path / "severity.json", severity_changed)
    with pytest.raises(ValueError, match="metadata does not match diagnostic"):
        apply_adoption_controls(copy.deepcopy(original), baseline=load_diagnostic_baseline(severity_path))

    duplicate = copy.deepcopy(payload)
    duplicate["diagnostics"].append(copy.deepcopy(duplicate["diagnostics"][0]))
    duplicate_path = _json_file(tmp_path / "duplicate.json", duplicate)
    with pytest.raises(ValueError, match="duplicate diagnostic baseline fingerprint"):
        load_diagnostic_baseline(duplicate_path)


def test_cli_can_write_and_enforce_a_diagnostic_baseline(project_files, tmp_path: Path, capsys) -> None:
    verilog, liberty, sdc = project_files(sdc="create_clock -name broken [get_ports absent]")
    baseline = tmp_path / "baseline.json"
    common = [
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

    assert main([*common, "--write-baseline", str(baseline), "--fail-on", "never"]) == 0
    capsys.readouterr()
    assert json.loads(baseline.read_text(encoding="utf-8"))["kind"] == "openconstraint-diagnostic-baseline"

    assert main([*common, "--baseline", str(baseline), "--strict-controls", "--fail-on", "warning"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["diagnostic_count"] == 0
    assert report["summary"]["adoption"]["baselined_count"] > 0
    assert report["summary"]["adoption"]["strict_failure"] is False


def test_cli_strict_controls_fail_stale_policy_even_with_fail_on_never(project_files, tmp_path: Path, capsys) -> None:
    verilog, liberty, sdc = project_files(sdc="create_clock -name broken [get_ports absent]")
    baseline = tmp_path / "baseline.json"
    common = [
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
        "--fail-on",
        "never",
    ]
    assert main([*common, "--write-baseline", str(baseline)]) == 0
    capsys.readouterr()
    sdc.write_text("", encoding="utf-8")

    assert main([*common, "--baseline", str(baseline), "--strict-controls"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["adoption"]["strict_failure"] is True
    assert report["summary"]["adoption"]["stale_baseline_count"] > 0


def test_cli_rejects_control_options_without_unambiguous_file_ownership(project_files, capsys) -> None:
    verilog, liberty, sdc = project_files(sdc="create_clock -name broken [get_ports absent]")
    common = [
        "audit",
        "--verilog",
        str(verilog),
        "--liberty",
        str(liberty),
        "--sdc",
        str(sdc),
        "--top",
        "top",
    ]
    for extra, message in (
        (["--strict-controls"], "requires --waivers or --baseline"),
        (["--write-baseline", "-"], "must name a file"),
    ):
        with pytest.raises(SystemExit) as caught:
            main([*common, *extra])
        assert caught.value.code == 2
        assert message in capsys.readouterr().err

    with pytest.raises(SystemExit) as caught:
        main([*common, "--baseline", "reviewed.json", "--write-baseline", "replacement.json"])
    assert caught.value.code == 2
    assert "not allowed with argument --baseline" in capsys.readouterr().err


def test_cli_rejects_baseline_path_that_all_format_would_overwrite(project_files, tmp_path: Path, capsys) -> None:
    verilog, liberty, sdc = project_files(sdc="create_clock -name broken [get_ports absent]")
    output = tmp_path / "reports"
    with pytest.raises(SystemExit) as caught:
        main(
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
                "all",
                "--output",
                str(output),
                "--write-baseline",
                str(output / "openconstraint-report.json"),
            ]
        )

    assert caught.value.code == 2
    assert "must not overlap" in capsys.readouterr().err


def test_cli_rejects_format_all_stdout_before_writing_baseline(project_files, tmp_path: Path, capsys) -> None:
    verilog, liberty, sdc = project_files(sdc="create_clock -name broken [get_ports absent]")
    baseline = tmp_path / "baseline.json"

    with pytest.raises(SystemExit) as caught:
        main(
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
                "all",
                "--output",
                "-",
                "--write-baseline",
                str(baseline),
            ]
        )

    assert caught.value.code == 2
    assert "requires --output to name a directory" in capsys.readouterr().err
    assert not baseline.exists()


def test_cli_rejects_write_baseline_that_overlaps_an_audit_input(project_files, capsys) -> None:
    verilog, liberty, sdc = project_files(sdc="create_clock -name broken [get_ports absent]")
    original = verilog.read_bytes()

    with pytest.raises(SystemExit) as caught:
        main(
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
                "--write-baseline",
                str(verilog),
            ]
        )

    assert caught.value.code == 2
    assert "--write-baseline path" in capsys.readouterr().err
    assert verilog.read_bytes() == original


def test_cli_rejects_report_outputs_that_overlap_waiver_or_baseline_inputs(
    audit_factory, project_files, tmp_path: Path, capsys
) -> None:
    result = audit_factory("create_clock -name broken [get_ports absent]")
    waiver = _json_file(tmp_path / "waivers.json", _waiver_payload(result.diagnostics[0]))
    baseline = _json_file(tmp_path / "baseline.json", baseline_from_result(result))
    verilog, liberty, sdc = project_files(sdc="create_clock -name core -period 10 [get_ports clk]")

    for option, protected in (("--waivers", waiver), ("--baseline", baseline)):
        original = protected.read_bytes()
        with pytest.raises(SystemExit) as caught:
            main(
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
                    option,
                    str(protected),
                    "--format",
                    "json",
                    "--output",
                    str(protected),
                ]
            )

        assert caught.value.code == 2
        assert f"must not overlap {option} input path" in capsys.readouterr().err
        assert protected.read_bytes() == original


def test_packaged_control_schemas_validate_generated_examples(audit_factory) -> None:
    result = audit_factory("create_clock -name broken [get_ports absent]")
    waiver = _waiver_payload(result.diagnostics[0])
    baseline = baseline_from_result(result)
    package = resources.files("openconstraint.schemas")
    for name, payload in (
        ("openconstraint-waivers.schema.json", waiver),
        ("openconstraint-diagnostic-baseline.schema.json", baseline),
    ):
        schema = json.loads(package.joinpath(name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(payload)


@pytest.mark.parametrize(
    ("kind", "title"),
    [
        ("report", "OpenConstraint audit report"),
        ("waivers", "OpenConstraint diagnostic waivers"),
        ("baseline", "OpenConstraint diagnostic baseline"),
    ],
)
def test_cli_exports_each_versioned_schema(kind: str, title: str, capsys) -> None:
    assert main(["schema", "--kind", kind]) == 0
    assert json.loads(capsys.readouterr().out)["title"] == title


def test_json_report_with_adoption_controls_validates_against_report_schema(audit_factory, tmp_path: Path) -> None:
    result = audit_factory("create_clock -name broken [get_ports absent]")
    waiver_path = _json_file(tmp_path / "waiver.json", _waiver_payload(result.diagnostics[0]))
    apply_adoption_controls(result, waivers=load_waivers([waiver_path], today=date(2026, 8, 31)))
    report = json.loads(render_json(result))
    schema = json.loads(
        resources.files("openconstraint.schemas")
        .joinpath("openconstraint-report.schema.json")
        .read_text(encoding="utf-8")
    )

    Draft202012Validator(schema).validate(report)
