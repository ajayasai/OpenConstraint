from __future__ import annotations

import errno
import json
import os
import stat
from pathlib import Path

import pytest

from openconstraint.cli import _mode_inputs, _write, main

from .conftest import COMPLETE_SDC


def _audit_args(verilog: Path, liberty: Path, sdc: Path) -> list[str]:
    return [
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


def test_cli_rules_text_and_json_expose_the_same_stable_catalog(capsys) -> None:
    assert main(["rules"]) == 0
    text = capsys.readouterr().out
    assert "OC0001" in text
    assert "OC5002" in text

    assert main(["rules", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert [item["id"] for item in payload] == sorted(item["id"] for item in payload)
    assert {item["id"] for item in payload} == {
        "OC0001",
        "OC0002",
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


def test_cli_schema_stdout_is_valid_json_schema(capsys) -> None:
    assert main(["schema"]) == 0
    schema = json.loads(capsys.readouterr().out)

    assert schema["$schema"].endswith("schema")
    assert schema["title"] == "OpenConstraint audit report"
    assert "modes" in schema["required"]


def test_cli_schema_can_be_copied_to_file(tmp_path: Path) -> None:
    output = tmp_path / "schema.json"

    assert main(["schema", "--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["title"] == "OpenConstraint audit report"


def test_cli_atomic_single_file_preserves_existing_permission_mode(tmp_path: Path) -> None:
    output = tmp_path / "schema.json"
    output.write_text("reviewed\n", encoding="utf-8")
    output.chmod(0o640)
    expected_mode = stat.S_IMODE(output.stat().st_mode)

    assert main(["schema", "--output", str(output)]) == 0

    assert stat.S_IMODE(output.stat().st_mode) == expected_mode
    assert json.loads(output.read_text(encoding="utf-8"))["title"] == "OpenConstraint audit report"


def test_cli_atomic_single_file_preserves_final_symlink(tmp_path: Path) -> None:
    referent = tmp_path / "referent.json"
    referent.write_text("reviewed\n", encoding="utf-8")
    output = tmp_path / "schema.json"
    try:
        output.symlink_to(referent)
    except OSError as error:
        pytest.skip(f"file symlinks are unavailable: {error}")

    assert main(["schema", "--output", str(output)]) == 0

    assert output.is_symlink()
    assert output.resolve() == referent.resolve()
    assert json.loads(referent.read_text(encoding="utf-8"))["title"] == "OpenConstraint audit report"


def test_cli_atomic_single_file_reports_final_symlink_loop_as_input_error(tmp_path: Path, capsys) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    try:
        first.symlink_to(second)
        second.symlink_to(first)
    except OSError as error:
        pytest.skip(f"file symlinks are unavailable: {error}")

    with pytest.raises(SystemExit) as caught:
        main(["schema", "--output", str(first)])

    assert caught.value.code == 2
    error = capsys.readouterr().err
    assert "could not resolve output path" in error
    assert "Traceback" not in error


def test_cli_atomic_single_file_classifies_win32_resolve_loop_as_input_error(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "schema.json"
    resolve_error = OSError(errno.EINVAL, "cannot resolve filename")
    resolve_error.winerror = 1921
    real_resolve = Path.resolve

    def fail_output_resolve(path: Path, strict: bool = False) -> Path:
        if path == output:
            raise resolve_error
        return real_resolve(path, strict=strict)

    monkeypatch.setattr(Path, "resolve", fail_output_resolve)
    with pytest.raises(SystemExit) as caught:
        main(["schema", "--output", str(output)])

    assert caught.value.code == 2
    error = capsys.readouterr().err
    assert "could not resolve output path" in error
    assert "Traceback" not in error


@pytest.mark.skipif(os.name == "nt", reason="POSIX umask semantics")
def test_cli_atomic_new_file_respects_process_umask(tmp_path: Path) -> None:
    output = tmp_path / "schema.json"
    previous_umask = os.umask(0o027)
    try:
        assert main(["schema", "--output", str(output)]) == 0
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(output.stat().st_mode) == 0o640


@pytest.mark.skipif(
    os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root can open a read-only file for writing",
)
def test_cli_atomic_single_file_honors_existing_read_only_policy(tmp_path: Path, capsys) -> None:
    output = tmp_path / "schema.json"
    original = b"reviewed\n"
    output.write_bytes(original)
    output.chmod(stat.S_IREAD)
    try:
        with pytest.raises(SystemExit) as caught:
            main(["schema", "--output", str(output)])
    finally:
        output.chmod(stat.S_IREAD | stat.S_IWRITE)

    assert caught.value.code == 2
    assert "input error" in capsys.readouterr().err
    assert output.read_bytes() == original


@pytest.mark.skipif(os.name == "nt", reason="POSIX NAME_MAX semantics")
def test_cli_atomic_single_file_supports_near_name_max_target(tmp_path: Path) -> None:
    name_max = os.pathconf(tmp_path, "PC_NAME_MAX")
    suffix = ".json"
    output = tmp_path / ("r" * (name_max - len(suffix)) + suffix)

    assert main(["schema", "--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["title"] == "OpenConstraint audit report"


def test_atomic_writer_cleanup_error_does_not_mask_replace_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "schema.json"
    output.write_text("reviewed\n", encoding="utf-8")
    original_unlink = Path.unlink

    def fail_replace(source: object, destination: object) -> None:
        raise OSError(f"primary replacement failure for {source!s} -> {destination!s}")

    def fail_temporary_cleanup(path: Path, *args, **kwargs) -> None:
        if path.name.startswith(".openconstraint-"):
            raise OSError("secondary cleanup failure")
        original_unlink(path, *args, **kwargs)

    monkeypatch.setattr("openconstraint.cli.os.replace", fail_replace)
    monkeypatch.setattr(Path, "unlink", fail_temporary_cleanup)

    with pytest.raises(OSError, match="primary replacement failure") as caught:
        _write("replacement\n", str(output))

    assert any("secondary cleanup failure" in note for note in caught.value.__notes__)
    assert output.read_text(encoding="utf-8") == "reviewed\n"


def test_cli_audit_json_stdout_and_success_exit_for_complete_design(project_files, capsys) -> None:
    verilog, liberty, sdc = project_files(sdc=COMPLETE_SDC)
    code = main([*_audit_args(verilog, liberty, sdc), "--format", "json", "--no-implicit-waveform-note"])
    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert payload["summary"]["coverage"] == {"default": 100.0}
    assert payload["summary"]["errors"] == 0


def test_cli_fail_on_error_does_not_fail_warnings_but_fail_on_warning_does(project_files, capsys) -> None:
    verilog, liberty, sdc = project_files(sdc="create_clock -name core -period 10 -waveform {0 5} [get_ports clk]")
    args = [*_audit_args(verilog, liberty, sdc), "--format", "json"]

    assert main([*args, "--fail-on", "error"]) == 0
    capsys.readouterr()
    assert main([*args, "--fail-on", "warning"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["warnings"] >= 1


def test_cli_fail_on_never_allows_diagnostics_but_not_minimum_coverage_failure(project_files, capsys) -> None:
    verilog, liberty, sdc = project_files(sdc="create_clock -name core -period 0 [get_ports clk]")
    args = [*_audit_args(verilog, liberty, sdc), "--format", "json", "--fail-on", "never"]

    assert main(args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["errors"] >= 1

    assert main([*args, "--min-coverage", "100"]) == 1
    capsys.readouterr()


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--min-coverage", "nan"),
        ("--min-coverage", "-1"),
        ("--min-coverage", "100.01"),
        ("--broad-match-count", "-1"),
        ("--broad-match-ratio", "nan"),
        ("--broad-match-ratio", "-0.1"),
        ("--broad-match-ratio", "1.1"),
    ],
)
def test_cli_rejects_invalid_numeric_policy_values(project_files, capsys, option: str, value: str) -> None:
    verilog, liberty, sdc = project_files(sdc=COMPLETE_SDC)

    with pytest.raises(SystemExit) as caught:
        main([*_audit_args(verilog, liberty, sdc), option, value])

    assert caught.value.code == 2
    assert "must be" in capsys.readouterr().err


def test_cli_writes_each_single_format_and_trailing_newline(project_files, tmp_path: Path) -> None:
    verilog, liberty, sdc = project_files(sdc=COMPLETE_SDC)
    for output_format, suffix in (("text", "txt"), ("json", "json"), ("sarif", "sarif"), ("html", "html")):
        output = tmp_path / f"report.{suffix}"
        assert main([*_audit_args(verilog, liberty, sdc), "--format", output_format, "--output", str(output)]) == 0
        rendered = output.read_text(encoding="utf-8")
        assert rendered
        if output_format in {"text", "json", "sarif"}:
            assert rendered.endswith("\n")
        if output_format == "html":
            assert rendered.startswith("<!doctype html>")


def test_cli_format_all_writes_exact_report_set(project_files, tmp_path: Path) -> None:
    verilog, liberty, sdc = project_files(sdc=COMPLETE_SDC)
    output = tmp_path / "all"

    assert main([*_audit_args(verilog, liberty, sdc), "--format", "all", "--output", str(output)]) == 0
    assert {path.name for path in output.iterdir()} == {
        "openconstraint-report.txt",
        "openconstraint-report.json",
        "openconstraint-report.sarif",
        "openconstraint-report.html",
    }
    assert json.loads((output / "openconstraint-report.json").read_text(encoding="utf-8"))["schema_version"] == "1.1.0"


@pytest.mark.parametrize("protected_kind", ["verilog", "sdc"])
def test_cli_rejects_report_output_that_resolves_to_design_input(
    project_files, tmp_path: Path, capsys, protected_kind: str
) -> None:
    verilog, liberty, sdc = project_files(sdc=COMPLETE_SDC)
    protected = {"verilog": verilog, "sdc": sdc}[protected_kind]
    original = protected.read_bytes()
    alias_parent = tmp_path / "report-alias"
    output = alias_parent / ".." / protected.name

    with pytest.raises(SystemExit) as caught:
        main([*_audit_args(verilog, liberty, sdc), "--format", "json", "--output", str(output)])

    assert caught.value.code == 2
    error = capsys.readouterr().err
    assert "report output path" in error
    assert "must not overlap" in error
    assert protected.read_bytes() == original
    assert not alias_parent.exists()


def test_cli_format_all_preflights_every_generated_path_before_writing(project_files, tmp_path: Path, capsys) -> None:
    verilog, liberty, _ = project_files(sdc=COMPLETE_SDC)
    output = tmp_path / "all"
    output.mkdir()
    sdc = output / "openconstraint-report.sarif"
    sdc.write_text(COMPLETE_SDC, encoding="utf-8", newline="\n")
    original = sdc.read_bytes()

    with pytest.raises(SystemExit) as caught:
        main(
            [
                "audit",
                "--verilog",
                str(verilog),
                "--liberty",
                str(liberty),
                "--mode",
                f"functional={sdc}",
                "--top",
                "top",
                "--format",
                "all",
                "--output",
                str(output),
            ]
        )

    assert caught.value.code == 2
    assert "must not overlap SDC input path" in capsys.readouterr().err
    assert sdc.read_bytes() == original
    assert {path.name for path in output.iterdir()} == {"openconstraint-report.sarif"}


def test_cli_rejects_report_output_that_overlaps_explicit_opensta_binary(project_files, tmp_path: Path, capsys) -> None:
    verilog, liberty, sdc = project_files(sdc=COMPLETE_SDC)
    executable = tmp_path / "trusted-sta"
    executable.write_bytes(b"do-not-overwrite")
    original = executable.read_bytes()

    with pytest.raises(SystemExit) as caught:
        main(
            [
                *_audit_args(verilog, liberty, sdc),
                "--opensta",
                "--opensta-bin",
                str(executable),
                "--format",
                "json",
                "--output",
                str(executable),
            ]
        )

    assert caught.value.code == 2
    assert "must not overlap --opensta-bin input path" in capsys.readouterr().err
    assert executable.read_bytes() == original


def test_cli_format_all_rejects_stdout_destination(project_files, capsys) -> None:
    verilog, liberty, sdc = project_files(sdc=COMPLETE_SDC)

    with pytest.raises(SystemExit) as caught:
        main([*_audit_args(verilog, liberty, sdc), "--format", "all", "--output", "-"])
    assert caught.value.code == 2
    assert "requires --output to name a directory" in capsys.readouterr().err


def test_mode_input_grouping_preserves_first_seen_mode_and_file_order() -> None:
    modes = _mode_inputs(None, ["scan=a.sdc", "functional=f.sdc", "scan=b.sdc"])

    assert [(mode.name, mode.sdc_paths) for mode in modes] == [
        ("scan", ["a.sdc", "b.sdc"]),
        ("functional", ["f.sdc"]),
    ]


@pytest.mark.parametrize("value", ["scan", "=scan.sdc", "scan="])
def test_mode_input_rejects_invalid_assignment(value: str) -> None:
    with pytest.raises(ValueError, match="expected NAME=FILE"):
        _mode_inputs(None, [value])


def test_mode_input_rejects_mixed_default_and_named_modes() -> None:
    with pytest.raises(ValueError, match="either --sdc or --mode"):
        _mode_inputs(["default.sdc"], ["scan=scan.sdc"])


def test_cli_named_modes_emit_cross_mode_report(project_files, tmp_path: Path) -> None:
    verilog, liberty, _ = project_files(sdc=COMPLETE_SDC)
    functional = tmp_path / "functional.sdc"
    scan = tmp_path / "scan.sdc"
    functional.write_text("create_clock -name core -period 10 [get_ports clk]\n", encoding="utf-8")
    scan.write_text("create_clock -name core -period 100 [get_ports clk2]\n", encoding="utf-8")
    output = tmp_path / "modes.json"
    code = main(
        [
            "audit",
            "--verilog",
            str(verilog),
            "--liberty",
            str(liberty),
            "--mode",
            f"functional={functional}",
            "--mode",
            f"scan={scan}",
            "--top",
            "top",
            "--format",
            "json",
            "--output",
            str(output),
            "--fail-on",
            "never",
        ]
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert code == 0
    assert [mode["name"] for mode in payload["modes"]] == ["functional", "scan"]
    assert any(finding["rule_id"] == "OC5001" for finding in payload["diagnostics"])


def test_cli_missing_input_is_exit_2_with_concise_error(project_files, capsys, tmp_path: Path) -> None:
    _, liberty, sdc = project_files(sdc=COMPLETE_SDC)

    with pytest.raises(SystemExit) as caught:
        main(_audit_args(tmp_path / "missing.v", liberty, sdc))
    assert caught.value.code == 2
    assert "openconstraint: input error:" in capsys.readouterr().err


def test_cli_version_uses_argparse_success_exit(capsys) -> None:
    with pytest.raises(SystemExit) as caught:
        main(["--version"])

    assert caught.value.code == 0
    assert capsys.readouterr().out.startswith("OpenConstraint ")


def test_demo_is_offline_deterministic_and_writes_inputs_plus_all_reports(tmp_path: Path, capsys) -> None:
    output = tmp_path / "demo"

    assert main(["demo", "--output-dir", str(output)]) == 0
    message = capsys.readouterr().out
    assert str(output.resolve()) in message
    assert {path.name for path in output.iterdir()} == {
        "inputs",
        "openconstraint-report.txt",
        "openconstraint-report.json",
        "openconstraint-report.sarif",
        "openconstraint-report.html",
    }
    assert {path.name for path in (output / "inputs").iterdir()} == {
        "tiny.v",
        "cells.lib",
        "constraints.sdc",
    }
    report = json.loads((output / "openconstraint-report.json").read_text(encoding="utf-8"))
    assert report["summary"]["coverage"] == {"functional": 100.0}
