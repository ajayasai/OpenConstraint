"""OpenConstraint command-line interface."""

from __future__ import annotations

import argparse
import json
import math
import shutil
import sys
from collections.abc import Sequence
from hashlib import sha256
from importlib import resources
from pathlib import Path

from openconstraint.adoption import (
    adoption_strict_failure,
    apply_adoption_controls,
    load_diagnostic_baseline,
    load_waivers,
    render_baseline,
)
from openconstraint.adoption import baseline_from_result as diagnostic_baseline_from_result
from openconstraint.benchmark import (
    BenchmarkManifest,
    baseline_from_result,
    fetch_suite,
    load_baseline,
    load_manifest,
    render_benchmark_json,
    run_suite,
)
from openconstraint.engine import AuditOptions, ModeInput, audit, audit_sdc_text
from openconstraint.model import (
    SEVERITY_RANK,
    AuditResult,
    Design,
    Diagnostic,
    ModeResult,
    Severity,
    SourceLocation,
    effective_io_delay_semantics,
)
from openconstraint.opensta import OpenSTAError, OpenSTAValidationResult, validate_with_opensta
from openconstraint.parsers.liberty import CellLibrary, parse_liberty
from openconstraint.parsers.verilog import elaborate, parse_verilog
from openconstraint.reporters.html import render_html
from openconstraint.reporters.json import render_json
from openconstraint.reporters.sarif import render_sarif
from openconstraint.reporters.text import render_text
from openconstraint.rules import RULES
from openconstraint.version import __version__

FORMATS = {"text": render_text, "json": render_json, "sarif": render_sarif, "html": render_html}
FORMAT_EXTENSIONS = {"text": "txt", "json": "json", "sarif": "sarif", "html": "html"}
SCHEMA_FILES = {
    "report": "openconstraint-report.schema.json",
    "waivers": "openconstraint-waivers.schema.json",
    "baseline": "openconstraint-diagnostic-baseline.schema.json",
}


def _percentage(value: str) -> float:
    try:
        result = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number from 0 through 100") from error
    if not math.isfinite(result) or not 0.0 <= result <= 100.0:
        raise argparse.ArgumentTypeError("must be a finite number from 0 through 100")
    return result


def _ratio(value: str) -> float:
    try:
        result = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number from 0 through 1") from error
    if not math.isfinite(result) or not 0.0 <= result <= 1.0:
        raise argparse.ArgumentTypeError("must be a finite number from 0 through 1")
    return result


def _nonnegative_integer(value: str) -> int:
    try:
        result = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a nonnegative integer") from error
    if result < 0:
        raise argparse.ArgumentTypeError("must be a nonnegative integer")
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openconstraint",
        description="Deterministic SDC constraint-quality auditing and structural coverage.",
    )
    parser.add_argument("--version", action="version", version=f"OpenConstraint {__version__}")
    subcommands = parser.add_subparsers(dest="command", required=True)

    audit_parser = subcommands.add_parser("audit", help="Audit one design and one or more SDC modes.")
    audit_parser.add_argument(
        "--verilog", action="append", required=True, metavar="FILE", help="Structural Verilog netlist (repeatable)."
    )
    audit_parser.add_argument(
        "--liberty", action="append", required=True, metavar="FILE", help="Liberty timing library (repeatable)."
    )
    audit_parser.add_argument(
        "--sdc", action="append", metavar="FILE", help="SDC file in the default mode (repeatable)."
    )
    audit_parser.add_argument(
        "--mode", action="append", metavar="NAME=FILE", help="Named-mode SDC; repeat NAME to combine files."
    )
    audit_parser.add_argument("--top", help="Top module; inferred when unambiguous.")
    audit_parser.add_argument("--format", choices=[*FORMATS, "all"], default="text", dest="output_format")
    audit_parser.add_argument(
        "--output", default="-", metavar="PATH", help="Output file, '-' for stdout, or directory with --format all."
    )
    audit_parser.add_argument("--fail-on", choices=["error", "warning", "never"], default="error")
    audit_parser.add_argument(
        "--min-coverage",
        type=_percentage,
        metavar="PERCENT",
        help="Fail when any mode is below this structural coverage (0 through 100).",
    )
    audit_parser.add_argument("--broad-match-count", type=_nonnegative_integer, default=50)
    audit_parser.add_argument("--broad-match-ratio", type=_ratio, default=0.8)
    audit_parser.add_argument("--no-implicit-waveform-note", action="store_true")
    audit_parser.add_argument(
        "--waivers",
        action="append",
        metavar="FILE",
        help="Versioned exact-fingerprint waiver file (repeatable).",
    )
    baseline_group = audit_parser.add_mutually_exclusive_group()
    baseline_group.add_argument(
        "--baseline",
        metavar="FILE",
        help="Reviewed diagnostic baseline; only findings absent from it remain active.",
    )
    baseline_group.add_argument(
        "--write-baseline",
        metavar="FILE",
        help="Write a deterministic baseline from raw findings before policy gates.",
    )
    audit_parser.add_argument(
        "--strict-controls",
        action="store_true",
        help="Fail when a waiver is unused or a baseline entry is stale.",
    )
    audit_parser.add_argument(
        "--opensta",
        action="store_true",
        help="Explicitly execute trusted SDC in an installed OpenSTA process for validation.",
    )
    audit_parser.add_argument(
        "--opensta-bin", metavar="PATH", help="OpenSTA executable (defaults to sta/opensta on PATH)."
    )
    audit_parser.add_argument("--opensta-timeout", type=float, default=120.0, metavar="SECONDS")

    rules_parser = subcommands.add_parser("rules", help="List stable diagnostics.")
    rules_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")

    schema_parser = subcommands.add_parser("schema", help="Print or copy a packaged JSON Schema.")
    schema_parser.add_argument("--kind", choices=SCHEMA_FILES, default="report")
    schema_parser.add_argument("--output", default="-", metavar="PATH")

    demo_parser = subcommands.add_parser("demo", help="Run the bundled synthetic design and write every report format.")
    demo_parser.add_argument("--output-dir", default="openconstraint-demo-report", metavar="DIR")

    benchmark_parser = subcommands.add_parser(
        "benchmark", help="Fetch and run checksum-pinned public-design benchmarks."
    )
    benchmark_commands = benchmark_parser.add_subparsers(dest="benchmark_command", required=True)
    for name, help_text in (
        ("fetch", "Populate or verify the content-addressed artifact cache."),
        ("run", "Run benchmark cases and optionally compare a semantic baseline."),
        ("baseline", "Write a deterministic semantic baseline from successful cases."),
    ):
        action = benchmark_commands.add_parser(name, help=help_text)
        action.add_argument("--manifest", required=True, metavar="FILE")
        action.add_argument(
            "--cache-dir",
            default=str(Path.home() / ".cache" / "openconstraint" / "benchmarks"),
            metavar="DIR",
        )
        action.add_argument("--dataset", action="append", metavar="ID", help="Select a dataset (repeatable).")
        action.add_argument(
            "--case", action="append", metavar="DATASET/CASE", help="Select a qualified case (repeatable)."
        )
        action.add_argument("--offline", action="store_true", help="Forbid downloads and require a verified cache.")
    benchmark_commands.choices["fetch"].add_argument("--output", default="-", metavar="FILE")
    benchmark_commands.choices["run"].add_argument("--baseline", metavar="FILE")
    benchmark_commands.choices["run"].add_argument("--output", default="-", metavar="FILE")
    benchmark_commands.choices["baseline"].add_argument("--output", required=True, metavar="FILE")
    return parser


def _mode_inputs(sdc: list[str] | None, values: list[str] | None) -> list[ModeInput]:
    if sdc and values:
        raise ValueError("use either --sdc or --mode, not both")
    if sdc:
        return [ModeInput("default", sdc)]
    if not values:
        raise ValueError("at least one --sdc FILE or --mode NAME=FILE is required")
    grouped: dict[str, list[str]] = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"invalid --mode {value!r}; expected NAME=FILE")
        name, path = value.split("=", 1)
        if not name.strip() or not path.strip():
            raise ValueError(f"invalid --mode {value!r}; expected NAME=FILE")
        grouped.setdefault(name.strip(), []).append(path.strip())
    return [ModeInput(name, paths) for name, paths in grouped.items()]


def _load_design(verilog_paths: list[str], liberty_paths: list[str], top: str | None) -> Design:
    library = CellLibrary()
    for path in liberty_paths:
        library.merge(parse_liberty(path))
    return elaborate(parse_verilog([Path(path) for path in verilog_paths]), library, top)


def _write(value: str, output: str) -> None:
    if output == "-":
        sys.stdout.write(value)
        return
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(value, encoding="utf-8", newline="\n")


def _write_all(result: AuditResult, output: str) -> None:
    if output == "-":
        raise ValueError("--format all requires --output to name a directory")
    destination = Path(output)
    destination.mkdir(parents=True, exist_ok=True)
    for name, renderer in FORMATS.items():
        (destination / f"openconstraint-report.{FORMAT_EXTENSIONS[name]}").write_text(
            renderer(result), encoding="utf-8", newline="\n"
        )


def _report_output_paths(output: str, output_format: str) -> tuple[Path, ...]:
    """Resolve every file that an audit report invocation can write."""

    if output == "-":
        if output_format == "all":
            raise ValueError("--format all requires --output to name a directory")
        return ()
    target = Path(output).resolve()
    if output_format != "all":
        return (target,)
    return tuple((target / f"openconstraint-report.{FORMAT_EXTENSIONS[name]}").resolve() for name in FORMATS)


def _validate_audit_output_paths(
    arguments: argparse.Namespace,
    modes: Sequence[ModeInput],
) -> None:
    """Reject report destinations that could overwrite an audit input."""

    report_targets = _report_output_paths(arguments.output, arguments.output_format)
    if arguments.write_baseline and arguments.output != "-":
        baseline_target = Path(arguments.write_baseline).resolve()
        output_target = Path(arguments.output).resolve()
        # Retain the historical directory-level check for --format all as well
        # as checking each concrete generated report file.
        if baseline_target == output_target or baseline_target in report_targets:
            raise ValueError("--write-baseline must not overlap a report output path")

    input_paths: list[tuple[str, str]] = []
    input_paths.extend(("--verilog", path) for path in arguments.verilog)
    input_paths.extend(("--liberty", path) for path in arguments.liberty)
    input_paths.extend(("SDC", path) for mode in modes for path in mode.sdc_paths)
    input_paths.extend(("--waivers", path) for path in (arguments.waivers or ()))
    if arguments.baseline:
        input_paths.append(("--baseline", arguments.baseline))
    if arguments.opensta and arguments.opensta_bin:
        input_paths.append(("--opensta-bin", arguments.opensta_bin))

    resolved_inputs = [(option, Path(path).resolve()) for option, path in input_paths]
    for report_target in report_targets:
        for option, input_target in resolved_inputs:
            if report_target == input_target:
                raise ValueError(
                    f"report output path {report_target} must not overlap {option} input path {input_target}"
                )
    if arguments.write_baseline:
        baseline_target = Path(arguments.write_baseline).resolve()
        for option, input_target in resolved_inputs:
            if baseline_target == input_target:
                raise ValueError(
                    f"--write-baseline path {baseline_target} must not overlap {option} input path {input_target}"
                )


def _quality_exit(result: AuditResult, fail_on: str, min_coverage: float | None) -> int:
    if min_coverage is not None and any(mode.coverage.score < min_coverage for mode in result.modes):
        return 1
    if adoption_strict_failure(result):
        return 1
    if fail_on == "never":
        return 0
    threshold = Severity.ERROR if fail_on == "error" else Severity.WARNING
    return 1 if any(SEVERITY_RANK[item.severity] >= SEVERITY_RANK[threshold] for item in result.diagnostics) else 0


def _mode_semantics(mode: ModeResult) -> dict[str, object]:
    exception_records = [
        {
            "kind": item.kind,
            "from": sorted(item.from_objects),
            "to": sorted(item.to_objects),
            "through": [sorted(group) for group in item.through_objects],
            "qualifiers": item.qualifiers,
        }
        for item in mode.exceptions
    ]
    exception_records.sort(key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    io_delay_records = effective_io_delay_semantics(mode.io_delays)
    return {
        "clocks": [
            {
                "name": clock.name,
                "targets": sorted(clock.targets),
                "period": clock.period,
                "waveform": list(clock.waveform) if clock.waveform is not None else None,
                "generated": clock.generated,
                "source_targets": sorted(clock.source_targets),
                "master_clock": clock.master_clock,
                "divide_by": clock.divide_by,
                "multiply_by": clock.multiply_by,
                "duty_cycle": clock.duty_cycle,
                "invert": clock.invert,
                "combinational": clock.combinational,
                "edges": list(clock.edges) if clock.edges is not None else None,
                "edge_shift": list(clock.edge_shift) if clock.edge_shift is not None else None,
            }
            for clock in sorted(mode.clocks.values(), key=lambda item: item.name)
        ],
        "exceptions": exception_records,
        "io_delays": io_delay_records,
        "coverage": mode.coverage.to_dict(),
    }


def _semantic_digest(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return sha256(encoded).hexdigest()


def _diagnostic_semantic_key(finding: Diagnostic) -> tuple[str, str, str]:
    return (
        finding.rule_id,
        finding.message,
        json.dumps(finding.evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
    )


def _merge_opensta(
    result: AuditResult,
    validation: OpenSTAValidationResult,
    design: Design,
    options: AuditOptions,
) -> None:
    mode_lookup = {mode.name: mode for mode in result.modes}
    public_modes: list[dict[str, object]] = []
    for mode_result in validation.modes:
        public_mode: dict[str, object] = {
            "mode": mode_result.mode,
            "succeeded": mode_result.succeeded,
            "return_code": mode_result.returncode,
            "timed_out": mode_result.timed_out,
            "duration_seconds": round(mode_result.duration_seconds, 6),
            "effective_sdc_sha256": mode_result.effective_sdc_sha256,
            "stdout": mode_result.stdout,
            "stderr": mode_result.stderr,
            "effective_audit": None,
        }
        public_modes.append(public_mode)
        if mode_result.succeeded:
            mode = mode_lookup.get(mode_result.mode)
            if mode is not None and mode_result.effective_sdc is not None:
                effective = audit_sdc_text(
                    design,
                    mode_result.mode,
                    mode_result.effective_sdc,
                    path=f"<opensta-effective:{mode_result.mode}>",
                    options=options,
                )
                existing = {_diagnostic_semantic_key(item) for item in mode.diagnostics}
                added = [item for item in effective.diagnostics if _diagnostic_semantic_key(item) not in existing]
                mode.diagnostics.extend(added)
                result.diagnostics.extend(added)
                static_semantics = _mode_semantics(mode)
                effective_semantics = _mode_semantics(effective)
                public_mode["effective_audit"] = {
                    "coverage": effective.coverage.to_dict(),
                    "diagnostic_count": len(effective.diagnostics),
                    "added_diagnostic_count": len(added),
                    "static_semantic_sha256": _semantic_digest(static_semantics),
                    "effective_semantic_sha256": _semantic_digest(effective_semantics),
                    "semantic_match": static_semantics == effective_semantics,
                }
            continue
        mode = mode_lookup.get(mode_result.mode)
        location = (
            mode.clocks[next(iter(mode.clocks))].location
            if mode is not None and mode.clocks
            else SourceLocation(f"<opensta:{mode_result.mode}>")
        )
        if mode_result.timed_out:
            message = f"OpenSTA validation for mode {mode_result.mode!r} timed out"
        else:
            message = (
                f"OpenSTA validation for mode {mode_result.mode!r} exited with "
                f"{mode_result.returncode if mode_result.returncode is not None else 'no status'}"
            )
        finding = Diagnostic(
            "OC6001",
            Severity.ERROR,
            message,
            location,
            "The optional engine-backed check did not produce a clean effective constraint snapshot.",
            "Review OpenSTA stdout/stderr, repair load or check_setup issues, and rerun with the same pinned OpenSTA version.",
            mode_result.mode,
            {
                "opensta_version": validation.version,
                "return_code": mode_result.returncode,
                "timed_out": mode_result.timed_out,
                "stderr_tail": mode_result.stderr[-4000:],
                "stdout_tail": mode_result.stdout[-4000:],
            },
        )
        result.diagnostics.append(finding)
        if mode is not None:
            mode.diagnostics.append(finding)
    result.summary["opensta"] = {
        "version": validation.version,
        "succeeded": validation.succeeded,
        "modes": public_modes,
    }
    result.summary["diagnostic_count"] = len(result.diagnostics)
    result.summary["errors"] = sum(item.severity == Severity.ERROR for item in result.diagnostics)
    result.summary["warnings"] = sum(item.severity == Severity.WARNING for item in result.diagnostics)
    result.summary["notes"] = sum(item.severity == Severity.NOTE for item in result.diagnostics)


def _audit_command(arguments: argparse.Namespace) -> int:
    waivers = None
    baseline = None
    if arguments.write_baseline:
        if arguments.waivers:
            raise ValueError("--write-baseline cannot be combined with --waivers")
        if arguments.strict_controls:
            raise ValueError("--strict-controls requires --waivers or --baseline")
        if arguments.write_baseline == "-":
            raise ValueError("--write-baseline must name a file, not stdout")
    else:
        if arguments.strict_controls and not arguments.waivers and not arguments.baseline:
            raise ValueError("--strict-controls requires --waivers or --baseline")
    modes = _mode_inputs(arguments.sdc, arguments.mode)
    _validate_audit_output_paths(arguments, modes)
    if not arguments.write_baseline:
        waivers = load_waivers(arguments.waivers) if arguments.waivers else None
        baseline = load_diagnostic_baseline(arguments.baseline) if arguments.baseline else None
    design = _load_design(arguments.verilog, arguments.liberty, arguments.top)
    options = AuditOptions(
        broad_match_count=arguments.broad_match_count,
        broad_match_ratio=arguments.broad_match_ratio,
        report_implicit_waveform=not arguments.no_implicit_waveform_note,
    )
    result = audit(design, modes, options)
    if arguments.opensta:
        validation = validate_with_opensta(
            arguments.verilog,
            arguments.liberty,
            design.top,
            modes,
            binary=arguments.opensta_bin,
            timeout=arguments.opensta_timeout,
        )
        _merge_opensta(result, validation, design, options)
    if arguments.write_baseline:
        _write(render_baseline(diagnostic_baseline_from_result(result)), arguments.write_baseline)
    elif waivers is not None or baseline is not None:
        apply_adoption_controls(result, waivers=waivers, baseline=baseline, strict=arguments.strict_controls)
    if arguments.output_format == "all":
        _write_all(result, arguments.output)
    else:
        _write(FORMATS[arguments.output_format](result), arguments.output)
    return _quality_exit(result, arguments.fail_on, arguments.min_coverage)


def _rules_command(as_json: bool) -> int:
    if as_json:
        payload = [
            {
                "id": rule.rule_id,
                "name": rule.name,
                "severity": rule.default_severity.value,
                "category": rule.category,
                "summary": rule.summary,
            }
            for rule in RULES.values()
        ]
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    else:
        for rule in RULES.values():
            sys.stdout.write(f"{rule.rule_id}  {rule.default_severity.value:<7}  {rule.name:<33} {rule.summary}\n")
    return 0


def _schema_command(kind: str, output: str) -> int:
    schema = resources.files("openconstraint.schemas").joinpath(SCHEMA_FILES[kind]).read_text(encoding="utf-8")
    _write(schema.rstrip() + "\n", output)
    return 0


def _demo_command(output_dir: str) -> int:
    destination = Path(output_dir).resolve()
    inputs = destination / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    package = resources.files("openconstraint.demo")
    for name in ("tiny.v", "cells.lib", "constraints.sdc"):
        with resources.as_file(package.joinpath(name)) as source:
            shutil.copyfile(source, inputs / name)
    design = _load_design([str(inputs / "tiny.v")], [str(inputs / "cells.lib")], "tiny_top")
    result = audit(design, [ModeInput("functional", [str(inputs / "constraints.sdc")])])
    _write_all(result, str(destination))
    sys.stdout.write(f"Wrote synthetic inputs and reports to {destination}\n")
    return _quality_exit(result, "error", 100.0)


def _validate_benchmark_output_path(
    arguments: argparse.Namespace,
    manifest: BenchmarkManifest | None = None,
) -> None:
    """Reject benchmark output that would overwrite a declared input."""

    if arguments.output == "-":
        return
    output = Path(arguments.output).resolve()
    inputs = [("--manifest", Path(arguments.manifest).resolve())]
    if getattr(arguments, "baseline", None):
        inputs.append(("--baseline", Path(arguments.baseline).resolve()))
    if manifest is not None:
        inputs.extend(
            ("suite file", (manifest.path.parent / item.path).resolve()) for item in manifest.suite_files.values()
        )
    for label, source in inputs:
        if output == source:
            raise ValueError(f"benchmark output path {output} must not overlap {label} input path {source}")


def _benchmark_command(arguments: argparse.Namespace) -> int:
    _validate_benchmark_output_path(arguments)
    manifest = load_manifest(arguments.manifest)
    _validate_benchmark_output_path(arguments, manifest)
    common = {
        "dataset_ids": arguments.dataset,
        "case_ids": arguments.case,
        "offline": arguments.offline,
    }
    if arguments.benchmark_command == "fetch":
        result = fetch_suite(manifest, arguments.cache_dir, **common)
        _write(render_benchmark_json(result), arguments.output)
        return 0
    if arguments.benchmark_command == "run":
        baseline = load_baseline(arguments.baseline, manifest) if arguments.baseline else None
        result = run_suite(manifest, arguments.cache_dir, baseline=baseline, **common)
        _write(render_benchmark_json(result), arguments.output)
        summary = result["summary"]
        return 1 if summary["regressions"] or summary["errors"] else 0
    result = run_suite(manifest, arguments.cache_dir, **common)
    baseline = baseline_from_result(result)
    _write(render_benchmark_json(baseline), arguments.output)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "audit":
            return _audit_command(arguments)
        if arguments.command == "rules":
            return _rules_command(arguments.json)
        if arguments.command == "schema":
            return _schema_command(arguments.kind, arguments.output)
        if arguments.command == "demo":
            return _demo_command(arguments.output_dir)
        if arguments.command == "benchmark":
            return _benchmark_command(arguments)
    except (OSError, UnicodeError, ValueError, OpenSTAError) as error:
        parser.exit(2, f"openconstraint: input error: {error}\n")
    return 2
