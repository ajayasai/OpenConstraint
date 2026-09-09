"""CLI for bounded structural cut-language comparison and evidence replay."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from dataclasses import asdict
from importlib.resources import files
from pathlib import Path
from typing import Any

from openconstraint.cli import _load_design
from openconstraint.cutcompare import ComparisonLimits, compare_structural_cuts, verify_comparison

_MAX_REPORT_BYTES = 64 * 1024 * 1024


def _read(path: str, limit: int) -> str:
    with Path(path).open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"input exceeds {limit} bytes: {path}")
    return data.decode("utf-8")


def _emit(value: dict[str, Any], output: str) -> None:
    text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
    if output == "-":
        sys.stdout.write(text)
    else:
        # O_EXCL also refuses broken links, hard-linked inputs, and existing
        # directories. No replace/check race can overwrite an input file.
        with Path(output).open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(text)


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openconstraint-cut-compare",
        description="Compare structural false-path coverage, not full timing equivalence.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("compare", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--verilog", action="append", required=True)
        command.add_argument("--liberty", action="append", required=True)
        command.add_argument("--top")
        command.add_argument("--before", required=True, help="Static baseline SDC; expand parameterized input first.")
        command.add_argument("--after", required=True, help="Static candidate SDC on the same design.")
        command.add_argument("--output", default="-", help="JSON destination; existing paths are refused.")
        for key, default in asdict(ComparisonLimits()).items():
            command.add_argument("--" + key.replace("_", "-"), type=int, default=default)
        if name == "compare":
            command.add_argument("--fail-on", choices=("change", "new-cut", "never"), default="change")
        else:
            command.add_argument("--report", required=True, help="Evidence to replay, not a trusted instruction file.")
    schema = commands.add_parser("schema")
    schema.add_argument("--output", default="-")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        # Refuse collisions before doing expensive work. Exclusive creation
        # below remains the authority if another process creates the path.
        if args.output != "-" and os.path.lexists(args.output):
            raise ValueError("output already exists; choose a fresh path")
        if args.command == "schema":
            _emit(
                json.loads(files("openconstraint.schemas").joinpath("cut-comparison.schema.json").read_text()),
                args.output,
            )
            return 0
        limits = ComparisonLimits(**{key: getattr(args, key) for key in asdict(ComparisonLimits())})
        before, after = _read(args.before, limits.max_source_bytes), _read(args.after, limits.max_source_bytes)
        design = _load_design(args.verilog, args.liberty, args.top)
        if args.command == "verify":
            report = json.loads(_read(args.report, _MAX_REPORT_BYTES), object_pairs_hook=_no_duplicates)
            if not isinstance(report, dict):
                raise ValueError("report must be a JSON object")
            verification = verify_comparison(design, before, after, report, limits=limits)
            _emit(verification, args.output)
            return 0 if verification["verified"] else 1
        result = compare_structural_cuts(design, before, after, limits=limits)
        _emit(result, args.output)
        if not result["complete"]:
            return 2
        if args.fail_on == "change":
            return int(result["status"] == "different_structural_cuts")
        if args.fail_on == "new-cut":
            return int(any(check["new_cuts"]["status"] == "witnessed" for check in result["checks"].values()))
        return 0
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        print(f"openconstraint-cut-compare: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
