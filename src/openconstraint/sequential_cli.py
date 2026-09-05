"""Command-line interface and safe waveform export for synchronous evidence."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from hashlib import sha256
from importlib.resources import files
from pathlib import Path
from typing import Any

from openconstraint.functional import FunctionalInputError, _digest, read_functional_json
from openconstraint.parsers.sdc import parse_sdc_text
from openconstraint.sequential import (
    ALGORITHM,
    EXCEPTION_COMMANDS,
    _binding,
    _checks,
    _cone,
    _contract,
    _source_manifest,
    analyze_sequential,
    validate_trace,
    verify_sequential,
)
from openconstraint.sequential_model import MODEL, Budget, SequentialLimits, build_machine, load_synchronous_model


def render_vcd(
    report: Mapping[str, Any],
    netlist: Mapping[str, Any],
    spec: Mapping[str, Any],
    check_id: str,
    *,
    limits: SequentialLimits | None = None,
    sdc_sources: Mapping[str, bytes] | None = None,
) -> str:
    """Export only a concretely replayed violation; source names are never VCD syntax.

    Time units are synthetic logical sampling steps, not SDC clock periods or
    gate-delay simulation. Other properties in the report need not be re-solved.
    """
    limits = limits or SequentialLimits()
    sources = sdc_sources or {}
    expected = {
        "schema_version": "1.0.0",
        "algorithm": ALGORITHM,
        "model": MODEL,
        "timing_signoff": False,
        "netlist_digest": _digest(netlist),
        "specification_digest": _digest(spec),
        "sdc_sources": _source_manifest(sources),
    }
    if report.get("report_digest") != _digest({k: v for k, v in report.items() if k != "report_digest"}):
        raise FunctionalInputError("waveform report integrity mismatch")
    if any(type(report.get(k)) is not type(v) or report.get(k) != v for k, v in expected.items()):
        raise FunctionalInputError("waveform source identity mismatch")
    checks = _checks(spec, limits)
    selected = [c for c in checks if c["id"] == check_id]
    entries = report.get("checks")
    if not isinstance(entries, list):
        raise FunctionalInputError("invalid report checks")
    saved = [c for c in entries if isinstance(c, dict) and c.get("id") == check_id]
    if len(selected) != 1 or len(saved) != 1 or saved[0].get("status") != "counterexample":
        raise FunctionalInputError("select exactly one check with a counterexample")
    check, entry = selected[0], saved[0]
    model = load_synchronous_model(netlist, spec["top"], spec["clock"], spec["edge"], limits)
    machine = build_machine(model, check, limits)
    if (
        entry.get("query_digest") != _digest(check)
        or entry.get("cone") != _cone(machine)
        or entry.get("binding") != _binding(check, sources, {})
    ):
        raise FunctionalInputError("waveform obligation mismatch")
    trace = entry.get("counterexample")
    if not validate_trace(machine, _contract(model, spec), trace, Budget(limits)):
        raise FunctionalInputError("waveform counterexample does not replay")
    names = [f"state_bit_{b}" for b in machine.states] + [f"event_history_{i}" for i in range(machine.history)]
    names += [f"input_bit_{b}" for b in machine.inputs] + [f"observed_{i}" for i in range(len(machine.observed))]
    lines = [
        "$comment Synthetic cycle samples only; NOT physical timing. $end",
        "$timescale 1 ns $end",
        "$scope module openconstraint $end",
    ]
    lines += [f"$var wire 1 v{i} {name} $end" for i, name in enumerate(names)]
    lines += ["$upscope $end", "$enddefinitions $end"]
    assert isinstance(trace, list)
    for cycle, frame in enumerate(trace):
        lines.append(f"#{cycle}")
        values = frame["state"] + frame["inputs"] + frame["observed"]
        lines.extend(f"{value}v{i}" for i, value in enumerate(values))
    return "\n".join(lines) + "\n"


def _read_sdc(path: str) -> bytes:
    with Path(path).open("rb") as stream:
        raw = stream.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024:
        raise FunctionalInputError("SDC input exceeds 16 MiB")
    return raw


def _sources(arguments: Sequence[str]) -> dict[str, bytes]:
    result = {}
    for argument in arguments:
        name, sep, path = argument.partition("=")
        if not name or not sep or not path or name in result:
            raise FunctionalInputError("use unique --sdc LOGICAL_ID=PATH inputs")
        result[name] = _read_sdc(path)
        _source_manifest(result)
    return result


def _write(text: str, output: str) -> None:
    if len(text.encode("utf-8")) > 16 * 1024 * 1024:
        raise FunctionalInputError("evidence exceeds the 16 MiB output contract; reduce the cone or state bound")
    if output == "-":
        sys.stdout.write(text)
    else:
        # Exclusive creation also refuses symlinks/hardlinks to an existing
        # source. No report, netlist, SDC, or user file is ever overwritten.
        with Path(output).open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(text)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Synchronous safety proofs and replay; NOT timing signoff")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("analyze", "verify", "witness"):
        child = commands.add_parser(name)
        child.add_argument("--netlist", required=True)
        child.add_argument("--spec", required=True)
        child.add_argument("--sdc", action="append", default=[], metavar="ID=PATH")
        child.add_argument("--output", default="-")
        for key, value in asdict(SequentialLimits()).items():
            child.add_argument("--" + key.replace("_", "-"), type=int, default=value)
        if name != "witness":
            child.add_argument(
                "--backend", choices=("enumerate", "z3"), default="z3" if name == "analyze" else "enumerate"
            )
        if name != "analyze":
            child.add_argument("--report", required=True)
        if name == "witness":
            child.add_argument("--check", required=True)
    child = commands.add_parser("schema")
    child.add_argument("--kind", choices=("spec", "result"), default="spec")
    child.add_argument("--output", default="-")
    child = commands.add_parser("sdc-index")
    child.add_argument("--sdc", required=True)
    child.add_argument("--source-id", default="constraints")
    child.add_argument("--output", default="-")
    args = parser.parse_args(argv)
    try:
        code = 0
        if args.command == "schema":
            text = (files("openconstraint.schemas") / f"openconstraint-sequential-{args.kind}.schema.json").read_text(
                encoding="utf-8"
            )
        elif args.command == "sdc-index":
            raw = _read_sdc(args.sdc)
            doc = parse_sdc_text(raw.decode("utf-8"), "<sdc-index>")
            sources = {args.source_id: raw}
            _source_manifest(sources)
            cache: dict[str, Any] = {}
            bindings = []
            for index, command in enumerate(doc.commands):
                if command.name in EXCEPTION_COMMANDS:
                    binding = {"source": args.source_id, "sha256": sha256(raw).hexdigest(), "command_index": index}
                    bindings.append(_binding({"binding": binding}, sources, cache))
            if doc.issues:
                raise FunctionalInputError("SDC index contains parse errors")
            text = (
                json.dumps(
                    {
                        "source": args.source_id,
                        "sha256": sha256(raw).hexdigest(),
                        "bindings": bindings,
                        "exception_validated": False,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            )
        else:
            limits = SequentialLimits(**{key: getattr(args, key) for key in asdict(SequentialLimits())})
            netlist, spec = read_functional_json(Path(args.netlist)), read_functional_json(Path(args.spec))
            sources = _sources(args.sdc)
            if args.command == "analyze":
                report = analyze_sequential(netlist, spec, backend=args.backend, limits=limits, sdc_sources=sources)
                code = int(not report["passed"])
            elif args.command == "verify":
                report = verify_sequential(
                    read_functional_json(Path(args.report)),
                    netlist,
                    spec,
                    backend=args.backend,
                    limits=limits,
                    sdc_sources=sources,
                )
                code = int(not report["verified"])
            else:
                text = render_vcd(
                    read_functional_json(Path(args.report)),
                    netlist,
                    spec,
                    args.check,
                    limits=limits,
                    sdc_sources=sources,
                )
            if args.command != "witness":
                text = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"
        _write(text, args.output)
        return code
    except (ValueError, OSError, UnicodeError, TypeError, KeyError, RecursionError, RuntimeError) as error:
        print(f"openconstraint-sequential: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
