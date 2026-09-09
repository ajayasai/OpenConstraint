"""CLI for source-bound hierarchy elaboration and complete replay."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict
from importlib.resources import files
from pathlib import Path
from typing import Any

from openconstraint.functional import read_functional_json
from openconstraint.hierarchy import HierarchyLimits, canonical, elaborate_hierarchy, verify_hierarchy


def _read(path: Path, maximum: int) -> dict[str, Any]:
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("elaboration pack exceeds its read limit")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("elaboration pack must be an object")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Hierarchical Yosys connectivity elaboration and replay; not timing signoff"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("compile", "verify"):
        child = commands.add_parser(name)
        child.add_argument("--netlist", required=True)
        child.add_argument("--top", required=True)
        child.add_argument("--output" if name == "compile" else "--pack", required=True)
        for key, value in asdict(HierarchyLimits()).items():
            child.add_argument("--" + key.replace("_", "-"), type=int, default=value)
    child = commands.add_parser("schema")
    child.add_argument("--output", default="-")
    args = parser.parse_args(argv)
    try:
        if args.command == "schema":
            text = (files("openconstraint.schemas") / "openconstraint-hierarchy.schema.json").read_text(
                encoding="utf-8"
            )
            if args.output == "-":
                sys.stdout.write(text)
            else:
                with Path(args.output).open("x", encoding="utf-8", newline="\n") as stream:
                    stream.write(text)
            return 0
        limits = HierarchyLimits(**{k: getattr(args, k) for k in asdict(HierarchyLimits())})
        netlist = read_functional_json(Path(args.netlist))
        if args.command == "verify":
            directory = Path(args.pack)
            pack = _read(directory / "hierarchy.json", limits.max_output_bytes)
            flat = _read(directory / "netlist.json", limits.max_output_bytes)
            verified = verify_hierarchy(pack, netlist, args.top, limits=limits) and canonical(flat) == canonical(
                pack["netlist"]
            )
            print(json.dumps({"verified": verified, "timing_signoff": False}, sort_keys=True))
            return 0 if verified else 1
        pack = elaborate_hierarchy(netlist, args.top, limits=limits)
        # Compute everything before creating output. Exclusive creation rejects
        # existing destinations/links; a later disk failure is an error, not success.
        pack_text = canonical(pack) + "\n"
        flat_text = canonical(pack["netlist"]) + "\n"
        directory = Path(args.output)
        directory.mkdir(parents=False, exist_ok=False)
        for name, text in (("hierarchy.json", pack_text), ("netlist.json", flat_text)):
            with (directory / name).open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(text)
        print(
            json.dumps(
                {"compiled": True, "counts": pack["provenance"]["counts"], "timing_signoff": False}, sort_keys=True
            )
        )
        return 0
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        print(f"openconstraint-hierarchy: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
