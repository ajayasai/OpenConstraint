"""Conformance checks against native Yosys flatten and a procedural RTL oracle.

Native tools process only this repository's fixed-name fixtures, not user scripts.
--yosys requires the actual executable: missing tools never silently downgrade.
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import shutil
import subprocess
from importlib.resources import files
from pathlib import Path

import z3
from jsonschema import Draft202012Validator

from openconstraint.functional import _evaluate, analyze_functional, verify_functional
from openconstraint.hierarchy import canonical, digest, elaborate_hierarchy, verify_hierarchy
from openconstraint.sequential import analyze_sequential, verify_sequential
from openconstraint.sequential_cli import render_vcd
from openconstraint.sequential_model import SequentialLimits, load_synchronous_model


def dump(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(canonical(value) + "\n")


def native_exports(output: Path) -> str:
    binary = shutil.which("yosys")
    if binary is None:
        raise RuntimeError("--yosys requires real Yosys; validation was not run")
    version = subprocess.run([binary, "-V"], capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    common = "read_verilog design.v; hierarchy -check -top top; proc; "
    scripts = {
        "native-export": common
        + "techmap; opt_clean; write_json hierarchical.json; flatten; delete t:$scopeinfo; opt_clean; write_json native-flat.json",
        "native-sat-agreement": common
        + "flatten; opt_clean; select top; sat -seq 6 -set-at 1 reset 1 -prove-skip 1 -prove bad_pair 0 -verify",
        "native-sat-negative": common
        + "flatten; opt_clean; select top; sat -seq 6 -set-at 1 reset 1 -prove-skip 1 -prove q_left 0 -falsify -dump_vcd native-negative.vcd",
    }
    for name, script in scripts.items():
        result = subprocess.run([binary, "-p", script], cwd=output, capture_output=True, text=True, timeout=90)
        (output / f"{name}.log").write_text(result.stdout + result.stderr, encoding="utf-8")
        result.check_returncode()
        if "sat" in name:
            marker = "model found: FAIL!" if name.endswith("negative") else "no model found: SUCCESS!"
            if marker not in result.stdout:
                raise RuntimeError(f"missing native SAT outcome: {name}")
    return version


def simulate(netlist: dict, sequences: list[list[dict[str, bool]]]) -> list:
    """Evaluate primitives after flattening; compare to independent RTL equations."""
    model = load_synchronous_model(netlist, "top", "clk", "posedge", SequentialLimits())
    observed = [(name, bit) for name, width in [("q_left", 2), ("q_right", 2), ("q_wide", 3)] for bit in range(width)]
    outputs = tuple(model.resolve({"net": name, "bit": bit}) for name, bit in observed)
    outputs += (model.resolve("comb"), model.resolve("bad_pair"))
    states = tuple(sorted(model.next_state))
    following = tuple(model.next_state[q] for q in states)
    all_outputs = []
    for sequence in sequences:
        values = dict.fromkeys(states, False)
        previous = (False,) * 7
        trace = []
        for sample in sequence:
            root_values = values | {model.resolve(k): v for k, v in sample.items()}
            evaluation = _evaluate(model.logic.gates, root_values, following + outputs)
            current = evaluation[len(states) :]
            # Procedural reference has no hierarchy traversal, union-find, or gate matching.
            assert current == previous + ((sample["a"] != sample["b"]) and sample["c"], False), current
            previous = (
                (False,) * 7
                if sample["reset"]
                else (sample["b"], sample["a"], sample["b"], sample["a"], sample["c"], sample["b"], sample["a"])
            )
            values = dict(zip(states, evaluation[: len(states)], strict=True))
            trace.append(current)
        all_outputs.append(trace)
    return all_outputs


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--yosys", action="store_true")
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).parent
    for name in ("design.v", "checks.json", "functional-checks.json"):
        shutil.copyfile(source / name, output / name)
    version = native_exports(output) if args.yosys else None
    if not args.yosys:
        shutil.copyfile(source / "netlist.json", output / "hierarchical.json")
    original = json.loads((output / "hierarchical.json").read_text())
    pack = elaborate_hierarchy(original, "top")
    assert pack["provenance"]["counts"]["instances"] >= 8  # No accidental flat-only reference.
    assert pack["provenance"]["counts"]["leaf_cells"] >= 7
    schema = json.loads((files("openconstraint.schemas") / "openconstraint-hierarchy.schema.json").read_text())
    Draft202012Validator(schema).validate(pack)
    assert verify_hierarchy(pack, original, "top")
    dump(output / "hierarchy.json", pack)
    dump(output / "openconstraint-flat.json", pack["netlist"])
    seq = json.loads((output / "checks.json").read_text())
    functional = json.loads((output / "functional-checks.json").read_text())
    exports = {"hierarchical": original, "openconstraint-flat": pack["netlist"]}
    if args.yosys:
        exports["native-flat"] = json.loads((output / "native-flat.json").read_text())
    results = {}
    for export_name, netlist in exports.items():
        for backend in ("enumerate", "z3"):
            key = f"{export_name}-{backend}"
            report = analyze_sequential(netlist, seq, backend=backend)
            assert [c["status"] for c in report["checks"]] == ["proven", "counterexample"], report
            replay = verify_sequential(report, netlist, seq, backend="enumerate")
            assert replay["verified"] and not replay["passed"], replay
            dump(output / f"{key}-sequential.json", report)
            dump(output / f"{key}-sequential-replay.json", replay)
            (output / f"{key}.vcd").write_text(
                render_vcd(report, netlist, seq, "negative-control-not-always-zero"), encoding="utf-8"
            )
            boolean = analyze_functional(netlist, functional, backend=backend)
            assert [c["status"] for c in boolean["checks"]] == ["independent", "dependent"], boolean
            assert verify_functional(boolean, netlist, functional, backend="enumerate")["verified"]
            dump(output / f"{key}-functional.json", boolean)
            results[key] = {
                "sequential": [c["status"] for c in report["checks"]],
                "boolean": [c["status"] for c in boolean["checks"]],
            }
    rng = random.Random(1729)
    sequences = [
        [dict.fromkeys(["reset", "a", "b", "c"], True)]
        + [{k: bool(rng.getrandbits(1)) for k in ("reset", "a", "b", "c")} for _ in range(15)]
        for _ in range(128)
    ]
    reference = simulate(original, sequences)
    for export in exports.values():
        assert simulate(export, sequences) == reference
    dump(output / "simulation-vectors.json", {"inputs": sequences, "observed": reference})
    dump(
        output / "validation.json",
        {
            "real_yosys": bool(args.yosys),
            "yosys_version": version,
            "python": platform.python_version(),
            "z3": z3.get_version_string(),
            "netlist_digest": digest(original),
            "results": results,
            "procedural_simulation_sequences": len(sequences),
            "cycles_per_sequence": len(sequences[0]),
            "native_sat_bound": 6 if args.yosys else None,
            "timing_signoff": False,
            "contract": "hierarchy connectivity plus existing declared Boolean/synchronous models; no commercial comparison",
        },
    )
    print(json.dumps({"validated": True, "real_yosys": bool(args.yosys), "counts": pack["provenance"]["counts"]}))


if __name__ == "__main__":
    main()
