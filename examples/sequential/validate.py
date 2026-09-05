"""Reproducible conformance, real-synthesis and synthetic cone-scale evidence.

Run from any checkout: python examples/sequential/validate.py --output NEW_DIR
Add --yosys to require a real Yosys synthesis and native SAT comparison.
The external tool only processes the repository-owned fixed-name fixture.
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import time
import tracemalloc
from hashlib import sha256
from importlib.resources import files
from pathlib import Path

import z3
from jsonschema import Draft202012Validator

from openconstraint.sequential import analyze_sequential, verify_sequential
from openconstraint.sequential_cli import render_vcd
from openconstraint.sequential_model import SequentialLimits


def dump(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as out:
        json.dump(value, out, indent=2, sort_keys=True)
        out.write("\n")


def run_yosys(output: Path) -> str:
    binary = shutil.which("yosys")
    if binary is None:
        raise RuntimeError("--yosys requires a separately installed Yosys executable")
    version = subprocess.run([binary, "-V"], text=True, capture_output=True, check=True, timeout=10).stdout.strip()
    (output / "yosys-version.txt").write_text(version + "\n", encoding="utf-8")
    common = "read_verilog design.v; hierarchy -check -top top; proc; flatten; "
    # Do not optimize away unknown initial state or merge identical state bits.
    # This is an explicitly documented conformance-export recipe.
    scripts = {
        "synthesis": common + "techmap; write_json netlist.json",
        "native-pair-proof": common + "sat -seq 8 -set-at 1 reset 1 -prove-skip 1 -prove bad_equal 0 -verify",
        "native-spacing-proof": common + "sat -seq 8 -set-at 1 reset 1 -prove-skip 1 -prove bad_spacing2 0 -verify",
        "native-spacing-counterexample": common
        + "sat -seq 8 -set-at 1 reset 1 -prove-skip 1 -prove bad_spacing3 0 -falsify -dump_vcd native-counterexample.vcd",
    }
    for name, script in scripts.items():
        result = subprocess.run([binary, "-p", script], cwd=output, text=True, capture_output=True, timeout=90)
        (output / f"{name}.log").write_text(result.stdout + result.stderr, encoding="utf-8")
        result.check_returncode()
        # A timeout or unexpected log is not accepted as proof/falsification.
        if name != "synthesis":
            marker = "model found: FAIL!" if "counterexample" in name else "no model found: SUCCESS!"
            if marker not in result.stdout:
                raise RuntimeError(f"Yosys did not confirm the expected outcome for {name}")
    return version


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--yosys", action="store_true")
    parser.add_argument("--scales", default="1000,10000,50000")
    args = parser.parse_args()
    sizes = [int(v) for v in args.scales.split(",")]
    if any(not 0 <= size <= 100_000 for size in sizes):
        raise ValueError("synthetic sizes must be 0..100000")
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).parent
    for name in ("design.v", "checks.json"):
        shutil.copyfile(source / name, output / name)
    version = run_yosys(output) if args.yosys else None
    if not args.yosys:
        shutil.copyfile(source / "netlist.json", output / "netlist.json")
    netlist = json.loads((output / "netlist.json").read_text())
    spec = json.loads((output / "checks.json").read_text())
    schema = json.loads((files("openconstraint.schemas") / "openconstraint-sequential-result.schema.json").read_text())
    expected = {
        "capture-spacing-2": "proven",
        "invalid-spacing-3": "counterexample",
        "captured-pair-coherent": "proven",
    }
    for backend in ("enumerate", "z3"):
        report = analyze_sequential(netlist, spec, backend=backend)
        Draft202012Validator(schema).validate(report)
        assert {c["id"]: c["status"] for c in report["checks"]} == expected, report
        assert report["passed"] is False
        replay = verify_sequential(report, netlist, spec)
        assert replay["verified"] and not replay["passed"], replay
        dump(output / f"{backend}.json", report)
        dump(output / f"{backend}-replay.json", replay)
        (output / f"{backend}-counterexample.vcd").write_text(
            render_vcd(report, netlist, spec, "invalid-spacing-3"), encoding="utf-8"
        )
    scales = []
    for size in sizes:
        # A sparse property in a deliberately large synthetic state bank, not
        # an industrial design and not a head-to-head commercial benchmark.
        large = json.loads((source / "netlist.json").read_text())
        cells = large["modules"]["top"]["cells"]
        for index in range(size):
            cells[f"unrelated_{index}"] = {"type": "$_DFF_P_", "connections": {"C": [2], "D": [5], "Q": [100 + index]}}
        small_spec = dict(spec) | {"checks": [spec["checks"][0]]}
        limits = SequentialLimits(max_cells=size + 100, max_bits=max(200_000, 4 * size))
        tracemalloc.start()
        start = time.perf_counter()
        report = analyze_sequential(large, small_spec, backend="enumerate", limits=limits)
        seconds = time.perf_counter() - start
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        assert report["passed"]
        assert report["checks"][0]["cone"]["state_bits"] == [4]
        assert verify_sequential(report, large, small_spec, limits=limits)["verified"]
        scales.append(
            {
                "unrelated_registers": size,
                "total_registers": size + 5,
                "property_registers": 1,
                "instrumented_seconds": seconds,
                "peak_traced_analysis_bytes": peak,
            }
        )
    dump(
        output / "scale.json",
        {
            "fixture": "synthetic sparse state bank",
            "measurement": "tracemalloc-instrumented analysis, excluding input construction and replay",
            "cases": scales,
        },
    )
    manifest = {p.name: sha256(p.read_bytes()).hexdigest() for p in sorted(output.iterdir()) if p.is_file()}
    dump(
        output / "validation.json",
        {
            "netlist_origin": "real_yosys_export" if args.yosys else "hand_written_fixture",
            "yosys_version": version,
            "z3_version": z3.get_version_string(),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "expected": expected,
            "all_checks_reproduced": True,
            "native_yosys_sat_controls": bool(args.yosys),
            "timing_signoff": False,
            "files_sha256": manifest,
        },
    )
    print(json.dumps({"output": str(output), "all_checks_reproduced": True, "real_yosys": bool(args.yosys)}))


if __name__ == "__main__":
    main()
