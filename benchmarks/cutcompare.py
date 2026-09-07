"""Reproducible reconvergent-path fixture; not an industrial performance claim."""

from __future__ import annotations

import argparse
import json
import platform
import time
import tracemalloc
from pathlib import Path

from openconstraint.cutcompare import compare_structural_cuts
from openconstraint.parsers.liberty import parse_liberty_text
from openconstraint.parsers.verilog import elaborate, parse_verilog_text

LIBERTY = """library (test) {
 cell (BUF) {pin (A) {direction : input;} pin (Y) {direction : output; function : "A";}}
 cell (OR2) {pin (A) {direction : input;} pin (B) {direction : input;} pin (Y) {direction : output; function : "A|B";}}
}"""


def fixture(layers: int) -> str:
    rows, nets = [], []
    for i in range(layers):
        source = "data" if i == 0 else f"j{i - 1}"
        nets.extend([f"l{i}", f"r{i}", f"j{i}"])
        rows.extend(
            [
                f"BUF left{i} (.A({source}),.Y(l{i}));",
                f"BUF right{i} (.A({source}),.Y(r{i}));",
                f"OR2 join{i} (.A(l{i}),.B(r{i}),.Y(j{i}));",
            ]
        )
    return (
        "module top(input data, output result); wire "
        + ",".join(nets)
        + ";"
        + "".join(rows)
        + f"BUF out (.A(j{layers - 1}),.Y(result)); endmodule"
    )


def run(layers: int) -> dict[str, object]:
    if type(layers) is not int or not 1 <= layers <= 500:
        raise ValueError("layers must be an integer in [1, 500]")
    design = elaborate(parse_verilog_text(fixture(layers)), parse_liberty_text(LIBERTY), "top")
    broad = "set_false_path -from [get_ports data] -to [get_ports result]"
    split = "\n".join(broad.replace("-to", f"-through [get_pins {branch}0/A] -to") for branch in ("left", "right"))
    tracemalloc.start()
    start = time.perf_counter()
    try:
        report = compare_structural_cuts(design, broad, split)
        elapsed = time.perf_counter() - start
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    if report["status"] != "equivalent_structural_cuts":
        raise RuntimeError(f"unexpected comparison result: {report['status']}: {report['reason']}")
    return {
        "family": "synthetic-layered-reconvergence",
        "layers": layers,
        "structural_routes": str(2**layers),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "tracemalloc_instrumented_seconds": elapsed,
        "python_peak_allocation_bytes": peak,
        "rss_measured": False,
        "proprietary_comparison_performed": False,
        "report": report,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--layers", type=int, default=45)
    parser.add_argument("--output", default="-")
    args = parser.parse_args()
    result = json.dumps(run(args.layers), indent=2, sort_keys=True) + "\n"
    if args.output == "-":
        print(result, end="")
    else:
        with Path(args.output).open("x", encoding="utf-8") as stream:
            stream.write(result)


if __name__ == "__main__":
    main()
