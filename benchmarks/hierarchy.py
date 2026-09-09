"""Synthetic repeat-instance elaboration benchmark, not an industrial proof claim."""

from __future__ import annotations

import argparse
import json
import time
import tracemalloc
from pathlib import Path

from openconstraint.hierarchy import elaborate_hierarchy, verify_hierarchy


def fixture(size: int) -> dict:
    if not 1 <= size <= 10_000:
        raise ValueError("size must be in [1, 10000]")
    inputs, outputs = list(range(2, size + 2)), list(range(size + 2, 2 * size + 2))
    leaf = {
        "ports": {"i": {"direction": "input", "bits": [2]}, "o": {"direction": "output", "bits": [4]}},
        "cells": {
            "first": {"type": "$_NOT_", "connections": {"A": [2], "Y": [3]}},
            "second": {"type": "$_NOT_", "connections": {"A": [3], "Y": [4]}},
        },
    }
    top = {
        "ports": {"i": {"direction": "input", "bits": inputs}, "o": {"direction": "output", "bits": outputs}},
        "cells": {
            f"u{index:05d}": {"type": "leaf", "connections": {"i": [inputs[index]], "o": [outputs[index]]}}
            for index in range(size)
        },
    }
    return {"modules": {"top": top, "leaf": leaf}}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", default="1000,5000")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    results = []
    for size in (int(s) for s in args.sizes.split(",")):
        netlist = fixture(size)
        tracemalloc.start()
        start = time.perf_counter()
        pack = elaborate_hierarchy(netlist, "top")
        seconds = time.perf_counter() - start
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        assert pack["provenance"]["counts"]["leaf_cells"] == 2 * size
        assert pack["provenance"]["counts"]["instances"] == size + 1
        assert verify_hierarchy(pack, netlist, "top")
        results.append(
            {
                "repeated_instances": size,
                "instrumented_seconds": seconds,
                "python_traced_peak_bytes": peak,
                "counts": pack["provenance"]["counts"],
                "replayed": True,
            }
        )
    with Path(args.output).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(
            {
                "fixture": "synthetic repeated two-inverter modules",
                "measurement": "elaboration including source snapshot and evidence serialization; excludes input construction and replay",
                "commercial_comparison": False,
                "results": results,
            },
            stream,
            indent=2,
        )
        stream.write("\n")


if __name__ == "__main__":
    main()
