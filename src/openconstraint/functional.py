"""Replayable Boolean-influence checks on a fail-closed Yosys gate model.

This is NOT delay-aware false-path signoff. Flip-flop Q pins are independent,
unconstrained state boundaries; no reset reachability or clock schedule is
inferred. A zero-delay independence result must never create an SDC exception.
"""

from __future__ import annotations

import argparse
import heapq
import importlib
import json
import math
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from hashlib import sha256
from importlib.resources import files
from itertools import product
from pathlib import Path
from typing import Any

from openconstraint.version import __version__

MODEL = "zero_delay_arbitrary_state"
ALGORITHM = "boolean-influence-v1"
MAX_JSON_BYTES = 16 * 1024 * 1024
Bit = int | str
# Yosys internal single-bit gate port order. Unknown cells are never blackboxed.
GATE_PORTS = {
    "$_BUF_": "A",
    "$_NOT_": "A",
    "$_AND_": "AB",
    "$_NAND_": "AB",
    "$_OR_": "AB",
    "$_NOR_": "AB",
    "$_XOR_": "AB",
    "$_XNOR_": "AB",
    "$_ANDNOT_": "AB",
    "$_ORNOT_": "AB",
    "$_MUX_": "ABS",
    "$_NMUX_": "ABS",
}
STATE_CELLS = frozenset({"$_DFF_P_", "$_DFF_N_"})
DECISIONS = frozenset({"independent", "dependent"})


class FunctionalInputError(ValueError):
    """An input is malformed or has semantics outside the declared model."""


class FunctionalLimitError(FunctionalInputError):
    """A deterministic front-end work bound prevented analysis."""


@dataclass(frozen=True)
class FunctionalLimits:
    max_gates: int = 50_000
    max_bits: int = 200_000
    max_checks: int = 256
    max_enum_inputs: int = 18
    max_enum_work: int = 5_000_000
    max_total_gate_work: int = 1_000_000
    solver_timeout_ms: int = 10_000
    solver_rlimit: int = 1_000_000

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.solver_timeout_ms > 2**31 - 1 or self.solver_rlimit > 2**31 - 1:
            raise ValueError("solver limits must fit a signed 32-bit integer")
        if self.max_enum_inputs > 24:
            raise ValueError("max_enum_inputs must not exceed 24")


@dataclass(frozen=True)
class Gate:
    name: str
    kind: str
    inputs: tuple[Bit, ...]
    output: int


@dataclass(frozen=True)
class LogicModel:
    top: str
    roots: frozenset[int]
    gates: tuple[Gate, ...]
    names: Mapping[str, tuple[Bit, ...]]
    drivers: Mapping[int, Gate]
    state_outputs: frozenset[int]

    def resolve(self, ref: object) -> Bit:
        if type(ref) is int:
            if ref in self.roots or ref in self.drivers:
                return ref
            raise FunctionalInputError(f"unknown or undriven bit ID {ref}")
        if isinstance(ref, str):
            name, index = ref, None
        else:
            item = _object(ref, "signal reference")
            _keys(item, {"net", "bit"}, {"net", "bit"}, "signal reference")
            name, index = item["net"], item["bit"]
            if not isinstance(name, str) or type(index) is not int or index < 0:
                raise FunctionalInputError("signal reference requires a name and nonnegative bits-array index")
        if name not in self.names:
            raise FunctionalInputError(f"unknown net {name!r}")
        bits = self.names[name]
        if index is None:
            if len(bits) != 1:
                raise FunctionalInputError(f"net {name!r} is not scalar; provide an explicit bits-array index")
            index = 0
        if index >= len(bits):
            raise FunctionalInputError(f"bits-array index outside net {name!r}")
        bit = bits[index]
        if isinstance(bit, int) and bit not in self.roots and bit not in self.drivers:
            raise FunctionalInputError(f"net {name!r} is undriven")
        return bit

    def cone(self, targets: tuple[Bit, ...]) -> tuple[tuple[Gate, ...], tuple[int, ...]]:
        needed: set[int] = set()
        pending = list(targets)
        while pending:
            bit = pending.pop()
            if not isinstance(bit, int) or bit in needed:
                continue
            needed.add(bit)
            if bit in self.drivers:
                pending.extend(self.drivers[bit].inputs)
        return tuple(g for g in self.gates if g.output in needed), tuple(sorted(needed & self.roots))


def _object(value: object, where: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise FunctionalInputError(f"{where} must be an object with string keys")
    return value


def _keys(item: Mapping[str, Any], allowed: set[str], required: set[str], where: str) -> None:
    if set(item) - allowed or required - set(item):
        raise FunctionalInputError(f"{where} has unknown or missing fields")


def _bit(value: object) -> Bit:
    if type(value) is int and value >= 0:
        return value
    if isinstance(value, str) and value in {"0", "1"}:
        return value
    raise FunctionalInputError("only integer signal IDs and binary constants are supported; X/Z is not modeled")


def _bits(value: object, where: str, maximum: int) -> tuple[Bit, ...]:
    if not isinstance(value, list) or not value:
        raise FunctionalInputError(f"{where} must contain a nonempty bits array")
    if len(value) > maximum:
        raise FunctionalLimitError(f"{where} exceeds the bit limit")
    return tuple(_bit(v) for v in value)


def _enabled(value: object) -> bool:
    return value not in (0, "", None) and not (isinstance(value, str) and set(value) == {"0"})


def load_logic_model(netlist: Mapping[str, Any], top: str, limits: FunctionalLimits) -> LogicModel:
    modules = _object(netlist.get("modules"), "modules")
    module = _object(modules.get(top), "selected top")
    attributes = _object(module.get("attributes", {}), "module attributes")
    if (
        any(_enabled(attributes.get(k)) for k in ("blackbox", "whitebox"))
        or module.get("memories")
        or module.get("processes")
    ):
        raise FunctionalInputError("blackboxes, whiteboxes, memories, and unlowered processes are not modeled")
    ports = _object(module.get("ports"), "ports")
    names_json = _object(module.get("netnames", {}), "netnames")
    cells = _object(module.get("cells"), "cells")
    if len(cells) > limits.max_gates:
        raise FunctionalLimitError("cell count exceeds max_gates")
    if len(ports) + len(names_json) > limits.max_bits:
        raise FunctionalLimitError("signal-name count exceeds max_bits")
    roots: set[int] = set()
    used: set[int] = set()
    all_bits: set[int] = set()
    names: dict[str, tuple[Bit, ...]] = {}
    retained = 0
    for category, entries in (("net", names_json), ("port", ports)):
        for name, raw in sorted(entries.items()):
            info = _object(raw, f"{category} {name!r}")
            bits = _bits(info.get("bits"), name, limits.max_bits)
            retained += len(bits)
            if retained > limits.max_bits * 8:
                raise FunctionalLimitError("retained signal aliases exceed eight times max_bits")
            if name in names and names[name] != bits:
                raise FunctionalInputError(f"conflicting port/net alias {name!r}")
            names[name] = bits
            all_bits.update(b for b in bits if isinstance(b, int))
            if category == "port":
                direction = info.get("direction")
                if direction not in {"input", "output"}:
                    raise FunctionalInputError("inout/unknown port directions are not modeled")
                if direction == "input":
                    if any(not isinstance(b, int) for b in bits):
                        raise FunctionalInputError("an input port cannot be a constant")
                    roots.update(b for b in bits if isinstance(b, int))
                else:
                    used.update(b for b in bits if isinstance(b, int))
    if len(all_bits) > limits.max_bits:
        raise FunctionalLimitError("signal count exceeds max_bits")
    drivers: dict[int, Gate] = {}
    state: set[int] = set()
    for name, raw in sorted(cells.items()):
        cell = _object(raw, f"cell {name!r}")
        kind = cell.get("type")
        if not isinstance(kind, str) or kind not in GATE_PORTS and kind not in STATE_CELLS:
            raise FunctionalInputError(f"unsupported cell {name!r} of type {kind!r}; flatten and techmap first")
        if cell.get("parameters"):
            raise FunctionalInputError(f"unexpected parameters on primitive {name!r}")
        connections = _object(cell.get("connections"), "cell connections")
        expected_inputs = "CD" if kind in STATE_CELLS else GATE_PORTS[kind]
        output_port = "Q" if kind in STATE_CELLS else "Y"
        if set(connections) != set(expected_inputs + output_port):
            raise FunctionalInputError(f"unexpected primitive ports on {name!r}")
        directions = _object(cell.get("port_directions", {}), "cell port directions")
        expected_directions = {p: "input" for p in expected_inputs} | {output_port: "output"}
        if directions and directions != expected_directions:
            raise FunctionalInputError(f"inconsistent primitive directions on {name!r}")
        if any(not isinstance(v, list) or len(v) != 1 for v in connections.values()):
            raise FunctionalInputError(f"primitive {name!r} requires single-bit connections")
        conns = {p: _bits(v, f"{name}/{p}", 1)[0] for p, v in connections.items()}
        output = conns[output_port]
        if not isinstance(output, int) or output in roots or output in drivers or output in state:
            raise FunctionalInputError(f"constant or multiply driven output on {name!r}")
        inputs = tuple(conns[p] for p in expected_inputs)
        used.update(b for b in inputs if isinstance(b, int))
        all_bits.update(b for b in conns.values() if isinstance(b, int))
        if len(all_bits) > limits.max_bits:
            raise FunctionalLimitError("signal count exceeds max_bits")
        if kind in STATE_CELLS:
            state.add(output)
        else:
            drivers[output] = Gate(name, kind, inputs, output)
    roots.update(state)
    missing = used - roots - drivers.keys()
    if missing:
        raise FunctionalInputError(f"undriven logic input(s): {sorted(missing)[:8]}")
    # Kahn ordering avoids Python recursion limits and rejects combinational loops.
    degree: dict[int, int] = {}
    consumers: dict[int, list[int]] = {}
    for output, gate in drivers.items():
        dependencies = {b for b in gate.inputs if isinstance(b, int) and b in drivers}
        degree[output] = len(dependencies)
        for bit in dependencies:
            consumers.setdefault(bit, []).append(output)
    ready = [bit for bit, count in degree.items() if count == 0]
    heapq.heapify(ready)
    ordered: list[Gate] = []
    while ready:
        bit = heapq.heappop(ready)
        ordered.append(drivers[bit])
        for consumer in consumers.get(bit, []):
            degree[consumer] -= 1
            if degree[consumer] == 0:
                heapq.heappush(ready, consumer)
    if len(ordered) != len(drivers):
        raise FunctionalInputError("combinational cycle detected")
    return LogicModel(top, frozenset(roots), tuple(ordered), names, drivers, frozenset(state))


def _specification(spec: Mapping[str, Any], limits: FunctionalLimits) -> list[dict[str, Any]]:
    _keys(
        spec,
        {"schema_version", "model", "top", "checks"},
        {"schema_version", "model", "top", "checks"},
        "specification",
    )
    if (
        spec["schema_version"] != "1.0.0"
        or spec["model"] != MODEL
        or not isinstance(spec["top"], str)
        or not spec["top"]
    ):
        raise FunctionalInputError("specification must explicitly select schema 1.0.0 and zero_delay_arbitrary_state")
    checks = spec["checks"]
    if not isinstance(checks, list) or not checks:
        raise FunctionalInputError("checks must be nonempty")
    if len(checks) > limits.max_checks:
        raise FunctionalLimitError("check count exceeds max_checks")
    seen: set[str] = set()
    parsed = []
    for raw in checks:
        check = _object(raw, "check")
        _keys(check, {"id", "sources", "targets", "assumptions"}, {"id", "sources", "targets"}, "check")
        ident = check["id"]
        if not isinstance(ident, str) or not ident or len(ident) > 200 or ident in seen:
            raise FunctionalInputError("check IDs must be unique, nonempty strings of at most 200 characters")
        seen.add(ident)
        for key in ("sources", "targets"):
            if not isinstance(check[key], list) or not check[key] or len(check[key]) > limits.max_bits:
                raise FunctionalInputError(f"{key} must be a nonempty, bounded array")
        assumptions = check.get("assumptions", [])
        if not isinstance(assumptions, list) or len(assumptions) > limits.max_bits:
            raise FunctionalInputError("assumptions must be a bounded array")
        for raw_assumption in assumptions:
            item = _object(raw_assumption, "assumption")
            _keys(item, {"signal", "value"}, {"signal", "value"}, "assumption")
            if type(item["value"]) is not int or item["value"] not in {0, 1}:
                raise FunctionalInputError("assumption value must be integer 0 or 1")
        parsed.append(check)
    return parsed


def _digest(value: object) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    ).hexdigest()


def _read_bit(bit: Bit, values: Mapping[int, bool]) -> bool:
    return bit == "1" if isinstance(bit, str) else values[bit]


def _evaluate(gates: tuple[Gate, ...], inputs: Mapping[int, bool], targets: tuple[Bit, ...]) -> tuple[bool, ...]:
    values = dict(inputs)
    for gate in gates:
        args = tuple(_read_bit(b, values) for b in gate.inputs)
        a = args[0]
        b = args[1] if len(args) > 1 else False
        kind = gate.kind
        if kind in {"$_BUF_", "$_NOT_"}:
            value = a if kind == "$_BUF_" else not a
        elif kind in {"$_AND_", "$_NAND_"}:
            value = a and b
        elif kind in {"$_OR_", "$_NOR_"}:
            value = a or b
        elif kind in {"$_XOR_", "$_XNOR_"}:
            value = a != b
        elif kind == "$_ANDNOT_":
            value = a and not b
        elif kind == "$_ORNOT_":
            value = a or not b
        else:  # MUX and NMUX, validated by the front end.
            value = b if args[2] else a
        if kind in {"$_NAND_", "$_NOR_", "$_XNOR_", "$_NMUX_"}:
            value = not value
        values[gate.output] = value
    return tuple(_read_bit(b, values) for b in targets)


def _witness(
    gates: tuple[Gate, ...], left: Mapping[int, bool], right: Mapping[int, bool], targets: tuple[Bit, ...]
) -> dict[str, Any]:
    return {
        label: {
            "inputs": {str(k): int(v) for k, v in sorted(world.items())},
            "targets": [int(v) for v in _evaluate(gates, world, targets)],
        }
        for label, world in (("left", left), ("right", right))
    }


def _check_witness(
    witness: object,
    gates: tuple[Gate, ...],
    roots: tuple[int, ...],
    sources: set[int],
    targets: tuple[Bit, ...],
    fixed: Mapping[int, bool],
) -> bool:
    try:
        w = _object(witness, "counterexample")
        if set(w) != {"left", "right"}:
            return False
        worlds: list[dict[int, bool]] = []
        for key in ("left", "right"):
            item = _object(w[key], "world")
            if set(item) != {"inputs", "targets"}:
                return False
            inputs = _object(item["inputs"], "inputs")
            if set(inputs) != {str(b) for b in roots} or any(
                type(v) is not int or v not in {0, 1} for v in inputs.values()
            ):
                return False
            values = {int(k): bool(v) for k, v in inputs.items()}
            if any(bit in values and values[bit] != value for bit, value in fixed.items()):
                return False
            if (
                not isinstance(item["targets"], list)
                or any(type(v) is not int or v not in {0, 1} for v in item["targets"])
                or item["targets"] != [int(v) for v in _evaluate(gates, values, targets)]
            ):
                return False
            worlds.append(values)
        left, right = worlds
        if any(left[b] != right[b] for b in roots if b not in sources):
            return False
        return _evaluate(gates, left, targets) != _evaluate(gates, right, targets)
    except (KeyError, TypeError, ValueError):
        return False


def _enumerate(
    gates: tuple[Gate, ...],
    roots: tuple[int, ...],
    sources: set[int],
    targets: tuple[Bit, ...],
    fixed: Mapping[int, bool],
    limits: FunctionalLimits,
) -> dict[str, Any]:
    active_sources = sorted(sources & set(roots))
    if not active_sources:
        return {
            "status": "independent",
            "reason": "no source occurs in the target Boolean cone",
            "counterexample": None,
        }
    free = [b for b in roots if b not in fixed]
    if (
        len(free) > limits.max_enum_inputs
        or (1 << len(free)) * max(1, len(gates) + len(roots) + len(targets)) > limits.max_enum_work
    ):
        return {"status": "bounded", "reason": "exhaustive backend work limit", "counterexample": None}
    side = [b for b in free if b not in sources]
    for side_values in product((False, True), repeat=len(side)):
        base = {b: fixed[b] for b in roots if b in fixed}
        base.update(zip(side, side_values, strict=True))
        base.update((b, False) for b in active_sources)
        reference = _evaluate(gates, base, targets)
        for source_values in product((False, True), repeat=len(active_sources)):
            if not any(source_values):
                continue
            other = base | dict(zip(active_sources, source_values, strict=True))
            if _evaluate(gates, other, targets) != reference:
                return {
                    "status": "dependent",
                    "reason": "a source perturbation changes a target in the declared model",
                    "counterexample": _witness(gates, base, other, targets),
                }
    return {"status": "independent", "reason": "exhaustive Boolean comparison completed", "counterexample": None}


def _z3_expression(z3: Any, kind: str, args: list[Any]) -> Any:
    a = args[0]
    if kind == "$_BUF_":
        return a
    if kind == "$_NOT_":
        return z3.Not(a)
    b = args[1]
    if kind in {"$_AND_", "$_NAND_"}:
        value = z3.And(a, b)
    elif kind in {"$_OR_", "$_NOR_"}:
        value = z3.Or(a, b)
    elif kind in {"$_XOR_", "$_XNOR_"}:
        value = z3.Xor(a, b)
    elif kind == "$_ANDNOT_":
        value = z3.And(a, z3.Not(b))
    elif kind == "$_ORNOT_":
        value = z3.Or(a, z3.Not(b))
    else:
        value = z3.If(args[2], b, a)
    return z3.Not(value) if kind in {"$_NAND_", "$_NOR_", "$_XNOR_", "$_NMUX_"} else value


def _solve_z3(
    z3: Any,
    gates: tuple[Gate, ...],
    roots: tuple[int, ...],
    sources: set[int],
    targets: tuple[Bit, ...],
    fixed: Mapping[int, bool],
    limits: FunctionalLimits,
) -> dict[str, Any]:
    solver = z3.Solver()
    solver.set(timeout=limits.solver_timeout_ms, rlimit=limits.solver_rlimit, random_seed=0)
    worlds: list[dict[Bit, Any]] = []
    for label in ("left", "right"):
        values: dict[Bit, Any] = {"0": z3.BoolVal(False), "1": z3.BoolVal(True)}
        for bit in roots:
            values[bit] = z3.Bool(f"{label if bit in sources else 'shared'}_{bit}")
            if bit in fixed:
                solver.add(values[bit] == fixed[bit])
        for gate in gates:
            values[gate.output] = z3.Bool(f"{label}_net_{gate.output}")
            solver.add(values[gate.output] == _z3_expression(z3, gate.kind, [values[b] for b in gate.inputs]))
        worlds.append(values)
    solver.add(z3.Or(*[z3.Xor(worlds[0][b], worlds[1][b]) for b in targets]))
    answer = solver.check()
    if answer == z3.unsat:
        return {"status": "independent", "reason": "Boolean influence miter is UNSAT", "counterexample": None}
    if answer != z3.sat:
        return {
            "status": "bounded",
            "reason": "solver returned unknown: " + str(solver.reason_unknown()),
            "counterexample": None,
        }
    model = solver.model()
    assignments = [{b: bool(z3.is_true(model.eval(w[b], model_completion=True))) for b in roots} for w in worlds]
    return {
        "status": "dependent",
        "reason": "Boolean influence miter is SAT",
        "counterexample": _witness(gates, assignments[0], assignments[1], targets),
    }


def _obligation(
    model: LogicModel, check: Mapping[str, Any]
) -> tuple[set[int], tuple[Bit, ...], dict[int, bool], str | None]:
    source_refs = [model.resolve(ref) for ref in check["sources"]]
    if any(not isinstance(b, int) or b not in model.roots for b in source_refs):
        raise FunctionalInputError("sources must be primary inputs or explicit DFF Q state boundaries")
    sources = {b for b in source_refs if isinstance(b, int)}
    targets = tuple(model.resolve(ref) for ref in check["targets"])
    fixed: dict[int, bool] = {}
    reason = None
    for item in check.get("assumptions", []):
        bit = model.resolve(item["signal"])
        if not isinstance(bit, int) or bit not in model.roots:
            raise FunctionalInputError("assumptions may constrain only primary inputs or DFF Q boundaries")
        value = bool(item["value"])
        if bit in fixed and fixed[bit] != value:
            reason = "contradictory assumptions on aliases of the same bit"
        fixed[bit] = value
    if sources & fixed.keys():
        reason = "assumptions fix a source under test; refusing a vacuous independence claim"
    return sources, targets, fixed, reason


def analyze_functional(
    netlist: Mapping[str, Any],
    specification: Mapping[str, Any],
    *,
    backend: str = "z3",
    limits: FunctionalLimits | None = None,
) -> dict[str, Any]:
    """Analyze explicit Boolean obligations, never SDC timing validity."""
    limits = limits or FunctionalLimits()
    checks = _specification(specification, limits)
    if backend not in {"z3", "enumerate"}:
        raise FunctionalInputError("backend must be z3 or enumerate")
    z3 = None
    solver_version = "builtin-v1"
    unavailable = None
    if backend == "z3":
        try:
            z3 = importlib.import_module("z3")
            solver_version = str(z3.get_version_string())
        except ImportError:
            unavailable = "Z3 is not installed; install openconstraint[formal] or select --backend enumerate"
            solver_version = "unavailable"
    model = None
    model_error = None
    model_status = "unsupported"
    try:
        model = load_logic_model(netlist, specification["top"], limits)
    except FunctionalLimitError as error:
        model_error, model_status = str(error), "bounded"
    except FunctionalInputError as error:
        model_error = str(error)
    results = []
    work = 0
    cones: dict[tuple[Bit, ...], tuple[tuple[Gate, ...], tuple[int, ...]]] = {}
    for check in checks:
        entry: dict[str, Any] = {"id": check["id"], "query_digest": _digest(check), "cone_gates": 0, "cone_inputs": 0}
        if model_error or unavailable:
            entry.update(
                status=model_status if model_error else "unsupported",
                reason=model_error or unavailable,
                counterexample=None,
            )
        elif work >= limits.max_total_gate_work:
            entry.update(status="bounded", reason="aggregate gate/variable work limit", counterexample=None)
        else:
            assert model is not None
            try:
                sources, targets, fixed, inconsistent = _obligation(model, check)
                if targets not in cones:
                    cones[targets] = model.cone(targets)
                gates, roots = cones[targets]
                work += 2 * (len(gates) + len(roots) + len(targets))
                entry.update(cone_gates=len(gates), cone_inputs=len(roots))
                if inconsistent:
                    entry.update(status="inconsistent_assumptions", reason=inconsistent, counterexample=None)
                elif work > limits.max_total_gate_work:
                    entry.update(status="bounded", reason="aggregate gate/variable work limit", counterexample=None)
                else:
                    answer = (
                        _enumerate(gates, roots, sources, targets, fixed, limits)
                        if backend == "enumerate"
                        else _solve_z3(z3, gates, roots, sources, targets, fixed, limits)
                    )
                    if answer["status"] == "dependent" and not _check_witness(
                        answer["counterexample"], gates, roots, sources, targets, fixed
                    ):
                        raise RuntimeError("solver counterexample failed independent concrete evaluation")
                    entry.update(answer)
            except FunctionalInputError as error:
                entry.update(status="unsupported", reason=str(error), counterexample=None)
        results.append(entry)
    report: dict[str, Any] = {
        "schema_version": "1.0.0",
        "tool": {"name": "OpenConstraint", "version": __version__},
        "algorithm": ALGORITHM,
        "model": MODEL,
        "timing_signoff": False,
        "netlist_digest": _digest(netlist),
        "specification_digest": _digest(specification),
        "backend": {"name": backend, "version": solver_version},
        "limits": asdict(limits),
        "summary": dict(sorted(Counter(item["status"] for item in results).items())),
        "checks": results,
    }
    report["report_digest"] = _digest(report)
    return report


def _validate_saved_report(expected: Mapping[str, Any]) -> None:
    required = {
        "schema_version",
        "tool",
        "algorithm",
        "model",
        "timing_signoff",
        "netlist_digest",
        "specification_digest",
        "backend",
        "limits",
        "summary",
        "checks",
        "report_digest",
    }
    _keys(expected, required, required, "saved report")
    for field, name in (("tool", "OpenConstraint"), ("backend", None)):
        item = _object(expected[field], field)
        _keys(item, {"name", "version"}, {"name", "version"}, field)
        if not isinstance(item["version"], str) or not item["version"]:
            raise FunctionalInputError(f"invalid {field} version")
        if item["name"] not in ({name} if name else {"z3", "enumerate"}):
            raise FunctionalInputError(f"invalid {field} name")
    saved_limits = _object(expected["limits"], "limits")
    limit_keys = set(asdict(FunctionalLimits()))
    _keys(saved_limits, limit_keys, limit_keys, "limits")
    FunctionalLimits(**saved_limits)
    statuses = DECISIONS | {"bounded", "unsupported", "inconsistent_assumptions"}
    summary = _object(expected["summary"], "summary")
    if not summary or set(summary) - statuses or any(type(v) is not int or v < 1 for v in summary.values()):
        raise FunctionalInputError("invalid summary counts")
    if not isinstance(expected["checks"], list) or not expected["checks"]:
        raise FunctionalInputError("invalid check inventory")
    fields = {"id", "query_digest", "cone_gates", "cone_inputs", "status", "reason", "counterexample"}
    for raw in expected["checks"]:
        check = _object(raw, "saved check")
        _keys(check, fields, fields, "saved check")
        if any(type(check[k]) is not int or check[k] < 0 for k in ("cone_gates", "cone_inputs")):
            raise FunctionalInputError("invalid cone counts")
        if not isinstance(check["reason"], str) or not check["reason"]:
            raise FunctionalInputError("invalid decision reason")


def verify_functional(
    expected: Mapping[str, Any],
    netlist: Mapping[str, Any],
    specification: Mapping[str, Any],
    *,
    backend: str = "enumerate",
    limits: FunctionalLimits | None = None,
) -> dict[str, Any]:
    """Re-solve decisions and independently evaluate stored counterexamples.

    Digests are integrity checks, not authentication. UNKNOWN/unsupported results
    never count as verified proofs, even when their bytes reproduce exactly.
    """
    errors = []
    try:
        _validate_saved_report(expected)
    except (FunctionalInputError, TypeError, ValueError) as error:
        errors.append("invalid report contract: " + str(error))
    if expected.get("report_digest") != _digest({k: v for k, v in expected.items() if k != "report_digest"}):
        errors.append("report integrity mismatch")
    actual = analyze_functional(netlist, specification, backend=backend, limits=limits)
    for key in (
        "schema_version",
        "algorithm",
        "model",
        "timing_signoff",
        "netlist_digest",
        "specification_digest",
        "summary",
    ):
        if expected.get(key) != actual[key]:
            errors.append(f"{key} mismatch")
    entries = expected.get("checks")
    if not isinstance(entries, list) or len(entries) != len(actual["checks"]):
        errors.append("check inventory mismatch")
        entries = []
    parsed_model = None
    try:
        parsed_model = load_logic_model(netlist, specification["top"], limits or FunctionalLimits())
    except FunctionalInputError:
        errors.append("model could not be reconstructed")
    for saved, fresh, spec in zip(entries, actual["checks"], specification["checks"], strict=False):
        if not isinstance(saved, dict):
            errors.append("invalid check record")
            continue
        for key in ("id", "query_digest", "status", "cone_gates", "cone_inputs"):
            if saved.get(key) != fresh[key]:
                errors.append(f"{fresh['id']!r}: {key} mismatch")
        if fresh["status"] not in DECISIONS:
            errors.append(f"{fresh['id']!r}: replay produced no decision")
        elif saved.get("status") == "dependent" and parsed_model is not None:
            sources, targets, fixed, _ = _obligation(parsed_model, spec)
            gates, roots = parsed_model.cone(targets)
            if not _check_witness(saved.get("counterexample"), gates, roots, sources, targets, fixed):
                errors.append(f"{fresh['id']!r}: invalid stored counterexample")
        elif saved.get("counterexample") is not None:
            errors.append(f"{fresh['id']!r}: unexpected counterexample")
    return {
        "verified": not errors,
        "timing_signoff": False,
        "model": MODEL,
        "replay_backend": actual["backend"],
        "all_independent": not errors and all(c["status"] == "independent" for c in actual["checks"]),
        "errors": errors,
    }


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FunctionalInputError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def read_functional_json(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise FunctionalLimitError("JSON input exceeds 16 MiB")

    # Check depth without recursion, respecting JSON strings and escapes.
    depth = 0
    quoted = False
    escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 128:
                raise FunctionalLimitError("JSON nesting exceeds 128 levels")
        elif byte in (93, 125):
            depth -= 1

    def reject_constant(value: str) -> None:
        raise FunctionalInputError(f"nonfinite JSON constant {value}")

    def finite_float(value: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            raise FunctionalInputError("nonfinite JSON number")
        return number

    try:
        return _object(
            json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=reject_constant,
                parse_float=finite_float,
            ),
            str(path),
        )
    except RecursionError as error:
        raise FunctionalLimitError("JSON nesting limit exceeded") from error


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Boolean influence evidence, NOT timing false-path signoff")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("analyze", "verify"):
        child = sub.add_parser(name)
        child.add_argument("--netlist", required=True)
        child.add_argument("--spec", required=True)
        child.add_argument("--backend", choices=("z3", "enumerate"), default="z3" if name == "analyze" else "enumerate")
        child.add_argument("--output", default="-")
        for key, value in asdict(FunctionalLimits()).items():
            child.add_argument("--" + key.replace("_", "-"), type=int, default=value)
        if name == "verify":
            child.add_argument("--report", required=True)
    child = sub.add_parser("schema")
    child.add_argument("--kind", choices=("spec", "result"), default="spec")
    child.add_argument("--output", default="-")
    args = parser.parse_args(argv)
    try:
        if args.command == "schema":
            text = (files("openconstraint.schemas") / f"openconstraint-functional-{args.kind}.schema.json").read_text(
                encoding="utf-8"
            )
            code = 0
        else:
            limits = FunctionalLimits(**{key: getattr(args, key) for key in asdict(FunctionalLimits())})
            netlist, spec = read_functional_json(Path(args.netlist)), read_functional_json(Path(args.spec))
            if args.command == "analyze":
                report = analyze_functional(netlist, spec, backend=args.backend, limits=limits)
                code = int(any(c["status"] != "independent" for c in report["checks"]))
            else:
                report = verify_functional(
                    read_functional_json(Path(args.report)), netlist, spec, backend=args.backend, limits=limits
                )
                code = int(not report["verified"])
            text = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"
        if args.output == "-":
            sys.stdout.write(text)
        else:
            # Exclusive creation prevents overwrites, including symlink/hardlink
            # aliases to a declared input. Source files are never modified.
            with Path(args.output).open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(text)
        return code
    except (ValueError, OSError, UnicodeError, RecursionError) as error:
        print(f"openconstraint-functional: {error!s}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
