"""Fail-closed synchronous transition systems and property-specific cone reduction.

The clock is an explicit logical tick, not a generated-clock or delay model.
Supported synchronous enable/reset primitives are lowered to Boolean muxes and
plain flip-flops. Asynchronous resets, latches and derived clocks are rejected.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

from openconstraint.functional import (
    Bit,
    FunctionalInputError,
    FunctionalLimits,
    Gate,
    LogicModel,
    _bit,
    _evaluate,
    _keys,
    _object,
    load_logic_model,
)

MODEL = "single_clock_synchronous_v1"


class SequentialLimitError(FunctionalInputError):
    """Analysis ran out of an explicitly specified work budget."""


class InconsistentContract(FunctionalInputError):
    """An assumption or property contradicts an alias of the same signal."""


@dataclass(frozen=True)
class SequentialLimits:
    max_cells: int = 50_000
    max_bits: int = 200_000
    max_checks: int = 64
    max_depth: int = 32
    max_prefix: int = 64
    max_history: int = 64
    max_state_bits: int = 4096
    max_enum_free_bits: int = 20
    max_states: int = 65_536
    max_work: int = 5_000_000
    max_solver_calls: int = 128
    solver_timeout_ms: int = 1000
    solver_rlimit: int = 1_000_000

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_enum_free_bits > 24 or self.max_depth > 256 or self.max_prefix > 256:
            raise ValueError("maximum enumeration bits/depth/prefix are 24/256/256")
        if self.max_history > 256 or self.max_state_bits > 65_536:
            raise ValueError("maximum history/state bits are 256/65536")
        if self.solver_timeout_ms > 2**31 - 1 or self.solver_rlimit > 2**31 - 1:
            raise ValueError("solver limits must fit a signed 32-bit integer")


@dataclass
class Budget:
    limits: SequentialLimits
    work: int = 0
    solver_calls: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0:
            raise ValueError("work charge cannot be negative")
        if amount > self.limits.max_work - self.work:
            raise SequentialLimitError("aggregate transition/encoding work limit")
        self.work += amount

    def solver_call(self) -> None:
        if self.solver_calls >= self.limits.max_solver_calls:
            raise SequentialLimitError("aggregate solver-call limit")
        self.solver_calls += 1


@dataclass(frozen=True)
class SynchronousModel:
    logic: LogicModel
    clock: int
    edge: str
    inputs: frozenset[int]
    next_state: Mapping[int, Bit]

    def resolve(self, ref: object) -> Bit:
        bit = self.logic.resolve(ref)
        if bit == self.clock:
            raise FunctionalInputError("the logical clock cannot be used as data or in a property")
        return bit


@dataclass(frozen=True)
class Machine:
    """A property cone closed under sequential next-state dependencies."""

    gates: tuple[Gate, ...]
    states: tuple[int, ...]
    inputs: tuple[int, ...]
    next_bits: tuple[Bit, ...]
    observed: tuple[Bit, ...]
    forbidden: tuple[bool, ...]
    history: int

    @property
    def width(self) -> int:
        return len(self.states) + self.history

    @property
    def cost(self) -> int:
        return max(1, len(self.gates) + self.width + len(self.inputs) + len(self.observed))

    def step(
        self, state: tuple[bool, ...], inputs: Mapping[int, bool], *, prefix: bool = False
    ) -> tuple[tuple[bool, ...], tuple[bool, ...], bool]:
        values = dict(zip(self.states, state[: len(self.states)], strict=True)) | dict(inputs)
        evaluated = _evaluate(self.gates, values, self.next_bits + self.observed)
        next_q = evaluated[: len(self.states)]
        observed = evaluated[len(self.states) :]
        if self.history:
            event = observed[0]
            bad = event and any(state[len(self.states) :])
            hist = (False,) * self.history if prefix else (event,) + state[len(self.states) : -1]
            return next_q + hist, observed, bad
        return next_q, observed, observed == self.forbidden


def _synchronous_primitive(kind: str) -> tuple[str, str, str | None, bool | None, bool | None]:
    """Return clock polarity, enable polarity, reset polarity/value and priority.

    Empty enable means none. Last flag is reset-over-enable; only synchronous
    cells appear in this table. The implementation follows the documented Yosys
    gate-level primitive interfaces, not inferred cell-name substrings.
    """
    if match := re.fullmatch(r"\$_DFF_([PN])_", kind):
        return match[1], "", None, None, None
    if match := re.fullmatch(r"\$_DFFE_([PN])([PN])_", kind):
        return match[1], match[2], None, None, None
    if match := re.fullmatch(r"\$_SDFF_([PN])([PN])([01])_", kind):
        return match[1], "", match[2], match[3] == "1", True
    if match := re.fullmatch(r"\$_(SDFFE|SDFFCE)_([PN])([PN])([01])([PN])_", kind):
        return match[2], match[5], match[3], match[4] == "1", match[1] == "SDFFE"
    raise FunctionalInputError(f"unsupported sequential primitive {kind!r}")


def load_synchronous_model(
    netlist: Mapping[str, Any], top: str, clock_ref: object, edge: str, limits: SequentialLimits
) -> SynchronousModel:
    modules = _object(netlist.get("modules"), "modules")
    module = _object(modules.get(top), "selected top")
    cells = _object(module.get("cells"), "cells")
    if len(cells) > limits.max_cells:
        raise SequentialLimitError("cell count exceeds max_cells")
    if edge not in {"posedge", "negedge"}:
        raise FunctionalInputError("clock edge must be posedge or negedge")
    # An explicit initial/reset contract is required; hidden initial-state
    # attributes are not silently ignored or interpreted as unconstrained.
    for raw in _object(module.get("netnames", {}), "netnames").values():
        info = _object(raw, "netname")
        attrs = _object(info.get("attributes", {}), "net attributes")
        if "init" in attrs:
            raise FunctionalInputError("Yosys init attributes require an explicit export without hidden init semantics")

    lowered: dict[str, Any] = dict(cells)
    q_to_d: dict[int, Bit] = {}
    clocks: list[tuple[Bit, str]] = []
    bit_ids: list[int] = []
    for raw in cells.values():
        for connection in _object(_object(raw, "cell").get("connections"), "connections").values():
            if isinstance(connection, list):
                bit_ids.extend(b for b in connection if type(b) is int and b >= 0)
    for key in ("ports", "netnames"):
        for raw in _object(module.get(key, {}), key).values():
            bits = _object(raw, key).get("bits", [])
            if isinstance(bits, list):
                bit_ids.extend(b for b in bits if type(b) is int and b >= 0)
    if len(bit_ids) > limits.max_bits * 16:
        raise SequentialLimitError("retained connectivity exceeds bit budget")
    next_bit = max(bit_ids, default=1) + 1
    serial = 0

    def mux(a: Bit, b: Bit, s: Bit, active_high: bool) -> Bit:
        nonlocal next_bit, serial
        while f"$openconstraint$sync${serial}" in lowered:
            serial += 1
        name = f"$openconstraint$sync${serial}"
        serial += 1
        output = next_bit
        next_bit += 1
        lowered[name] = {
            "type": "$_MUX_",
            "connections": {"A": [a if active_high else b], "B": [b if active_high else a], "S": [s], "Y": [output]},
        }
        if len(lowered) > limits.max_cells:
            raise SequentialLimitError("lowered synchronous cells exceed max_cells")
        return output

    for name, raw in sorted(cells.items()):
        cell = _object(raw, f"cell {name!r}")
        kind = cell.get("type")
        if not isinstance(kind, str):
            raise FunctionalInputError("cell type must be a string")
        if kind in modules:
            raise FunctionalInputError("user-defined modules may not override primitive cell semantics")
        if not kind.startswith(("$_DFF", "$_SDFF")):
            continue  # The shared Boolean front end rejects every other unknown cell.
        cp, ep, rp, rv, reset_first = _synchronous_primitive(kind)
        conns = _object(cell.get("connections"), "connections")
        inputs = "CD" + ("E" if ep else "") + ("R" if rp else "")
        if set(conns) != set(inputs + "Q") or cell.get("parameters"):
            raise FunctionalInputError(f"invalid synchronous primitive interface on {name!r}")
        directions = _object(cell.get("port_directions", {}), "directions")
        if directions and directions != ({k: "input" for k in inputs} | {"Q": "output"}):
            raise FunctionalInputError(f"invalid synchronous primitive directions on {name!r}")
        if any(not isinstance(v, list) or len(v) != 1 for v in conns.values()):
            raise FunctionalInputError("synchronous primitive connections must be single-bit")
        conn = {k: _bit(v[0]) for k, v in conns.items()}
        q = conn["Q"]
        if type(q) is not int or q in q_to_d:
            raise FunctionalInputError("duplicate or constant sequential driver")
        d = conn["D"]
        if ep and (not rp or reset_first):
            d = mux(q, d, conn["E"], ep == "P")
        if rp:
            d = mux(d, "1" if rv else "0", conn["R"], rp == "P")
        if ep and rp and not reset_first:
            d = mux(q, d, conn["E"], ep == "P")
        q_to_d[q] = d
        clocks.append((conn["C"], "posedge" if cp == "P" else "negedge"))
        lowered[name] = {"type": f"$_DFF_{cp}_", "connections": {"C": [conn["C"]], "D": [d], "Q": [q]}}
    logic = load_logic_model(
        {"modules": {top: dict(module) | {"cells": lowered}}},
        top,
        FunctionalLimits(max_gates=limits.max_cells, max_bits=limits.max_bits),
    )
    clock = logic.resolve(clock_ref)
    inputs_set = logic.roots - logic.state_outputs
    if type(clock) is not int or clock not in inputs_set:
        raise FunctionalInputError("clock must be a direct primary input")
    if any(c != clock or e != edge for c, e in clocks):
        raise FunctionalInputError("multiple, derived, or mixed-edge clocks are outside the synchronous model")
    if any(clock in g.inputs for g in logic.gates) or clock in q_to_d.values():
        raise FunctionalInputError("clock-as-data and combinational clock use are not modeled")
    if logic.state_outputs != q_to_d.keys():
        raise FunctionalInputError("sequential state inventory mismatch")
    return SynchronousModel(logic, clock, edge, frozenset(inputs_set - {clock}), q_to_d)


def assignments(model: SynchronousModel, raw: object, allowed: frozenset[int], label: str) -> dict[int, bool]:
    if not isinstance(raw, list):
        raise FunctionalInputError(f"{label} must be an array")
    fixed: dict[int, bool] = {}
    for entry in raw:
        item = _object(entry, label)
        _keys(item, {"signal", "value"}, {"signal", "value"}, label)
        bit = model.resolve(item["signal"])
        if type(bit) is not int or bit not in allowed:
            raise FunctionalInputError(f"{label} targets a signal outside the allowed input/state boundary")
        value = item["value"]
        if type(value) is not int or value not in {0, 1}:
            raise FunctionalInputError(f"{label} values must be integer 0 or 1")
        if bit in fixed and fixed[bit] != bool(value):
            raise InconsistentContract(f"{label} contradicts an alias of bit {bit}")
        fixed[bit] = bool(value)
    return fixed


def build_machine(model: SynchronousModel, check: Mapping[str, Any], limits: SequentialLimits) -> Machine:
    kind = check["kind"]
    if kind == "forbid":
        items = check["forbid"]
        if not isinstance(items, list) or not items or len(items) > limits.max_bits:
            raise FunctionalInputError("forbid must be a nonempty bounded array")
        observed: list[Bit] = []
        forbidden: list[bool] = []
        aliases: dict[Bit, bool] = {}
        for raw in items:
            item = _object(raw, "forbidden assignment")
            _keys(item, {"signal", "value"}, {"signal", "value"}, "forbidden assignment")
            bit = model.resolve(item["signal"])
            value = item["value"]
            if type(value) is not int or value not in {0, 1}:
                raise FunctionalInputError("forbidden values must be integer 0 or 1")
            if bit in aliases and aliases[bit] != bool(value):
                raise InconsistentContract("forbidden predicate contradicts an alias; refusing a vacuous property")
            if isinstance(bit, str) and (bit == "1") != bool(value):
                raise InconsistentContract("forbidden predicate contains an impossible constant")
            aliases[bit] = bool(value)
            observed.append(bit)
            forbidden.append(bool(value))
        history = 0
    elif kind == "min_spacing":
        cycles = check["cycles"]
        if type(cycles) is not int or not 2 <= cycles <= limits.max_history + 1:
            raise FunctionalInputError("min_spacing cycles must be 2..max_history+1")
        observed, forbidden, history = [model.resolve(check["event"])], [], cycles - 1
    else:
        raise FunctionalInputError("unknown sequential property kind")
    needed: set[int] = set()
    pending = list(observed)
    while pending:
        bit = pending.pop()
        if type(bit) is not int or bit in needed:
            continue
        needed.add(bit)
        if bit in model.next_state:
            pending.append(model.next_state[bit])
        elif bit in model.logic.drivers:
            pending.extend(model.logic.drivers[bit].inputs)
    states = tuple(sorted(needed & model.next_state.keys()))
    if len(states) + history > limits.max_state_bits:
        raise SequentialLimitError("property cone exceeds max_state_bits")
    gates = tuple(g for g in model.logic.gates if g.output in needed)
    return Machine(
        gates,
        states,
        tuple(sorted(needed & model.inputs)),
        tuple(model.next_state[q] for q in states),
        tuple(observed),
        tuple(forbidden),
        history,
    )
