"""Core data structures shared by parsers, rules, and reporters."""

from __future__ import annotations

import json
import math
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Any


class Severity(StrEnum):
    """Diagnostic severity, ordered by impact in :data:`SEVERITY_RANK`."""

    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"


SEVERITY_RANK = {Severity.NOTE: 0, Severity.WARNING: 1, Severity.ERROR: 2}


@dataclass(frozen=True, slots=True)
class SourceLocation:
    """A stable source location."""

    path: str
    line: int = 1
    column: int = 1

    def __post_init__(self) -> None:
        if not self.path.startswith("<"):
            object.__setattr__(self, "path", self.path.replace("\\", "/"))

    @classmethod
    def from_path(cls, path: str | Path, line: int = 1, column: int = 1) -> SourceLocation:
        return cls(str(Path(path)), line, column)

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "line": self.line, "column": self.column}


@dataclass(slots=True)
class Diagnostic:
    """One actionable audit finding."""

    rule_id: str
    severity: Severity
    message: str
    location: SourceLocation
    rationale: str
    suggestion: str
    mode: str = "default"
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        source_path = self.location.path.replace("\\", "/")
        if not source_path.startswith("<"):
            source_path = "/".join(part for part in source_path.split("/") if part)[-240:]
            path_parts = source_path.split("/")
            source_path = "/".join(path_parts[-4:])
        payload = "\x1f".join(
            (
                self.rule_id,
                self.mode,
                source_path,
                str(self.location.line),
                self.message,
            )
        )
        return sha256(payload.encode("utf-8")).hexdigest()[:20]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "location": self.location.to_dict(),
            "rationale": self.rationale,
            "suggestion": self.suggestion,
            "mode": self.mode,
            "fingerprint": self.fingerprint,
            "evidence": self.evidence,
        }


@dataclass(slots=True)
class Port:
    name: str
    direction: str
    net: str


@dataclass(slots=True)
class Pin:
    path: str
    instance: str
    name: str
    direction: str
    net: str | None
    is_clock: bool = False
    is_data: bool = False


@dataclass(slots=True)
class Instance:
    path: str
    cell_type: str
    pins: dict[str, Pin]
    sequential: bool = False


@dataclass(slots=True)
class Design:
    """Elaborated structural design index used by static rules."""

    top: str
    ports: dict[str, Port]
    nets: set[str]
    instances: dict[str, Instance]
    pins: dict[str, Pin]
    drivers: dict[str, set[str]] = field(default_factory=dict)
    loads: dict[str, set[str]] = field(default_factory=dict)
    combinational_arcs: dict[str, set[str]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def sequential_instances(self) -> list[Instance]:
        return [instance for instance in self.instances.values() if instance.sequential]

    @property
    def sequential_endpoints(self) -> set[str]:
        return {pin.path for instance in self.sequential_instances for pin in instance.pins.values() if pin.is_data}

    @property
    def sequential_clock_pins(self) -> set[str]:
        return {pin.path for instance in self.sequential_instances for pin in instance.pins.values() if pin.is_clock}

    def objects(self, kind: str) -> set[str]:
        mapping = {
            "ports": set(self.ports),
            "pins": set(self.pins),
            "cells": set(self.instances),
            "nets": set(self.nets),
            "registers": {item.path for item in self.sequential_instances},
        }
        return mapping.get(kind, set())


@dataclass(slots=True)
class Clock:
    name: str
    targets: set[str]
    period: float | None
    waveform: tuple[float, ...] | None
    waveform_explicit: bool
    location: SourceLocation
    generated: bool = False
    source_targets: set[str] = field(default_factory=set)
    master_clock: str | None = None
    divide_by: int | None = None
    multiply_by: int | None = None
    duty_cycle: float | None = None
    invert: bool = False
    combinational: bool = False
    edges: tuple[int, ...] | None = None
    edge_shift: tuple[float, ...] | None = None

    @property
    def effective_waveform(self) -> tuple[float, ...] | None:
        """Return the explicit or valid implicit waveform used for timing."""

        if self.waveform is not None:
            return self.waveform
        if (
            not self.generated
            and not self.waveform_explicit
            and self.period is not None
            and math.isfinite(self.period)
            and self.period > 0
        ):
            return (0.0, self.period / 2.0)
        return None


@dataclass(slots=True)
class ExceptionPath:
    kind: str
    from_objects: set[str]
    to_objects: set[str]
    through_objects: tuple[frozenset[str], ...]
    location: SourceLocation
    raw: str
    qualifiers: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class IODelay:
    kind: str
    ports: frozenset[str]
    value: float | None
    clocks: frozenset[str]
    reference_pin: str | None
    source_latency_included: bool
    network_latency_included: bool
    min_max: frozenset[str]
    transitions: frozenset[str]
    clock_edge: str
    additive: bool
    valid: bool
    location: SourceLocation
    raw: str

    def semantic_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "ports": sorted(self.ports),
            "value": self.value,
            "clocks": sorted(self.clocks),
            "reference_pin": self.reference_pin,
            "source_latency_included": self.source_latency_included,
            "network_latency_included": self.network_latency_included,
            "min_max": sorted(self.min_max),
            "transitions": sorted(self.transitions),
            "clock_edge": self.clock_edge,
            "additive": self.additive,
            "valid": self.valid,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.semantic_dict(), "location": self.location.to_dict(), "raw": self.raw}


@dataclass(slots=True)
class _ActiveIODelayRelationship:
    """OpenSTA's per-port/per-clock-edge I/O-delay storage object."""

    values: dict[tuple[str, str], float] = field(default_factory=dict)
    reference_pin: str | None = None
    source_latency_included: bool = False
    network_latency_included: bool = False


_IODelayRelationshipKey = tuple[str, str, tuple[str, ...], str]


@dataclass(frozen=True, slots=True)
class _IODelayAtomicKey:
    kind: str
    clocks: tuple[str, ...]
    reference_pin: str | None
    source_latency_included: bool
    network_latency_included: bool
    clock_edge: str
    value: float
    transition: str
    min_max: str


@dataclass(frozen=True, slots=True)
class _IODelayMatrixKey:
    kind: str
    clocks: tuple[str, ...]
    reference_pin: str | None
    source_latency_included: bool
    network_latency_included: bool
    clock_edge: str
    value: float
    ports: tuple[str, ...]


def _io_delay_rectangles(
    cells: set[tuple[str, str]],
) -> list[tuple[tuple[str, ...], tuple[str, ...]]]:
    """Cover a two-by-two transition/min-max matrix without inventing cells."""

    transition_groups = (("fall", "rise"), ("fall",), ("rise",))
    min_max_groups = (("max", "min"), ("max",), ("min",))
    candidates = sorted(
        (
            (transitions, min_max, {(transition, sense) for transition in transitions for sense in min_max})
            for transitions in transition_groups
            for min_max in min_max_groups
        ),
        key=lambda item: (-len(item[2]), item[0], item[1]),
    )
    remaining = set(cells)
    rectangles: list[tuple[tuple[str, ...], tuple[str, ...]]] = []
    while remaining:
        for transitions, min_max, candidate_cells in candidates:
            if candidate_cells <= remaining:
                rectangles.append((transitions, min_max))
                remaining.difference_update(candidate_cells)
                break
    return rectangles


def effective_io_delay_semantics(io_delays: Iterable[IODelay]) -> list[dict[str, Any]]:
    """Replay I/O-delay commands into a deterministic active-state snapshot.

    ``ModeResult.io_delays`` deliberately retains command history for reports
    and diagnostics.  This projection mirrors the pinned OpenSTA
    ``Sdc::setInputDelay``/``setOutputDelay`` storage behavior for semantic
    comparison for already-resolved command records:

    * a non-``-add_delay`` command retains the selected clock-edge
      relationship, removes competing relationships for the same port, and
      replaces only the selected rise/fall and min/max slots;
    * ``-add_delay`` retains every relationship and merges selected values by
      analysis sense (minimum for ``-min``, maximum for ``-max``);
    * reference-pin and latency-inclusion properties belong to the whole
      relationship and are updated by every command that touches it.

    Invalid static records cannot create OpenSTA state and are omitted.  The
    returned records compact only exact rectangular groups of active slots and
    ports; they never imply a slot that was not constrained.  ``additive`` is
    normalized to false because it is a replay operation, not a property of
    the resulting state.  The current model does not retain clock-object
    generations across clock redefinitions or ``unset_*_delay`` commands, so
    those operations remain outside this projection's contract.
    """

    active: dict[_IODelayRelationshipKey, _ActiveIODelayRelationship] = {}

    for item in io_delays:
        if not item.valid or item.value is None or not item.ports or len(item.clocks) > 1:
            continue
        clocks = tuple(sorted(item.clocks))
        # OpenSTA represents a clockless relationship with a null ClockEdge;
        # -clock_fall therefore cannot create a distinct clockless object.
        clock_edge = item.clock_edge if clocks else "rise"
        for port in sorted(item.ports):
            key: _IODelayRelationshipKey = (item.kind, port, clocks, clock_edge)
            relationship = active.get(key)
            if relationship is None:
                relationship = _ActiveIODelayRelationship()
                active[key] = relationship

            if not item.additive:
                for candidate in list(active):
                    if candidate != key and candidate[:2] == key[:2]:
                        del active[candidate]

            for transition in sorted(item.transitions):
                for min_max in sorted(item.min_max):
                    slot = (transition, min_max)
                    current = relationship.values.get(slot)
                    if not item.additive or current is None:
                        relationship.values[slot] = item.value
                    elif min_max == "min":
                        relationship.values[slot] = min(current, item.value)
                    else:
                        relationship.values[slot] = max(current, item.value)

            relationship.reference_pin = item.reference_pin
            relationship.source_latency_included = item.source_latency_included if item.reference_pin is None else False
            relationship.network_latency_included = (
                item.network_latency_included if item.reference_pin is None else False
            )

    atomic_ports: dict[_IODelayAtomicKey, set[str]] = {}
    for (kind, port, clocks, clock_edge), relationship in active.items():
        for (transition, min_max), value in relationship.values.items():
            atomic_key = _IODelayAtomicKey(
                kind=kind,
                clocks=clocks,
                reference_pin=relationship.reference_pin,
                source_latency_included=relationship.source_latency_included,
                network_latency_included=relationship.network_latency_included,
                clock_edge=clock_edge,
                value=value,
                transition=transition,
                min_max=min_max,
            )
            atomic_ports.setdefault(atomic_key, set()).add(port)

    matrices: dict[_IODelayMatrixKey, set[tuple[str, str]]] = {}
    for atomic_key, ports in atomic_ports.items():
        matrix_key = _IODelayMatrixKey(
            kind=atomic_key.kind,
            clocks=atomic_key.clocks,
            reference_pin=atomic_key.reference_pin,
            source_latency_included=atomic_key.source_latency_included,
            network_latency_included=atomic_key.network_latency_included,
            clock_edge=atomic_key.clock_edge,
            value=atomic_key.value,
            ports=tuple(sorted(ports)),
        )
        matrices.setdefault(matrix_key, set()).add((atomic_key.transition, atomic_key.min_max))

    records: list[dict[str, Any]] = []
    for matrix_key, cells in matrices.items():
        for rectangle_transitions, rectangle_min_max in _io_delay_rectangles(cells):
            records.append(
                {
                    "kind": matrix_key.kind,
                    "ports": list(matrix_key.ports),
                    "value": matrix_key.value,
                    "clocks": list(matrix_key.clocks),
                    "reference_pin": matrix_key.reference_pin,
                    "source_latency_included": matrix_key.source_latency_included,
                    "network_latency_included": matrix_key.network_latency_included,
                    "min_max": list(rectangle_min_max),
                    "transitions": list(rectangle_transitions),
                    "clock_edge": matrix_key.clock_edge,
                    "additive": False,
                    "valid": True,
                }
            )
    records.sort(key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    return records


@dataclass(slots=True)
class CoverageComponent:
    key: str
    label: str
    covered: int
    total: int
    weight: float
    explanation: str

    @property
    def percentage(self) -> float | None:
        if self.total == 0:
            return None
        return round(100.0 * self.covered / self.total, 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "covered": self.covered,
            "total": self.total,
            "percentage": self.percentage,
            "weight": self.weight,
            "explanation": self.explanation,
        }


@dataclass(slots=True)
class Coverage:
    score: float
    grade: str
    components: list[CoverageComponent]

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "grade": self.grade,
            "components": [component.to_dict() for component in self.components],
        }


@dataclass(slots=True)
class ModeResult:
    name: str
    clocks: dict[str, Clock]
    exceptions: list[ExceptionPath]
    io_delays: list[IODelay]
    diagnostics: list[Diagnostic]
    coverage: Coverage
    graph: dict[str, Any]
    # Invalid definitions remain in ``clocks`` as review evidence, but only
    # these names participate in active query, graph, comparison, and coverage
    # semantics.
    valid_clocks: frozenset[str] = frozenset()


@dataclass(slots=True)
class AuditResult:
    tool_version: str
    design: dict[str, Any]
    modes: list[ModeResult]
    diagnostics: list[Diagnostic]
    summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.1.0",
            "tool": {"name": "OpenConstraint", "version": self.tool_version},
            "design": self.design,
            "summary": self.summary,
            "modes": [
                {
                    "name": mode.name,
                    "coverage": mode.coverage.to_dict(),
                    "clocks": [
                        {
                            "name": clock.name,
                            "targets": sorted(clock.targets),
                            "period": clock.period,
                            "waveform": list(clock.waveform) if clock.waveform else None,
                            "waveform_explicit": clock.waveform_explicit,
                            "valid": clock.name in mode.valid_clocks,
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
                            "location": clock.location.to_dict(),
                        }
                        for clock in sorted(mode.clocks.values(), key=lambda item: item.name)
                    ],
                    "exceptions": [
                        {
                            "kind": item.kind,
                            "from": sorted(item.from_objects),
                            "to": sorted(item.to_objects),
                            "through": [sorted(group) for group in item.through_objects],
                            "location": item.location.to_dict(),
                            "raw": item.raw,
                            "qualifiers": item.qualifiers,
                        }
                        for item in mode.exceptions
                    ],
                    "io_delays": [item.to_dict() for item in mode.io_delays],
                    "graph": mode.graph,
                    "diagnostics": [finding.to_dict() for finding in mode.diagnostics],
                }
                for mode in self.modes
            ],
            "diagnostics": [finding.to_dict() for finding in self.diagnostics],
        }
