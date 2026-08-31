"""Core data structures shared by parsers, rules, and reporters."""

from __future__ import annotations

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
    location: SourceLocation
    generated: bool = False
    source_targets: set[str] = field(default_factory=set)
    master_clock: str | None = None


@dataclass(slots=True)
class ExceptionPath:
    kind: str
    from_objects: set[str]
    to_objects: set[str]
    through_objects: tuple[frozenset[str], ...]
    location: SourceLocation
    raw: str


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
    diagnostics: list[Diagnostic]
    coverage: Coverage
    graph: dict[str, Any]


@dataclass(slots=True)
class AuditResult:
    tool_version: str
    design: dict[str, Any]
    modes: list[ModeResult]
    diagnostics: list[Diagnostic]
    summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
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
                            "generated": clock.generated,
                            "source_targets": sorted(clock.source_targets),
                            "master_clock": clock.master_clock,
                            "location": clock.location.to_dict(),
                        }
                        for clock in mode.clocks.values()
                    ],
                    "exceptions": [
                        {
                            "kind": item.kind,
                            "from": sorted(item.from_objects),
                            "to": sorted(item.to_objects),
                            "through": [sorted(group) for group in item.through_objects],
                            "location": item.location.to_dict(),
                            "raw": item.raw,
                        }
                        for item in mode.exceptions
                    ],
                    "graph": mode.graph,
                    "diagnostics": [finding.to_dict() for finding in mode.diagnostics],
                }
                for mode in self.modes
            ],
            "diagnostics": [finding.to_dict() for finding in self.diagnostics],
        }
