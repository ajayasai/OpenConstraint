"""Deterministic object-query resolution for the static backend."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass

from openconstraint.model import Clock, Design
from openconstraint.parsers.sdc import Selector


@dataclass(slots=True)
class ResolvedQuery:
    selector: Selector
    matches: set[str]
    universe_size: int
    error: str | None = None
    unmatched_patterns: tuple[str, ...] = ()


_OF_OBJECTS_SOURCE_KINDS = {
    # These are the object-type matrices used by OpenSTA's get_* Tcl
    # commands.  ``registers`` is an instance collection when it appears as a
    # source (for example through all_registers).
    "cells": frozenset({"nets", "pins", "ports"}),
    "nets": frozenset({"cells", "pins"}),
    "pins": frozenset({"cells", "nets"}),
    "ports": frozenset({"nets"}),
}


def _collection_kind(selector: Selector) -> str:
    if selector.kind in {"all_inputs", "all_outputs"}:
        return "ports"
    if selector.kind == "registers":
        return "cells"
    if selector.kind == "all_clocks":
        return "clocks"
    return selector.kind


def _universe(selector: Selector, design: Design, clocks: dict[str, Clock]) -> set[str]:
    if selector.kind == "all_inputs":
        return {name for name, port in design.ports.items() if port.direction in {"input", "inout"}}
    if selector.kind == "all_outputs":
        return {name for name, port in design.ports.items() if port.direction in {"output", "inout"}}
    if selector.kind in {"clocks", "all_clocks"}:
        return set(clocks)
    return design.objects(selector.kind)


def _nets_for_objects(objects: set[str], design: Design) -> set[str]:
    nets: set[str] = set()
    for name in objects:
        if name in design.nets:
            nets.add(name)
        if name in design.ports:
            nets.add(design.ports[name].net)
        if name in design.pins and design.pins[name].net is not None:
            nets.add(design.pins[name].net or "")
        if name in design.instances:
            nets.update(pin.net for pin in design.instances[name].pins.values() if pin.net is not None)
    return nets


def _related_universe(selector: Selector, design: Design, clocks: dict[str, Clock]) -> tuple[set[str], str | None]:
    if selector.of_objects is None:
        return _universe(selector, design, clocks), None
    source = resolve_selector(selector.of_objects, design, clocks)
    if source.error:
        return set(), f"unsupported -of_objects source: {source.error}"
    source_kind = _collection_kind(selector.of_objects)
    allowed_source_kinds = _OF_OBJECTS_SOURCE_KINDS.get(selector.kind)
    if allowed_source_kinds is None:
        return set(), f"-of_objects is not modeled for {selector.kind} queries"
    if source_kind not in allowed_source_kinds:
        expected = ", ".join(sorted(allowed_source_kinds))
        return (
            set(),
            f"invalid -of_objects source kind '{source_kind}' for {selector.kind}; expected one of: {expected}",
        )
    objects = source.matches
    nets = _nets_for_objects(objects, design)
    if selector.kind == "nets":
        return nets, None
    if selector.kind == "pins":
        pins = {
            pin.path for name in objects if name in design.instances for pin in design.instances[name].pins.values()
        }
        if source_kind == "nets":
            for net in nets:
                pins.update(design.drivers.get(net, set()))
                pins.update(design.loads.get(net, set()))
        return pins, None
    if selector.kind == "cells":
        cells: set[str] = set()
        cells.update(design.pins[name].instance for name in objects if name in design.pins)
        if source_kind in {"nets", "ports"}:
            for net in nets:
                cells.update(
                    design.pins[pin].instance
                    for pin in design.drivers.get(net, set()) | design.loads.get(net, set())
                    if pin in design.pins
                )
        return cells, None
    if selector.kind == "ports":
        return {name for name, port in design.ports.items() if port.net in nets}, None
    return set(), f"-of_objects is not modeled for {selector.kind} queries"


def _match_pattern(pattern: str, candidates: set[str], selector: Selector) -> tuple[set[str], str | None]:
    if pattern in candidates:
        return {pattern}, None
    # OpenSTA accepts -nocase without -regexp but warns that it is ignored.
    # Preserve the matching semantics even though this static resolver does
    # not duplicate the tool's console warning.
    flags = re.IGNORECASE if selector.regexp and selector.nocase else 0
    if selector.regexp:
        try:
            expression = re.compile(pattern, flags)
        except re.error as error:
            return set(), f"invalid regular expression: {error}"
        return {candidate for candidate in candidates if expression.search(candidate)}, None
    translated = fnmatch.translate(pattern)
    expression = re.compile(translated, flags)
    matches = {candidate for candidate in candidates if expression.fullmatch(candidate)}
    if selector.hierarchical and "/" not in pattern:
        matches.update(candidate for candidate in candidates if expression.fullmatch(candidate.rsplit("/", 1)[-1]))
    return matches, None


def _apply_filter(values: set[str], selector: Selector, design: Design) -> tuple[set[str], str | None]:
    expression = selector.filter_expression
    if expression is None:
        return values, None
    if not expression.strip():
        return set(), "empty filter expression"
    direction = re.fullmatch(
        r"\s*direction\s*(?:==|=~)\s*['\"]?(input|output|inout|unknown)['\"]?\s*",
        expression,
        re.IGNORECASE,
    )
    if direction:
        expected = direction.group(1).lower()

        def object_direction(name: str) -> str:
            if name in design.ports:
                return design.ports[name].direction
            if name in design.pins:
                return design.pins[name].direction
            return "unknown"

        return {name for name in values if object_direction(name) == expected}, None
    sequential = re.fullmatch(
        r"\s*(?:is_sequential|is_sequential_cell)\s*==\s*(true|false|1|0)\s*",
        expression,
        re.IGNORECASE,
    )
    if sequential and selector.kind in {"cells", "registers"}:
        expected = sequential.group(1).lower() in {"true", "1"}
        return {
            name
            for name in values
            if (design.instances.get(name) is not None and design.instances[name].sequential) == expected
        }, None
    return set(), f"unsupported static filter expression: {expression}"


def resolve_selector(selector: Selector, design: Design, clocks: dict[str, Clock]) -> ResolvedQuery:
    if selector.parse_error:
        candidates = _universe(selector, design, clocks)
        return ResolvedQuery(selector, set(), len(candidates), error=selector.parse_error)
    candidates, universe_error = _related_universe(selector, design, clocks)
    if universe_error:
        return ResolvedQuery(selector, set(), len(candidates), error=universe_error)
    if selector.dynamic:
        return ResolvedQuery(
            selector,
            set(),
            len(candidates),
            error="contains Tcl variable or nested dynamic expression",
        )
    matches: set[str]
    unmatched_patterns: list[str] = []
    if selector.kind in {"all_inputs", "all_outputs", "all_clocks"} or selector.of_objects is not None:
        # OpenSTA warns about positional patterns supplied with -of_objects,
        # then ignores them.  Applying those patterns here would make the
        # static and effective collections disagree.
        matches = set(candidates)
    else:
        matches = set()
        for pattern in selector.patterns:
            selected, error = _match_pattern(pattern, candidates, selector)
            if error:
                return ResolvedQuery(selector, set(), len(candidates), error=error)
            if not selected:
                unmatched_patterns.append(pattern)
            matches.update(selected)
    matches, filter_error = _apply_filter(matches, selector, design)
    return ResolvedQuery(
        selector,
        matches,
        len(candidates),
        error=filter_error,
        unmatched_patterns=tuple(unmatched_patterns),
    )


def has_glob(selector: Selector) -> bool:
    if selector.of_objects is not None:
        return False
    return selector.regexp or any(any(character in pattern for character in "*?[") for pattern in selector.patterns)
