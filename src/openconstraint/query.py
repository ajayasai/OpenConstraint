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


def _universe(selector: Selector, design: Design, clocks: dict[str, Clock]) -> set[str]:
    if selector.kind == "all_inputs":
        return {name for name, port in design.ports.items() if port.direction in {"input", "inout"}}
    if selector.kind == "all_outputs":
        return {name for name, port in design.ports.items() if port.direction in {"output", "inout"}}
    if selector.kind in {"clocks", "all_clocks"}:
        return set(clocks)
    return design.objects(selector.kind)


def _match_pattern(pattern: str, candidates: set[str], selector: Selector) -> tuple[set[str], str | None]:
    if pattern in candidates:
        return {pattern}, None
    flags = re.IGNORECASE if selector.nocase else 0
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
    if not expression:
        return values, None
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
    candidates = _universe(selector, design, clocks)
    if selector.dynamic:
        return ResolvedQuery(selector, set(), len(candidates), "contains Tcl variable or nested dynamic expression")
    matches: set[str]
    if selector.kind in {"all_inputs", "all_outputs", "all_clocks"}:
        matches = set(candidates)
    else:
        matches = set()
        for pattern in selector.patterns:
            selected, error = _match_pattern(pattern, candidates, selector)
            if error:
                return ResolvedQuery(selector, set(), len(candidates), error)
            matches.update(selected)
    matches, filter_error = _apply_filter(matches, selector, design)
    return ResolvedQuery(selector, matches, len(candidates), filter_error)


def has_glob(selector: Selector) -> bool:
    return selector.regexp or any(any(character in pattern for character in "*?[") for pattern in selector.patterns)
