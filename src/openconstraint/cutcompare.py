"""Exact, bounded comparison of structural false-path languages.

The language is a finite directed walk from an input port/register output to an
output port/register data pin, containing one node from each ordered through
collection. Each occurrence consumes at most one through group. This is NOT a
transition-, clock-tag-, delay-, or function-aware STA equivalence proof.
"""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Any

from openconstraint.engine import audit_sdc_text
from openconstraint.model import Design, Severity
from openconstraint.parsers.sdc import parse_sdc_text
from openconstraint.proof import (
    GraphNode,
    ProofLimitError,
    ProofLimits,
    StructuralGraph,
    _default_sources,
    _default_targets,
    _exception_scope_kinds,
    _expand_objects,
    build_structural_graph,
)
from openconstraint.version import __version__

ALGORITHM = "structural-cut-language-product-v1"
SCHEMA_VERSION = "1.0.0"
CONTRACT = {
    "model": "directed-structural-walks-with-ordered-through-groups",
    "endpoints": "input-ports/register-outputs to output-ports/register-data-pins",
    "analysis_senses": ["setup", "hold"],
    "transition_qualified_scopes": False,
    "clock_tagged_scopes": False,
    "sequential_state_crossed": False,
    "timing_equivalence": False,
    "timing_signoff": False,
    "functional_exception_validity": False,
    "excluded_semantics": ["clock timing", "I/O delay values", "path delays", "functional sensitization"],
}
_ALLOWED_COMMANDS = frozenset(
    {
        "create_clock",
        "create_generated_clock",
        "set_input_delay",
        "set_output_delay",
        "current_design",
        "set_false_path",
    }
)
_SUPPORTED_KINDS = frozenset({"ports", "pins", "nets", "cells", "registers", "all_inputs", "all_outputs", "literal"})
_DEAD = 255


@dataclass(frozen=True, slots=True)
class ComparisonLimits:
    """Deterministic algorithmic ceilings, shared across both analysis senses."""

    max_source_bytes: int = 2_097_152
    max_graph_nodes: int = 200_000
    max_graph_edges: int = 500_000
    max_rules: int = 128
    max_commands: int = 1024
    max_through_groups: int = 32
    max_selector_nodes: int = 500_000
    max_states: int = 100_000
    max_state_cells: int = 2_000_000
    max_steps: int = 5_000_000
    max_witness_nodes: int = 4096

    def __post_init__(self) -> None:
        ceilings = {
            "max_source_bytes": 2_097_152,
            "max_graph_nodes": 200_000,
            "max_graph_edges": 500_000,
            "max_commands": 1024,
            "max_rules": 128,
            "max_through_groups": 32,
            "max_selector_nodes": 500_000,
            "max_states": 100_000,
            "max_state_cells": 2_000_000,
            "max_steps": 5_000_000,
            "max_witness_nodes": 4096,
        }
        for name, ceiling in ceilings.items():
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= ceiling:
                raise ValueError(f"{name} must be an integer in [1, {ceiling}]")


class _Bounded(ValueError):
    pass


class _Unresolved(ValueError):
    pass


@dataclass(slots=True)
class _Budget:
    limits: ComparisonLimits
    states: int = 0
    state_cells: int = 0
    steps: int = 0
    selector_nodes: int = 0
    rules: int = 0
    commands: int = 0

    def charge(self, key: str, count: int) -> None:
        value = getattr(self, key) + count
        if value > getattr(self.limits, f"max_{key}"):
            raise _Bounded(f"comparison exceeded max_{key}={getattr(self.limits, f'max_{key}')}")
        setattr(self, key, value)

    def record(self) -> dict[str, int]:
        return {
            key: getattr(self, key) for key in ("states", "state_cells", "steps", "selector_nodes", "rules", "commands")
        }


@dataclass(frozen=True, slots=True)
class _Rule:
    index: int
    sources: frozenset[GraphNode]
    targets: frozenset[GraphNode]
    through: tuple[frozenset[GraphNode], ...]
    senses: frozenset[str]

    def semantic(self) -> dict[str, Any]:
        return {
            "sources": [node.to_dict() for node in sorted(self.sources)],
            "targets": [node.to_dict() for node in sorted(self.targets)],
            "through": [[node.to_dict() for node in sorted(group)] for group in self.through],
            "senses": sorted(self.senses),
        }


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _digest(value: object) -> str:
    return sha256(_json(value).encode("utf-8")).hexdigest()


def _compile(
    design: Design,
    text: str,
    side: str,
    budget: _Budget,
) -> tuple[tuple[_Rule, ...], list[dict[str, Any]]]:
    document = parse_sdc_text(text, f"<{side}>")
    if document.issues:
        raise _Unresolved(f"{side}: malformed or oversized SDC")
    for command in document.commands:
        budget.charge("commands", 1)
        if command.name not in _ALLOWED_COMMANDS:
            raise _Unresolved(f"{side}:{command.location.line}: {command.name!r} is outside the comparison contract")
        if command.parse_errors or command.dynamic_name or command.opaque_substitutions:
            raise _Unresolved(f"{side}:{command.location.line}: malformed or dynamic command")
        if command.name == "set_false_path":
            budget.charge("rules", 1)
            if command.has("-reset_path"):
                raise _Unresolved(f"{side}:{command.location.line}: -reset_path is not supported")
            # Even paired rise/fall flags are rejected: no transition tags are
            # carried by this graph and no approximation is permitted here.
            if any(option.startswith(("-rise", "-fall")) for option in command.options):
                raise _Unresolved(f"{side}:{command.location.line}: transition-qualified false paths are not supported")
            if (
                sum(len(values) for key, values in command.options.items() if key == "-through")
                > budget.limits.max_through_groups
            ):
                raise _Bounded(f"{side}: comparison exceeded max_through_groups={budget.limits.max_through_groups}")
    mode = audit_sdc_text(design, side, text, path=f"<{side}>")
    # Missing timing coverage is not a malformed structural cut language.
    # All other error diagnostics, including partially unmatched queries, gate
    # comparison. The ordinary audit remains responsible for clock coverage.
    errors = [d for d in mode.diagnostics if d.severity == Severity.ERROR and d.rule_id != "OC2101"]
    if errors:
        first = errors[0]
        raise _Unresolved(f"{side}:{first.location.line}: {first.rule_id}: {first.message}")
    default_sources, default_targets = _default_sources(design), _default_targets(design)
    rules: list[_Rule] = []
    records: list[dict[str, Any]] = []
    for index, exception in enumerate(mode.exceptions):
        kinds = _exception_scope_kinds(exception)
        if exception.kind != "false_path" or not exception.qualifiers.get("scope_resolvable") or kinds is None:
            raise _Unresolved(f"{side}:{exception.location.line}: unresolved exception scope")
        used_kinds = (kinds.from_kind, kinds.to_kind, *kinds.through_kinds)
        if any(kind is not None and kind not in _SUPPORTED_KINDS for kind in used_kinds):
            raise _Unresolved(f"{side}:{exception.location.line}: clock-tagged or unsupported selector kind")
        if len(exception.through_objects) > budget.limits.max_through_groups:
            raise _Bounded(f"{side}: comparison exceeded max_through_groups={budget.limits.max_through_groups}")
        expanded: list[frozenset[GraphNode]] = []
        roles = [
            (exception.from_objects, "source", kinds.from_kind, exception.qualifiers.get("from_specified")),
            (exception.to_objects, "target", kinds.to_kind, exception.qualifiers.get("to_specified")),
            *(
                (objects, "through", kind, True)
                for objects, kind in zip(exception.through_objects, kinds.through_kinds, strict=True)
            ),
        ]
        for objects, role, kind, specified in roles:
            # Literal clocks must not slip past the explicit clock-kind gate.
            if kind == "literal" and any(name in mode.clocks for name in objects):
                raise _Unresolved(f"{side}:{exception.location.line}: literal clock or ambiguous clock/object name")
            if not specified:
                nodes = default_sources if role == "source" else default_targets
                ambiguities: set[str] = set()
            else:
                nodes, ambiguities = _expand_objects(design, mode, objects, role, kind)
            if ambiguities:
                raise _Unresolved(f"{side}:{exception.location.line}: ambiguous object names")
            if specified and not nodes:
                raise _Unresolved(f"{side}:{exception.location.line}: selector expands to no supported nodes")
            if (role == "source" and not nodes <= default_sources) or (
                role == "target" and not nodes <= default_targets
            ):
                raise _Unresolved(
                    f"{side}:{exception.location.line}: from/to objects must be structural launch/capture endpoints"
                )
            budget.charge("selector_nodes", len(nodes))
            expanded.append(frozenset(nodes))
        rule = _Rule(
            index, expanded[0], expanded[1], tuple(expanded[2:]), frozenset(exception.qualifiers["applies_to"])
        )
        rules.append(rule)
        records.append(
            {"index": index, "line": exception.location.line, "raw": exception.raw, "scope": rule.semantic()}
        )
    return tuple(rules), records


def _matches(rule: _Rule, path: Sequence[GraphNode]) -> bool:
    """Independent full-witness checker using a set of subsequence prefixes."""
    if not path or path[0] not in rule.sources or path[-1] not in rule.targets:
        return False
    prefixes = {0}
    for node in path:
        prefixes |= {index + 1 for index in prefixes if index < len(rule.through) and node in rule.through[index]}
    return len(rule.through) in prefixes


def _matched(rules: Sequence[_Rule], path: Sequence[GraphNode]) -> list[int]:
    return [rule.index for rule in rules if _matches(rule, path)]


def _outcome(status: str, reason: str | None = None) -> dict[str, Any]:
    return {"status": status, "reason": reason, "witness": [], "matched_before": [], "matched_after": []}


_State = tuple[GraphNode, bytes]


def _compare_sense(
    graph: StructuralGraph,
    before: tuple[_Rule, ...],
    after: tuple[_Rule, ...],
    sense: str,
    budget: _Budget,
    outcomes: dict[str, Any],
) -> None:
    left = tuple(rule for rule in before if sense in rule.senses)
    right = tuple(rule for rule in after if sense in rule.senses)
    rules = left + right
    width = len(rules)
    if not rules:
        outcomes.update(new_cuts=_outcome("absent"), removed_cuts=_outcome("absent"))
        return
    # A state includes progress for every rule in BOTH unions. Comparing only
    # endpoints or one exception against one other exception is insufficient.
    parents: dict[_State, _State | None] = {}
    queue: deque[_State] = deque()

    def visit(state: _State, parent: _State | None) -> None:
        if state in parents:
            return
        budget.charge("states", 1)
        budget.charge("state_cells", max(width, 1))
        parents[state] = parent
        queue.append(state)

    sources = sorted(set().union(*(rule.sources for rule in rules)))
    for source in sources:
        budget.charge("steps", width)
        progress = bytes(
            (1 if rule.through and source in rule.through[0] else 0) if source in rule.sources else _DEAD
            for rule in rules
        )
        visit((source, progress), None)

    while queue:
        state = queue.popleft()
        node, progress = state
        budget.charge("steps", width)
        acceptance = [
            pos == len(rule.through) and node in rule.targets for pos, rule in zip(progress, rules, strict=True)
        ]
        was_cut, now_cut = any(acceptance[: len(left)]), any(acceptance[len(left) :])
        direction = "new_cuts" if now_cut and not was_cut else "removed_cuts" if was_cut and not now_cut else None
        if direction is not None and outcomes[direction]["status"] != "witnessed":
            path: list[GraphNode] = []
            cursor: _State | None = state
            while cursor is not None:
                if len(path) >= budget.limits.max_witness_nodes:
                    raise _Bounded(f"comparison exceeded max_witness_nodes={budget.limits.max_witness_nodes}")
                path.append(cursor[0])
                cursor = parents[cursor]
            path.reverse()
            budget.charge("steps", len(path) * max(1, sum(len(rule.through) + 1 for rule in rules)))
            matched_before, matched_after = _matched(left, path), _matched(right, path)
            if bool(matched_before) != was_cut or bool(matched_after) != now_cut:
                raise _Unresolved("internal witness replay mismatch")
            if any(
                target not in graph.adjacency.get(source, ()) for source, target in zip(path, path[1:], strict=False)
            ):
                raise _Unresolved("internal witness contains a nonexistent edge")
            outcomes[direction] = {
                "status": "witnessed",
                "reason": None,
                "witness": [n.to_dict() for n in path],
                "matched_before": matched_before,
                "matched_after": matched_after,
            }
            if all(outcomes[d]["status"] == "witnessed" for d in ("new_cuts", "removed_cuts")):
                return
        for target in graph.adjacency[node]:
            budget.charge("steps", width + 1)
            updated = bytes(
                pos + 1 if pos < len(rule.through) and target in rule.through[pos] else pos
                for pos, rule in zip(progress, rules, strict=True)
            )
            visit((target, updated), state)
    for direction in ("new_cuts", "removed_cuts"):
        if outcomes[direction]["status"] != "witnessed":
            outcomes[direction] = _outcome("absent")


def compare_structural_cuts(
    design: Design,
    before: str,
    after: str,
    *,
    limits: ComparisonLimits | None = None,
) -> dict[str, Any]:
    """Compare two static SDC snapshots on ONE structural design.

    ``absent`` is emitted only after exhaustive product-state search. Resource
    limits and unknown semantics never become equivalence. Partial witnesses
    may survive a bounded run, but the run is not complete.
    """
    chosen = limits or ComparisonLimits()
    budget = _Budget(chosen)
    checks = {sense: {d: _outcome("pending") for d in ("new_cuts", "removed_cuts")} for sense in ("setup", "hold")}
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "algorithm": ALGORITHM,
        "tool": {"name": "OpenConstraint", "version": __version__},
        "contract": json.loads(_json(CONTRACT)),
        "limits": asdict(chosen),
        "source_hashes": {},
        "design": {"top": design.top, "graph_digest": None, "endpoint_digest": None, "nodes": 0, "edges": 0},
        "rules": {"before": [], "after": []},
        "checks": checks,
        "status": "unresolved",
        "complete": False,
        "reason": None,
    }
    try:
        total_bytes = 0
        for side, text in (("before", before), ("after", after)):
            # Bound before UTF-8 allocation; one codepoint occupies >=1 byte.
            if len(text) > chosen.max_source_bytes:
                raise _Bounded(f"comparison exceeded max_source_bytes={chosen.max_source_bytes}")
            encoded = text.encode("utf-8")
            total_bytes += len(encoded)
            if total_bytes > chosen.max_source_bytes:
                raise _Bounded(f"comparison exceeded max_source_bytes={chosen.max_source_bytes}")
            result["source_hashes"][side] = sha256(encoded).hexdigest()
        if design.warnings:
            raise _Unresolved("the structural model has parser/elaboration warnings")
        if len(design.ports) + len(design.pins) + len(design.nets) > chosen.max_graph_nodes:
            raise _Bounded(f"comparison exceeded max_graph_nodes={chosen.max_graph_nodes}")
        left, left_records = _compile(design, before, "before", budget)
        right, right_records = _compile(design, after, "after", budget)
        result["rules"] = {"before": left_records, "after": right_records}
        graph = build_structural_graph(design, ProofLimits(max_graph_edges=chosen.max_graph_edges))
        if len(graph.nodes) > chosen.max_graph_nodes:
            raise _Bounded(f"comparison exceeded max_graph_nodes={chosen.max_graph_nodes}")
        sources, targets = _default_sources(design), _default_targets(design)
        result["design"] = {
            "top": design.top,
            "graph_digest": graph.digest,
            "nodes": len(graph.nodes),
            "edges": graph.edge_count,
            "endpoint_digest": _digest(
                {"sources": [n.to_dict() for n in sorted(sources)], "targets": [n.to_dict() for n in sorted(targets)]}
            ),
        }
        for sense in ("setup", "hold"):
            _compare_sense(graph, left, right, sense, budget, checks[sense])
        changed = any(value["status"] == "witnessed" for check in checks.values() for value in check.values())
        result.update(status="different_structural_cuts" if changed else "equivalent_structural_cuts", complete=True)
    except (_Bounded, ProofLimitError) as exc:
        result.update(status="bounded", reason=str(exc))
    except (_Unresolved, UnicodeError, RecursionError) as exc:
        result.update(status="unresolved", reason=str(exc) or "invalid text or excessive recursion")
    for check in checks.values():
        for direction, outcome in check.items():
            if outcome["status"] == "pending":
                check[direction] = _outcome(result["status"], result["reason"])
    result["work"] = budget.record()
    result["report_digest"] = _digest(result)
    return result


def verify_comparison(
    design: Design,
    before: str,
    after: str,
    report: Mapping[str, Any],
    *,
    limits: ComparisonLimits | None = None,
) -> dict[str, Any]:
    """Replay from caller-provided inputs; never execute report-provided paths.

    Limits are caller-selected, not taken from untrusted evidence. Matching a
    bounded/unresolved report confirms its reproduction, NOT an equivalence.
    """
    rebuilt = compare_structural_cuts(design, before, after, limits=limits)
    try:
        same = _json(report) == _json(rebuilt)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        same = False
    return {
        "verified": same,
        "comparison_status": rebuilt["status"],
        "complete": rebuilt["complete"],
        "report_digest": rebuilt["report_digest"],
    }
