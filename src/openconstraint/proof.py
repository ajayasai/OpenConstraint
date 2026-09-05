"""Proof-carrying structural exception analysis and deterministic repair plans.

This module deliberately proves only properties of OpenConstraint's complete,
modeled structural graph.  It never labels a path functionally false and never
executes Tcl.  Proof packs are replayable: the verifier rebuilds the graph from
the supplied inputs and compares graph, exception, and certificate digests.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from collections import Counter, deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from importlib.resources import files
from pathlib import Path

from openconstraint.engine import AuditOptions, ModeInput, _propagate_clock, audit
from openconstraint.model import AuditResult, Design, Diagnostic, ExceptionPath, ModeResult
from openconstraint.opensta import tcl_quote
from openconstraint.parsers.liberty import CellLibrary, parse_liberty
from openconstraint.parsers.sdc import (
    _COMMAND_GRAMMARS,
    ParsedCommand,
    _canonical_modeled_option,
    _is_keyword,
    parse_sdc_text,
)
from openconstraint.parsers.tcl import TclSyntaxError, decode_tcl_word
from openconstraint.parsers.verilog import elaborate, parse_verilog
from openconstraint.version import __version__

PROOF_SCHEMA_VERSION = "1.0.0"
REPAIR_SCHEMA_VERSION = "1.0.0"
PROOF_ALGORITHM = "ordered-structural-path-v1"
DEFAULT_MAX_GRAPH_EDGES = 5_000_000
DEFAULT_MAX_SEARCH_STATES = 1_000_000
DEFAULT_MAX_WITNESS_NODES = 256
_FATAL_MODEL_RULES = frozenset({"OC0001", "OC0002", "OC0003", "OC1003", "OC1004"})


class ProofStatus(StrEnum):
    """Result of a bounded structural exception proof."""

    WITNESSED = "witnessed"
    VACUOUS = "vacuous"
    UNRESOLVED = "unresolved"
    BOUNDED = "bounded"


@dataclass(frozen=True, slots=True)
class ProofLimits:
    """Deterministic resource limits for proof construction."""

    max_graph_edges: int = DEFAULT_MAX_GRAPH_EDGES
    max_search_states: int = DEFAULT_MAX_SEARCH_STATES
    max_witness_nodes: int = DEFAULT_MAX_WITNESS_NODES

    def __post_init__(self) -> None:
        for name, value in (
            ("max_graph_edges", self.max_graph_edges),
            ("max_search_states", self.max_search_states),
            ("max_witness_nodes", self.max_witness_nodes),
        ):
            if value < 1:
                raise ValueError(f"{name} must be positive")


@dataclass(frozen=True, order=True, slots=True)
class GraphNode:
    """A typed node in the structural timing graph."""

    kind: str
    name: str

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.name}"

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "name": self.name}


@dataclass(frozen=True, slots=True)
class StructuralGraph:
    """Canonical directed graph used by the replayable proof algorithm."""

    nodes: tuple[GraphNode, ...]
    adjacency: Mapping[GraphNode, tuple[GraphNode, ...]]
    edge_count: int
    digest: str


@dataclass(frozen=True, slots=True)
class _SearchOutcome:
    status: ProofStatus
    witness: tuple[GraphNode, ...]
    visited_count: int
    visited_digest: str
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class _ScopeKinds:
    from_kind: str | None
    to_kind: str | None
    through_kinds: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "from": self.from_kind,
            "to": self.to_kind,
            "through": list(self.through_kinds),
        }


class ProofLimitError(ValueError):
    """Raised when graph construction exceeds an explicit proof limit."""


def _node_for_object(design: Design, name: str) -> GraphNode | None:
    if name in design.ports:
        return GraphNode("port", name)
    if name in design.pins:
        return GraphNode("pin", name)
    if name in design.nets:
        return GraphNode("net", name)
    return None


def _add_edge(
    adjacency: dict[GraphNode, set[GraphNode]],
    source: GraphNode,
    target: GraphNode,
    *,
    limits: ProofLimits,
    edge_counter: list[int],
) -> None:
    targets = adjacency.setdefault(source, set())
    adjacency.setdefault(target, set())
    if target in targets:
        return
    edge_counter[0] += 1
    if edge_counter[0] > limits.max_graph_edges:
        raise ProofLimitError(f"structural proof graph exceeds max_graph_edges={limits.max_graph_edges}")
    targets.add(target)


def build_structural_graph(design: Design, limits: ProofLimits | None = None) -> StructuralGraph:
    """Build a deterministic pin/net/port graph without crossing sequential state."""

    selected_limits = limits or ProofLimits()
    adjacency: dict[GraphNode, set[GraphNode]] = {}
    edge_counter = [0]

    for name in sorted(design.ports):
        adjacency.setdefault(GraphNode("port", name), set())
    for name in sorted(design.pins):
        adjacency.setdefault(GraphNode("pin", name), set())
    for name in sorted(design.nets):
        adjacency.setdefault(GraphNode("net", name), set())

    # Explicit direction-derived edges make the graph robust even when a
    # parser warning prevents a driver/load index entry.  Such a warning still
    # makes proofs unresolved; the edges exist only for deterministic review.
    for port in sorted(design.ports.values(), key=lambda item: item.name):
        port_node = GraphNode("port", port.name)
        net_node = GraphNode("net", port.net)
        if port.direction in {"input", "inout"}:
            _add_edge(adjacency, port_node, net_node, limits=selected_limits, edge_counter=edge_counter)
        if port.direction in {"output", "inout"}:
            _add_edge(adjacency, net_node, port_node, limits=selected_limits, edge_counter=edge_counter)

    for pin in sorted(design.pins.values(), key=lambda item: item.path):
        if pin.net is None:
            continue
        pin_node = GraphNode("pin", pin.path)
        net_node = GraphNode("net", pin.net)
        if pin.direction in {"output", "inout"}:
            _add_edge(adjacency, pin_node, net_node, limits=selected_limits, edge_counter=edge_counter)
        if pin.direction in {"input", "inout"}:
            _add_edge(adjacency, net_node, pin_node, limits=selected_limits, edge_counter=edge_counter)

    for source_name, arc_targets in sorted(design.combinational_arcs.items()):
        source = GraphNode("pin", source_name)
        for target_name in sorted(arc_targets):
            _add_edge(
                adjacency,
                source,
                GraphNode("pin", target_name),
                limits=selected_limits,
                edge_counter=edge_counter,
            )

    canonical_adjacency = {node: tuple(sorted(graph_targets)) for node, graph_targets in sorted(adjacency.items())}
    nodes = tuple(canonical_adjacency)
    digest = sha256()
    for node in nodes:
        digest.update(b"N\0")
        digest.update(node.key.encode("utf-8"))
        digest.update(b"\n")
    for source, targets in canonical_adjacency.items():
        for target in targets:
            digest.update(b"E\0")
            digest.update(source.key.encode("utf-8"))
            digest.update(b"\0")
            digest.update(target.key.encode("utf-8"))
            digest.update(b"\n")
    return StructuralGraph(nodes, canonical_adjacency, edge_counter[0], digest.hexdigest())


def _target_nets(design: Design, targets: Iterable[str]) -> set[str]:
    nets: set[str] = set()
    for target in targets:
        if target in design.ports:
            nets.add(design.ports[target].net)
        elif target in design.pins and design.pins[target].net is not None:
            nets.add(str(design.pins[target].net))
        elif target in design.nets:
            nets.add(target)
        elif target in design.instances:
            nets.update(str(pin.net) for pin in design.instances[target].pins.values() if pin.net is not None)
    return nets


def _clocked_instances(
    design: Design, mode: ModeResult, clock_name: str, clock_cache: dict[str, frozenset[str]] | None = None
) -> frozenset[str]:
    if clock_cache is not None and clock_name in clock_cache:
        return clock_cache[clock_name]
    clock = mode.clocks.get(clock_name)
    if clock is None or clock_name not in mode.valid_clocks:
        return frozenset()
    _nets, reached_pins = _propagate_clock(design, clock.targets)
    instances = frozenset(design.pins[pin_path].instance for pin_path in reached_pins & design.sequential_clock_pins)
    if clock_cache is not None:
        clock_cache[clock_name] = instances
    return instances


def _instance_nodes(design: Design, instance_name: str, role: str) -> set[GraphNode]:
    instance = design.instances.get(instance_name)
    if instance is None:
        return set()
    if role == "source":
        selected = [pin for pin in instance.pins.values() if pin.direction in {"output", "inout"}]
    elif role == "target":
        selected = [
            pin
            for pin in instance.pins.values()
            if pin.is_data or (pin.direction in {"input", "inout"} and not pin.is_clock)
        ]
    else:
        selected = list(instance.pins.values())
    return {GraphNode("pin", pin.path) for pin in selected}


def _clock_nodes(
    design: Design, mode: ModeResult, clock_name: str, role: str, clock_cache: dict[str, frozenset[str]] | None = None
) -> set[GraphNode]:
    instances = _clocked_instances(design, mode, clock_name, clock_cache)
    expanded: set[GraphNode] = set()
    if role == "source":
        for instance_name in instances:
            expanded.update(_instance_nodes(design, instance_name, "source"))
    elif role == "target":
        for instance_name in instances:
            expanded.update(
                GraphNode("pin", pin.path) for pin in design.instances[instance_name].pins.values() if pin.is_data
            )
    return expanded


def _default_sources(design: Design) -> set[GraphNode]:
    sources = {GraphNode("port", port.name) for port in design.ports.values() if port.direction in {"input", "inout"}}
    sources.update(
        GraphNode("pin", pin.path)
        for instance in design.sequential_instances
        for pin in instance.pins.values()
        if pin.direction in {"output", "inout"}
    )
    return sources


def _default_targets(design: Design) -> set[GraphNode]:
    targets = {GraphNode("port", port.name) for port in design.ports.values() if port.direction in {"output", "inout"}}
    targets.update(GraphNode("pin", name) for name in design.sequential_endpoints)
    return targets


_FROM_SCOPE_OPTIONS = ("-from", "-rise_from", "-fall_from")
_TO_SCOPE_OPTIONS = ("-to", "-rise_to", "-fall_to")
_THROUGH_SCOPE_OPTIONS = frozenset({"-through", "-rise_through", "-fall_through"})


def _selected_selector_kind(command: ParsedCommand, options: Sequence[str]) -> str | None:
    for option in options:
        values = command.options.get(option, [])
        if not values:
            continue
        selected_value = values[-1]
        for recorded_option, recorded_value, selector in reversed(command.option_selector_occurrences):
            if recorded_option == option and recorded_value == selected_value:
                return selector.kind if selector is not None else "literal"
        return "literal"
    return None


def _exception_scope_kinds(exception: ExceptionPath) -> _ScopeKinds | None:
    if exception.kind == "clock_group":
        return _ScopeKinds("clocks", "clocks", ())
    document = parse_sdc_text(exception.raw, "<proof-scope>")
    if document.issues or len(document.commands) != 1:
        return None
    command = document.commands[0]
    if command.parse_errors or command.name != f"set_{exception.kind}":
        return None
    through_kinds = tuple(
        selector.kind if selector is not None else "literal"
        for option, _value, selector in command.option_selector_occurrences
        if option in _THROUGH_SCOPE_OPTIONS
    )
    if len(through_kinds) != len(exception.through_objects):
        return None
    return _ScopeKinds(
        _selected_selector_kind(command, _FROM_SCOPE_OPTIONS),
        _selected_selector_kind(command, _TO_SCOPE_OPTIONS),
        through_kinds,
    )


def _nodes_for_selector_kind(
    design: Design,
    mode: ModeResult,
    name: str,
    role: str,
    selector_kind: str,
    clock_cache: dict[str, frozenset[str]] | None = None,
) -> set[GraphNode]:
    if selector_kind in {"ports", "all_inputs", "all_outputs"}:
        return {GraphNode("port", name)} if name in design.ports else set()
    if selector_kind == "pins":
        return {GraphNode("pin", name)} if name in design.pins else set()
    if selector_kind == "nets":
        return {GraphNode("net", name)} if name in design.nets else set()
    if selector_kind in {"cells", "registers"}:
        return _instance_nodes(design, name, role) if name in design.instances else set()
    if selector_kind in {"clocks", "all_clocks"}:
        return _clock_nodes(design, mode, name, role, clock_cache) if name in mode.clocks else set()
    return set()


def _literal_nodes(
    design: Design,
    mode: ModeResult,
    name: str,
    role: str,
    clock_cache: dict[str, frozenset[str]] | None = None,
) -> tuple[set[GraphNode], bool]:
    candidates: list[set[GraphNode]] = []
    if name in design.ports:
        candidates.append({GraphNode("port", name)})
    if name in design.pins:
        candidates.append({GraphNode("pin", name)})
    if name in design.instances:
        candidates.append(_instance_nodes(design, name, role))
    if role == "through" and name in design.nets:
        candidates.append({GraphNode("net", name)})
    if role != "through" and name in mode.clocks:
        candidates.append(_clock_nodes(design, mode, name, role, clock_cache))
    if len(candidates) > 1:
        return set(), True
    return (candidates[0], False) if candidates else (set(), False)


def _expand_objects(
    design: Design,
    mode: ModeResult,
    objects: Iterable[str],
    role: str,
    selector_kind: str | None,
    clock_cache: dict[str, frozenset[str]] | None = None,
) -> tuple[set[GraphNode], set[str]]:
    expanded: set[GraphNode] = set()
    ambiguous: set[str] = set()
    for name in objects:
        if selector_kind == "literal":
            nodes, collision = _literal_nodes(design, mode, name, role, clock_cache)
            expanded.update(nodes)
            if collision:
                ambiguous.add(name)
        elif selector_kind is None:
            ambiguous.add(name)
        else:
            expanded.update(_nodes_for_selector_kind(design, mode, name, role, selector_kind, clock_cache))
    return expanded, ambiguous


def _scope_is_resolvable(exception: ExceptionPath) -> bool:
    if exception.kind == "clock_group":
        return (
            bool(exception.from_objects)
            and bool(exception.to_objects)
            and exception.qualifiers.get("relation") != "unspecified"
            and exception.qualifiers.get("allow_paths") is not True
        )
    return exception.qualifiers.get("scope_resolvable", True) is True


def _model_is_trusted(design: Design, mode: ModeResult) -> bool:
    return not design.warnings and not any(finding.rule_id in _FATAL_MODEL_RULES for finding in mode.diagnostics)


def _advance_through(node: GraphNode, index: int, through: Sequence[frozenset[GraphNode]]) -> int:
    if index < len(through) and node in through[index]:
        return index + 1
    return index


_SearchState = tuple[GraphNode, int]


def _search(
    graph: StructuralGraph,
    sources: set[GraphNode],
    targets: set[GraphNode],
    through: Sequence[frozenset[GraphNode]],
    limits: ProofLimits,
) -> _SearchOutcome:
    queue: deque[_SearchState] = deque()
    predecessor: dict[_SearchState, _SearchState | None] = {}
    depth: dict[_SearchState, int] = {}
    visit_digest = sha256()

    def visit(state: _SearchState, parent: _SearchState | None, state_depth: int) -> bool:
        if state in predecessor:
            return True
        if len(predecessor) >= limits.max_search_states:
            return False
        predecessor[state] = parent
        depth[state] = state_depth
        queue.append(state)
        visit_digest.update(state[0].key.encode("utf-8"))
        visit_digest.update(b"\0")
        visit_digest.update(str(state[1]).encode("ascii"))
        visit_digest.update(b"\n")
        return True

    for source in sorted(sources):
        if not visit((source, _advance_through(source, 0, through)), None, 0):
            return _SearchOutcome(
                ProofStatus.BOUNDED,
                (),
                len(predecessor),
                visit_digest.hexdigest(),
                f"search exceeded max_search_states={limits.max_search_states}",
            )

    while queue:
        state = queue.popleft()
        node, through_index = state
        if depth[state] > 0 and node in targets and through_index == len(through):
            path: list[GraphNode] = []
            cursor: _SearchState | None = state
            while cursor is not None:
                path.append(cursor[0])
                cursor = predecessor[cursor]
            path.reverse()
            return _SearchOutcome(
                ProofStatus.WITNESSED,
                tuple(path),
                len(predecessor),
                visit_digest.hexdigest(),
            )
        for target in graph.adjacency.get(node, ()):
            next_state = (target, _advance_through(target, through_index, through))
            if not visit(next_state, state, depth[state] + 1):
                return _SearchOutcome(
                    ProofStatus.BOUNDED,
                    (),
                    len(predecessor),
                    visit_digest.hexdigest(),
                    f"search exceeded max_search_states={limits.max_search_states}",
                )

    return _SearchOutcome(
        ProofStatus.VACUOUS,
        (),
        len(predecessor),
        visit_digest.hexdigest(),
        "no directed structural path satisfies the ordered scope",
    )


def _location_identity(location: Mapping[str, object]) -> dict[str, object]:
    return {
        "line": location.get("line"),
        "column": location.get("column"),
    }


def _exception_payload(exception: ExceptionPath, scope_kinds: _ScopeKinds | None) -> dict[str, object]:
    return {
        "kind": exception.kind,
        "from": sorted(exception.from_objects),
        "to": sorted(exception.to_objects),
        "through": [sorted(group) for group in exception.through_objects],
        "scope_kinds": scope_kinds.to_dict() if scope_kinds is not None else None,
        "qualifiers": exception.qualifiers,
        "location": _location_identity(exception.location.to_dict()),
        "raw": exception.raw,
    }


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _certificate_identity(proof: Mapping[str, object]) -> dict[str, object]:
    payload = dict(proof)
    payload.pop("certificate_id", None)
    location = payload.get("location")
    if isinstance(location, dict):
        payload["location"] = _location_identity(location)
    return payload


def _replay_projection(value: object) -> object:
    if isinstance(value, dict):
        projected: dict[str, object] = {}
        for key, item in value.items():
            if key in {"pack_digest", "replay_digest"}:
                continue
            if key == "location" and isinstance(item, dict):
                projected[key] = _location_identity(item)
            elif key == "parser_warnings" and isinstance(item, list):
                projected[key] = {"count": len(item)}
            else:
                projected[key] = _replay_projection(item)
        return projected
    if isinstance(value, list):
        return [_replay_projection(item) for item in value]
    return value


def _witness_payload(witness: tuple[GraphNode, ...], limit: int) -> tuple[list[dict[str, str]], int]:
    if len(witness) <= limit:
        return [node.to_dict() for node in witness], 0
    head_count = (limit + 1) // 2
    tail_count = limit - head_count
    retained = witness[:head_count]
    if tail_count:
        retained = (*retained, *witness[-tail_count:])
    return [node.to_dict() for node in retained], len(witness) - len(retained)


def _proof_for_exception(
    design: Design,
    mode: ModeResult,
    graph: StructuralGraph,
    exception: ExceptionPath,
    index: int,
    limits: ProofLimits,
    clock_cache: dict[str, frozenset[str]] | None = None,
) -> dict[str, object]:
    scope_kinds = _exception_scope_kinds(exception)
    payload = _exception_payload(exception, scope_kinds)
    exception_digest = _canonical_digest(payload)
    base: dict[str, object] = {
        "index": index,
        "kind": exception.kind,
        "mode": mode.name,
        "location": exception.location.to_dict(),
        "raw": exception.raw,
        "scope_kinds": scope_kinds.to_dict() if scope_kinds is not None else None,
        "exception_digest": exception_digest,
        "algorithm": PROOF_ALGORITHM,
        "graph_digest": graph.digest,
    }

    if not _model_is_trusted(design, mode):
        base.update(
            {
                "status": ProofStatus.UNRESOLVED.value,
                "reason": "the structural or SDC model is incomplete",
                "visited_states": 0,
                "visited_digest": None,
                "witness": [],
                "witness_omitted_nodes": 0,
            }
        )
    elif not _scope_is_resolvable(exception):
        base.update(
            {
                "status": ProofStatus.UNRESOLVED.value,
                "reason": "the exception scope is not statically resolvable",
                "visited_states": 0,
                "visited_digest": None,
                "witness": [],
                "witness_omitted_nodes": 0,
            }
        )
    elif scope_kinds is None:
        base.update(
            {
                "status": ProofStatus.UNRESOLVED.value,
                "reason": "the selector kinds could not be reconstructed safely",
                "visited_states": 0,
                "visited_digest": None,
                "witness": [],
                "witness_omitted_nodes": 0,
            }
        )
    else:
        from_specified = exception.kind == "clock_group" or exception.qualifiers.get("from_specified") is True
        to_specified = exception.kind == "clock_group" or exception.qualifiers.get("to_specified") is True
        if from_specified:
            sources, source_ambiguities = _expand_objects(
                design,
                mode,
                exception.from_objects,
                "source",
                scope_kinds.from_kind,
                clock_cache,
            )
        else:
            sources, source_ambiguities = _default_sources(design), set()
        if to_specified:
            targets, target_ambiguities = _expand_objects(
                design,
                mode,
                exception.to_objects,
                "target",
                scope_kinds.to_kind,
                clock_cache,
            )
        else:
            targets, target_ambiguities = _default_targets(design), set()
        through_expansions = [
            _expand_objects(design, mode, group, "through", selector_kind, clock_cache)
            for group, selector_kind in zip(
                exception.through_objects,
                scope_kinds.through_kinds,
                strict=True,
            )
        ]
        through = tuple(frozenset(nodes) for nodes, _ambiguities in through_expansions)
        ambiguous_names = source_ambiguities | target_ambiguities
        for _nodes, ambiguities in through_expansions:
            ambiguous_names.update(ambiguities)
        if ambiguous_names:
            sample = ", ".join(repr(name) for name in sorted(ambiguous_names)[:8])
            suffix = f" (and {len(ambiguous_names) - 8} more)" if len(ambiguous_names) > 8 else ""
            base.update(
                {
                    "status": ProofStatus.UNRESOLVED.value,
                    "reason": "literal scope names collide across object namespaces: " + sample + suffix,
                    "visited_states": 0,
                    "visited_digest": None,
                    "witness": [],
                    "witness_omitted_nodes": 0,
                }
            )
        elif not sources or not targets or any(not group for group in through):
            empty_parts = []
            if not sources:
                empty_parts.append("source")
            if not targets:
                empty_parts.append("target")
            if any(not group for group in through):
                empty_parts.append("through")
            base.update(
                {
                    "status": ProofStatus.UNRESOLVED.value,
                    "reason": "timing-node expansion is empty for: " + ", ".join(empty_parts),
                    "visited_states": 0,
                    "visited_digest": None,
                    "witness": [],
                    "witness_omitted_nodes": 0,
                }
            )
        else:
            outcome = _search(graph, sources, targets, through, limits)
            witness, omitted = _witness_payload(outcome.witness, limits.max_witness_nodes)
            base.update(
                {
                    "status": outcome.status.value,
                    "reason": outcome.reason,
                    "source_node_count": len(sources),
                    "target_node_count": len(targets),
                    "through_group_count": len(through),
                    "visited_states": outcome.visited_count,
                    "visited_digest": outcome.visited_digest,
                    "witness": witness,
                    "witness_node_count": len(outcome.witness),
                    "witness_omitted_nodes": omitted,
                }
            )

    base["certificate_id"] = _canonical_digest(_certificate_identity(base))
    return base


def analyze_proofs(
    design: Design,
    result: AuditResult,
    limits: ProofLimits | None = None,
) -> dict[str, object]:
    """Produce a deterministic, replayable proof pack for every modeled exception."""

    selected_limits = limits or ProofLimits()
    graph = build_structural_graph(design, selected_limits)
    modes: list[dict[str, object]] = []
    overall = Counter[str]()
    for mode in result.modes:
        clock_cache: dict[str, frozenset[str]] = {}
        proofs = [
            _proof_for_exception(design, mode, graph, exception, index, selected_limits, clock_cache)
            for index, exception in enumerate(mode.exceptions)
        ]
        counts = Counter(str(item["status"]) for item in proofs)
        overall.update(counts)
        modes.append(
            {
                "name": mode.name,
                "trusted_model": _model_is_trusted(design, mode),
                "summary": {status.value: counts[status.value] for status in ProofStatus},
                "proofs": proofs,
            }
        )
    pack: dict[str, object] = {
        "schema_version": PROOF_SCHEMA_VERSION,
        "tool": {"name": "OpenConstraint", "version": __version__},
        "algorithm": PROOF_ALGORITHM,
        "limits": {
            "max_graph_edges": selected_limits.max_graph_edges,
            "max_search_states": selected_limits.max_search_states,
            "max_witness_nodes": selected_limits.max_witness_nodes,
        },
        "model": {
            "top": design.top,
            "trusted": not design.warnings,
            "parser_warnings": list(design.warnings),
            "node_count": len(graph.nodes),
            "edge_count": graph.edge_count,
            "graph_digest": graph.digest,
        },
        "summary": {status.value: overall[status.value] for status in ProofStatus},
        "modes": modes,
    }
    pack["replay_digest"] = _canonical_digest(_replay_projection(pack))
    pack["pack_digest"] = _canonical_digest(pack)
    return pack


def _mode_map(result: AuditResult) -> dict[str, ModeResult]:
    return {mode.name: mode for mode in result.modes}


def _candidate_universe(design: Design, mode: ModeResult | None, kind: str) -> set[str]:
    if kind in {"ports", "pins", "cells", "nets", "registers"}:
        return design.objects(kind)
    if kind == "clocks" and mode is not None:
        return set(mode.valid_clocks)
    if kind == "all_inputs":
        return {name for name, port in design.ports.items() if port.direction in {"input", "inout"}}
    if kind == "all_outputs":
        return {name for name, port in design.ports.items() if port.direction in {"output", "inout"}}
    return set()


def _suggest_names(pattern: str, universe: Iterable[str]) -> list[dict[str, object]]:
    needle = re.sub(r"[?*\[\]]", "", pattern).strip()
    if not needle:
        return []
    scored = sorted(
        ((difflib.SequenceMatcher(a=needle, b=candidate).ratio(), candidate) for candidate in universe),
        key=lambda item: (-item[0], item[1]),
    )
    return [{"candidate": candidate, "similarity": round(score, 4)} for score, candidate in scored[:3] if score >= 0.55]


def _tcl_word_or_placeholder(value: object, placeholder: str) -> str:
    if not isinstance(value, str):
        return placeholder
    try:
        return tcl_quote(value)
    except ValueError:
        return placeholder


def _sdc_collection(design: Design, names: Sequence[str]) -> str:
    """Render an exact homogeneous SDC collection with substitution-safe Tcl words."""

    if not names:
        return "<OBJECT_COLLECTION>"
    command: str | None = None
    if all(name in design.ports for name in names):
        command = "get_ports"
    elif all(name in design.pins for name in names):
        command = "get_pins"
    elif all(name in design.nets for name in names):
        command = "get_nets"
    elif all(name in design.instances for name in names):
        command = "get_cells"
    if command is None:
        return "<OBJECT_COLLECTION>"
    pattern_list = _exact_pattern_list(names)
    if pattern_list is None:
        return "<OBJECT_COLLECTION>"
    return f"[{command} {pattern_list}]"


def _exact_pattern_list(names: Sequence[str]) -> str | None:
    # One Tcl argument containing a list. Wildcards and unrepresentable
    # OpenSTA list spellings require review rather than silently broadening.
    if any(
        not name or name.startswith("-") or any(c in name for c in '*?"{}\\') or any(ord(c) < 32 for c in name)
        for name in names
    ):
        return None
    return tcl_quote(" ".join('"' + name + '"' for name in names))


def _multicycle_pair_templates(exception: ExceptionPath, expected_hold: int) -> list[str]:
    document = parse_sdc_text(exception.raw, "<repair-multicycle>")
    if document.issues or len(document.commands) != 1:
        return []
    command = document.commands[0]
    if command.parse_errors or command.name != "set_multicycle_path" or len(command.positionals) != 1:
        return []
    setup_multiplier = exception.qualifiers.get("multiplier")
    if type(setup_multiplier) is not int or setup_multiplier < 2 or command.has("-reset_path"):
        return []

    words = list(command.tcl.words)
    positional_indices: list[int] = []
    phase_indices: set[int] = set()
    index = 1
    while index < len(words):
        try:
            decoded = decode_tcl_word(words[index])
        except TclSyntaxError:
            return []
        option = (
            _canonical_modeled_option(decoded, _COMMAND_GRAMMARS["set_multicycle_path"])
            if _is_keyword(decoded)
            else None
        )
        if option is None:
            positional_indices.append(index)
            index += 1
            continue
        canonical, arity = option
        if canonical in {"-setup", "-hold"}:
            phase_indices.add(index)
        if arity == "value":
            index += 2
        else:
            index += 1

    if len(positional_indices) != 1:
        return []
    multiplier_index = positional_indices[0]
    try:
        if decode_tcl_word(words[multiplier_index]) != command.positionals[0]:
            return []
    except TclSyntaxError:
        return []

    def render(multiplier: int, phase: str) -> str:
        rendered: list[str] = []
        for word_index, word in enumerate(words):
            if word_index in phase_indices:
                continue
            rendered.append(str(multiplier) if word_index == multiplier_index else word)
        rendered.insert(1, phase)
        return " ".join(rendered)

    templates = [render(setup_multiplier, "-setup"), render(expected_hold, "-hold")]
    checked = parse_sdc_text("\n".join(templates), "<repair-roundtrip>")
    if checked.issues or len(checked.commands) != 2 or any(item.parse_errors for item in checked.commands):
        return []
    return templates


def _action_id(payload: Mapping[str, object]) -> str:
    return "OCRP-" + _canonical_digest(payload)[:16].upper()


def _action(
    *,
    mode: str,
    kind: str,
    confidence: str,
    title: str,
    rationale: str,
    source: Mapping[str, object],
    review: str,
    sdc_template: Sequence[str] = (),
) -> dict[str, object]:
    core: dict[str, object] = {
        "mode": mode,
        "kind": kind,
        "confidence": confidence,
        "automatic": False,
        "title": title,
        "rationale": rationale,
        "source": dict(source),
        "review": review,
        "sdc_template": list(sdc_template),
    }
    return {"id": _action_id(core), **core}


def _diagnostic_action(
    design: Design,
    result: AuditResult,
    diagnostic: Diagnostic,
) -> dict[str, object] | None:
    modes = _mode_map(result)
    mode = modes.get(diagnostic.mode)
    source = {
        "type": "diagnostic",
        "rule_id": diagnostic.rule_id,
        "fingerprint": diagnostic.fingerprint,
        "location": diagnostic.location.to_dict(),
        "message": diagnostic.message,
        "suggestion": diagnostic.suggestion,
    }

    if diagnostic.rule_id == "OC1001":
        kind = str(diagnostic.evidence.get("object_kind", ""))
        patterns = diagnostic.evidence.get("unmatched_patterns", [])
        suggestions = {
            str(pattern): _suggest_names(str(pattern), _candidate_universe(design, mode, kind))
            for pattern in patterns
            if isinstance(pattern, str)
        }
        return _action(
            mode=diagnostic.mode,
            kind="repair_object_query",
            confidence="medium",
            title="Review unmatched object-query spelling or hierarchy",
            rationale=diagnostic.rationale,
            source={**source, "suggestions": suggestions},
            review="Confirm the intended design object before changing the SDC; similar names are evidence, not intent.",
        )

    if diagnostic.rule_id in {"OC3001", "OC3002"}:
        direction = "input" if diagnostic.rule_id == "OC3001" else "output"
        ports_value = diagnostic.evidence.get("ports", [])
        ports = sorted(str(item) for item in ports_value) if isinstance(ports_value, list) else []
        clock_reference = "<CLOCK>"
        if mode is not None and len(mode.valid_clocks) == 1:
            clock_patterns = _exact_pattern_list([next(iter(mode.valid_clocks))])
            if clock_patterns is not None:
                clock_reference = f"[get_clocks {clock_patterns}]"
        collection = _sdc_collection(design, ports).replace("<OBJECT_COLLECTION>", "<PORT_COLLECTION>")
        templates = [
            f"set_{direction}_delay <MIN_RISE> -min -rise -clock {clock_reference} {collection}",
            f"set_{direction}_delay <MIN_FALL> -min -fall -clock {clock_reference} {collection}",
            f"set_{direction}_delay <MAX_RISE> -max -rise -clock {clock_reference} {collection}",
            f"set_{direction}_delay <MAX_FALL> -max -fall -clock {clock_reference} {collection}",
        ]
        return _action(
            mode=diagnostic.mode,
            kind=f"complete_{direction}_delay_matrix",
            confidence="high",
            title=f"Complete {direction}-delay min/max and rise/fall coverage",
            rationale=diagnostic.rationale,
            source=source,
            review="Replace every angle-bracket placeholder using the interface timing contract before applying this template.",
            sdc_template=templates,
        )

    if diagnostic.rule_id == "OC2001" and mode is not None:
        clock_name = diagnostic.evidence.get("clock")
        clock_spec = mode.clocks.get(str(clock_name))
        if clock_spec is not None and clock_spec.generated:
            return _action(
                mode=diagnostic.mode,
                kind="repair_generated_clock_timing",
                confidence="medium",
                title=f"Repair generated-clock timing for {clock_name!r}",
                rationale=diagnostic.rationale,
                source={
                    **source,
                    "master_clock": clock_spec.master_clock,
                    "source_targets": sorted(clock_spec.source_targets),
                },
                review="Correct the source/master relationship and one transform mechanism; do not replace a generated clock with a guessed primary period.",
            )
        targets = sorted(clock_spec.targets) if clock_spec is not None else []
        target = _sdc_collection(design, targets).replace("<OBJECT_COLLECTION>", "<CLOCK_TARGET>")
        clock_word = _tcl_word_or_placeholder(clock_name, "<CLOCK_NAME>")
        return _action(
            mode=diagnostic.mode,
            kind="repair_clock_period",
            confidence="medium",
            title=f"Provide a positive period for clock {clock_name!r}",
            rationale=diagnostic.rationale,
            source=source,
            review="Obtain the period and waveform from the architecture or interface specification; they cannot be inferred safely from connectivity.",
            sdc_template=[f"create_clock -name {clock_word} -period <PERIOD> {target}"],
        )

    if diagnostic.rule_id == "OC2101":
        endpoints = diagnostic.evidence.get("unconstrained_endpoints", [])
        return _action(
            mode=diagnostic.mode,
            kind="connect_unconstrained_endpoints",
            confidence="medium",
            title="Create or repair clocks reaching unconstrained sequential endpoints",
            rationale=diagnostic.rationale,
            source={**source, "endpoints": endpoints},
            review="Trace each endpoint's clock pin to its architectural source, then define the primary and generated clocks explicitly.",
        )

    if diagnostic.rule_id == "OC4011" and mode is not None:
        expected = diagnostic.evidence.get("expected_hold_multiplier")
        matching = next(
            (
                item
                for item in mode.exceptions
                if item.kind == "multicycle_path" and item.location == diagnostic.location
            ),
            None,
        )
        templates = (
            _multicycle_pair_templates(matching, expected) if matching is not None and isinstance(expected, int) else []
        )
        return _action(
            mode=diagnostic.mode,
            kind="pair_multicycle_hold",
            confidence="medium",
            title="Replace the multicycle command with an explicit setup/hold pair",
            rationale=diagnostic.rationale,
            source=source,
            review="Replace the original command with the reviewed pair rather than appending it. The N/N-1 convention is common, not universal; confirm launch/capture edge intent first. Empty templates require manual review, including -reset_path history.",
            sdc_template=templates,
        )

    if diagnostic.rule_id == "OC1002":
        return _action(
            mode=diagnostic.mode,
            kind="narrow_broad_collection",
            confidence="medium",
            title="Replace a broad wildcard with a reviewed exact collection",
            rationale=diagnostic.rationale,
            source={
                **source,
                "query": diagnostic.evidence.get("query"),
                "sample": diagnostic.evidence.get("sample", []),
            },
            review="Compare the complete matched collection with design intent, then commit an exact or tightly scoped selector.",
        )

    if diagnostic.rule_id in {"OC2003", "OC2006"}:
        return _action(
            mode=diagnostic.mode,
            kind="normalize_primary_clock_definition",
            confidence="high",
            title=diagnostic.message,
            rationale=diagnostic.rationale,
            source=source,
            review="Retain one authoritative clock definition, explicit name, positive period, waveform where required, and an exact target collection.",
        )

    if diagnostic.rule_id == "OC2004":
        return _action(
            mode=diagnostic.mode,
            kind="resolve_multiple_clock_reachability",
            confidence="medium",
            title=diagnostic.message,
            rationale=diagnostic.rationale,
            source={**source, "pins": diagnostic.evidence.get("pins", {})},
            review="Confirm whether clocks are logically/physically exclusive, asynchronous, or mode-specific before adding clock groups or splitting modes.",
        )

    if diagnostic.rule_id in {"OC2010", "OC2011", "OC2012"}:
        return _action(
            mode=diagnostic.mode,
            kind="repair_generated_clock_definition",
            confidence="medium",
            title=diagnostic.message,
            rationale=diagnostic.rationale,
            source={**source, "evidence": diagnostic.evidence},
            review="Select one reachable source, one valid master clock, and one valid divide/multiply/edge transform from the clock architecture.",
        )

    if diagnostic.rule_id in {"OC3010", "OC3011", "OC3012", "OC3013", "OC3014"}:
        return _action(
            mode=diagnostic.mode,
            kind="repair_io_delay_relationship",
            confidence="medium",
            title=diagnostic.message,
            rationale=diagnostic.rationale,
            source={**source, "evidence": diagnostic.evidence},
            review="Rebuild this relationship from the interface contract: exact ports, direction, reference clock/pin, min/max, rise/fall, and additive semantics.",
        )

    if diagnostic.rule_id in {"OC4001", "OC4002", "OC4012"}:
        return _action(
            mode=diagnostic.mode,
            kind="resolve_exception_conflict",
            confidence="medium",
            title=diagnostic.message,
            rationale=diagnostic.rationale,
            source={**source, "evidence": diagnostic.evidence},
            review="Keep one valid expression of intent or make the scopes disjoint; do not rely on command order or exception precedence.",
        )

    if diagnostic.rule_id in {"OC5001", "OC5002"}:
        return _action(
            mode=diagnostic.mode,
            kind="review_mode_drift",
            confidence="high",
            title=diagnostic.message,
            rationale=diagnostic.rationale,
            source={**source, "evidence": diagnostic.evidence},
            review="Record the intended per-mode difference as policy, or align the definitions before comparing timing results.",
        )

    if diagnostic.rule_id in {"OC0001", "OC0002", "OC0003", "OC1003", "OC1004"}:
        return _action(
            mode=diagnostic.mode,
            kind="restore_static_model_completeness",
            confidence="high",
            title=diagnostic.message,
            rationale=diagnostic.rationale,
            source={**source, "evidence": diagnostic.evidence},
            review="Flatten or replace the unsupported construct with an equivalent reviewed static form, or validate trusted original inputs in an isolated execution backend.",
        )
    return None


def build_repair_plan(
    design: Design,
    result: AuditResult,
    proof_pack: Mapping[str, object],
) -> dict[str, object]:
    """Create deterministic, review-required repair actions and SDC templates."""

    actions = [
        action
        for diagnostic in result.diagnostics
        if (action := _diagnostic_action(design, result, diagnostic)) is not None
    ]
    modes_value = proof_pack.get("modes", [])
    if isinstance(modes_value, list):
        for mode_value in modes_value:
            if not isinstance(mode_value, dict):
                continue
            mode_name = str(mode_value.get("name", "default"))
            proofs_value = mode_value.get("proofs", [])
            if not isinstance(proofs_value, list):
                continue
            for proof in proofs_value:
                if not isinstance(proof, dict) or proof.get("status") != ProofStatus.VACUOUS.value:
                    continue
                source = {
                    "type": "proof",
                    "certificate_id": proof.get("certificate_id"),
                    "location": proof.get("location"),
                    "kind": proof.get("kind"),
                }
                actions.append(
                    _action(
                        mode=mode_name,
                        kind="remove_or_narrow_vacuous_exception",
                        confidence="high",
                        title="Remove or narrow a structurally vacuous timing exception",
                        rationale="A complete replayable search found no structural path satisfying this exception scope.",
                        source=source,
                        review="Confirm that the analyzed structural model represents the implementation stage where this exception is intended to apply.",
                        sdc_template=[f"# REVIEW/REMOVE: {str(proof.get('raw', '')).strip()}"],
                    )
                )
    actions.sort(
        key=lambda item: (
            str(item["mode"]),
            str(item["kind"]),
            str(item["id"]),
        )
    )
    placeholder_pattern = r"<[A-Z][A-Z0-9_]*>"
    placeholder_token_set: set[str] = set()
    for action in actions:
        templates_value = action.get("sdc_template", [])
        if not isinstance(templates_value, list):
            continue
        for template in templates_value:
            if not isinstance(template, str):
                continue
            placeholder_token_set.update(re.findall(placeholder_pattern, template))
    placeholder_tokens = sorted(placeholder_token_set)
    plan: dict[str, object] = {
        "schema_version": REPAIR_SCHEMA_VERSION,
        "tool": {"name": "OpenConstraint", "version": __version__},
        "proof_pack_digest": proof_pack.get("pack_digest"),
        "safety": {
            "automatic_changes": False,
            "placeholder_pattern": placeholder_pattern,
            "placeholder_tokens": placeholder_tokens,
            "statement": "Every action requires human review; numeric timing intent is never guessed.",
        },
        "summary": {
            "action_count": len(actions),
            "by_confidence": dict(sorted(Counter(str(item["confidence"]) for item in actions).items())),
            "by_kind": dict(sorted(Counter(str(item["kind"]) for item in actions).items())),
        },
        "actions": actions,
    }
    plan["plan_digest"] = _canonical_digest(plan)
    return plan


def render_proof_text(pack: Mapping[str, object]) -> str:
    model = pack.get("model", {})
    model_map = model if isinstance(model, dict) else {}
    lines = [
        f"OpenConstraint proof pack {pack.get('schema_version')} ({pack.get('algorithm')})",
        (f"Design: {model_map.get('top')} · {model_map.get('node_count')} nodes · {model_map.get('edge_count')} edges"),
        f"Graph digest: {model_map.get('graph_digest')}",
        "",
    ]
    modes = pack.get("modes", [])
    if isinstance(modes, list):
        for mode in modes:
            if not isinstance(mode, dict):
                continue
            lines.append(f"Mode {mode.get('name')} (trusted={mode.get('trusted_model')})")
            proofs = mode.get("proofs", [])
            if isinstance(proofs, list):
                for proof in proofs:
                    if not isinstance(proof, dict):
                        continue
                    location = proof.get("location", {})
                    location_map = location if isinstance(location, dict) else {}
                    lines.append(
                        f"  {str(proof.get('status')).upper():10} {proof.get('kind')} "
                        f"{location_map.get('path')}:{location_map.get('line')} "
                        f"certificate={str(proof.get('certificate_id'))[:16]}"
                    )
                    witness = proof.get("witness", [])
                    if isinstance(witness, list) and witness:
                        rendered = " -> ".join(
                            f"{item.get('kind')}:{item.get('name')}" for item in witness if isinstance(item, dict)
                        )
                        lines.append(f"    witness: {rendered}")
                    if proof.get("reason"):
                        lines.append(f"    reason: {proof.get('reason')}")
            lines.append("")
    lines.append(f"Replay digest: {pack.get('replay_digest')}")
    lines.append(f"Pack digest: {pack.get('pack_digest')}")
    return "\n".join(lines) + "\n"


def render_repair_sdc(plan: Mapping[str, object]) -> str:
    """Render every physical line, including untrusted metadata, as a comment."""

    def comment(prefix: str, value: object) -> list[str]:
        normalized = str(value).replace("\r\n", "\n").replace("\r", "\n")
        return [prefix + line for line in normalized.split("\n")]

    lines = [
        "# OpenConstraint deterministic repair plan",
        "# REVIEW REQUIRED: placeholders and all proposed edits must be approved by a timing owner.",
        *comment("# Plan digest: ", plan.get("plan_digest")),
        "",
    ]
    actions = plan.get("actions", [])
    if isinstance(actions, list):
        for action in actions:
            if not isinstance(action, dict):
                continue
            templates = action.get("sdc_template", [])
            if not isinstance(templates, list) or not templates:
                continue
            lines.extend(comment("# ", f"{action.get('id')} [{action.get('confidence')}] {action.get('title')}"))
            lines.extend(comment("# Review: ", action.get("review")))
            for template in templates:
                lines.extend(comment("# PROPOSED: ", template))
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _certificate_integrity(pack: Mapping[str, object]) -> tuple[set[str], list[str]]:
    certificates: set[str] = set()
    invalid: list[str] = []
    modes = pack.get("modes", [])
    if not isinstance(modes, list):
        return certificates, ["<modes-not-an-array>"]
    for mode in modes:
        if not isinstance(mode, dict):
            invalid.append("<mode-not-an-object>")
            continue
        proofs = mode.get("proofs", [])
        if not isinstance(proofs, list):
            invalid.append(f"{mode.get('name', '<mode>')}:<proofs-not-an-array>")
            continue
        for proof in proofs:
            if not isinstance(proof, dict):
                invalid.append(f"{mode.get('name', '<mode>')}:<proof-not-an-object>")
                continue
            certificate = proof.get("certificate_id")
            if not isinstance(certificate, str):
                invalid.append(f"{mode.get('name', '<mode>')}:{proof.get('index', '?')}:<missing>")
                continue
            if certificate != _canonical_digest(_certificate_identity(proof)):
                invalid.append(certificate)
            certificates.add(certificate)
    return certificates, sorted(invalid)


def _pack_integrity(pack: Mapping[str, object]) -> bool:
    digest = pack.get("pack_digest")
    if not isinstance(digest, str):
        return False
    payload = dict(pack)
    del payload["pack_digest"]
    return digest == _canonical_digest(payload)


def _replay_integrity(pack: Mapping[str, object]) -> bool:
    digest = pack.get("replay_digest")
    return isinstance(digest, str) and digest == _canonical_digest(_replay_projection(dict(pack)))


def verify_proof_pack(expected: Mapping[str, object], actual: Mapping[str, object]) -> dict[str, object]:
    """Validate exact packs internally, then compare path-independent replay identity."""

    expected_model = expected.get("model", {})
    actual_model = actual.get("model", {})
    expected_graph = expected_model.get("graph_digest") if isinstance(expected_model, dict) else None
    actual_graph = actual_model.get("graph_digest") if isinstance(actual_model, dict) else None
    expected_certificates, invalid_expected = _certificate_integrity(expected)
    actual_certificates, invalid_actual = _certificate_integrity(actual)
    expected_pack_integrity = _pack_integrity(expected)
    actual_pack_integrity = _pack_integrity(actual)
    expected_replay_integrity = _replay_integrity(expected)
    actual_replay_integrity = _replay_integrity(actual)
    differences: dict[str, object] = {
        "expected_pack_integrity": expected_pack_integrity,
        "actual_pack_integrity": actual_pack_integrity,
        "expected_replay_integrity": expected_replay_integrity,
        "actual_replay_integrity": actual_replay_integrity,
        "invalid_expected_certificates": invalid_expected,
        "invalid_actual_certificates": invalid_actual,
        "graph_digest_matches": expected_graph == actual_graph,
        "replay_digest_matches": expected.get("replay_digest") == actual.get("replay_digest"),
        "pack_digest_matches": expected.get("pack_digest") == actual.get("pack_digest"),
        "missing_certificates": sorted(expected_certificates - actual_certificates),
        "unexpected_certificates": sorted(actual_certificates - expected_certificates),
        "expected_replay_digest": expected.get("replay_digest"),
        "actual_replay_digest": actual.get("replay_digest"),
        "expected_pack_digest": expected.get("pack_digest"),
        "actual_pack_digest": actual.get("pack_digest"),
    }
    verified = (
        expected_pack_integrity
        and actual_pack_integrity
        and expected_replay_integrity
        and actual_replay_integrity
        and not invalid_expected
        and not invalid_actual
        and differences["graph_digest_matches"] is True
        and differences["replay_digest_matches"] is True
        and not differences["missing_certificates"]
        and not differences["unexpected_certificates"]
    )
    return {"verified": verified, **differences}


def _mode_inputs(sdc: list[str], mode_specs: list[str]) -> list[ModeInput]:
    if bool(sdc) == bool(mode_specs):
        raise ValueError("provide either one or more --sdc files or one or more --mode NAME=FILE entries")
    if sdc:
        return [ModeInput("default", sdc)]
    grouped: dict[str, list[str]] = {}
    order: list[str] = []
    for specification in mode_specs:
        name, separator, path = specification.partition("=")
        if not separator or not name or not path:
            raise ValueError(f"invalid --mode value {specification!r}; expected NAME=FILE")
        if name not in grouped:
            grouped[name] = []
            order.append(name)
        grouped[name].append(path)
    return [ModeInput(name, grouped[name]) for name in order]


def _load_design(verilog: Sequence[str], liberty: Sequence[str], top: str | None) -> Design:
    library = CellLibrary()
    for path in liberty:
        library.merge(parse_liberty(path))
    return elaborate(parse_verilog([Path(path) for path in verilog]), library, top)


def _write(path: str, text: str) -> None:
    if path == "-":
        sys.stdout.write(text)
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8", newline="\n")


def _paths_alias(left: Path, right: Path) -> bool:
    try:
        if left.resolve(strict=False) == right.resolve(strict=False):
            return True
        return left.exists() and right.exists() and left.samefile(right)
    except (OSError, RuntimeError):
        return False


def _declared_input_paths(arguments: argparse.Namespace) -> list[Path]:
    paths = [Path(value) for value in (*arguments.verilog, *arguments.liberty, *arguments.sdc)]
    for specification in arguments.mode:
        _, separator, path = specification.partition("=")
        if separator and path:
            paths.append(Path(path))
    if arguments.command == "verify":
        paths.append(Path(arguments.expected_pack_path))
    return paths


def _validate_output_paths(arguments: argparse.Namespace) -> None:
    if arguments.output == "-":
        return
    output = Path(arguments.output)
    targets = [output]
    if arguments.command == "analyze" and arguments.format == "all":
        targets.extend(
            output / name
            for name in (
                "openconstraint-proof.json",
                "openconstraint-proof.txt",
                "openconstraint-repair.json",
                "openconstraint-repair.sdc",
            )
        )
    for target in targets:
        for input_path in _declared_input_paths(arguments):
            if _paths_alias(target, input_path):
                raise ValueError(f"output path {target} must not overlap input path {input_path}")


def _common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--verilog", action="append", required=True, metavar="FILE")
    parser.add_argument("--liberty", action="append", required=True, metavar="FILE")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--sdc", action="append", default=[], metavar="FILE")
    group.add_argument("--mode", action="append", default=[], metavar="NAME=FILE")
    parser.add_argument("--top")
    parser.add_argument("--max-graph-edges", type=int, default=DEFAULT_MAX_GRAPH_EDGES)
    parser.add_argument("--max-search-states", type=int, default=DEFAULT_MAX_SEARCH_STATES)
    parser.add_argument("--max-witness-nodes", type=int, default=DEFAULT_MAX_WITNESS_NODES)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openconstraint-prove",
        description="Replayable structural path proofs and review-required SDC repair plans.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze_parser = subparsers.add_parser("analyze")
    _common_arguments(analyze_parser)
    analyze_parser.add_argument("--format", choices=("json", "text", "all"), default="all")
    analyze_parser.add_argument("--output", default="openconstraint-proof")
    analyze_parser.add_argument(
        "--fail-on",
        choices=("never", "vacuous", "unresolved", "bounded", "inconclusive", "any"),
        default="never",
    )

    verify_parser = subparsers.add_parser("verify")
    _common_arguments(verify_parser)
    verify_parser.add_argument("--proof", dest="expected_pack_path", required=True, metavar="FILE")
    verify_parser.add_argument("--output", default="-")

    schema_parser = subparsers.add_parser("schema")
    schema_parser.add_argument("--kind", choices=("proof", "repair"), default="proof")
    schema_parser.add_argument("--output", default="-")
    return parser


def _limits(arguments: argparse.Namespace) -> ProofLimits:
    return ProofLimits(
        max_graph_edges=arguments.max_graph_edges,
        max_search_states=arguments.max_search_states,
        max_witness_nodes=arguments.max_witness_nodes,
    )


def _run_analysis(arguments: argparse.Namespace) -> tuple[Design, AuditResult, dict[str, object], dict[str, object]]:
    design = _load_design(arguments.verilog, arguments.liberty, arguments.top)
    mode_inputs = _mode_inputs(arguments.sdc, arguments.mode)
    result = audit(design, mode_inputs, AuditOptions())
    proof_pack = analyze_proofs(design, result, _limits(arguments))
    repair_plan = build_repair_plan(design, result, proof_pack)
    return design, result, proof_pack, repair_plan


def _gate(pack: Mapping[str, object], fail_on: str) -> int:
    if fail_on == "never":
        return 0
    if fail_on not in {"vacuous", "unresolved", "bounded", "inconclusive", "any"}:
        raise ValueError("unknown proof gate")
    summary = pack.get("summary", {})
    counts = summary if isinstance(summary, dict) else {}
    selected = {fail_on}
    if fail_on == "inconclusive":
        selected = {"unresolved", "bounded"}
    elif fail_on == "any":
        selected = {"vacuous", "unresolved", "bounded"}
    if "unresolved" in selected:
        modes = pack.get("modes")
        if (
            not isinstance(modes, list)
            or not modes
            or any(not isinstance(mode, dict) or mode.get("trusted_model") is not True for mode in modes)
        ):
            return 1
    return int(any(isinstance(counts.get(status), int) and counts[status] > 0 for status in selected))


def _schema_text(kind: str) -> str:
    name = "openconstraint-proof.schema.json" if kind == "proof" else "openconstraint-repair.schema.json"
    return (files("openconstraint.schemas") / name).read_text(encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "schema":
            _write(arguments.output, _schema_text(arguments.kind))
            return 0
        _validate_output_paths(arguments)
        _, _, proof_pack, repair_plan = _run_analysis(arguments)
        if arguments.command == "verify":
            expected_value = json.loads(Path(arguments.expected_pack_path).read_text(encoding="utf-8"))
            if not isinstance(expected_value, dict):
                raise ValueError("proof pack root must be a JSON object")
            verification = verify_proof_pack(expected_value, proof_pack)
            _write(arguments.output, json.dumps(verification, indent=2, sort_keys=True) + "\n")
            return 0 if verification["verified"] is True else 1

        if arguments.format == "json":
            bundle = {"proof": proof_pack, "repair": repair_plan}
            _write(arguments.output, json.dumps(bundle, indent=2, sort_keys=True) + "\n")
        elif arguments.format == "text":
            _write(arguments.output, render_proof_text(proof_pack))
        else:
            output = Path(arguments.output)
            output.mkdir(parents=True, exist_ok=True)
            _write(str(output / "openconstraint-proof.json"), json.dumps(proof_pack, indent=2, sort_keys=True) + "\n")
            _write(str(output / "openconstraint-proof.txt"), render_proof_text(proof_pack))
            _write(str(output / "openconstraint-repair.json"), json.dumps(repair_plan, indent=2, sort_keys=True) + "\n")
            _write(str(output / "openconstraint-repair.sdc"), render_repair_sdc(repair_plan))
        return _gate(proof_pack, arguments.fail_on)
    except (OSError, ValueError) as error:
        print(f"openconstraint-prove: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover - exercised through the console entry point
    raise SystemExit(main())
