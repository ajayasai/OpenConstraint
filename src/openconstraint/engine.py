"""Audit orchestration and deterministic structural/semantic rules."""

from __future__ import annotations

import math
import re
from collections import Counter, deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from openconstraint.model import (
    AuditResult,
    Clock,
    Coverage,
    CoverageComponent,
    Design,
    Diagnostic,
    ExceptionPath,
    ModeResult,
    Severity,
    SourceLocation,
)
from openconstraint.parsers.sdc import ParsedCommand, SdcDocument, Selector, parse_sdc
from openconstraint.query import ResolvedQuery, has_glob, resolve_selector
from openconstraint.version import __version__


@dataclass(slots=True)
class AuditOptions:
    broad_match_count: int = 50
    broad_match_ratio: float = 0.8
    broad_match_min_universe: int = 5
    report_implicit_waveform: bool = True


@dataclass(slots=True)
class ModeInput:
    name: str
    sdc_paths: list[str]


@dataclass(slots=True)
class _ModeState:
    name: str
    documents: list[SdcDocument]
    clocks: dict[str, Clock] = field(default_factory=dict)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    queries: list[ResolvedQuery] = field(default_factory=list)
    exceptions: list[ExceptionPath] = field(default_factory=list)
    delayed_inputs: set[str] = field(default_factory=set)
    delayed_outputs: set[str] = field(default_factory=set)
    duplicate_clocks: list[tuple[Clock, Clock]] = field(default_factory=list)
    clock_reach: dict[str, set[str]] = field(default_factory=dict)


def _number(value: str | None) -> float | None:
    if value is None:
        return None
    candidate = value.strip().strip('{}"')
    try:
        result = float(candidate)
        return result if math.isfinite(result) else None
    except ValueError:
        return None


def _numbers(value: str | None) -> tuple[float, ...] | None:
    if value is None:
        return None
    candidate = value.strip().strip('{}"')
    try:
        values = tuple(float(item) for item in re.split(r"[\s,]+", candidate) if item)
    except ValueError:
        return None
    return values if values and all(math.isfinite(item) for item in values) else None


def _plain(value: str | None) -> str | None:
    if value is None:
        return None
    candidate = value.strip()
    if len(candidate) >= 2 and (
        (candidate[0] == "{" and candidate[-1] == "}") or (candidate[0] == '"' and candidate[-1] == '"')
    ):
        candidate = candidate[1:-1]
    return candidate


def _finding(
    state: _ModeState,
    rule_id: str,
    severity: Severity,
    message: str,
    location: SourceLocation,
    rationale: str,
    suggestion: str,
    evidence: dict[str, object] | None = None,
) -> None:
    state.diagnostics.append(
        Diagnostic(rule_id, severity, message, location, rationale, suggestion, state.name, evidence or {})
    )


def _selectors_for(command: ParsedCommand, excluding_options: Iterable[str] = ()) -> list[Selector]:
    excluded_raw = {value for option in excluding_options for value in command.options.get(option, [])}
    return [selector for selector in command.selectors if selector.raw not in excluded_raw]


def _resolve_many(
    selectors: Iterable[Selector], design: Design, clocks: dict[str, Clock]
) -> tuple[set[str], list[ResolvedQuery]]:
    matches: set[str] = set()
    resolutions: list[ResolvedQuery] = []
    for selector in selectors:
        resolved = resolve_selector(selector, design, clocks)
        resolutions.append(resolved)
        matches.update(resolved.matches)
    return matches, resolutions


def _literal_targets(command: ParsedCommand, design: Design) -> set[str]:
    targets: set[str] = set()
    for value in command.positionals:
        candidate = _plain(value)
        if candidate in design.ports or candidate in design.pins or candidate in design.nets:
            targets.add(candidate)
    return targets


def _build_clocks(state: _ModeState, design: Design) -> None:
    commands = [command for document in state.documents for command in document.commands]
    for generated_pass in (False, True):
        for command in commands:
            is_generated = command.name == "create_generated_clock"
            if command.name not in {"create_clock", "create_generated_clock"} or is_generated != generated_pass:
                continue
            excluded = ("-source", "-master_clock") if is_generated else ()
            selectors = _selectors_for(command, excluded)
            targets, resolutions = _resolve_many(selectors, design, state.clocks)
            targets.update(_literal_targets(command, design))
            state.queries.extend(resolutions)
            source_targets: set[str] = set()
            if is_generated:
                source_word = command.option("-source")
                source_selector = next((item for item in command.selectors if item.raw == source_word), None)
                if source_selector:
                    source_result = resolve_selector(source_selector, design, state.clocks)
                    state.queries.append(source_result)
                    source_targets.update(source_result.matches)
                elif _plain(source_word) in design.ports or _plain(source_word) in design.pins:
                    source_targets.add(_plain(source_word) or "")
            name = _plain(command.option("-name"))
            if not name:
                name = (
                    sorted(targets)[0]
                    if targets
                    else f"<unnamed@{Path(command.location.path).name}:{command.location.line}>"
                )
            period = _number(command.option("-period"))
            waveform = _numbers(command.option("-waveform"))
            master = _plain(command.option("-master_clock"))
            if is_generated and period is None:
                divide = _number(command.option("-divide_by"))
                multiply = _number(command.option("-multiply_by"))
                source_clock = state.clocks.get(master or "")
                if source_clock is None:
                    source_clock = next(
                        (
                            clock
                            for clock in state.clocks.values()
                            if source_targets
                            & (
                                clock.targets
                                | _target_nets(design, clock.targets)
                                | _propagate_clock(design, clock.targets)[0]
                                | _propagate_clock(design, clock.targets)[1]
                            )
                        ),
                        None,
                    )
                if source_clock and source_clock.period:
                    period = source_clock.period * (divide or 1.0) / (multiply or 1.0)
                    master = master or source_clock.name
            clock = Clock(
                name=name,
                targets=targets,
                period=period,
                waveform=waveform,
                location=command.location,
                generated=is_generated,
                source_targets=source_targets,
                master_clock=master,
            )
            previous = state.clocks.get(name)
            if previous:
                if command.has("-add") and previous.period == clock.period and previous.waveform == clock.waveform:
                    previous.targets.update(clock.targets)
                    continue
                state.duplicate_clocks.append((previous, clock))
            state.clocks[name] = clock


def _target_nets(design: Design, targets: set[str]) -> set[str]:
    nets: set[str] = set()
    for target in targets:
        if target in design.ports:
            nets.add(design.ports[target].net)
        elif target in design.pins and design.pins[target].net:
            nets.add(design.pins[target].net or "")
        elif target in design.nets:
            nets.add(target)
        elif target in design.instances:
            nets.update(pin.net for pin in design.instances[target].pins.values() if pin.net)
    return nets


def _propagate_clock(design: Design, targets: set[str]) -> tuple[set[str], set[str]]:
    reached_nets = _target_nets(design, targets)
    reached_pins: set[str] = {target for target in targets if target in design.pins}
    queue: deque[str] = deque(reached_nets)
    while queue:
        net = queue.popleft()
        for pin_path in design.loads.get(net, set()):
            if pin_path not in design.pins:
                continue
            reached_pins.add(pin_path)
            pin = design.pins[pin_path]
            instance = design.instances[pin.instance]
            if instance.sequential:
                continue
            for output in instance.pins.values():
                if output.direction != "output" or output.net is None or output.net in reached_nets:
                    continue
                reached_nets.add(output.net)
                queue.append(output.net)
    return reached_nets, reached_pins


def _audit_queries(state: _ModeState, options: AuditOptions) -> None:
    seen: set[tuple[str, int, str]] = set()
    for query in state.queries:
        selector = query.selector
        identity = (selector.location.path, selector.location.line, selector.raw)
        if identity in seen:
            continue
        seen.add(identity)
        if query.error:
            _finding(
                state,
                "OC1003" if selector.dynamic else "OC1004",
                Severity.WARNING,
                f"Object query cannot be resolved statically: {selector.raw}",
                selector.location,
                "An unresolved dynamic or unsupported query prevents deterministic coverage analysis.",
                "Replace it with a static query, or validate this file with the optional trusted OpenSTA backend.",
                {"query": selector.raw, "reason": query.error},
            )
            continue
        if not query.matches:
            _finding(
                state,
                "OC1001",
                Severity.ERROR,
                f"Object query matches zero {selector.kind}: {selector.raw}",
                selector.location,
                "A constraint on an empty collection is silently ineffective in common SDC flows.",
                "Correct the pattern or hierarchy and confirm the intended object exists in this mode.",
                {"query": selector.raw, "object_kind": selector.kind, "universe_size": query.universe_size},
            )
            continue
        broad = (
            has_glob(selector)
            and query.universe_size >= options.broad_match_min_universe
            and (
                len(query.matches) >= options.broad_match_count
                or len(query.matches) / max(1, query.universe_size) >= options.broad_match_ratio
            )
            and selector.kind not in {"all_inputs", "all_outputs", "all_clocks"}
        )
        if broad:
            _finding(
                state,
                "OC1002",
                Severity.WARNING,
                f"Wildcard query matches {len(query.matches)} of {query.universe_size} {selector.kind}",
                selector.location,
                "Broad collections can grow silently after synthesis or hierarchy changes and change exception scope.",
                "Narrow the pattern, list intentional groups, or review and baseline the exact matched objects.",
                {"query": selector.raw, "matched_count": len(query.matches), "sample": sorted(query.matches)[:20]},
            )


def _audit_clocks(state: _ModeState, design: Design, options: AuditOptions) -> dict[str, set[str]]:
    pin_to_clocks: dict[str, set[str]] = {}
    for clock in state.clocks.values():
        reached_nets, reached_pins = _propagate_clock(design, clock.targets)
        state.clock_reach[clock.name] = reached_nets | reached_pins | clock.targets
        if clock.period is None or clock.period <= 0:
            _finding(
                state,
                "OC2001",
                Severity.ERROR,
                f"Clock {clock.name!r} has no valid positive period",
                clock.location,
                "A primary clock needs a positive period; generated clocks need a resolvable master or explicit period.",
                "Add -period for a primary clock or fix the generated-clock master/source relationship.",
                {"clock": clock.name, "period": clock.period},
            )
        elif clock.waveform is None and options.report_implicit_waveform and not clock.generated:
            _finding(
                state,
                "OC2002",
                Severity.NOTE,
                f"Clock {clock.name!r} uses the implicit 50% duty-cycle waveform",
                clock.location,
                "The default waveform is valid, but an explicit waveform makes intent reviewable for non-50% clocks.",
                "Add -waveform only when the real active edges differ from {0, period/2}.",
                {"clock": clock.name, "implicit_waveform": [0.0, clock.period / 2.0]},
            )
        if clock.generated:
            if not clock.source_targets:
                _finding(
                    state,
                    "OC2010",
                    Severity.ERROR,
                    f"Generated clock {clock.name!r} has no resolvable -source object",
                    clock.location,
                    "Generated-clock phase and frequency must be related to a real source pin or port.",
                    "Point -source at the master clock path and ensure the object query matches this netlist.",
                    {"clock": clock.name},
                )
            masters = [
                master
                for master in state.clocks.values()
                if master.name != clock.name and clock.source_targets & state.clock_reach.get(master.name, set())
            ]
            if clock.master_clock:
                masters = [master for master in masters if master.name == clock.master_clock]
            if not masters:
                _finding(
                    state,
                    "OC2011",
                    Severity.ERROR,
                    f"Generated clock {clock.name!r} source is not reachable from its master clock",
                    clock.location,
                    "A generated clock with an unrelated source creates an invalid or ambiguous timing relationship.",
                    "Fix -source/-master_clock or the netlist clock path; inspect the HTML clock graph.",
                    {"clock": clock.name, "source_targets": sorted(clock.source_targets), "master": clock.master_clock},
                )
        for pin_path in design.sequential_clock_pins & reached_pins:
            pin_to_clocks.setdefault(pin_path, set()).add(clock.name)
    for first, second in state.duplicate_clocks:
        severity = (
            Severity.ERROR if first.period != second.period or first.targets != second.targets else Severity.WARNING
        )
        _finding(
            state,
            "OC2003",
            severity,
            f"Clock {second.name!r} is defined more than once without a clean additive merge",
            second.location,
            "Duplicate clock definitions can override one another and make mode behavior order-dependent.",
            "Use one definition, or use -add only for intentional clocks sharing a source object.",
            {"clock": second.name, "previous_location": first.location.to_dict()},
        )
    multiple = {pin: clocks for pin, clocks in pin_to_clocks.items() if len(clocks) > 1}
    if multiple:
        location = next(iter(state.clocks.values())).location if state.clocks else SourceLocation("<design>")
        _finding(
            state,
            "OC2004",
            Severity.WARNING,
            f"{len(multiple)} sequential clock pin(s) receive multiple clocks",
            location,
            "Multiple clocks on one sequential clock pin may be intentional but require explicit mode and exclusivity review.",
            "Declare the intended clock groups or split the analysis by mode; inspect the reported pin-to-clock map.",
            {"pins": {pin: sorted(clocks) for pin, clocks in sorted(multiple.items())}},
        )
    return pin_to_clocks


def _collect_nonclock_constraints(state: _ModeState, design: Design) -> None:
    for document in state.documents:
        for issue in document.issues:
            _finding(
                state,
                "OC0001",
                Severity.ERROR,
                f"Malformed Tcl/SDC: {issue.message}",
                issue.location,
                "Malformed grouping can change how every following SDC token is interpreted.",
                "Fix the Tcl syntax before trusting any downstream result.",
            )
        for command in document.commands:
            if command.name in {"create_clock", "create_generated_clock"}:
                continue
            resolutions = [resolve_selector(selector, design, state.clocks) for selector in command.selectors]
            state.queries.extend(resolutions)
            matches = set().union(*(result.matches for result in resolutions)) if resolutions else set()
            if command.name == "set_input_delay":
                state.delayed_inputs.update(name for name in matches if name in design.ports)
            elif command.name == "set_output_delay":
                state.delayed_outputs.update(name for name in matches if name in design.ports)
            elif command.name in {"set_false_path", "set_multicycle_path", "set_max_delay", "set_min_delay"}:
                state.exceptions.append(_exception_from_command(command, design, state.clocks))
            elif command.name == "set_clock_groups":
                state.exceptions.extend(_clock_group_exceptions(command, design, state.clocks))


def _objects_from_option(command: ParsedCommand, option: str, design: Design, clocks: dict[str, Clock]) -> set[str]:
    values = command.options.get(option, [])
    selectors = [selector for selector in command.selectors if selector.raw in values]
    values_resolved, _ = _resolve_many(selectors, design, clocks)
    for value in values:
        literal = _plain(value)
        if literal in design.ports or literal in design.pins or literal in design.instances or literal in clocks:
            values_resolved.add(literal or "")
    return values_resolved


def _objects_from_word(command: ParsedCommand, value: str, design: Design, clocks: dict[str, Clock]) -> set[str]:
    selectors = [selector for selector in command.selectors if selector.raw == value]
    values_resolved, _ = _resolve_many(selectors, design, clocks)
    literal = _plain(value)
    if literal in design.ports or literal in design.pins or literal in design.instances or literal in clocks:
        values_resolved.add(literal or "")
    return values_resolved


def _exception_from_command(command: ParsedCommand, design: Design, clocks: dict[str, Clock]) -> ExceptionPath:
    from_objects = _objects_from_option(command, "-from", design, clocks)
    to_objects = _objects_from_option(command, "-to", design, clocks)
    through_groups = tuple(
        frozenset(_objects_from_word(command, value, design, clocks)) for value in command.options.get("-through", [])
    )
    return ExceptionPath(
        command.name.removeprefix("set_"), from_objects, to_objects, through_groups, command.location, command.raw
    )


def _clock_group_exceptions(command: ParsedCommand, design: Design, clocks: dict[str, Clock]) -> list[ExceptionPath]:
    groups: list[set[str]] = []
    for group_word in command.options.get("-group", []):
        selectors = [selector for selector in command.selectors if selector.raw == group_word]
        matches, _ = _resolve_many(selectors, design, clocks)
        literal = _plain(group_word)
        if not matches and literal in clocks:
            matches.add(literal or "")
        groups.append(matches)
    exceptions: list[ExceptionPath] = []
    for left_index, left in enumerate(groups):
        for right in groups[left_index + 1 :]:
            exceptions.append(ExceptionPath("clock_group", set(left), set(right), (), command.location, command.raw))
            exceptions.append(ExceptionPath("clock_group", set(right), set(left), (), command.location, command.raw))
    return exceptions


def _sets_overlap(left: set[str], right: set[str]) -> bool:
    return not left or not right or bool(left & right)


def _audit_exceptions(state: _ModeState) -> None:
    for index, left in enumerate(state.exceptions):
        for right in state.exceptions[index + 1 :]:
            if left.location == right.location and left.kind == right.kind == "clock_group":
                continue
            if not _sets_overlap(left.from_objects, right.from_objects) or not _sets_overlap(
                left.to_objects, right.to_objects
            ):
                continue
            if left.through_objects and right.through_objects:
                left_through = set().union(*left.through_objects)
                right_through = set().union(*right.through_objects)
                if not left_through & right_through:
                    continue
            kinds = {left.kind, right.kind}
            if "false_path" in kinds and "multicycle_path" in kinds:
                severity = Severity.ERROR
                message = "False-path and multicycle exceptions overlap"
                rationale = "A false path removes timing analysis while a multicycle path modifies it; applying both obscures intent."
            elif "clock_group" in kinds and "multicycle_path" in kinds:
                severity = Severity.ERROR
                message = "Clock-group cut and multicycle exception overlap"
                rationale = "A clock-group cut removes paths that the multicycle constraint attempts to time."
            elif "clock_group" in kinds and "false_path" in kinds:
                severity = Severity.NOTE
                message = "False-path exception is redundant with a clock-group cut"
                rationale = "Redundant exceptions increase review surface and can hide later scope changes."
            elif left.kind == right.kind:
                severity = Severity.WARNING
                message = f"Two {left.kind.replace('_', '-')} exceptions overlap"
                rationale = "Duplicate or intersecting exceptions can make precedence and later maintenance unclear."
            else:
                continue
            _finding(
                state,
                "OC4001",
                severity,
                message,
                right.location,
                rationale,
                "Narrow the collections or keep one constraint that states the intended timing policy.",
                {
                    "first": left.location.to_dict(),
                    "second": right.location.to_dict(),
                    "from_intersection": sorted(left.from_objects & right.from_objects)[:20],
                    "to_intersection": sorted(left.to_objects & right.to_objects)[:20],
                },
            )


def _required_io(design: Design, state: _ModeState) -> tuple[set[str], set[str]]:
    clock_ports: set[str] = set()
    for clock in state.clocks.values():
        for target in clock.targets:
            if target not in design.ports:
                continue
            _, reached_pins = _propagate_clock(design, {target})
            if reached_pins & design.sequential_clock_pins:
                clock_ports.add(target)
    inputs = {name for name, port in design.ports.items() if port.direction in {"input", "inout"}} - clock_ports
    outputs = {name for name, port in design.ports.items() if port.direction in {"output", "inout"}}
    return inputs, outputs


def _audit_coverage(state: _ModeState, design: Design, pin_to_clocks: dict[str, set[str]]) -> Coverage:
    constrained_endpoints = {
        endpoint
        for endpoint in design.sequential_endpoints
        if any(
            pin.path in pin_to_clocks
            for pin in design.instances[design.pins[endpoint].instance].pins.values()
            if pin.is_clock
        )
    }
    missing_endpoints = design.sequential_endpoints - constrained_endpoints
    if missing_endpoints:
        location = SourceLocation("<design>")
        _finding(
            state,
            "OC2101",
            Severity.ERROR,
            f"{len(missing_endpoints)} of {len(design.sequential_endpoints)} sequential endpoint(s) are unconstrained",
            location,
            "Without a reachable clock, setup/hold analysis cannot meaningfully cover these sequential data endpoints.",
            "Create or repair clocks/generated clocks so each endpoint's clock pin is reached in this mode.",
            {"unconstrained_endpoints": sorted(missing_endpoints), "sample": sorted(missing_endpoints)[:50]},
        )
    required_inputs, required_outputs = _required_io(design, state)
    missing_inputs = required_inputs - state.delayed_inputs
    missing_outputs = required_outputs - state.delayed_outputs
    if missing_inputs:
        _finding(
            state,
            "OC3001",
            Severity.WARNING,
            f"{len(missing_inputs)} input port(s) have no input delay",
            SourceLocation("<design>"),
            "Undelayed non-clock inputs have no modeled external launch relationship.",
            "Add set_input_delay for synchronous interfaces or document an intentional asynchronous exception.",
            {"ports": sorted(missing_inputs)},
        )
    if missing_outputs:
        _finding(
            state,
            "OC3002",
            Severity.WARNING,
            f"{len(missing_outputs)} output port(s) have no output delay",
            SourceLocation("<design>"),
            "Undelayed outputs have no modeled external capture requirement.",
            "Add set_output_delay per interface and reference the appropriate clock.",
            {"ports": sorted(missing_outputs)},
        )
    static_queries = [query for query in state.queries if not query.selector.dynamic]
    healthy_queries = [query for query in static_queries if not query.error and query.matches]
    components = [
        CoverageComponent(
            "sequential_endpoints",
            "Clocked sequential endpoints",
            len(constrained_endpoints),
            len(design.sequential_endpoints),
            0.50,
            "Sequential data pins whose instance has a clock pin reached by a defined clock.",
        ),
        CoverageComponent(
            "input_delays",
            "Input-delay coverage",
            len(required_inputs & state.delayed_inputs),
            len(required_inputs),
            0.20,
            "Non-clock input/inout ports matched by at least one set_input_delay.",
        ),
        CoverageComponent(
            "output_delays",
            "Output-delay coverage",
            len(required_outputs & state.delayed_outputs),
            len(required_outputs),
            0.20,
            "Output/inout ports matched by at least one set_output_delay.",
        ),
        CoverageComponent(
            "query_health",
            "Resolvable object queries",
            len(healthy_queries),
            len(static_queries),
            0.10,
            "Static SDC object queries that resolve to at least one design object.",
        ),
    ]
    applicable = [component for component in components if component.total]
    denominator = sum(component.weight for component in applicable)
    score = (
        100.0 * sum(component.weight * component.covered / component.total for component in applicable) / denominator
        if denominator
        else 100.0
    )
    rounded = round(score, 2)
    grade = "A" if rounded >= 95 else "B" if rounded >= 85 else "C" if rounded >= 70 else "D" if rounded >= 50 else "F"
    return Coverage(rounded, grade, components)


def _make_graph(state: _ModeState, design: Design, pin_to_clocks: dict[str, set[str]]) -> dict[str, object]:
    nodes: list[dict[str, object]] = []
    edges: list[dict[str, object]] = []
    for clock in sorted(state.clocks.values(), key=lambda item: item.name):
        nodes.append(
            {
                "id": f"clock:{clock.name}",
                "label": clock.name,
                "kind": "generated_clock" if clock.generated else "clock",
            }
        )
        for target in sorted(clock.targets):
            target_id = f"object:{target}"
            nodes.append({"id": target_id, "label": target, "kind": "target"})
            edges.append({"source": f"clock:{clock.name}", "target": target_id, "kind": "defines"})
        if clock.master_clock:
            edges.append(
                {"source": f"clock:{clock.master_clock}", "target": f"clock:{clock.name}", "kind": "generates"}
            )
    for pin, clocks in sorted(pin_to_clocks.items()):
        pin_id = f"endpoint_clock:{pin}"
        nodes.append({"id": pin_id, "label": pin, "kind": "sequential_clock_pin"})
        for clock_name in sorted(clocks):
            edges.append({"source": f"clock:{clock_name}", "target": pin_id, "kind": "reaches"})
    for index, exception in enumerate(state.exceptions):
        exception_id = f"exception:{index}"
        nodes.append({"id": exception_id, "label": exception.kind.replace("_", " "), "kind": "exception"})
        for source in sorted(exception.from_objects):
            source_id = f"scope:{source}"
            nodes.append({"id": source_id, "label": source, "kind": "scope"})
            edges.append({"source": source_id, "target": exception_id, "kind": "from"})
        for target in sorted(exception.to_objects):
            target_id = f"scope:{target}"
            nodes.append({"id": target_id, "label": target, "kind": "scope"})
            edges.append({"source": exception_id, "target": target_id, "kind": "to"})
    deduplicated = {str(node["id"]): node for node in nodes}
    return {"nodes": list(deduplicated.values()), "edges": edges}


def _audit_mode(name: str, paths: list[str], design: Design, options: AuditOptions) -> ModeResult:
    state = _ModeState(name, [parse_sdc(path) for path in paths])
    _build_clocks(state, design)
    _collect_nonclock_constraints(state, design)
    _audit_queries(state, options)
    pin_to_clocks = _audit_clocks(state, design, options)
    _audit_exceptions(state)
    coverage = _audit_coverage(state, design, pin_to_clocks)
    state.diagnostics.sort(key=lambda item: (item.location.path, item.location.line, item.rule_id, item.message))
    return ModeResult(
        name, state.clocks, state.exceptions, state.diagnostics, coverage, _make_graph(state, design, pin_to_clocks)
    )


def _cross_mode_diagnostics(modes: list[ModeResult]) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    if len(modes) < 2:
        return diagnostics
    all_clock_names = sorted(set().union(*(set(mode.clocks) for mode in modes)))
    for clock_name in all_clock_names:
        definitions = {
            mode.name: (
                mode.clocks[clock_name].period,
                tuple(sorted(mode.clocks[clock_name].targets)),
                mode.clocks[clock_name].generated,
            )
            for mode in modes
            if clock_name in mode.clocks
        }
        if len(definitions) != len(modes) or len(set(definitions.values())) > 1:
            first_clock = next(mode.clocks[clock_name] for mode in modes if clock_name in mode.clocks)
            diagnostics.append(
                Diagnostic(
                    "OC5001",
                    Severity.NOTE,
                    f"Clock {clock_name!r} differs across constraint modes",
                    first_clock.location,
                    "Mode-specific clocks are common, but unintended period/target drift can invalidate comparisons.",
                    "Review the per-mode definitions and record intentional differences in version control.",
                    "cross-mode",
                    {
                        "clock": clock_name,
                        "definitions": definitions,
                        "missing_modes": [mode.name for mode in modes if clock_name not in mode.clocks],
                    },
                )
            )
    signatures = {
        mode.name: {
            (item.kind, tuple(sorted(item.from_objects)), tuple(sorted(item.to_objects))) for item in mode.exceptions
        }
        for mode in modes
    }
    baseline = modes[0]
    for mode in modes[1:]:
        added = signatures[mode.name] - signatures[baseline.name]
        removed = signatures[baseline.name] - signatures[mode.name]
        if added or removed:
            diagnostics.append(
                Diagnostic(
                    "OC5002",
                    Severity.NOTE,
                    f"Exception topology differs between modes {baseline.name!r} and {mode.name!r}",
                    SourceLocation("<mode-comparison>"),
                    "Constraint-mode diffs should be explicit because scan/test exceptions can leak into functional analysis.",
                    "Review the mode diff in JSON/HTML and confirm each added or removed exception is intentional.",
                    "cross-mode",
                    {
                        "baseline": baseline.name,
                        "compared": mode.name,
                        "added_count": len(added),
                        "removed_count": len(removed),
                    },
                )
            )
    return diagnostics


def audit(design: Design, modes: list[ModeInput], options: AuditOptions | None = None) -> AuditResult:
    selected_options = options or AuditOptions()
    mode_results = [_audit_mode(mode.name, mode.sdc_paths, design, selected_options) for mode in modes]
    diagnostics = [finding for mode in mode_results for finding in mode.diagnostics]
    diagnostics.extend(_cross_mode_diagnostics(mode_results))
    counts = Counter(finding.severity.value for finding in diagnostics)
    summary = {
        "diagnostic_count": len(diagnostics),
        "errors": counts["error"],
        "warnings": counts["warning"],
        "notes": counts["note"],
        "mode_count": len(mode_results),
        "coverage": {mode.name: mode.coverage.score for mode in mode_results},
    }
    design_summary = {
        "top": design.top,
        "ports": len(design.ports),
        "nets": len(design.nets),
        "instances": len(design.instances),
        "sequential_instances": len(design.sequential_instances),
        "sequential_endpoints": len(design.sequential_endpoints),
        "parser_warnings": design.warnings,
    }
    return AuditResult(__version__, design_summary, mode_results, diagnostics, summary)
