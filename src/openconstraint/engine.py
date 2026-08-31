"""Audit orchestration and deterministic structural/semantic rules."""

from __future__ import annotations

import json
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
    IODelay,
    ModeResult,
    Severity,
    SourceLocation,
    effective_io_delay_semantics,
)
from openconstraint.parsers.sdc import (
    MODELED_SDC_COMMANDS,
    ParsedCommand,
    SdcDocument,
    Selector,
    parse_sdc,
    parse_sdc_text,
)
from openconstraint.parsers.tcl import TclSyntaxError, split_tcl_list
from openconstraint.query import ResolvedQuery, has_glob, resolve_selector
from openconstraint.version import __version__

STRUCTURAL_WARNING_SAMPLE_LIMIT = 50
_MAX_LITERAL_COLLECTION_RECURSION = 64
_IODelayAuditRelationshipKey = tuple[str, str, tuple[str, ...], str]
_IODelayAuditSlotKey = tuple[str, str]
_TCL_NUMERIC_WHITESPACE = " \t\n\v\f\r"
_TCL_DECIMAL_FLOAT = re.compile(
    r"[+-]?(?:(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?|[0-9]+[eE][+-]?[0-9]+)\Z",
    re.ASCII,
)


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


@dataclass(frozen=True, slots=True)
class _Multicycle:
    """Normalized multicycle intent used for setup/hold consistency checks."""

    multiplier: int | None
    applies_to: frozenset[str]
    from_objects: frozenset[str]
    to_objects: frozenset[str]
    through_objects: tuple[frozenset[str], ...]
    from_transition: str
    to_transition: str
    end_transition: str
    through_transitions: tuple[str, ...]
    start_end: str
    scope_resolvable: bool
    location: SourceLocation
    raw: str

    @property
    def selector_scope(
        self,
    ) -> tuple[
        frozenset[str],
        frozenset[str],
        tuple[frozenset[str], ...],
        str,
        str,
        str,
        tuple[str, ...],
    ]:
        return (
            self.from_objects,
            self.to_objects,
            self.through_objects,
            self.from_transition,
            self.to_transition,
            self.end_transition,
            self.through_transitions,
        )

    @property
    def scope(
        self,
    ) -> tuple[
        frozenset[str],
        frozenset[str],
        tuple[frozenset[str], ...],
        str,
        str,
        str,
        tuple[str, ...],
        str,
    ]:
        return (*self.selector_scope, self.effective_reference)

    @property
    def effective_reference(self) -> str:
        """Return OpenSTA's effective launch/capture clock reference.

        OpenSTA defaults a hold-only multicycle to the start clock. Setup-only
        and combined setup/hold constraints default to the end clock.
        """

        if self.start_end != "default":
            return self.start_end
        return "start" if self.applies_to == frozenset({"hold"}) else "end"


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
    io_delays: list[IODelay] = field(default_factory=list)
    multicycles: list[_Multicycle] = field(default_factory=list)
    duplicate_clocks: list[tuple[Clock, Clock]] = field(default_factory=list)
    clock_reach: dict[str, set[str]] = field(default_factory=dict)
    valid_clocks: set[str] = field(default_factory=set)
    invalid_clocks: set[str] = field(default_factory=set)


def _active_clocks(state: _ModeState) -> dict[str, Clock]:
    """Return only definitions proven valid by the clock audit."""

    return {name: clock for name, clock in state.clocks.items() if name in state.valid_clocks}


def _tcl_integer(value: str) -> int | None:
    """Parse the finite integer spellings accepted by Tcl 8.6.

    This intentionally performs no Tcl word decoding: the SDC parser has
    already decoded the command operand exactly once.
    """

    candidate = value.strip(_TCL_NUMERIC_WHITESPACE)
    if not candidate:
        return None
    sign = 1
    if candidate[0] in "+-":
        sign = -1 if candidate[0] == "-" else 1
        candidate = candidate[1:]
    if not candidate:
        return None
    base = 10
    digits = candidate
    if candidate.startswith(("0x", "0X")):
        base, digits = 16, candidate[2:]
        valid_digits = "0123456789abcdefABCDEF"
    elif candidate.startswith(("0b", "0B")):
        base, digits = 2, candidate[2:]
        valid_digits = "01"
    elif candidate.startswith(("0o", "0O")):
        base, digits = 8, candidate[2:]
        valid_digits = "01234567"
    elif len(candidate) > 1 and candidate.startswith("0"):
        base = 8
        valid_digits = "01234567"
    else:
        valid_digits = "0123456789"
    if not digits or any(char not in valid_digits for char in digits):
        return None
    return sign * int(digits, base)


def _number(value: str | None) -> float | None:
    if value is None:
        return None
    candidate = value.strip(_TCL_NUMERIC_WHITESPACE)
    if not candidate:
        return None
    try:
        integer = _tcl_integer(candidate)
        if integer is not None:
            result = float(integer)
        elif _TCL_DECIMAL_FLOAT.fullmatch(candidate):
            result = float(candidate)
        else:
            return None
        return result if math.isfinite(result) else None
    except (OverflowError, ValueError):
        return None


def _numbers(value: str | None) -> tuple[float, ...] | None:
    if value is None:
        return None
    try:
        words = split_tcl_list(value)
    except TclSyntaxError:
        return None
    values = tuple(_number(item) for item in words)
    if not values or any(item is None for item in values):
        return None
    return tuple(item for item in values if item is not None)


def _integer(value: str | None) -> int | None:
    if value is None:
        return None
    integer = _tcl_integer(value)
    # OpenSTA c821ad1 calls Tcl 8.6 ``string is integer`` rather than the
    # wider/bignum classes. Mirror its magnitude limit and retain exactness.
    return integer if integer is not None and abs(integer) <= 0xFFFFFFFF else None


def _integers(value: str | None) -> tuple[int, ...] | None:
    if value is None:
        return None
    try:
        words = split_tcl_list(value)
    except TclSyntaxError:
        return None
    integers = tuple(_integer(item) for item in words)
    if not integers or any(item is None for item in integers):
        return None
    return tuple(item for item in integers if item is not None)


def _plain(value: str | None) -> str | None:
    # Command operands were decoded by the SDC parser. A second trim/unquote
    # changes literal identities such as ``{{core}}`` into ``core``.
    return value


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


def _selectors_for(command: ParsedCommand) -> list[Selector]:
    """Return only positional collection selectors for a command target."""

    return [selector for selector in command.selectors if selector.option is None]


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


def _literal_targets(command: ParsedCommand, design: Design, *, allow_nets: bool) -> tuple[set[str], list[str]]:
    targets: set[str] = set()
    problems: list[str] = []
    candidates = set(design.ports) | set(design.pins)
    if allow_nets:
        candidates.update(design.nets)
    for value in command.positionals:
        if any(selector.option is None and selector.raw == value for selector in command.selectors):
            continue
        _, literal_targets, unknown, error = _literal_collection(value, candidates)
        targets.update(literal_targets)
        if error is not None:
            problems.append(f"target literal is not a well-formed Tcl object list: {error}")
        if unknown:
            sample = ", ".join(repr(item) for item in unknown[:8])
            suffix = f" (and {len(unknown) - 8} more)" if len(unknown) > 8 else ""
            problems.append(f"target literal contains unresolved object(s): {sample}{suffix}")
    return targets, problems


def _validated_waveform(state: _ModeState, command: ParsedCommand, period: float | None) -> tuple[float, ...] | None:
    raw = command.option("-waveform")
    if raw is None:
        return None
    waveform = _numbers(raw)
    problems: list[str] = []
    if waveform is None:
        problems.append("edge list is not finite numeric data")
    else:
        if len(waveform) % 2:
            problems.append("edge list must contain an even number of entries")
        if any(right <= left for left, right in zip(waveform, waveform[1:], strict=False)):
            problems.append("edge times must be strictly increasing")
        if period is not None and period > 0 and any(edge > period * 2 for edge in waveform):
            problems.append("an edge is more than two periods from time zero")
    if problems:
        _finding(
            state,
            "OC2005",
            Severity.ERROR,
            "Clock waveform is invalid",
            command.location,
            "Malformed clock edges can invert active relationships or be rejected differently by timing engines.",
            "Use a finite, strictly increasing even-length edge list within two clock periods.",
            {"waveform": raw, "problems": problems},
        )
        return None
    return waveform


def _generated_clock_parameters(
    state: _ModeState, command: ParsedCommand
) -> tuple[int | None, int | None, float | None, tuple[int, ...] | None, tuple[float, ...] | None, bool]:
    divide = _integer(command.option("-divide_by"))
    multiply = _integer(command.option("-multiply_by"))
    duty_cycle = _number(command.option("-duty_cycle"))
    edges = _integers(command.option("-edges"))
    edge_shift = _numbers(command.option("-edge_shift"))
    combinational = command.has("-combinational")
    problems: list[str] = []
    mechanisms = sum(
        (
            command.option("-divide_by") is not None,
            command.option("-multiply_by") is not None,
            command.option("-edges") is not None,
            combinational,
        )
    )
    if mechanisms == 0:
        problems.append("one of -divide_by, -multiply_by, -edges, or -combinational is required")
    elif mechanisms > 1 and not (combinational and divide == 1 and mechanisms == 2):
        problems.append("generated-clock transform mechanisms are mutually exclusive")
    if command.option("-divide_by") is not None and (divide is None or divide < 1):
        problems.append("-divide_by must be a positive integer")
        divide = None
    if command.option("-multiply_by") is not None and (multiply is None or multiply < 1):
        problems.append("-multiply_by must be a positive integer")
        multiply = None
    if command.option("-divide_by") is not None and command.option("-multiply_by") is not None:
        problems.append("-divide_by and -multiply_by are mutually exclusive")
    if combinational and divide not in {None, 1}:
        problems.append("-combinational requires -divide_by 1 when a divisor is present")
    if command.option("-duty_cycle") is not None:
        if command.option("-multiply_by") is None:
            problems.append("-duty_cycle requires -multiply_by")
        elif duty_cycle is None or not 0 <= duty_cycle <= 100:
            problems.append("-duty_cycle must be between 0 and 100")
            duty_cycle = None
    if command.option("-edges") is not None:
        if edges is None or len(edges) != 3 or any(edge < 1 for edge in edges):
            problems.append("-edges must contain exactly three positive integers")
            edges = None
        elif any(right <= left for left, right in zip(edges, edges[1:], strict=False)):
            problems.append("-edges entries must be strictly increasing")
        if command.option("-edge_shift") is not None and (
            edge_shift is None or edges is None or len(edge_shift) != len(edges)
        ):
            problems.append("-edge_shift must contain one finite value per generated edge")
            edge_shift = None
    elif command.option("-edge_shift") is not None:
        problems.append("-edge_shift requires -edges")
        edge_shift = None
    if command.has("-invert") and not (
        command.option("-divide_by") is not None or command.option("-multiply_by") is not None or combinational
    ):
        problems.append("-invert requires divide, multiply, or combinational generation")
    if command.has("-add") and (command.option("-name") is None or command.option("-master_clock") is None):
        problems.append("-add requires both -name and -master_clock")
    if problems:
        _finding(
            state,
            "OC2012",
            Severity.ERROR,
            "Generated-clock transform is invalid",
            command.location,
            "Conflicting or malformed generated-clock options can create the wrong frequency, phase, or active edge.",
            "Use one valid transform and make its master/source relationship explicit.",
            {"clock": _plain(command.option("-name")), "problems": problems},
        )
        return divide, multiply, duty_cycle, edges, edge_shift, False
    if combinational and divide is None:
        # OpenSTA represents the combinational transform as divide-by-one.
        divide = 1
    return divide, multiply, duty_cycle, edges, edge_shift, True


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _invert_generated_waveform(waveform: tuple[float, ...], period: float) -> tuple[float, ...]:
    """Rotate generated-clock edges exactly as OpenSTA's Clock::generate does."""

    first_time = waveform[0]
    offset = period if first_time >= period else 0.0
    return tuple(edge - offset for edge in waveform[1:]) + (first_time - offset + period,)


def _derive_generated_clock_timing(
    source_clock: Clock,
    divide: int | None,
    multiply: int | None,
    duty_cycle: float | None,
    edges: tuple[int, ...] | None,
    edge_shift: tuple[float, ...] | None,
    invert: bool,
) -> tuple[float, tuple[float, ...], tuple[float, float, float] | None] | None:
    """Derive generated-clock timing using pinned OpenSTA Clock.cc semantics.

    The final tuple contains the period, stored rise/fall waveform, and (only
    for ``-edges``) all three shifted reference edges used for validation.
    """

    source_period = source_clock.period
    source_waveform = source_clock.effective_waveform
    if source_period is None or source_period <= 0 or source_waveform is None or len(source_waveform) < 2:
        return None

    shifted_edges: tuple[float, float, float] | None = None
    waveform: tuple[float, ...]
    if edges is not None:
        shifts = edge_shift or (0.0, 0.0, 0.0)
        selected: list[float] = []
        for edge, shift in zip(edges, shifts, strict=True):
            periods, waveform_index = divmod(edge - 1, len(source_waveform))
            selected.append(source_waveform[waveform_index] + periods * source_period + shift)
        shifted_edges = (selected[0], selected[1], selected[2])
        rise, fall, third = shifted_edges
        period = third - rise
        # The third edge establishes the next rising edge; OpenSTA stores only
        # the generated rise/fall pair in the waveform.
        waveform = (rise, fall)
    elif divide is not None:
        if divide == 1:
            period = source_period
            waveform = (source_waveform[0], source_waveform[1])
        elif _is_power_of_two(divide):
            period = source_period * divide
            rise = source_waveform[0]
            waveform = (rise, rise + period / 2.0)
        else:
            period = source_period * divide
            waveform = tuple(edge * divide for edge in source_waveform)
    elif multiply is not None:
        scale = 1.0 / multiply
        period = source_period * scale
        if duty_cycle is not None and duty_cycle != 0.0:
            rise = source_waveform[0] * scale
            waveform = (rise, rise + period * duty_cycle / 100.0)
        else:
            # OpenSTA treats an explicit zero duty cycle like the default and
            # scales every source waveform edge.
            waveform = tuple(edge * scale for edge in source_waveform)
    else:
        return None

    if invert:
        waveform = _invert_generated_waveform(waveform, period)
    return period, waveform, shifted_edges


def _build_clocks(state: _ModeState, design: Design) -> None:
    commands = [command for document in state.documents for command in document.commands]
    for generated_pass in (False, True):
        for command in commands:
            is_generated = command.name == "create_generated_clock"
            if command.name not in {"create_clock", "create_generated_clock"} or is_generated != generated_pass:
                continue
            if command.parse_errors or command.opaque_substitutions:
                # Tcl evaluates nested collection commands before invoking the
                # outer command. Audit those selectors, but never construct a
                # clock from a command whose outer argument semantics are not
                # statically trustworthy.
                state.queries.extend(resolve_selector(selector, design, state.clocks) for selector in command.selectors)
                continue
            selectors = _selectors_for(command)
            allowed_target_kinds = {"ports", "pins", "all_inputs", "all_outputs"}
            if is_generated:
                allowed_target_kinds.add("nets")
            resolutions = [resolve_selector(selector, design, state.clocks) for selector in selectors]
            targets = {
                match
                for resolution in resolutions
                if resolution.selector.kind in allowed_target_kinds
                for match in resolution.matches
            }
            invalid_target_kinds = sorted(
                {
                    resolution.selector.kind
                    for resolution in resolutions
                    if resolution.selector.kind not in allowed_target_kinds
                }
            )
            literal_targets, literal_target_problems = _literal_targets(command, design, allow_nets=is_generated)
            targets.update(literal_targets)
            target_net_problems: list[str] = []
            if is_generated:
                converted_targets: set[str] = set()
                for target in targets:
                    if target not in design.nets:
                        converted_targets.add(target)
                        continue
                    drivers = sorted(design.drivers.get(target, set()))
                    if len(drivers) == 1:
                        converted_targets.add(drivers[0])
                    elif not drivers:
                        target_net_problems.append(f"net {target!r} has no driver port/pin")
                    else:
                        target_net_problems.append(
                            f"net {target!r} has multiple driver ports/pins: {', '.join(drivers)}"
                        )
                targets = converted_targets
            state.queries.extend(resolutions)
            target_argument_present = bool(command.positionals)
            definition_invalid = False
            source_targets: set[str] = set()
            source_match_count = 0
            source_collection_valid = True
            source_type_valid = True
            if is_generated:
                source_word = command.option("-source")
                source_selector = _option_selector(command, "-source", source_word)
                if source_selector:
                    source_result = resolve_selector(source_selector, design, state.clocks)
                    state.queries.append(source_result)
                    source_targets.update(source_result.matches)
                    source_match_count = source_result.match_count
                    source_collection_valid = source_result.error is None and not source_result.unmatched_patterns
                    source_type_valid = source_selector.kind in {"ports", "pins", "all_inputs", "all_outputs"}
                elif source_word is not None:
                    source_elements, literal_sources, unknown_sources, source_error = _literal_singleton(
                        source_word,
                        set(design.ports) | set(design.pins) | set(design.nets),
                    )
                    source_targets.update(literal_sources)
                    source_match_count = len(source_elements)
                    source_collection_valid = source_error is None and not unknown_sources
            name = _plain(command.option("-name"))
            if not name:
                name = (
                    sorted(targets)[0]
                    if targets
                    else f"<unnamed@{Path(command.location.path).name}:{command.location.line}>"
                )
            if not is_generated:
                problems = list(literal_target_problems)
                if len(command.positionals) > 1:
                    problems.append(
                        f"create_clock accepts at most one positional target collection; got {len(command.positionals)}"
                    )
                if command.option("-name") is None and not targets:
                    problems.append("-name or a nonempty port/pin target is required")
                if command.has("-add") and command.option("-name") is None:
                    problems.append("-add requires -name")
                if target_argument_present and not targets:
                    problems.append("the supplied clock target collection is empty")
                if invalid_target_kinds:
                    problems.append(
                        "primary clock targets must be ports or pins, not " + ", ".join(invalid_target_kinds)
                    )
                if problems:
                    definition_invalid = True
                    _finding(
                        state,
                        "OC2006",
                        Severity.ERROR,
                        "Primary clock definition is invalid",
                        command.location,
                        "A malformed clock identity or target can create an unintended virtual clock or additive definition.",
                        "Provide a stable -name, use -add only with that name, and resolve every supplied target.",
                        {"clock": name, "problems": problems},
                    )
            period = _number(command.option("-period"))
            waveform = _validated_waveform(state, command, period) if not is_generated else None
            if not is_generated and command.option("-waveform") is not None and waveform is None:
                definition_invalid = True
            master_word = command.option("-master_clock")
            master = _plain(master_word)
            divide: int | None = None
            multiply: int | None = None
            duty_cycle: float | None = None
            edges: tuple[int, ...] | None = None
            edge_shift: tuple[float, ...] | None = None
            transform_valid = True
            if is_generated:
                divide, multiply, duty_cycle, edges, edge_shift, transform_valid = _generated_clock_parameters(
                    state, command
                )
                if not transform_valid:
                    definition_invalid = True
                generated_problems: list[str] = []
                generated_problems.extend(literal_target_problems)
                if len(command.positionals) != 1:
                    generated_problems.append(
                        "create_generated_clock requires exactly one positional target collection; "
                        f"got {len(command.positionals)}"
                    )
                elif not targets:
                    generated_problems.append("one nonempty generated-clock target collection is required")
                if invalid_target_kinds:
                    generated_problems.append(
                        "generated clock targets must be ports, pins, or nets, not " + ", ".join(invalid_target_kinds)
                    )
                generated_problems.extend(target_net_problems)
                if source_match_count != 1 or not source_collection_valid or len(source_targets) != 1:
                    generated_problems.append("-source must resolve to exactly one port or pin")
                elif not source_type_valid or not source_targets.issubset(set(design.ports) | set(design.pins)):
                    generated_problems.append("-source must resolve to a port or pin, not a net or other object")
                if generated_problems:
                    transform_valid = False
                    definition_invalid = True
                    _finding(
                        state,
                        "OC2012",
                        Severity.ERROR,
                        "Generated clock source or target cardinality is invalid",
                        command.location,
                        "A generated clock needs one unambiguous source port/pin and a nonempty target collection.",
                        "Narrow -source to one port or pin and resolve the generated-clock target collection.",
                        {"clock": name, "source_targets": sorted(source_targets), "problems": generated_problems},
                    )
                master_selector = _option_selector(command, "-master_clock", master_word)
                master_names: set[str] = set()
                master_match_count = 0
                master_collection_valid = True
                master_selector_type_valid = True
                if master_selector is not None:
                    master_result = resolve_selector(master_selector, design, state.clocks)
                    state.queries.append(master_result)
                    master_selector_type_valid = master_selector.kind in {"clocks", "all_clocks"}
                    master_names.update(name for name in master_result.matches if name in state.clocks)
                    master_match_count = master_result.match_count
                    master_collection_valid = master_result.error is None and not master_result.unmatched_patterns
                elif master_word is not None:
                    master_elements, literal_masters, unknown_masters, master_error = _literal_singleton(
                        master_word, set(state.clocks)
                    )
                    master_names.update(literal_masters)
                    master_match_count = len(master_elements)
                    master_collection_valid = master_error is None and not unknown_masters
                explicit_master_valid = master_word is None
                if master_word is not None:
                    if (
                        master_selector_type_valid
                        and master_collection_valid
                        and master_match_count == 1
                        and len(master_names) == 1
                        and next(iter(master_names)) not in state.invalid_clocks
                    ):
                        master = next(iter(master_names))
                        explicit_master_valid = True
                    else:
                        transform_valid = False
                        definition_invalid = True
                        _finding(
                            state,
                            "OC2012",
                            Severity.ERROR,
                            "Generated clock has an invalid -master_clock collection",
                            command.location,
                            "One generated clock transform must have one unambiguous master clock.",
                            "Resolve -master_clock to exactly one valid clock defined earlier in this mode.",
                            {
                                "clock": name,
                                "master_selector_kind": master_selector.kind if master_selector else None,
                                "masters": sorted(master_names),
                            },
                        )
                        master = None
                source_candidates = [
                    clock
                    for clock in state.clocks.values()
                    if clock.name != name and clock.name not in state.invalid_clocks
                    if source_targets
                    & (
                        clock.targets
                        | _target_nets(design, clock.targets)
                        | _propagate_clock(design, clock.targets)[0]
                        | _propagate_clock(design, clock.targets)[1]
                    )
                ]
                if master_word is not None and not explicit_master_valid:
                    source_candidates = []
                elif master is not None:
                    source_candidates = [clock for clock in source_candidates if clock.name == master]
                elif len(source_candidates) > 1:
                    transform_valid = False
                    definition_invalid = True
                    _finding(
                        state,
                        "OC2012",
                        Severity.ERROR,
                        "Generated clock has multiple inferred master clocks",
                        command.location,
                        "A source reached by multiple clocks makes the generated phase/frequency relationship ambiguous.",
                        "Specify one -master_clock or split the analysis into exclusive modes.",
                        {"clock": name, "masters": sorted(clock.name for clock in source_candidates)},
                    )
                source_clock = source_candidates[0] if len(source_candidates) == 1 else None
                if source_clock and transform_valid:
                    timing = _derive_generated_clock_timing(
                        source_clock,
                        divide,
                        multiply,
                        duty_cycle,
                        edges,
                        edge_shift,
                        command.has("-invert"),
                    )
                    if timing is not None:
                        period, waveform, generated_edges = timing
                        if generated_edges is not None and any(
                            right <= left for left, right in zip(generated_edges, generated_edges[1:], strict=False)
                        ):
                            transform_valid = False
                            definition_invalid = True
                            period = None
                            waveform = None
                            _finding(
                                state,
                                "OC2012",
                                Severity.ERROR,
                                "Generated-clock edge shifts produce non-increasing edges",
                                command.location,
                                "Shifted generated edges must preserve a positive pulse width and period.",
                                "Correct -edge_shift so all three generated edges remain strictly increasing.",
                                {"clock": name, "generated_edges": list(generated_edges)},
                            )
                    master = master or source_clock.name
            clock = Clock(
                name=name,
                targets=targets,
                period=period,
                waveform=waveform,
                waveform_explicit=command.option("-waveform") is not None,
                location=command.location,
                generated=is_generated,
                source_targets=source_targets,
                master_clock=master,
                divide_by=divide,
                multiply_by=multiply,
                duty_cycle=duty_cycle,
                invert=command.has("-invert"),
                combinational=command.has("-combinational"),
                edges=edges,
                edge_shift=edge_shift,
            )
            previous = state.clocks.get(name)
            if previous:
                same_definition = _clock_signature(previous, include_targets=False) == _clock_signature(
                    clock, include_targets=False
                )
                if command.has("-add") and same_definition:
                    if definition_invalid:
                        state.invalid_clocks.add(name)
                    else:
                        previous.targets.update(clock.targets)
                    continue
                state.duplicate_clocks.append((previous, clock))
            state.clocks[name] = clock
            if definition_invalid:
                state.invalid_clocks.add(name)
            else:
                state.invalid_clocks.discard(name)


def _clock_signature(clock: Clock, *, include_targets: bool = True) -> tuple[object, ...]:
    """Return every timing-relevant field used to classify a redefinition."""

    signature: tuple[object, ...] = (
        clock.period,
        clock.waveform,
        clock.waveform_explicit,
        clock.generated,
        frozenset(clock.source_targets),
        clock.master_clock,
        clock.divide_by,
        clock.multiply_by,
        clock.duty_cycle,
        clock.invert,
        clock.combinational,
        clock.edges,
        clock.edge_shift,
    )
    return (frozenset(clock.targets), *signature) if include_targets else signature


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
            for output_path in design.combinational_arcs.get(pin_path, set()):
                output = design.pins[output_path]
                reached_pins.add(output_path)
                if output.net is None or output.net in reached_nets:
                    continue
                reached_nets.add(output.net)
                queue.append(output.net)
    return reached_nets, reached_pins


def _audit_queries(state: _ModeState, design: Design, options: AuditOptions) -> None:
    seen: set[tuple[str, int, str]] = set()
    nested_queries: list[ResolvedQuery] = []
    for query in tuple(state.queries):
        pending = list(query.selector.nested_selectors)
        while pending:
            nested = pending.pop()
            nested_queries.append(resolve_selector(nested, design, state.clocks))
            pending.extend(nested.nested_selectors)
    state.queries.extend(nested_queries)
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
                Severity.ERROR,
                f"Object query cannot be resolved statically: {selector.raw}",
                selector.location,
                "An unresolved dynamic or unsupported query prevents deterministic coverage analysis.",
                "Replace it with a static query, or validate this file with the optional trusted OpenSTA backend.",
                {"query": selector.raw, "reason": query.error},
            )
            continue
        if not query.matches or query.unmatched_patterns:
            evidence = {
                "query": selector.raw,
                "object_kind": selector.kind,
                "universe_size": query.universe_size,
                "matched_count": len(query.matches),
                "unmatched_patterns": list(query.unmatched_patterns),
            }
            partial = bool(query.matches and query.unmatched_patterns)
            _finding(
                state,
                "OC1001",
                Severity.ERROR,
                (
                    f"Object query has {len(query.unmatched_patterns)} unmatched {selector.kind} pattern(s): "
                    f"{selector.raw}"
                    if partial
                    else f"Object query matches zero {selector.kind}: {selector.raw}"
                ),
                selector.location,
                (
                    "A failed pattern in a multi-pattern collection can be masked by other matches and leave "
                    "part of the intended constraint ineffective."
                    if partial
                    else "A constraint on an empty collection is silently ineffective in common SDC flows."
                ),
                "Correct every unmatched pattern or hierarchy and confirm each intended object exists in this mode.",
                evidence,
            )
            if not query.matches:
                continue
        broad = (
            has_glob(selector)
            and query.universe_size >= options.broad_match_min_universe
            and (
                len(query.matches) >= options.broad_match_count
                or len(query.matches) / max(1, query.universe_size) >= options.broad_match_ratio
            )
            and not selector.command_name.startswith("all_")
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
        period_valid = clock.period is not None and clock.period > 0
        valid = period_valid and clock.name not in state.invalid_clocks
        if not period_valid:
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
        elif (
            clock.waveform is None
            and not clock.waveform_explicit
            and options.report_implicit_waveform
            and not clock.generated
        ):
            assert clock.period is not None
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
                valid = False
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
                valid = False
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
        if valid:
            state.valid_clocks.add(clock.name)
            for pin_path in design.sequential_clock_pins & reached_pins:
                pin_to_clocks.setdefault(pin_path, set()).add(clock.name)
    for first, second in state.duplicate_clocks:
        severity = Severity.WARNING if _clock_signature(first) == _clock_signature(second) else Severity.ERROR
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
    active_clocks = _active_clocks(state)
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
            if command.parse_errors:
                _finding(
                    state,
                    "OC0001",
                    Severity.ERROR,
                    f"Malformed {command.name or '<dynamic>'} command grammar",
                    command.location,
                    "An invalid option or missing option operand can change which SDC arguments become constraints or targets.",
                    "Use the pinned OpenSTA command spelling and option arity before trusting downstream results.",
                    {"command": command.name or "<dynamic>", "problems": command.parse_errors},
                )
            unsupported_command = command.name not in MODELED_SDC_COMMANDS
            command_last_lexed_line = command.location.line + command.raw.count("\n") + 1
            has_related_syntax_error = any(
                command.location.line <= issue.location.line <= command_last_lexed_line for issue in document.issues
            )
            opaque_without_syntax_error = bool(command.opaque_substitutions) and (not has_related_syntax_error)
            if command.dynamic_name or unsupported_command or opaque_without_syntax_error:
                effective_name = "<dynamic>" if command.dynamic_name else command.name
                evidence: dict[str, object] = {"command": effective_name}
                if opaque_without_syntax_error:
                    evidence.update(
                        {
                            "opaque_argument_count": len(command.opaque_substitutions),
                            "opaque_arguments": [word[:160] for word in command.opaque_substitutions[:8]],
                        }
                    )
                _finding(
                    state,
                    "OC0003",
                    Severity.ERROR,
                    f"Tcl command {effective_name!r} is outside the static command subset",
                    command.location,
                    "Unsupported commands or opaque Tcl substitutions can hide constraints and make static coverage incomplete.",
                    "Flatten trusted constraints to the documented static SDC subset, or validate the original file with the optional sandboxed OpenSTA path.",
                    evidence,
                )
            if command.name in {"create_clock", "create_generated_clock"}:
                continue
            resolutions = [resolve_selector(selector, design, active_clocks) for selector in command.selectors]
            state.queries.extend(resolutions)
            if command.parse_errors or command.opaque_substitutions or unsupported_command:
                if (
                    command.opaque_substitutions
                    and not command.parse_errors
                    and command.name in {"set_input_delay", "set_output_delay"}
                ):
                    # Preserve the established rule-specific explanation for
                    # dynamic I/O operands, then roll back the modeled record:
                    # OC0003 makes the command non-authoritative.
                    io_delay_count = len(state.io_delays)
                    delayed_inputs = set(state.delayed_inputs)
                    delayed_outputs = set(state.delayed_outputs)
                    _collect_io_delay(
                        state,
                        command,
                        design,
                        "input" if command.name == "set_input_delay" else "output",
                    )
                    del state.io_delays[io_delay_count:]
                    state.delayed_inputs = delayed_inputs
                    state.delayed_outputs = delayed_outputs
                continue
            if command.name == "current_design":
                selected_top = command.positionals[0]
                if selected_top != design.top:
                    _finding(
                        state,
                        "OC0001",
                        Severity.ERROR,
                        f"current_design selects {selected_top!r}, but the elaborated top is {design.top!r}",
                        command.location,
                        "The static backend has one elaborated design context and cannot safely apply constraints in another context.",
                        "Select the elaborated top, split hierarchical contexts into separate audits, or validate the original flow with OpenSTA.",
                        {"selected_design": selected_top, "elaborated_top": design.top},
                    )
                continue
            if command.name == "set_input_delay":
                _collect_io_delay(state, command, design, "input")
            elif command.name == "set_output_delay":
                _collect_io_delay(state, command, design, "output")
            elif command.name in {"set_false_path", "set_multicycle_path", "set_max_delay", "set_min_delay"}:
                exception = _exception_from_command(command, design, active_clocks)
                definition_problems = exception.qualifiers.get("definition_problems", [])
                if isinstance(definition_problems, list) and definition_problems:
                    _finding(
                        state,
                        "OC4002",
                        Severity.ERROR,
                        f"{command.name} definition is invalid",
                        command.location,
                        "An invalid exception scope or value can be ignored by timing engines or broadened unexpectedly.",
                        "Provide one resolvable from/through/to scope and all required finite values.",
                        {"command": command.name, "problems": definition_problems},
                    )
                if command.name == "set_multicycle_path":
                    _collect_multicycle(state, command, exception)
                if command.has("-reset_path") and exception.qualifiers.get("definition_valid") is True:
                    _reset_prior_exceptions(state, exception)
                state.exceptions.append(exception)
            elif command.name == "set_clock_groups":
                state.exceptions.extend(_clock_group_exceptions(state, command, design))


def _literal_collection(
    value: str | None, candidates: set[str]
) -> tuple[tuple[str, ...], set[str], tuple[str, ...], str | None]:
    """Parse a recursively nested literal object collection.

    The SDC parser has already decoded the outer Tcl command word.  The
    OpenSTA object-list helpers recursively expand elements that are themselves
    multi-element lists.  Preserve every resulting leaf so unresolved members
    cannot disappear merely because some siblings resolve.

    Pinned OpenSTA c821ad1 ``tcl/CmdArgs.tcl::get_object_args`` (lines 79-168)
    and ``get_clocks_warn`` (lines 934-956) warn and retain known siblings for
    several commands.  OpenConstraint intentionally applies a stricter audit
    policy: callers keep the resolved members only as evidence and mark the
    entire modeled definition invalid when ``unknown`` is nonempty.
    """

    if value is None:
        return (), set(), (), None

    leaves: list[str] = []

    def flatten(objects: str, depth: int) -> None:
        if depth > _MAX_LITERAL_COLLECTION_RECURSION:
            raise TclSyntaxError(
                f"literal object collection exceeds recursion limit {_MAX_LITERAL_COLLECTION_RECURSION}"
            )
        for element in split_tcl_list(objects):
            nested = split_tcl_list(element)
            if len(nested) > 1:
                flatten(element, depth + 1)
            elif element:
                leaves.append(element)

    try:
        flatten(value, 1)
    except TclSyntaxError as error:
        return (), set(), (), str(error)
    elements = tuple(leaves)
    matches = {item for item in leaves if item in candidates}
    unknown = tuple(item for item in leaves if item not in candidates)
    return elements, matches, unknown, None


def _literal_singleton(
    value: str | None, candidates: set[str]
) -> tuple[tuple[str, ...], set[str], tuple[str, ...], str | None]:
    """Validate a singular Tcl object argument without candidate-biased count.

    OpenSTA's singular helpers use ``llength`` only for cardinality, then look
    up the original argument value.  In particular, an extra nested brace or
    quote layer is part of the object name rather than another expansion step.
    """

    if value is None:
        return (), set(), (), None
    try:
        elements = split_tcl_list(value)
    except TclSyntaxError as error:
        return (), set(), (), str(error)
    matches = {value} if len(elements) == 1 and value in candidates else set()
    unknown = (value,) if len(elements) == 1 and value not in candidates else ()
    return elements, matches, unknown, None


def _option_selector(command: ParsedCommand, option: str, value: str | None) -> Selector | None:
    """Return the selector belonging to the effective (last) option value."""

    if value is None:
        return None
    return next(
        (selector for selector in reversed(command.selectors) if selector.option == option and selector.raw == value),
        None,
    )


def _clock_references(command: ParsedCommand, design: Design, clocks: dict[str, Clock]) -> tuple[set[str], bool]:
    clock_word = command.option("-clock")
    if clock_word is None:
        return set(), True
    selector = _option_selector(command, "-clock", clock_word)
    if selector is not None:
        resolution = resolve_selector(selector, design, clocks)
        names = {name for name in resolution.matches if name in clocks}
        valid = (
            selector.kind in {"clocks", "all_clocks"}
            and resolution.error is None
            and not resolution.unmatched_patterns
            and resolution.match_count == 1
            and len(names) == 1
            and not selector.dynamic
        )
        return names, valid

    elements, names, unknown, error = _literal_singleton(clock_word, set(clocks))
    dynamic = "$" in clock_word or clock_word.lstrip().startswith("[")
    valid = error is None and not unknown and len(elements) == 1 and len(names) == 1 and not dynamic
    return names, valid


def _reference_pin(
    command: ParsedCommand, design: Design, clocks: dict[str, Clock]
) -> tuple[str | None, bool, set[str]]:
    """Resolve ``-reference_pin`` with OpenSTA's singular port/pin contract."""

    raw = command.option("-reference_pin")
    if raw is None:
        return None, True, set()
    candidates = set(design.ports) | set(design.pins)
    selector = _option_selector(command, "-reference_pin", raw)
    if selector is not None:
        resolution = resolve_selector(selector, design, clocks)
        matches = resolution.matches & candidates
        valid = (
            selector.kind in {"ports", "pins", "all_inputs", "all_outputs"}
            and resolution.error is None
            and not resolution.unmatched_patterns
            and resolution.match_count == 1
            and len(matches) == 1
            and not selector.dynamic
        )
    else:
        elements, matches, unknown, error = _literal_singleton(raw, candidates)
        dynamic = "$" in raw or raw.lstrip().startswith("[")
        valid = error is None and not unknown and len(elements) == 1 and len(matches) == 1 and not dynamic
    reference_pin = next(iter(matches)) if valid else None
    return reference_pin, valid, matches


def _collect_io_delay(state: _ModeState, command: ParsedCommand, design: Design, kind: str) -> None:
    active_clocks = _active_clocks(state)
    delay_word = command.positionals[0] if command.positionals else None
    delay = _number(delay_word)
    target_words = command.positionals[1:]
    target_selectors = [
        selector
        for selector in command.selectors
        if selector.option is None
        and selector.raw in target_words
        and selector.kind in {"ports", "all_inputs", "all_outputs"}
    ]
    ports, _ = _resolve_many(target_selectors, design, active_clocks)
    target_collection_valid = True
    target_collection_unknown: list[str] = []
    target_collection_errors: list[str] = []
    for word in target_words:
        if any(selector.option is None and selector.raw == word for selector in command.selectors):
            continue
        elements, literal_ports, unknown, error = _literal_collection(word, set(design.ports))
        ports.update(literal_ports)
        if error is not None:
            target_collection_valid = False
            target_collection_errors.append(error)
        if not elements:
            target_collection_valid = False
            target_collection_errors.append("target collection is empty")
        if unknown:
            target_collection_valid = False
            target_collection_unknown.extend(unknown)
    ports.intersection_update(design.ports)

    shape_valid = len(command.positionals) == 2
    dynamic_delay = bool(delay_word and ("$" in delay_word or delay_word.lstrip().startswith("[")))
    if not shape_valid or delay is None:
        severity = Severity.WARNING if dynamic_delay and shape_valid else Severity.ERROR
        if not shape_valid:
            reason = "invalid positional-operand count"
            remediation = "Provide exactly one finite delay and one port collection."
        elif dynamic_delay:
            reason = "dynamic delay expression"
            remediation = (
                "Use a finite numeric delay in the static file, or validate the dynamic expression with OpenSTA."
            )
        else:
            reason = "missing or non-finite numeric delay"
            remediation = "Use a finite numeric delay in the static file."
        evidence: dict[str, object] = {
            "command": command.name,
            "delay": delay_word,
            "positionals": command.positionals,
        }
        if not shape_valid:
            evidence.update(
                {
                    "expected_positional_count": 2,
                    "actual_positional_count": len(command.positionals),
                }
            )
        _finding(
            state,
            "OC3010",
            severity,
            f"{command.name} has a {reason}",
            command.location,
            "An invalid I/O-delay command cannot establish a reviewable interface timing requirement.",
            remediation,
            evidence,
        )
    if shape_valid and delay is not None and not target_collection_valid:
        _finding(
            state,
            "OC3010",
            Severity.ERROR,
            f"{command.name} has an unresolved or malformed literal target collection",
            command.location,
            "OpenSTA rejects the entire I/O-delay command when any literal target-list member is not a design port.",
            "Use one well-formed Tcl list containing only existing design ports.",
            {
                "command": command.name,
                "target": target_words[0] if target_words else None,
                "unknown_members": target_collection_unknown,
                "list_errors": target_collection_errors,
            },
        )

    clocks, clock_valid = _clock_references(command, design, active_clocks)
    if clocks and not clocks.issubset(state.valid_clocks):
        clock_valid = False
    if command.option("-clock") is None:
        _finding(
            state,
            "OC3011",
            Severity.NOTE,
            f"{command.name} is not referenced to a clock",
            command.location,
            "Clockless I/O delays are legal, but they hide the intended launch or capture relationship during review.",
            "Reference the appropriate real or virtual clock unless the clockless constraint is intentional.",
            {"command": command.name, "ports": sorted(ports)},
        )
    elif not clock_valid:
        _finding(
            state,
            "OC3011",
            Severity.ERROR,
            f"{command.name} has an unresolved or invalid -clock reference",
            command.location,
            "An I/O delay tied to a missing or dynamic clock may be ignored or interpreted differently by downstream tools.",
            "Define the clock first and use a static clock name or get_clocks query that resolves exactly.",
            {"command": command.name, "clock": command.option("-clock"), "ports": sorted(ports)},
        )

    reference_pin, reference_valid, reference_matches = _reference_pin(command, design, active_clocks)
    reference_word = command.option("-reference_pin")
    if reference_word is not None and not reference_valid:
        _finding(
            state,
            "OC3011",
            Severity.ERROR,
            f"{command.name} has an unresolved or non-singleton -reference_pin",
            command.location,
            "OpenSTA requires -reference_pin to resolve to exactly one design port or pin.",
            "Use one static get_ports/get_pins result or one exact port/pin name.",
            {
                "command": command.name,
                "reference_pin": reference_word,
                "matches": sorted(reference_matches),
            },
        )

    source_latency_included = command.has("-source_latency_included")
    network_latency_included = command.has("-network_latency_included")
    ignored_latency_flags = [
        flag
        for flag, present in (
            ("-source_latency_included", source_latency_included),
            ("-network_latency_included", network_latency_included),
        )
        if present
    ]
    if reference_pin is not None and ignored_latency_flags:
        _finding(
            state,
            "OC3011",
            Severity.WARNING,
            f"{command.name} latency-inclusion flag(s) are ignored with -reference_pin",
            command.location,
            "OpenSTA accepts these flags but ignores their latency semantics when -reference_pin is present.",
            "Remove the ignored flags or remove -reference_pin if explicit source/network latency inclusion is intended.",
            {
                "command": command.name,
                "reference_pin": reference_pin,
                "ignored_flags": ignored_latency_flags,
            },
        )

    valid_directions = {"input", "inout"} if kind == "input" else {"output", "inout"}
    wrong_direction = {name for name in ports if design.ports[name].direction not in valid_directions}
    if wrong_direction:
        _finding(
            state,
            "OC3012",
            Severity.ERROR,
            f"{command.name} targets {len(wrong_direction)} port(s) with the wrong direction",
            command.location,
            "Input delays belong on input/inout ports and output delays belong on output/inout ports.",
            "Correct the collection or use the matching input/output delay command.",
            {"command": command.name, "ports": sorted(wrong_direction)},
        )
    valid_ports = ports - wrong_direction
    same_clock_ports = {
        port
        for port in valid_ports
        if clock_valid and any(port in active_clocks[clock_name].targets for clock_name in clocks)
    }
    if same_clock_ports:
        _finding(
            state,
            "OC3011",
            Severity.ERROR,
            f"{command.name} is relative to a clock defined on the same port",
            command.location,
            "OpenSTA rejects an I/O delay whose target port/pin is also a source of its referenced clock.",
            "Remove the clock-source port from the delay target collection or reference the intended external clock.",
            {
                "command": command.name,
                "ports": sorted(same_clock_ports),
                "clocks": sorted(clocks),
            },
        )
        valid_ports.difference_update(same_clock_ports)
    min_max = frozenset(item for item, flag in (("min", "-min"), ("max", "-max")) if command.has(flag)) or frozenset(
        {"min", "max"}
    )
    transitions = frozenset(
        item for item, flag in (("rise", "-rise"), ("fall", "-fall")) if command.has(flag)
    ) or frozenset({"rise", "fall"})
    item = IODelay(
        kind=kind,
        ports=frozenset(valid_ports),
        value=delay,
        clocks=frozenset(clocks),
        reference_pin=reference_pin,
        source_latency_included=source_latency_included,
        network_latency_included=network_latency_included,
        min_max=min_max,
        transitions=transitions,
        clock_edge="fall" if command.has("-clock_fall") else "rise",
        additive=command.has("-add_delay"),
        valid=(
            shape_valid
            and delay is not None
            and target_collection_valid
            and clock_valid
            and reference_valid
            and bool(valid_ports)
        ),
        location=command.location,
        raw=command.raw,
    )
    state.io_delays.append(item)
    if shape_valid and delay is not None and target_collection_valid and clock_valid and reference_valid:
        if kind == "input":
            state.delayed_inputs.update(valid_ports)
        else:
            state.delayed_outputs.update(valid_ports)


def _audit_io_delays(state: _ModeState) -> None:
    active: dict[_IODelayAuditRelationshipKey, dict[_IODelayAuditSlotKey, tuple[float, IODelay]]] = {}

    def source_order(source: IODelay) -> tuple[str, int, int, str]:
        return (source.location.path, source.location.line, source.location.column, source.raw)

    for item in state.io_delays:
        if not item.valid or item.value is None:
            continue
        clocks = tuple(sorted(item.clocks))
        clock_edge = item.clock_edge if clocks else "rise"
        selected_slots = {(transition, min_max) for transition in item.transitions for min_max in item.min_max}
        for port in sorted(item.ports):
            key: _IODelayAuditRelationshipKey = (item.kind, port, clocks, clock_edge)
            relationship = active.setdefault(key, {})
            overwritten: dict[
                _IODelayAuditRelationshipKey,
                dict[_IODelayAuditSlotKey, tuple[float, IODelay]],
            ] = {}
            if not item.additive:
                for candidate_key in list(active):
                    if candidate_key[:2] != key[:2]:
                        continue
                    candidate = active[candidate_key]
                    removed_slots = set(candidate) if candidate_key != key else selected_slots & set(candidate)
                    if removed_slots:
                        overwritten[candidate_key] = {slot: candidate[slot] for slot in removed_slots}
                    if candidate_key != key:
                        del active[candidate_key]

            if overwritten:
                overwritten_relationships: list[dict[str, object]] = []
                sources: list[IODelay] = []
                overwritten_slots: set[_IODelayAuditSlotKey] = set()
                for prior_key, prior_slots in sorted(overwritten.items()):
                    prior_sources = sorted(
                        {source_order(source): source for _value, source in prior_slots.values()}.values(),
                        key=source_order,
                    )
                    sources.extend(prior_sources)
                    overwritten_slots.update(prior_slots)
                    overwritten_relationships.append(
                        {
                            "clock": list(prior_key[2]),
                            "clock_edge": prior_key[3],
                            "min_max": sorted({slot[1] for slot in prior_slots}),
                            "transitions": sorted({slot[0] for slot in prior_slots}),
                            "locations": [source.location.to_dict() for source in prior_sources],
                            "reason": "slot_replaced" if prior_key == key else "relationship_removed",
                            "slots": [
                                {
                                    "transition": slot[0],
                                    "min_max": slot[1],
                                    "value": prior_slots[slot][0],
                                    "location": prior_slots[slot][1].location.to_dict(),
                                }
                                for slot in sorted(prior_slots)
                            ],
                        }
                    )
                first = min(sources, key=source_order)
                _finding(
                    state,
                    "OC3014",
                    Severity.WARNING,
                    f"{item.kind} delay for port {port!r} overwrites an earlier constraint",
                    item.location,
                    "A non-additive I/O delay replaces selected slots in its relationship and removes competing "
                    "clock/edge relationships for the same port.",
                    "Remove the duplicate, narrow its scope, or use -add_delay when multiple relationships are intentional.",
                    {
                        "port": port,
                        "clock": list(clocks),
                        "clock_edge": clock_edge,
                        "min_max": sorted({slot[1] for slot in overwritten_slots}),
                        "transitions": sorted({slot[0] for slot in overwritten_slots}),
                        "previous_location": first.location.to_dict(),
                        "overwritten_relationships": overwritten_relationships,
                    },
                )

            relationship = active[key]
            for slot in sorted(selected_slots):
                current = relationship.get(slot)
                min_max = slot[1]
                if (
                    not item.additive
                    or current is None
                    or (min_max == "min" and item.value < current[0])
                    or (min_max == "max" and item.value > current[0])
                ):
                    relationship[slot] = (item.value, item)

    coverage: dict[_IODelayAuditRelationshipKey, dict[str, set[str]]] = {}
    for key, slots in active.items():
        transition_coverage = coverage.setdefault(key, {})
        for transition, min_max in slots:
            transition_coverage.setdefault(transition, set()).add(min_max)
    for key, by_transition in sorted(coverage.items()):
        missing_by_transition = {
            transition: sorted({"min", "max"} - covered)
            for transition, covered in sorted(by_transition.items())
            if {"min", "max"} - covered
        }
        if not missing_by_transition:
            continue
        kind, port, clocks, clock_edge = key
        present = set.intersection(*(set(values) for values in by_transition.values()))
        missing = set().union(*(set(values) for values in missing_by_transition.values()))
        item = min((source for _value, source in active[key].values()), key=source_order)
        _finding(
            state,
            "OC3013",
            Severity.WARNING,
            f"{kind} delay for port {port!r} is missing an explicit {sorted(missing)[0]} constraint",
            item.location,
            "Constraining only one analysis sense can leave setup or hold interface timing under-specified.",
            "Provide both -min and -max delays, or omit both flags when the same value intentionally applies to both.",
            {
                "port": port,
                "clock": list(clocks),
                "present": sorted(present),
                "missing": sorted(missing),
                "missing_by_transition": missing_by_transition,
            },
        )


def _collect_multicycle(state: _ModeState, command: ParsedCommand, exception: ExceptionPath) -> None:
    multiplier_word = command.positionals[0] if command.positionals else None
    multiplier = _integer(multiplier_word)
    if command.has("-setup") and not command.has("-hold"):
        applies_to = frozenset({"setup"})
    elif command.has("-hold") and not command.has("-setup"):
        applies_to = frozenset({"hold"})
    else:
        applies_to = frozenset({"setup", "hold"})
    start_end = "start" if command.has("-start") else "end" if command.has("-end") else "default"
    invalid_reason: str | None = None
    if len(command.positionals) != 1:
        invalid_reason = f"exactly one positional path multiplier is required; got {len(command.positionals)}"
    elif multiplier is None:
        invalid_reason = "missing or non-integer path multiplier"
    elif "setup" in applies_to and multiplier < 1:
        invalid_reason = "setup multiplier must be at least 1"
    elif "hold" in applies_to and multiplier < 0:
        invalid_reason = "hold multiplier must be non-negative"
    elif command.has("-start") and command.has("-end"):
        invalid_reason = "-start and -end are mutually exclusive"
    if invalid_reason:
        _finding(
            state,
            "OC4010",
            Severity.ERROR,
            f"Invalid multicycle-path definition: {invalid_reason}",
            command.location,
            "Invalid multiplier or edge-reference semantics can shift setup/hold checks unpredictably.",
            "Use an integer multiplier and one consistent -start/-end relationship.",
            {
                "multiplier": multiplier_word,
                "positionals": command.positionals,
                "applies_to": sorted(applies_to),
                "start_end": start_end,
            },
        )
    exception.qualifiers.update(
        {
            "multiplier": None if invalid_reason is not None else multiplier,
            "applies_to": sorted(applies_to),
            "start_end": start_end,
            "reset_path": command.has("-reset_path"),
        }
    )
    if invalid_reason is not None:
        problems = exception.qualifiers.get("definition_problems")
        if isinstance(problems, list) and invalid_reason not in problems:
            problems.append(invalid_reason)
        exception.qualifiers["definition_valid"] = False
        exception.qualifiers["scope_resolvable"] = False
        return
    item = _Multicycle(
        multiplier=multiplier,
        applies_to=applies_to,
        from_objects=frozenset(exception.from_objects),
        to_objects=frozenset(exception.to_objects),
        through_objects=exception.through_objects,
        from_transition=str(exception.qualifiers["from_transition"]),
        to_transition=str(exception.qualifiers["to_transition"]),
        end_transition=str(exception.qualifiers["end_transition"]),
        through_transitions=tuple(str(value) for value in exception.qualifiers["through_transitions"]),
        start_end=start_end,
        scope_resolvable=exception.qualifiers["scope_resolvable"] is True,
        location=command.location,
        raw=command.raw,
    )
    state.multicycles.append(item)


def _objects_from_word(
    command: ParsedCommand,
    value: str,
    design: Design,
    clocks: dict[str, Clock],
    *,
    allowed_selector_kinds: frozenset[str],
) -> tuple[set[str], set[str], list[str]]:
    selectors = [selector for selector in command.selectors if selector.raw == value]
    valid_selectors = [selector for selector in selectors if selector.kind in allowed_selector_kinds]
    invalid_kinds = {selector.kind for selector in selectors if selector.kind not in allowed_selector_kinds}
    values_resolved, _ = _resolve_many(valid_selectors, design, clocks)
    candidates: set[str] = set()
    if allowed_selector_kinds & {"ports", "all_inputs", "all_outputs"}:
        candidates.update(design.ports)
    if "pins" in allowed_selector_kinds:
        candidates.update(design.pins)
    if "cells" in allowed_selector_kinds:
        candidates.update(design.instances)
    if allowed_selector_kinds & {"clocks", "all_clocks"}:
        candidates.update(clocks)
    if "nets" in allowed_selector_kinds:
        candidates.update(design.nets)
    literal_problems: list[str] = []
    if not selectors:
        _, literal_matches, unknown, error = _literal_collection(value, candidates)
        values_resolved.update(literal_matches)
        if error is not None:
            literal_problems.append(f"literal collection is not a well-formed Tcl object list: {error}")
        if unknown:
            sample = ", ".join(repr(item) for item in unknown[:8])
            suffix = f" (and {len(unknown) - 8} more)" if len(unknown) > 8 else ""
            literal_problems.append(f"literal collection contains unresolved object(s): {sample}{suffix}")
    return values_resolved, invalid_kinds, literal_problems


def _selected_exception_option(command: ParsedCommand, options: tuple[str, ...]) -> tuple[str, str] | None:
    """Return OpenSTA's selected mutually exclusive from/to key and its last value."""

    for option in options:
        values = command.options.get(option, [])
        if values:
            return option, values[-1]
    return None


def _option_transition(option: str | None, rise_option: str, fall_option: str) -> str:
    if option == rise_option:
        return "rise"
    if option == fall_option:
        return "fall"
    return "rise_fall"


def _end_transition(command: ParsedCommand) -> str:
    rise = command.has("-rise")
    fall = command.has("-fall")
    if rise and not fall:
        return "rise"
    if fall and not rise:
        return "fall"
    return "rise_fall"


def _exception_from_command(command: ParsedCommand, design: Design, clocks: dict[str, Clock]) -> ExceptionPath:
    from_options = ("-from", "-rise_from", "-fall_from")
    to_options = ("-to", "-rise_to", "-fall_to")
    from_entry = _selected_exception_option(command, from_options)
    to_entry = _selected_exception_option(command, to_options)
    endpoint_kinds = frozenset(
        {"clocks", "all_clocks", "cells", "registers", "ports", "pins", "all_inputs", "all_outputs"}
    )
    through_kinds = frozenset({"cells", "registers", "ports", "pins", "nets", "all_inputs", "all_outputs"})
    from_objects, invalid_from_kinds, from_literal_problems = (
        _objects_from_word(
            command,
            from_entry[1],
            design,
            clocks,
            allowed_selector_kinds=endpoint_kinds,
        )
        if from_entry is not None
        else (set(), set(), [])
    )
    to_objects, invalid_to_kinds, to_literal_problems = (
        _objects_from_word(
            command,
            to_entry[1],
            design,
            clocks,
            allowed_selector_kinds=endpoint_kinds,
        )
        if to_entry is not None
        else (set(), set(), [])
    )
    through_options = {"-through", "-rise_through", "-fall_through"}
    through_entries = [(option, value) for option, value in command.option_occurrences if option in through_options]
    resolved_through = [
        _objects_from_word(
            command,
            value,
            design,
            clocks,
            allowed_selector_kinds=through_kinds,
        )
        for _, value in through_entries
    ]
    through_groups = tuple(frozenset(objects) for objects, _, _ in resolved_through)
    invalid_through_kinds = set().union(*(kinds for _, kinds, _ in resolved_through)) if resolved_through else set()
    through_literal_problems = [problems for _, _, problems in resolved_through]
    from_transition = _option_transition(from_entry[0] if from_entry else None, "-rise_from", "-fall_from")
    to_transition = _option_transition(to_entry[0] if to_entry else None, "-rise_to", "-fall_to")
    from_specified = from_entry is not None
    to_specified = to_entry is not None
    definition_problems: list[str] = []
    present_from_options = [option for option in from_options if command.has(option)]
    present_to_options = [option for option in to_options if command.has(option)]
    if len(present_from_options) > 1:
        definition_problems.append("-from, -rise_from, and -fall_from are mutually exclusive")
    if len(present_to_options) > 1:
        definition_problems.append("-to, -rise_to, and -fall_to are mutually exclusive")
    if invalid_from_kinds:
        definition_problems.append(
            "from-scope selectors must return clocks, cells, ports, or pins, not "
            + ", ".join(sorted(invalid_from_kinds))
        )
    if invalid_to_kinds:
        definition_problems.append(
            "to-scope selectors must return clocks, cells, ports, or pins, not " + ", ".join(sorted(invalid_to_kinds))
        )
    if invalid_through_kinds:
        definition_problems.append(
            "through-scope selectors must return cells, ports, pins, or nets, not "
            + ", ".join(sorted(invalid_through_kinds))
        )
    definition_problems.extend(f"from scope {problem}" for problem in from_literal_problems)
    definition_problems.extend(f"to scope {problem}" for problem in to_literal_problems)
    for index, problems in enumerate(through_literal_problems, start=1):
        definition_problems.extend(f"through scope {index} {problem}" for problem in problems)
    from_has_selector = bool(
        from_entry is not None and any(selector.raw == from_entry[1] for selector in command.selectors)
    )
    to_has_selector = bool(to_entry is not None and any(selector.raw == to_entry[1] for selector in command.selectors))
    if from_specified and not from_objects and not from_has_selector:
        definition_problems.append("the specified from scope resolves to no objects")
    if to_specified and not to_objects and not to_has_selector:
        definition_problems.append("the specified to scope resolves to no objects")
    for index, (group, (_, word)) in enumerate(zip(through_groups, through_entries, strict=True), start=1):
        has_selector = any(selector.raw == word for selector in command.selectors)
        if not group and not has_selector:
            definition_problems.append(f"specified through scope {index} resolves to no objects")
    has_implicit_end_scope = command.has("-rise") or command.has("-fall")
    if not from_specified and not to_specified and not through_entries and not has_implicit_end_scope:
        definition_problems.append("at least one -from, -through, or -to scope is required")
    if command.name in {"set_max_delay", "set_min_delay"} and (
        len(command.positionals) != 1 or _number(command.positionals[0]) is None
    ):
        definition_problems.append("exactly one finite delay value is required")
    if command.name == "set_multicycle_path" and len(command.positionals) != 1:
        definition_problems.append(
            f"exactly one positional path multiplier is required; got {len(command.positionals)}"
        )
    definition_valid = not definition_problems
    scope_resolvable = (
        definition_valid
        and (not from_specified or bool(from_objects))
        and (not to_specified or bool(to_objects))
        and all(through_groups)
    )
    qualifiers: dict[str, object] = {
        "from_transition": from_transition,
        "to_transition": to_transition,
        "end_transition": _end_transition(command),
        "through_transitions": [
            "rise" if option == "-rise_through" else "fall" if option == "-fall_through" else "rise_fall"
            for option, _ in through_entries
        ],
        "from_specified": from_specified,
        "to_specified": to_specified,
        "scope_resolvable": scope_resolvable,
        "definition_valid": definition_valid,
        "definition_problems": definition_problems,
        "reset_path": command.has("-reset_path"),
    }
    if command.name in {"set_max_delay", "set_min_delay"}:
        qualifiers["delay"] = _number(command.positionals[0] if command.positionals else None)
        qualifiers["probe"] = command.has("-probe")
        qualifiers["ignore_clock_latency"] = command.has("-ignore_clock_latency")
    if command.name in {"set_false_path", "set_multicycle_path"}:
        if command.has("-setup") and not command.has("-hold"):
            qualifiers["applies_to"] = ["setup"]
        elif command.has("-hold") and not command.has("-setup"):
            qualifiers["applies_to"] = ["hold"]
        else:
            qualifiers["applies_to"] = ["hold", "setup"]
    return ExceptionPath(
        command.name.removeprefix("set_"),
        from_objects,
        to_objects,
        through_groups,
        command.location,
        command.raw,
        qualifiers,
    )


def _reset_prior_exceptions(state: _ModeState, reset: ExceptionPath) -> None:
    """Apply the deterministic exact-scope portion of SDC -reset_path history."""

    reset_signature = (
        frozenset(reset.from_objects),
        frozenset(reset.to_objects),
        reset.through_objects,
        reset.qualifiers.get("from_transition"),
        reset.qualifiers.get("to_transition"),
        reset.qualifiers.get("end_transition"),
        tuple(reset.qualifiers.get("through_transitions", [])),
    )
    retained: list[ExceptionPath] = []
    removed_locations: set[tuple[str, int, int]] = set()
    for previous in state.exceptions:
        previous_signature = (
            frozenset(previous.from_objects),
            frozenset(previous.to_objects),
            previous.through_objects,
            previous.qualifiers.get("from_transition"),
            previous.qualifiers.get("to_transition"),
            previous.qualifiers.get("end_transition"),
            tuple(previous.qualifiers.get("through_transitions", [])),
        )
        if (
            previous.kind != "clock_group"
            and previous_signature == reset_signature
            and bool(_analysis_senses(previous) & _analysis_senses(reset))
        ):
            removed_locations.add((previous.location.path, previous.location.line, previous.location.column))
        else:
            retained.append(previous)
    state.exceptions = retained
    state.multicycles = [
        item
        for item in state.multicycles
        if (item.location.path, item.location.line, item.location.column) not in removed_locations
    ]


def _clock_group_exceptions(state: _ModeState, command: ParsedCommand, design: Design) -> list[ExceptionPath]:
    active_clocks = _active_clocks(state)
    groups: list[set[str]] = []
    group_problems: list[list[str]] = []
    for group_word in command.options.get("-group", []):
        selectors = [
            selector for selector in command.selectors if selector.option == "-group" and selector.raw == group_word
        ]
        allowed_selector_kinds = {"clocks", "all_clocks"}
        valid_selectors = [selector for selector in selectors if selector.kind in allowed_selector_kinds]
        invalid_selector_kinds = sorted(
            {selector.kind for selector in selectors if selector.kind not in allowed_selector_kinds}
        )
        matches, resolutions = _resolve_many(valid_selectors, design, active_clocks)
        problems_for_group: list[str] = []
        if invalid_selector_kinds:
            problems_for_group.append("selectors must return clocks, not " + ", ".join(invalid_selector_kinds))
        for resolution in resolutions:
            if resolution.error is not None:
                problems_for_group.append("selector cannot be resolved statically")
            if resolution.unmatched_patterns:
                problems_for_group.append(
                    f"selector contains {len(resolution.unmatched_patterns)} unmatched clock pattern(s)"
                )
        if not selectors:
            _, literal_matches, unknown, error = _literal_collection(group_word, set(active_clocks))
            matches.update(literal_matches)
            if error is not None:
                problems_for_group.append(f"literal is not a well-formed Tcl clock list: {error}")
            if unknown:
                sample = ", ".join(repr(item) for item in unknown[:8])
                suffix = f" (and {len(unknown) - 8} more)" if len(unknown) > 8 else ""
                problems_for_group.append(f"literal contains unresolved clock(s): {sample}{suffix}")
        groups.append(matches)
        group_problems.append(problems_for_group)
    exceptions: list[ExceptionPath] = []
    relation_options = [
        name for name in ("-asynchronous", "-logically_exclusive", "-physically_exclusive") if command.has(name)
    ]
    problems: list[str] = []
    for index, problems_for_group in enumerate(group_problems, start=1):
        problems.extend(f"group {index} {problem}" for problem in problems_for_group)
    if len(relation_options) != 1:
        problems.append("exactly one clock-group relationship is required")
    if command.has("-exclusive"):
        problems.append("-exclusive is not an OpenSTA set_clock_groups relationship")
    if len(groups) < 2:
        problems.append("at least two -group collections are required")
    empty_groups = [index + 1 for index, group in enumerate(groups) if not group]
    if empty_groups:
        problems.append(f"group collection(s) {empty_groups} resolve to no clocks")
    overlap = set()
    for index, group in enumerate(groups):
        overlap.update(group & set().union(*groups[:index], *groups[index + 1 :]))
    if overlap:
        problems.append("the same clock appears in multiple groups")
    if problems:
        _finding(
            state,
            "OC4002",
            Severity.ERROR,
            "Clock-group definition is invalid",
            command.location,
            "Malformed or overlapping groups can cut the wrong inter-clock paths.",
            "Choose exactly one relationship and provide at least two nonempty, disjoint clock groups.",
            {"problems": problems, "groups": [sorted(group) for group in groups]},
        )
        return exceptions
    relation = relation_options[0].removeprefix("-")
    qualifiers = {"relation": relation, "allow_paths": command.has("-allow_paths")}
    for left_index, left in enumerate(groups):
        for right in groups[left_index + 1 :]:
            exceptions.append(
                ExceptionPath("clock_group", set(left), set(right), (), command.location, command.raw, dict(qualifiers))
            )
            exceptions.append(
                ExceptionPath("clock_group", set(right), set(left), (), command.location, command.raw, dict(qualifiers))
            )
    return exceptions


def _sets_overlap(left: set[str], right: set[str]) -> bool:
    return not left or not right or bool(left & right)


def _transition_values(exception: ExceptionPath, key: str) -> set[str]:
    value = exception.qualifiers.get(key, "rise_fall")
    if not isinstance(value, str) or value == "rise_fall":
        return {"rise", "fall"}
    return {value}


def _transitions_overlap(left: ExceptionPath, right: ExceptionPath, key: str) -> bool:
    return bool(_transition_values(left, key) & _transition_values(right, key))


def _analysis_senses(exception: ExceptionPath) -> set[str]:
    value = exception.qualifiers.get("applies_to")
    if isinstance(value, list):
        senses = {item for item in value if isinstance(item, str) and item in {"setup", "hold"}}
        if senses:
            return senses
    if exception.kind == "max_delay":
        return {"setup"}
    if exception.kind == "min_delay":
        return {"hold"}
    return {"setup", "hold"}


def _through_entries(exception: ExceptionPath) -> list[tuple[frozenset[str], str]]:
    raw_transitions = exception.qualifiers.get("through_transitions", [])
    transitions = raw_transitions if isinstance(raw_transitions, list) else []
    return [
        (
            objects,
            transitions[index]
            if index < len(transitions) and transitions[index] in {"rise", "fall", "rise_fall"}
            else "rise_fall",
        )
        for index, objects in enumerate(exception.through_objects)
    ]


def _through_entry_overlap(left: tuple[frozenset[str], str], right: tuple[frozenset[str], str]) -> bool:
    left_objects, left_transition = left
    right_objects, right_transition = right
    left_edges = {"rise", "fall"} if left_transition == "rise_fall" else {left_transition}
    right_edges = {"rise", "fall"} if right_transition == "rise_fall" else {right_transition}
    return bool(left_objects & right_objects) and bool(left_edges & right_edges)


def _ordered_through_embeds(
    shorter: list[tuple[frozenset[str], str]], longer: list[tuple[frozenset[str], str]]
) -> bool:
    cursor = 0
    for candidate in longer:
        if _through_entry_overlap(shorter[cursor], candidate):
            cursor += 1
            if cursor == len(shorter):
                return True
    return False


def _through_scopes_overlap(left: ExceptionPath, right: ExceptionPath) -> bool:
    left_entries = _through_entries(left)
    right_entries = _through_entries(right)
    if not left_entries or not right_entries:
        return True
    return _ordered_through_embeds(left_entries, right_entries) or _ordered_through_embeds(right_entries, left_entries)


def _exception_scope_resolvable(exception: ExceptionPath) -> bool:
    if exception.kind == "clock_group":
        return (
            bool(exception.from_objects)
            and bool(exception.to_objects)
            and exception.qualifiers.get("relation") != "unspecified"
            and exception.qualifiers.get("allow_paths") is not True
        )
    return exception.qualifiers.get("scope_resolvable", True) is True


def _audit_exceptions(state: _ModeState) -> None:
    for index, left in enumerate(state.exceptions):
        for right in state.exceptions[index + 1 :]:
            if left.location == right.location and left.kind == right.kind == "clock_group":
                continue
            if not _exception_scope_resolvable(left) or not _exception_scope_resolvable(right):
                continue
            if not _sets_overlap(left.from_objects, right.from_objects) or not _sets_overlap(
                left.to_objects, right.to_objects
            ):
                continue
            if not (_analysis_senses(left) & _analysis_senses(right)):
                continue
            if not _transitions_overlap(left, right, "from_transition"):
                continue
            if not _transitions_overlap(left, right, "to_transition"):
                continue
            if not _transitions_overlap(left, right, "end_transition"):
                continue
            if not _through_scopes_overlap(left, right):
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


def _audit_multicycles(state: _ModeState) -> None:
    seen: dict[tuple[object, ...], _Multicycle] = {}
    for item in state.multicycles:
        if item.multiplier is None or not item.scope_resolvable:
            continue
        for phase in sorted(item.applies_to):
            key = (*item.scope, phase)
            previous = seen.get(key)
            if previous is not None and previous.multiplier != item.multiplier:
                _finding(
                    state,
                    "OC4012",
                    Severity.ERROR,
                    f"Conflicting {phase} multicycle multipliers target the same path scope",
                    item.location,
                    "Order-dependent multicycle values on one scope make setup/hold intent ambiguous.",
                    "Keep one multiplier per setup/hold scope and remove or narrow the conflicting definition.",
                    {
                        "phase": phase,
                        "first_multiplier": previous.multiplier,
                        "second_multiplier": item.multiplier,
                        "previous_location": previous.location.to_dict(),
                    },
                )
            seen[key] = item

    for setup in state.multicycles:
        if (
            setup.multiplier is None
            or setup.multiplier <= 1
            or "setup" not in setup.applies_to
            or not setup.scope_resolvable
        ):
            continue
        if setup.applies_to == frozenset({"setup", "hold"}):
            _finding(
                state,
                "OC4011",
                Severity.WARNING,
                f"Multicycle path applies multiplier {setup.multiplier} to both setup and hold",
                setup.location,
                "Applying one multiplier to both checks commonly shifts hold too far and can hide a real short-path failure.",
                "State setup and hold separately; the usual same-clock pairing is setup N with hold N-1.",
                {"setup_multiplier": setup.multiplier, "expected_hold_multiplier": setup.multiplier - 1},
            )
            continue
        expected_hold = setup.multiplier - 1
        paired = any(
            hold.multiplier == expected_hold
            and hold.applies_to == frozenset({"hold"})
            and hold.selector_scope == setup.selector_scope
            and hold.scope_resolvable
            for hold in state.multicycles
        )
        if not paired:
            _finding(
                state,
                "OC4011",
                Severity.WARNING,
                f"Setup multicycle {setup.multiplier} has no matching hold multicycle {expected_hold}",
                setup.location,
                "A setup-only multicycle can leave the default hold relationship inconsistent with the intended data cadence.",
                "Review the clock relationship and add the corresponding hold constraint when the usual N/N-1 pairing applies.",
                {"setup_multiplier": setup.multiplier, "expected_hold_multiplier": expected_hold},
            )


def _required_io(design: Design, state: _ModeState) -> tuple[set[str], set[str]]:
    clock_ports: set[str] = set()
    for clock in _active_clocks(state).values():
        for target in clock.targets:
            if target not in design.ports:
                continue
            _, reached_pins = _propagate_clock(design, {target})
            if reached_pins & design.sequential_clock_pins:
                clock_ports.add(target)
    inputs = {name for name, port in design.ports.items() if port.direction in {"input", "inout"}} - clock_ports
    outputs = {name for name, port in design.ports.items() if port.direction in {"output", "inout"}}
    return inputs, outputs


def _io_delay_slot_counts(state: _ModeState, kind: str, required_ports: set[str]) -> tuple[int, int]:
    """Count covered and required I/O-delay analysis slots.

    Every distinct active clock/reference-pin/clock-edge relationship for a
    required port owns the four min/max by rise/fall slots. OpenSTA overwrite
    and additive history is replayed before those active slots are counted.
    Invalid records establish an attempted relationship but cover no slots. A
    port with no relationship still owns one default four-slot obligation.
    """

    relationship_slots: dict[
        str,
        dict[tuple[frozenset[str], str | None, str], set[tuple[str, str]]],
    ] = {}
    for record in effective_io_delay_semantics(state.io_delays):
        if record["kind"] != kind:
            continue
        relationship = (
            frozenset(str(clock) for clock in record["clocks"]),
            str(record["reference_pin"]) if record["reference_pin"] is not None else None,
            str(record["clock_edge"]),
        )
        ports = {str(port) for port in record["ports"]} & required_ports
        min_max = {str(value) for value in record["min_max"]} & {"min", "max"}
        transitions = {str(value) for value in record["transitions"]} & {"rise", "fall"}
        for port in ports:
            covered_slots = relationship_slots.setdefault(port, {}).setdefault(relationship, set())
            covered_slots.update((analysis, transition) for analysis in min_max for transition in transitions)

    # Invalid attempted relationships never enter OpenSTA's active state, but
    # they remain explicit zero-covered obligations instead of disappearing
    # from the coverage denominator.
    for item in state.io_delays:
        if item.kind != kind or item.valid:
            continue
        relationship = (item.clocks, item.reference_pin, item.clock_edge)
        for port in item.ports & required_ports:
            relationship_slots.setdefault(port, {}).setdefault(relationship, set())

    covered = 0
    total = 0
    for port in required_ports:
        relationships = relationship_slots.get(port)
        if not relationships:
            total += 4
            continue
        total += 4 * len(relationships)
        covered += sum(len(slots) for slots in relationships.values())
    return covered, total


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
    covered_input_slots, total_input_slots = _io_delay_slot_counts(state, "input", required_inputs)
    covered_output_slots, total_output_slots = _io_delay_slot_counts(state, "output", required_outputs)
    audited_queries = list(state.queries)
    healthy_queries = [
        query for query in audited_queries if not query.error and query.matches and not query.unmatched_patterns
    ]
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
            covered_input_slots,
            total_input_slots,
            0.20,
            "Min/max by rise/fall slots covered for each required input port and I/O relationship.",
        ),
        CoverageComponent(
            "output_delays",
            "Output-delay coverage",
            covered_output_slots,
            total_output_slots,
            0.20,
            "Min/max by rise/fall slots covered for each required output port and I/O relationship.",
        ),
        CoverageComponent(
            "query_health",
            "Resolvable object queries",
            len(healthy_queries),
            len(audited_queries),
            0.10,
            "All parsed SDC object queries that resolve completely to at least one design object.",
        ),
    ]
    applicable = [component for component in components if component.total]
    denominator = sum(component.weight for component in applicable)
    score = (
        100.0 * sum(component.weight * component.covered / component.total for component in applicable) / denominator
        if denominator
        else 100.0
    )
    if design.warnings or any(
        finding.rule_id in {"OC0001", "OC0003", "OC1003", "OC1004"} for finding in state.diagnostics
    ):
        return Coverage(0.0, "F", components)
    rounded = round(score, 2)
    grade = "A" if rounded >= 95 else "B" if rounded >= 85 else "C" if rounded >= 70 else "D" if rounded >= 50 else "F"
    return Coverage(rounded, grade, components)


def _make_graph(state: _ModeState, design: Design, pin_to_clocks: dict[str, set[str]]) -> dict[str, object]:
    nodes: list[dict[str, object]] = []
    edges: list[dict[str, object]] = []
    for clock in sorted(_active_clocks(state).values(), key=lambda item: item.name):
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
        for source_target in sorted(clock.source_targets):
            source_id = f"source_object:{source_target}"
            nodes.append(
                {
                    "id": source_id,
                    "label": source_target,
                    "kind": "generated_clock_source",
                }
            )
            edges.append({"source": source_id, "target": f"clock:{clock.name}", "kind": "source"})
        if clock.master_clock:
            edges.append(
                {"source": f"clock:{clock.master_clock}", "target": f"clock:{clock.name}", "kind": "generates"}
            )
    for pin, clocks in sorted(pin_to_clocks.items()):
        pin_id = f"endpoint_clock:{pin}"
        nodes.append({"id": pin_id, "label": pin, "kind": "sequential_clock_pin"})
        for clock_name in sorted(clocks):
            edges.append({"source": f"clock:{clock_name}", "target": pin_id, "kind": "reaches"})
    graph_exceptions = [item for item in state.exceptions if _exception_scope_resolvable(item)]
    for index, exception in enumerate(graph_exceptions):
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
        raw_transitions = exception.qualifiers.get("through_transitions", [])
        through_transitions = raw_transitions if isinstance(raw_transitions, list) else []
        for through_index, through_group in enumerate(exception.through_objects):
            transition = (
                through_transitions[through_index]
                if through_index < len(through_transitions)
                and through_transitions[through_index] in {"rise", "fall", "rise_fall"}
                else "rise_fall"
            )
            for through_object in sorted(through_group):
                through_id = f"scope:{through_object}"
                nodes.append({"id": through_id, "label": through_object, "kind": "scope"})
                edges.append(
                    {
                        "source": through_id,
                        "target": exception_id,
                        "kind": "through",
                        "through_index": through_index,
                        "transition": transition,
                    }
                )
    deduplicated = {str(node["id"]): node for node in nodes}
    return {"nodes": list(deduplicated.values()), "edges": edges}


def _audit_documents(name: str, documents: list[SdcDocument], design: Design, options: AuditOptions) -> ModeResult:
    state = _ModeState(name, documents)
    _build_clocks(state, design)
    pin_to_clocks = _audit_clocks(state, design, options)
    _collect_nonclock_constraints(state, design)
    _audit_queries(state, design, options)
    _audit_exceptions(state)
    _audit_multicycles(state)
    _audit_io_delays(state)
    coverage = _audit_coverage(state, design, pin_to_clocks)
    state.diagnostics.sort(key=lambda item: (item.location.path, item.location.line, item.rule_id, item.message))
    return ModeResult(
        name,
        state.clocks,
        state.exceptions,
        state.io_delays,
        state.diagnostics,
        coverage,
        _make_graph(state, design, pin_to_clocks),
        frozenset(state.valid_clocks),
    )


def _audit_mode(name: str, paths: list[str], design: Design, options: AuditOptions) -> ModeResult:
    return _audit_documents(name, [parse_sdc(path) for path in paths], design, options)


def audit_sdc_text(
    design: Design,
    name: str,
    text: str,
    *,
    path: str = "<effective-sdc>",
    options: AuditOptions | None = None,
) -> ModeResult:
    """Audit an in-memory SDC snapshot using the same deterministic rule pipeline."""

    return _audit_documents(name, [parse_sdc_text(text, path)], design, options or AuditOptions())


def _clock_definition(clock: Clock) -> dict[str, object]:
    """Return a JSON-safe clock definition for cross-mode diagnostics."""

    waveform = clock.waveform
    edges = clock.edges
    edge_shift = clock.edge_shift
    return {
        "period": clock.period,
        "targets": sorted(clock.targets),
        "generated": clock.generated,
        "waveform": list(waveform) if waveform is not None else None,
        "waveform_explicit": clock.waveform_explicit,
        "source_targets": sorted(clock.source_targets),
        "master_clock": clock.master_clock,
        "divide_by": clock.divide_by,
        "multiply_by": clock.multiply_by,
        "duty_cycle": clock.duty_cycle,
        "invert": clock.invert,
        "combinational": clock.combinational,
        "edges": list(edges) if edges is not None else None,
        "edge_shift": list(edge_shift) if edge_shift is not None else None,
    }


def _cross_mode_diagnostics(modes: list[ModeResult]) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    if len(modes) < 2:
        return diagnostics
    all_clock_names = sorted(set().union(*(set(mode.valid_clocks) for mode in modes)))
    for clock_name in all_clock_names:
        clock_signatures = {
            mode.name: (
                mode.clocks[clock_name].period,
                tuple(sorted(mode.clocks[clock_name].targets)),
                mode.clocks[clock_name].generated,
                mode.clocks[clock_name].waveform,
                mode.clocks[clock_name].waveform_explicit,
                tuple(sorted(mode.clocks[clock_name].source_targets)),
                mode.clocks[clock_name].master_clock,
                mode.clocks[clock_name].divide_by,
                mode.clocks[clock_name].multiply_by,
                mode.clocks[clock_name].duty_cycle,
                mode.clocks[clock_name].invert,
                mode.clocks[clock_name].combinational,
                mode.clocks[clock_name].edges,
                mode.clocks[clock_name].edge_shift,
            )
            for mode in modes
            if clock_name in mode.valid_clocks
        }
        if len(clock_signatures) != len(modes) or len(set(clock_signatures.values())) > 1:
            first_clock = next(mode.clocks[clock_name] for mode in modes if clock_name in mode.valid_clocks)
            definitions = {
                mode.name: _clock_definition(mode.clocks[clock_name])
                for mode in modes
                if clock_name in mode.valid_clocks
            }
            diagnostics.append(
                Diagnostic(
                    "OC5001",
                    Severity.NOTE,
                    f"Clock {clock_name!r} differs across constraint modes",
                    first_clock.location,
                    "Mode-specific clocks are common, but unintended target, waveform, source, or transform drift can invalidate comparisons.",
                    "Review the per-mode definitions and record intentional differences in version control.",
                    "cross-mode",
                    {
                        "clock": clock_name,
                        "definitions": definitions,
                        "missing_modes": [mode.name for mode in modes if clock_name not in mode.valid_clocks],
                    },
                )
            )
    exception_signatures = {
        mode.name: {
            (
                item.kind,
                tuple(sorted(item.from_objects)),
                tuple(sorted(item.to_objects)),
                tuple(tuple(sorted(group)) for group in item.through_objects),
                json.dumps(item.qualifiers, sort_keys=True, separators=(",", ":")),
            )
            for item in mode.exceptions
            if _exception_scope_resolvable(item)
        }
        for mode in modes
    }
    baseline = modes[0]
    for mode in modes[1:]:
        added = exception_signatures[mode.name] - exception_signatures[baseline.name]
        removed = exception_signatures[baseline.name] - exception_signatures[mode.name]
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
    if design.warnings:
        warning_sample = design.warnings[:STRUCTURAL_WARNING_SAMPLE_LIMIT]
        diagnostics.append(
            Diagnostic(
                "OC0002",
                Severity.ERROR,
                f"Structural design model is incomplete ({len(design.warnings)} parser/elaboration warning(s))",
                SourceLocation("<design>"),
                "Ignored, inferred, malformed, or truncated structural input can invalidate every downstream constraint result.",
                "Use a supported synthesized netlist and complete Liberty inputs; resolve every parser warning before gating constraints.",
                "design",
                {
                    "warning_count": len(design.warnings),
                    "warning_sample": warning_sample,
                    "omitted_warning_count": len(design.warnings) - len(warning_sample),
                },
            )
        )
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
