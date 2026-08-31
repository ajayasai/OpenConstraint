"""Deterministic object-query resolution for the static backend."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from openconstraint.model import Clock, Design
from openconstraint.parsers.sdc import Selector


@dataclass(slots=True)
class ResolvedQuery:
    selector: Selector
    matches: set[str]
    universe_size: int
    # Tcl collection commands return lists, not mathematical sets.  Retain
    # the effective result cardinality so singleton contracts can reject
    # duplicate/overlapping patterns while the rest of the static engine
    # continues to use stable set semantics for object relationships.
    match_count: int = 0
    multiplicities: dict[str, int] = field(default_factory=dict)
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

_EXACT_LOOKUP_KINDS = frozenset({"cells", "nets", "pins"})
_DESIGN_QUERY_KINDS = frozenset({"cells", "nets", "pins", "ports", "registers"})
_REGEXP_ROUTING_METACHARACTERS = frozenset(".+*?[]")
_REGEXP_ESCAPED_LITERALS = frozenset(r"\.^$*+?{}[]()|-")
_MAX_REGEXP_PATTERN_LENGTH = 4_096
_MAX_REGEXP_GROUP_DEPTH = 64
_MAX_REGEXP_QUANTIFIERS = 8
_MAX_GLOB_WORK = 1_000_000
_MAX_GLOB_COLLECTION_WORK = 10_000_000
_MAX_REGEXP_COLLECTION_WORK = 10_000_000
_BUS_RANGE_PATTERN = re.compile(r"\[\s*-?\d+\s*:\s*-?\d+\s*\]")


class _GlobWorkLimitError(ValueError):
    """Raised before a glob comparison can exceed deterministic work."""


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


def _add_occurrences(multiplicities: dict[str, int], name: str | None, count: int) -> None:
    if name is not None and count > 0:
        multiplicities[name] = multiplicities.get(name, 0) + count


def _connected_pins(net: str, design: Design) -> set[str]:
    return design.drivers.get(net, set()) | design.loads.get(net, set())


def _related_universe(
    selector: Selector, design: Design, clocks: dict[str, Clock]
) -> tuple[set[str], dict[str, int], str | None]:
    if selector.of_objects is None:
        universe = _universe(selector, design, clocks)
        return universe, dict.fromkeys(universe, 1), None
    source = resolve_selector(selector.of_objects, design, clocks)
    if source.error:
        return set(), {}, f"unsupported -of_objects source: {source.error}"
    source_kind = _collection_kind(selector.of_objects)
    allowed_source_kinds = _OF_OBJECTS_SOURCE_KINDS.get(selector.kind)
    if allowed_source_kinds is None:
        return set(), {}, f"-of_objects is not modeled for {selector.kind} queries"
    if source_kind not in allowed_source_kinds:
        expected = ", ".join(sorted(allowed_source_kinds))
        return (
            set(),
            {},
            f"invalid -of_objects source kind '{source_kind}' for {selector.kind}; expected one of: {expected}",
        )

    source_multiplicities = source.multiplicities
    related: dict[str, int] = {}
    if selector.kind == "nets":
        for name, count in source_multiplicities.items():
            if source_kind == "pins" and name in design.pins:
                _add_occurrences(related, design.pins[name].net, count)
            elif source_kind == "cells" and name in design.instances:
                for instance_pin in design.instances[name].pins.values():
                    _add_occurrences(related, instance_pin.net, count)
        return set(related), related, None
    if selector.kind == "pins":
        for name, count in source_multiplicities.items():
            if source_kind == "cells" and name in design.instances:
                for instance_pin in design.instances[name].pins.values():
                    _add_occurrences(related, instance_pin.path, count)
            elif source_kind == "nets" and name in design.nets:
                for pin_path in _connected_pins(name, design):
                    _add_occurrences(related, pin_path, count)
        return set(related), related, None
    if selector.kind == "cells":
        for name, count in source_multiplicities.items():
            if source_kind == "pins" and name in design.pins:
                _add_occurrences(related, design.pins[name].instance, count)
                continue
            net: str | None = None
            if source_kind == "nets" and name in design.nets:
                net = name
            elif source_kind == "ports" and name in design.ports:
                net = design.ports[name].net
            if net is not None:
                for pin_path in _connected_pins(net, design):
                    if pin_path in design.pins:
                        _add_occurrences(related, design.pins[pin_path].instance, count)
        return set(related), related, None
    if selector.kind == "ports":
        for name, count in source_multiplicities.items():
            if source_kind != "nets" or name not in design.nets:
                continue
            for port_name, port in design.ports.items():
                if port.net == name:
                    _add_occurrences(related, port_name, count)
        return set(related), related, None
    return set(), {}, f"-of_objects is not modeled for {selector.kind} queries"


def _glob_matches(pattern: str, value: str) -> bool:
    """Match pinned OpenSTA byte-glob semantics within a fixed work bound.

    ``PatternMatch::patternMatch`` operates on UTF-8 bytes and gives a
    non-final ``*`` retry positions only while input remains.  The latter is
    observable for adjacent stars (``data**`` does not match ``data``), so a
    normalizing glob library would be incorrect.  This bottom-up form is
    stack safe and performs at most ``(pattern + 1) * (value + 1)`` work.
    """

    pattern_bytes = pattern.encode("utf-8")
    value_bytes = value.encode("utf-8")
    pattern_length = len(pattern_bytes)
    value_length = len(value_bytes)
    work = (pattern_length + 1) * (value_length + 1)
    if work > _MAX_GLOB_WORK:
        raise _GlobWorkLimitError(f"glob comparison requires {work} states; deterministic limit is {_MAX_GLOB_WORK}")

    # dp[j] is the result for the already-processed pattern suffix and the
    # value suffix beginning at byte j.  The empty pattern matches only the
    # empty value.
    following = [False] * (value_length + 1)
    following[value_length] = True
    question = ord("?")
    star = ord("*")
    for pattern_index in range(pattern_length - 1, -1, -1):
        pattern_byte = pattern_bytes[pattern_index]
        current = [False] * (value_length + 1)
        if pattern_byte == star:
            if pattern_index + 1 == pattern_length:
                current = [True] * (value_length + 1)
            else:
                # A non-final star never retries at the end position; this is
                # the exact boundary in OpenSTA's recursive while loop.
                for value_index in range(value_length - 1, -1, -1):
                    current[value_index] = following[value_index] or current[value_index + 1]
        else:
            for value_index in range(value_length - 1, -1, -1):
                current[value_index] = (
                    pattern_byte in {question, value_bytes[value_index]} and following[value_index + 1]
                )
        following = current
    return following[0]


def _pattern_has_wildcards(pattern: str, selector: Selector) -> bool:
    """Mirror OpenSTA c821ad1 ``PatternMatch::hasWildcards``.

    The regexp routing predicate is intentionally not equivalent to "contains
    regexp syntax".  OpenSTA checks only ``.+*?[]`` before choosing between a
    collection walk and an exact object lookup.
    """

    metacharacters = _REGEXP_ROUTING_METACHARACTERS if selector.regexp else frozenset("*?")
    return any(character in metacharacters for character in pattern)


def _pattern_universe(pattern: str, candidates: set[str], selector: Selector) -> set[str]:
    """Return the flattened objects visible to one non-hierarchical walk.

    OpenSTA's SDC network walks one instance-path component at a time.  A
    wildcard without a hierarchy separator therefore searches only the
    current instance: top nets, direct-child cells, and direct-child pins for
    the special ``get_pins *`` case.  OpenConstraint has no ``current_instance``
    command and its design model flattens module instances, so the current
    instance is necessarily the linked top and module cells/boundary pins are
    absent.  Keeping candidates at the pattern's path depth is the exact
    behavior representable by that flattened model.

    Literal patterns retain the complete universe so exact deep paths still
    resolve without requiring ``-hierarchical``.
    """

    if (
        selector.hierarchical
        or selector.kind not in _EXACT_LOOKUP_KINDS
        or not _pattern_has_wildcards(pattern, selector)
    ):
        return candidates
    path_depth = pattern.count("/")
    if selector.kind == "pins" and not selector.regexp and pattern == "*":
        path_depth = 1
    return {candidate for candidate in candidates if candidate.count("/") == path_depth}


def _hierarchical_match_name(candidate: str, selector: Selector) -> str:
    """Return the name compared by OpenSTA's hierarchical query walkers.

    OpenSTA c821ad1 compares the local object name for cells and nets.  Its
    pin walker instead constructs ``local_instance/pin``; it does not compare
    either the bare pin leaf or the complete path from the current instance.
    """

    if not selector.hierarchical:
        return candidate
    if selector.kind in {"cells", "nets", "registers"}:
        return candidate.rsplit("/", 1)[-1]
    if selector.kind == "pins":
        components = candidate.rsplit("/", 2)
        return "/".join(components[-2:])
    return candidate


def _unsupported_regexp_syntax(pattern: str) -> str | None:
    """Reject syntax outside a conservative Tcl-ARE/Python shared subset.

    The static backend uses Python's regexp engine, while OpenSTA c821ad1 uses
    Tcl advanced regular expressions.  Only constructs whose boolean matching
    behavior is shared are accepted.  In particular, alphabetic/numeric
    escapes, counted or modified quantifiers, ``(?...)`` extensions, and
    advanced bracket expressions fail closed rather than acquiring Python
    semantics accidentally.
    """

    if len(pattern) > _MAX_REGEXP_PATTERN_LENGTH:
        return f"regular expression exceeds the {_MAX_REGEXP_PATTERN_LENGTH}-character static limit"
    if pattern.startswith(("*", "+", "?")):
        return "invalid regular expression: a leading quantifier has no operand"

    in_character_class = False
    class_start = -1
    previous_quantifier = False
    group_stack: list[list[bool]] = []
    closed_group_traits: tuple[bool, bool] | None = None
    quantifier_count = 0
    quantifiers_in_component = 0
    unbounded_quantifiers_in_component = 0
    alternations_in_component = 0
    top_level_alternation_in_component = False
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "\\":
            if index + 1 >= len(pattern):
                return "a trailing escape is outside the modeled Tcl ARE subset"
            escaped = pattern[index + 1]
            if escaped not in _REGEXP_ESCAPED_LITERALS:
                return f"escape \\{escaped} is outside the modeled Tcl ARE subset"
            previous_quantifier = False
            closed_group_traits = None
            index += 2
            continue
        if character == "[" and not in_character_class:
            in_character_class = True
            class_start = index
            previous_quantifier = False
            closed_group_traits = None
        elif character == "[" and in_character_class:
            return "nested/POSIX bracket expressions are outside the modeled Tcl ARE subset"
        elif character == "]" and in_character_class:
            if index == class_start + 1 or (index == class_start + 2 and pattern[class_start + 1] == "^"):
                return "literal closing brackets in character classes are outside the modeled Tcl ARE subset"
            in_character_class = False
            previous_quantifier = False
            closed_group_traits = None
        elif character == "(" and not in_character_class and index + 1 < len(pattern) and pattern[index + 1] == "?":
            return "(?...) extensions are outside the modeled Tcl ARE subset"
        elif character == "(" and not in_character_class:
            if len(group_stack) >= _MAX_REGEXP_GROUP_DEPTH:
                return f"regular-expression group nesting exceeds the static limit of {_MAX_REGEXP_GROUP_DEPTH}"
            # [contains alternation, contains quantifier]
            group_stack.append([False, False])
            previous_quantifier = False
            closed_group_traits = None
        elif character == ")" and not in_character_class:
            if not group_stack:
                # Let the compiler provide the ordinary unmatched-group
                # diagnostic; no deep recursion is possible at this point.
                closed_group_traits = None
            else:
                traits = group_stack.pop()
                closed_group_traits = (traits[0], traits[1])
                if group_stack:
                    group_stack[-1][0] = group_stack[-1][0] or traits[0]
                    group_stack[-1][1] = group_stack[-1][1] or traits[1]
            previous_quantifier = False
        elif character == "|" and not in_character_class:
            alternations_in_component += 1
            if alternations_in_component > 1:
                return "multiple alternations in one path component are outside the complexity-bounded subset"
            if group_stack:
                group_stack[-1][0] = True
            else:
                top_level_alternation_in_component = True
                if quantifiers_in_component:
                    return (
                        "top-level alternation with repetition in one path component is outside the "
                        "complexity-bounded subset"
                    )
            previous_quantifier = False
            closed_group_traits = None
        elif not in_character_class and character in "{}":
            return "counted repetition is outside the modeled Tcl ARE subset"
        elif not in_character_class and character in "*+?":
            if previous_quantifier:
                return "modified or repeated quantifiers are outside the modeled Tcl ARE subset"
            quantifier_count += 1
            quantifiers_in_component += 1
            if quantifier_count > _MAX_REGEXP_QUANTIFIERS:
                return f"regular expression exceeds the static limit of {_MAX_REGEXP_QUANTIFIERS} quantifiers"
            if top_level_alternation_in_component:
                return (
                    "top-level alternation with repetition in one path component is outside the "
                    "complexity-bounded subset"
                )
            if character in "*+":
                unbounded_quantifiers_in_component += 1
                if unbounded_quantifiers_in_component > 1:
                    return (
                        "multiple unbounded quantifiers in one path component are outside the complexity-bounded subset"
                    )
            if closed_group_traits is not None and any(closed_group_traits):
                return (
                    "quantified groups containing alternation or repetition are outside the complexity-bounded subset"
                )
            if group_stack:
                group_stack[-1][1] = True
            previous_quantifier = True
            closed_group_traits = None
        else:
            if in_character_class and index + 1 < len(pattern):
                pair = pattern[index : index + 2]
                if pair in {"&&", "--", "~~", "||"}:
                    return "set operations in character classes are outside the modeled Tcl ARE subset"
            previous_quantifier = False
            if not in_character_class:
                closed_group_traits = None
                if character == "/":
                    # Non-hierarchical path regexps are compiled one path
                    # component at a time; a literal divider prevents either
                    # repetition from consuming the other's input.
                    quantifiers_in_component = 0
                    unbounded_quantifiers_in_component = 0
                    alternations_in_component = 0
                    top_level_alternation_in_component = False
        index += 1
    if in_character_class:
        # Python's compiler would also reject this, but keep the diagnostic
        # independent of Python's exact error wording.
        return "an unterminated character class is outside the modeled Tcl ARE subset"
    return None


def _translate_tcl_end_anchors(pattern: str) -> str:
    """Give Tcl's strict end anchor semantics to Python's regexp engine."""

    translated: list[str] = []
    in_character_class = False
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "\\" and index + 1 < len(pattern):
            translated.extend((character, pattern[index + 1]))
            index += 2
            continue
        if character == "[" and not in_character_class:
            in_character_class = True
        elif character == "]" and in_character_class:
            in_character_class = False
        if character == "$" and not in_character_class:
            translated.append(r"\Z")
        else:
            translated.append(character)
        index += 1
    return "".join(translated)


def _compile_regexp(pattern: str, flags: int) -> tuple[re.Pattern[str] | None, str | None]:
    try:
        # PatternMatch::compileRegexp injects these anchors as plain text; it
        # does not wrap the user's expression in a grouping construct.
        translated = _translate_tcl_end_anchors(pattern)
        return re.compile(rf"\A{translated}\Z", flags | re.DOTALL), None
    except (re.error, RecursionError) as error:
        return None, f"invalid regular expression: {error}"


def _regexp_search(expression: re.Pattern[str], value: str) -> tuple[bool, str | None]:
    try:
        return expression.search(value) is not None, None
    except RecursionError as error:
        return False, f"regular-expression matching exceeded Python's recursion limit: {error}"


def _unsupported_glob_syntax(pattern: str, selector: Selector) -> str | None:
    if selector.kind in _DESIGN_QUERY_KINDS and r"\/" in pattern:
        return "escaped hierarchy dividers are ambiguous in the flattened static model"
    if selector.kind in _DESIGN_QUERY_KINDS and _BUS_RANGE_PATTERN.search(pattern):
        return "bus-range-shaped object patterns require declaration provenance that is not statically modeled"
    return None


def _collection_work_error(
    pattern: str,
    candidates: set[str],
    selector: Selector,
    *,
    limit: int,
    grammar: str,
) -> str | None:
    pattern_size = len(pattern.encode("utf-8")) + 1
    work = 0
    for candidate in candidates:
        comparison_name = _hierarchical_match_name(candidate, selector)
        work += pattern_size * (len(comparison_name.encode("utf-8")) + 1)
        if work > limit:
            return f"{grammar} collection comparison exceeds the deterministic work limit of {limit} states"
    return None


def _match_nonhierarchical_paths(
    pattern: str, candidates: set[str], selector: Selector, flags: int
) -> tuple[set[str], str | None]:
    """Match SDC paths one current-instance component at a time."""

    if selector.regexp and not _pattern_has_wildcards(pattern, selector):
        # c821ad1 routes these through exact object lookup despite -regexp.
        return ({pattern} if pattern in candidates else set()), None
    if selector.kind == "pins" and not selector.regexp and pattern == "*":
        # SdcNetwork has a dedicated fast path for all pins of direct child
        # instances.  `_pattern_universe` has already limited that collection.
        return set(candidates), None
    pattern_components = pattern.split("/")
    component_regexps: list[re.Pattern[str] | None] = []
    if selector.regexp:
        for component in pattern_components:
            if _pattern_has_wildcards(component, selector):
                if selector.nocase and not component.isascii():
                    return set(), "non-ASCII -nocase matching is outside the modeled Tcl ARE subset"
                expression, error = _compile_regexp(component, flags)
                if expression is None:
                    return set(), error
                component_regexps.append(expression)
            else:
                component_regexps.append(None)

    matches: set[str] = set()
    for candidate in candidates:
        candidate_components = candidate.split("/")
        if len(pattern_components) != len(candidate_components):
            continue
        matched = True
        for index, (pattern_component, candidate_component) in enumerate(
            zip(pattern_components, candidate_components, strict=True)
        ):
            if selector.regexp:
                expression = component_regexps[index]
                if expression is None:
                    component_matches = pattern_component == candidate_component
                else:
                    if selector.nocase and not candidate_component.isascii():
                        return set(), "non-ASCII -nocase matching is outside the modeled Tcl ARE subset"
                    # Tcl_RegExpExec searches with the injected anchors.
                    # ``fullmatch`` would add grouping semantics around an
                    # alternation such as ``a|b``.
                    component_matches, error = _regexp_search(expression, candidate_component)
                    if error is not None:
                        return set(), error
            else:
                try:
                    component_matches = _glob_matches(pattern_component, candidate_component)
                except _GlobWorkLimitError as error:
                    return set(), str(error)
            if not component_matches:
                matched = False
                break
        if matched:
            matches.add(candidate)
    return matches, None


def _match_pattern(pattern: str, candidates: set[str], selector: Selector) -> tuple[set[str], str | None]:
    # OpenSTA accepts -nocase without -regexp but warns that it is ignored.
    # Preserve the matching semantics even though this static resolver does
    # not duplicate the tool's console warning.
    flags = re.IGNORECASE if selector.regexp and selector.nocase else 0
    if selector.regexp:
        unsupported = _unsupported_regexp_syntax(pattern)
        if unsupported is not None:
            return set(), unsupported
        scans_collection = (
            selector.hierarchical
            or selector.kind not in _EXACT_LOOKUP_KINDS
            or _pattern_has_wildcards(pattern, selector)
        )
        if scans_collection:
            work_error = _collection_work_error(
                pattern,
                candidates,
                selector,
                limit=_MAX_REGEXP_COLLECTION_WORK,
                grammar="regular-expression",
            )
            if work_error is not None:
                return set(), work_error
        expression, error = _compile_regexp(pattern, flags)
        if expression is None:
            return set(), error
        if not selector.hierarchical and selector.kind in _EXACT_LOOKUP_KINDS:
            return _match_nonhierarchical_paths(pattern, candidates, selector, flags)
        if selector.nocase and (not pattern.isascii() or any(not candidate.isascii() for candidate in candidates)):
            return set(), "non-ASCII -nocase matching is outside the modeled Tcl ARE subset"
        matches: set[str] = set()
        for candidate in candidates:
            matched, error = _regexp_search(expression, _hierarchical_match_name(candidate, selector))
            if error is not None:
                return set(), error
            if matched:
                matches.add(candidate)
        return matches, None
    unsupported = _unsupported_glob_syntax(pattern, selector)
    if unsupported is not None:
        return set(), unsupported
    if pattern == "*":
        return set(candidates), None
    if not selector.hierarchical and not _pattern_has_wildcards(pattern, selector):
        return ({pattern} if pattern in candidates else set()), None
    work_error = _collection_work_error(
        pattern,
        candidates,
        selector,
        limit=_MAX_GLOB_COLLECTION_WORK,
        grammar="glob",
    )
    if work_error is not None:
        return set(), work_error
    if not selector.hierarchical and selector.kind in _EXACT_LOOKUP_KINDS:
        return _match_nonhierarchical_paths(pattern, candidates, selector, flags)
    matches = set()
    for candidate in candidates:
        try:
            matched = _glob_matches(pattern, _hierarchical_match_name(candidate, selector))
        except _GlobWorkLimitError as error:
            return set(), str(error)
        if matched:
            matches.add(candidate)
    return matches, None


def _apply_filter(values: set[str], selector: Selector, design: Design) -> tuple[set[str], str | None]:
    expression = selector.filter_expression
    if expression is None:
        return values, None
    if not expression.strip():
        return set(), "empty filter expression"
    direction = re.fullmatch(
        r"\s*(direction|port_direction|pin_direction)\s*(?:==|=~)\s*"
        r"(input|output|tristate|bidirect|internal|ground|power|well|unknown)\s*",
        expression,
    )
    if direction:
        property_name = direction.group(1)
        expected = direction.group(2)
        allowed_properties = {
            "ports": frozenset({"direction", "port_direction"}),
            "pins": frozenset({"direction", "pin_direction"}),
        }.get(selector.kind)
        if allowed_properties is None or property_name not in allowed_properties:
            return set(), f"direction property {property_name} is not valid for {selector.kind} queries"

        def object_direction(name: str) -> str:
            if name in design.ports:
                value = design.ports[name].direction
                return "bidirect" if value == "inout" else value
            if name in design.pins:
                value = design.pins[name].direction
                return "bidirect" if value == "inout" else value
            return "unknown"

        return {name for name in values if object_direction(name) == expected}, None
    sequential = re.fullmatch(
        r"\s*(is_sequential|is_sequential_cell)\s*==\s*(true|false|1|0)\s*",
        expression,
    )
    if sequential:
        property_name = sequential.group(1)
        if selector.command_name != "get_registers":
            return set(), f"sequential property {property_name} is only valid for get_registers queries"
        expected = sequential.group(2) in {"true", "1"}
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
    candidates, candidate_multiplicities, universe_error = _related_universe(selector, design, clocks)
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
    multiplicities: dict[str, int]
    unmatched_patterns: list[str] = []
    if selector.kind in {"all_inputs", "all_outputs", "all_clocks"} or selector.of_objects is not None:
        # OpenSTA warns about positional patterns supplied with -of_objects,
        # then ignores them.  Applying those patterns here would make the
        # static and effective collections disagree.
        matches = set(candidates)
        multiplicities = dict(candidate_multiplicities)
    else:
        matches = set()
        multiplicities = {}
        searched_candidates: set[str] = set()
        for pattern in selector.patterns:
            pattern_candidates = _pattern_universe(pattern, candidates, selector)
            searched_candidates.update(pattern_candidates)
            selected, error = _match_pattern(pattern, pattern_candidates, selector)
            if error:
                return ResolvedQuery(selector, set(), len(candidates), error=error)
            if not selected:
                unmatched_patterns.append(pattern)
            for match in selected:
                multiplicities[match] = multiplicities.get(match, 0) + 1
            matches.update(selected)
        candidates = searched_candidates
    matches, filter_error = _apply_filter(matches, selector, design)
    match_count = sum(multiplicities.get(match, 0) for match in matches) if filter_error is None else 0
    return ResolvedQuery(
        selector,
        matches,
        len(candidates),
        match_count=match_count,
        multiplicities={match: multiplicities[match] for match in matches},
        error=filter_error,
        unmatched_patterns=tuple(unmatched_patterns),
    )


def has_glob(selector: Selector) -> bool:
    if selector.of_objects is not None:
        return False
    if selector.regexp and (selector.hierarchical or selector.kind not in _EXACT_LOOKUP_KINDS):
        return True
    return any(_pattern_has_wildcards(pattern, selector) for pattern in selector.patterns)
