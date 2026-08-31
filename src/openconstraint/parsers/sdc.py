"""Static SDC command and object-query parsing."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

from openconstraint.model import SourceLocation
from openconstraint.parsers import tcl as tcl_parser
from openconstraint.parsers.tcl import (
    MAX_TCL_LIST_ELEMENTS,
    TclCommand,
    TclParseIssue,
    TclSyntaxError,
    bracket_body,
    decode_tcl_word,
    parse_tcl,
    split_tcl_list_preserving_backslashes,
    split_words,
    tcl_word_has_substitution,
)

QUERY_KINDS = {
    "get_ports": "ports",
    "get_pins": "pins",
    "get_cells": "cells",
    "get_nets": "nets",
    "get_clocks": "clocks",
    "get_registers": "registers",
    "all_inputs": "all_inputs",
    "all_outputs": "all_outputs",
    "all_clocks": "all_clocks",
    "all_registers": "registers",
}

_QUERY_COMMAND_ALIASES = {
    "get_cell": "get_cells",
    "get_clock": "get_clocks",
    "get_net": "get_nets",
    "get_pin": "get_pins",
    "get_port": "get_ports",
}

_ALL_REGISTER_FLAGS = frozenset(
    {
        "-cells",
        "-data_pins",
        "-clock_pins",
        "-async_pins",
        "-output_pins",
        "-level_sensitive",
        "-edge_triggered",
    }
)
_ALL_REGISTER_VALUES = frozenset({"-clock", "-rise_clock", "-fall_clock"})

# Accepted option spelling and arity is command-specific in OpenSTA.  Keep
# that grammar separate from the smaller subset the static backend models so
# valid-but-unmodeled options fail closed instead of changing a collection.
_SELECTOR_FLAG_OPTIONS: dict[str, frozenset[str]] = {
    "get_cells": frozenset({"-hierarchical", "-regexp", "-nocase", "-quiet"}),
    "get_clocks": frozenset({"-regexp", "-nocase", "-quiet"}),
    "get_nets": frozenset({"-hierarchical", "-regexp", "-nocase", "-quiet"}),
    "get_pins": frozenset({"-hierarchical", "-regexp", "-nocase", "-quiet"}),
    "get_ports": frozenset({"-regexp", "-nocase", "-quiet"}),
    # get_registers is an OpenConstraint extension. Preserve its existing
    # static matching flags while applying the same fail-closed parsing.
    "get_registers": frozenset({"-hierarchical", "-regexp", "-nocase", "-quiet"}),
    "all_inputs": frozenset({"-no_clocks"}),
    "all_outputs": frozenset(),
    "all_clocks": frozenset(),
    "all_registers": _ALL_REGISTER_FLAGS,
}
_SELECTOR_VALUE_OPTIONS: dict[str, frozenset[str]] = {
    "get_cells": frozenset({"-filter", "-of_objects", "-hsc"}),
    "get_clocks": frozenset({"-filter"}),
    "get_nets": frozenset({"-filter", "-of_objects", "-hsc"}),
    "get_pins": frozenset({"-filter", "-of_objects", "-hsc"}),
    "get_ports": frozenset({"-filter", "-of_objects"}),
    "get_registers": frozenset({"-filter", "-of_objects", "-hsc"}),
    "all_inputs": frozenset(),
    "all_outputs": frozenset(),
    "all_clocks": frozenset(),
    "all_registers": _ALL_REGISTER_VALUES,
}
_UNMODELED_SELECTOR_OPTIONS: dict[str, frozenset[str]] = {
    "get_cells": frozenset({"-hsc"}),
    "get_nets": frozenset({"-hsc"}),
    "get_pins": frozenset({"-hsc"}),
    "get_registers": frozenset({"-hsc", "-of_objects"}),
    "all_inputs": frozenset({"-no_clocks"}),
    "all_registers": _ALL_REGISTER_FLAGS | _ALL_REGISTER_VALUES,
}
_ALL_SELECTOR_FLAGS = frozenset(option for options in _SELECTOR_FLAG_OPTIONS.values() for option in options)
_ALL_SELECTOR_VALUES = frozenset(option for options in _SELECTOR_VALUE_OPTIONS.values() for option in options)
MAX_SELECTOR_NESTING = 64
MAX_SELECTOR_PARSE_WORK = tcl_parser.MAX_SDC_INPUT_BYTES
_MAX_SELECTOR_ERROR_RAW_CHARACTERS = 256
_MAX_SELECTOR_PREFIX_SCAN = 256
_TCL_SELECTOR_PREFIX_WHITESPACE = " \t\n\v\f\r"

FLAG_OPTIONS = {
    "-add",
    "-hierarchical",
    "-regexp",
    "-nocase",
    "-quiet",
    "-rise",
    "-fall",
    "-min",
    "-max",
    "-setup",
    "-hold",
    "-start",
    "-end",
    "-combinational",
    "-source_latency_included",
    "-network_latency_included",
    "-clock_fall",
    "-level_sensitive",
    "-asynchronous",
    "-exclusive",
    "-logically_exclusive",
    "-physically_exclusive",
    "-allow_paths",
    "-add_delay",
    "-reset_path",
    "-invert",
    "-probe",
    "-ignore_clock_latency",
}


@dataclass(frozen=True, slots=True)
class Selector:
    command_name: str
    kind: str
    patterns: tuple[str, ...]
    raw: str
    location: SourceLocation
    hierarchical: bool = False
    regexp: bool = False
    nocase: bool = False
    filter_expression: str | None = None
    of_objects: Selector | None = None
    of_objects_raw: str | None = None
    nested_selectors: tuple[Selector, ...] = ()
    dynamic: bool = False
    parse_error: str | None = None
    option: str | None = None


@dataclass(slots=True)
class _SelectorParseBudget:
    """Bound reparsing and retained selector suffixes for one SDC document."""

    limit: int = field(default_factory=lambda: MAX_SELECTOR_PARSE_WORK)
    used: int = 0

    def charge(self, characters: int) -> bool:
        if characters < 0:
            raise ValueError("selector parse-work charge cannot be negative")
        if characters > self.limit - self.used:
            return False
        self.used += characters
        return True


@dataclass(slots=True)
class _SelectorParseContext:
    """Command-local memoization backed by a document-wide work budget."""

    budget: _SelectorParseBudget = field(default_factory=_SelectorParseBudget)
    # Identity keys avoid hashing an untrusted long word before its work has
    # been charged. Values retain the word so an object id cannot be reused
    # while the context remains live.
    memo: dict[tuple[int, int], tuple[str, Selector | None]] = field(default_factory=dict)


@dataclass(slots=True)
class ParsedCommand:
    tcl: TclCommand
    options: dict[str, list[str]] = field(default_factory=dict)
    option_occurrences: list[tuple[str, str]] = field(default_factory=list)
    option_selector_occurrences: list[tuple[str, str, Selector | None]] = field(default_factory=list)
    positionals: list[str] = field(default_factory=list)
    positional_selector_occurrences: list[tuple[str, Selector | None]] = field(default_factory=list)
    selectors: list[Selector] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    opaque_substitutions: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.tcl.name

    @property
    def dynamic_name(self) -> bool:
        if not self.tcl.words:
            return False
        try:
            return tcl_word_has_substitution(self.tcl.words[0])
        except TclSyntaxError:
            return True

    @property
    def location(self) -> SourceLocation:
        return self.tcl.location

    @property
    def raw(self) -> str:
        return self.tcl.raw

    def option(self, key: str) -> str | None:
        values = self.options.get(key, [])
        return values[-1] if values else None

    def has(self, key: str) -> bool:
        return key in self.options


@dataclass(slots=True)
class SdcDocument:
    path: str
    commands: list[ParsedCommand]
    issues: list[TclParseIssue]
    retained_source_bytes: int | None = None


@dataclass(frozen=True, slots=True)
class _CommandGrammar:
    """Pinned OpenSTA ``parse_key_args`` grammar for a modeled command.

    OpenSTA resolves an abbreviated keyword by taking the first declared key
    that starts with the supplied spelling, then the first declared flag.
    Repeated ``-through`` and ``-group`` operands are parsed later by their
    command procedures and therefore require their exact spellings.
    """

    value_options: tuple[str, ...]
    flag_options: tuple[str, ...]
    repeated_value_options: tuple[str, ...] = ()
    semantic_error_flags: tuple[str, ...] = ()


_EXCEPTION_VALUE_OPTIONS = (
    "-from",
    "-rise_from",
    "-fall_from",
    "-to",
    "-rise_to",
    "-fall_to",
    "-comment",
)
_EXCEPTION_THROUGH_OPTIONS = ("-through", "-rise_through", "-fall_through")
_COMMAND_GRAMMARS: dict[str, _CommandGrammar] = {
    # OpenSTA's ``write_sdc`` emits this single context directive before the
    # constraint commands.  It is statically safe only with one literal
    # design name; the engine verifies that name against the elaborated top.
    "current_design": _CommandGrammar((), ()),
    "create_clock": _CommandGrammar(
        ("-name", "-period", "-waveform", "-comment"),
        ("-add",),
    ),
    "create_generated_clock": _CommandGrammar(
        (
            "-name",
            "-source",
            "-master_clock",
            "-divide_by",
            "-multiply_by",
            "-duty_cycle",
            "-edges",
            "-edge_shift",
            "-comment",
        ),
        ("-invert", "-combinational", "-add"),
    ),
    "set_input_delay": _CommandGrammar(
        ("-clock", "-reference_pin"),
        (
            "-rise",
            "-fall",
            "-max",
            "-min",
            "-clock_fall",
            "-add_delay",
            "-source_latency_included",
            "-network_latency_included",
        ),
    ),
    "set_output_delay": _CommandGrammar(
        ("-clock", "-reference_pin"),
        (
            "-rise",
            "-fall",
            "-max",
            "-min",
            "-clock_fall",
            "-add_delay",
            "-source_latency_included",
            "-network_latency_included",
        ),
    ),
    "set_false_path": _CommandGrammar(
        _EXCEPTION_VALUE_OPTIONS,
        ("-setup", "-hold", "-rise", "-fall", "-reset_path"),
        _EXCEPTION_THROUGH_OPTIONS,
    ),
    "set_multicycle_path": _CommandGrammar(
        _EXCEPTION_VALUE_OPTIONS,
        ("-setup", "-hold", "-rise", "-fall", "-start", "-end", "-reset_path"),
        _EXCEPTION_THROUGH_OPTIONS,
    ),
    "set_max_delay": _CommandGrammar(
        _EXCEPTION_VALUE_OPTIONS,
        ("-rise", "-fall", "-ignore_clock_latency", "-reset_path", "-probe"),
        _EXCEPTION_THROUGH_OPTIONS,
    ),
    "set_min_delay": _CommandGrammar(
        _EXCEPTION_VALUE_OPTIONS,
        ("-rise", "-fall", "-ignore_clock_latency", "-reset_path", "-probe"),
        _EXCEPTION_THROUGH_OPTIONS,
    ),
    "set_clock_groups": _CommandGrammar(
        ("-name", "-comment"),
        ("-logically_exclusive", "-physically_exclusive", "-asynchronous", "-allow_paths"),
        ("-group",),
        # Keep this legacy alias visible to the dedicated OC4002 diagnostic,
        # which rejects it without creating any clock-group exceptions.
        ("-exclusive",),
    ),
}
MODELED_SDC_COMMANDS = frozenset(_COMMAND_GRAMMARS)

# A recognized selector substitution is statically trustworthy only where the
# modeled command expects an object collection.  Tcl still evaluates selectors
# used as scalar strings (for example ``-name [get_ports clk]``), but preserving
# their source spelling would silently change the scalar value.  Those
# occurrences are retained for independent query auditing and marked opaque by
# the command parser below.
_EXCEPTION_COLLECTION_SELECTOR_OPTIONS = frozenset(
    option for option in _EXCEPTION_VALUE_OPTIONS + _EXCEPTION_THROUGH_OPTIONS if option != "-comment"
)
_COLLECTION_SELECTOR_OPTIONS: dict[str, frozenset[str]] = {
    "create_generated_clock": frozenset({"-source", "-master_clock"}),
    "set_input_delay": frozenset({"-clock", "-reference_pin"}),
    "set_output_delay": frozenset({"-clock", "-reference_pin"}),
    "set_false_path": _EXCEPTION_COLLECTION_SELECTOR_OPTIONS,
    "set_multicycle_path": _EXCEPTION_COLLECTION_SELECTOR_OPTIONS,
    "set_max_delay": _EXCEPTION_COLLECTION_SELECTOR_OPTIONS,
    "set_min_delay": _EXCEPTION_COLLECTION_SELECTOR_OPTIONS,
    "set_clock_groups": frozenset({"-group"}),
}


def _selector_positional_is_opaque(command_name: str, positional_index: int) -> bool:
    """Return whether a selector occupies a scalar/unsupported positional role."""

    if command_name == "current_design":
        return True
    if command_name in {"set_input_delay", "set_output_delay"}:
        return positional_index == 0
    if command_name in {"set_multicycle_path", "set_max_delay", "set_min_delay"}:
        return positional_index == 0
    # Clock target selectors and extra operands remain available to their
    # rule-specific arity diagnostics. False paths and clock groups already
    # reject stray positionals canonically as OC0001.
    return False


def _normalize_selector_option(command_name: str, word: str) -> str:
    """Apply Tcl word quoting and modeled OpenSTA option abbreviations."""

    # Leading/trailing whitespace inside a Tcl quoted or braced word is part
    # of the argument.  OpenSTA's parse_key_args therefore treats
    # ``{ -quiet }`` as a positional pattern, not the ``-quiet`` flag.  Do not
    # trim it here or a zero-match query can be widened to the implicit ``*``.
    value = decode_tcl_word(word)
    if not (len(value) >= 2 and value[0] == "-" and value[1].isalpha()):
        return value
    options = _SELECTOR_FLAG_OPTIONS[command_name] | _SELECTOR_VALUE_OPTIONS[command_name]
    if value in options:
        return value
    matches = sorted(option for option in options if option.startswith(value))
    return matches[0] if len(matches) == 1 else value


def _parse_selector_body(body: str) -> tuple[tuple[TclCommand, ...], tuple[TclParseIssue, ...]]:
    """Parse one bracket body without retaining source text process-globally."""

    commands, issues = parse_tcl(body, "<selector>")
    return tuple(commands), tuple(issues)


def _could_be_selector_word(word: str) -> bool:
    """Recognize a possible whole-word bracket selector with bounded lookahead."""

    if not word or word.startswith("{"):
        return False
    index = 1 if word.startswith('"') else 0
    stop = min(len(word), index + _MAX_SELECTOR_PREFIX_SCAN)
    while index < stop and word[index] in _TCL_SELECTOR_PREFIX_WHITESPACE:
        index += 1
    return index < len(word) and index < stop and word[index] == "["


def _selector_parse_limit_error(word: str, location: SourceLocation, limit: int) -> Selector:
    if len(word) <= _MAX_SELECTOR_ERROR_RAW_CHARACTERS:
        retained_raw = word
    else:
        retained_raw = word[: _MAX_SELECTOR_ERROR_RAW_CHARACTERS - 3] + "..."
    return Selector(
        command_name="<selector>",
        kind="unknown",
        patterns=(),
        raw=retained_raw,
        location=location,
        dynamic=False,
        parse_error=f"selector parsing exceeds the aggregate static work limit of {limit} characters",
    )


def _parse_selector(
    word: str,
    location: SourceLocation,
    depth: int = 0,
    *,
    context: _SelectorParseContext | None = None,
) -> Selector | None:
    if not _could_be_selector_word(word):
        return None
    if context is None:
        context = _SelectorParseContext()
    memo_key = (id(word), depth)
    cached = context.memo.get(memo_key)
    if cached is not None and cached[0] is word:
        return cached[1]
    if not context.budget.charge(len(word)):
        # Do not memoize or retain the rejected full suffix. The bounded raw
        # spelling is enough to join the deterministic OC1004 diagnostic.
        return _selector_parse_limit_error(word, location, context.budget.limit)
    parsed = _parse_selector_charged(word, location, depth, context=context)
    context.memo[memo_key] = (word, parsed)
    return parsed


def _parse_selector_charged(
    word: str,
    location: SourceLocation,
    depth: int,
    *,
    context: _SelectorParseContext,
) -> Selector | None:
    body = bracket_body(word)
    if body is None:
        return None
    commands, issues = _parse_selector_body(body)
    if not commands:
        return None
    first_command = commands[0]
    words = list(first_command.words)
    try:
        command_name = decode_tcl_word(words.pop(0))
    except TclSyntaxError:
        return None
    command_name = _QUERY_COMMAND_ALIASES.get(command_name, command_name)
    if command_name not in QUERY_KINDS:
        return None
    kind = QUERY_KINDS[command_name]
    if issues or len(commands) != 1:
        reasons: list[str] = []
        if len(commands) != 1:
            reasons.append(f"selector command substitution must contain exactly one Tcl command; got {len(commands)}")
        reasons.extend(f"selector command has malformed Tcl: {issue.message}" for issue in issues)
        return Selector(
            command_name=command_name,
            kind=kind,
            patterns=(),
            raw=word,
            location=location,
            dynamic=False,
            parse_error="; ".join(reasons),
        )
    if depth >= MAX_SELECTOR_NESTING:
        return Selector(
            command_name=command_name,
            kind=kind,
            patterns=(),
            raw=word,
            location=location,
            dynamic=False,
            parse_error=f"selector nesting exceeds the static limit of {MAX_SELECTOR_NESTING}",
        )
    hierarchical = False
    regexp = False
    nocase = False
    filter_expression: str | None = None
    of_objects: Selector | None = None
    of_objects_raw: str | None = None
    nested_selectors: list[Selector] = []
    patterns: list[str] = []
    positional_dynamic = False
    positional_count = 0
    parse_errors: list[str] = []
    pattern_retention_failed = False

    def reject_pattern_retention(message: str) -> None:
        nonlocal pattern_retention_failed
        patterns.clear()
        if not pattern_retention_failed:
            parse_errors.append(message)
        pattern_retention_failed = True

    def retain_patterns(items: tuple[str, ...]) -> None:
        if pattern_retention_failed:
            return
        if len(items) > MAX_TCL_LIST_ELEMENTS - len(patterns):
            reject_pattern_retention(f"{command_name} selector pattern list exceeds {MAX_TCL_LIST_ELEMENTS} elements")
            return
        patterns.extend(items)

    allowed_flags = _SELECTOR_FLAG_OPTIONS[command_name]
    allowed_values = _SELECTOR_VALUE_OPTIONS[command_name]
    unmodeled_options = _UNMODELED_SELECTOR_OPTIONS.get(command_name, frozenset())
    index = 0
    while index < len(words):
        raw_value = words[index]
        try:
            value = _normalize_selector_option(command_name, raw_value)
        except TclSyntaxError as error:
            positional_count += 1
            parse_errors.append(f"{command_name} has malformed Tcl word: {error}")
            index += 1
            continue
        if value in _ALL_SELECTOR_VALUES:
            supported_by_command = value in allowed_values
            if not supported_by_command:
                parse_errors.append(f"{command_name} does not support option {value}")
            if index + 1 >= len(words):
                if supported_by_command:
                    parse_errors.append(f"{command_name} {value} missing value")
            else:
                index += 1
                operand = words[index]
                nested = _parse_selector(operand, location, depth + 1, context=context)
                if nested is not None:
                    nested_selectors.append(nested)
                if value == "-of_objects":
                    # Tcl evaluates the operand before the outer command
                    # validates whether -of_objects is legal. Retain that
                    # query for independent auditing even if the option fails.
                    of_objects_raw = (
                        nested.raw if nested is not None and nested.command_name == "<selector>" else operand
                    )
                    of_objects = nested
                if supported_by_command and value in unmodeled_options:
                    parse_errors.append(f"{command_name} {value} is not modeled by the static backend")
                elif supported_by_command and value == "-filter":
                    try:
                        filter_expression = decode_tcl_word(operand)
                    except TclSyntaxError as error:
                        parse_errors.append(f"{command_name} {value} has malformed Tcl value: {error}")
        elif value in _ALL_SELECTOR_FLAGS:
            if value not in allowed_flags:
                parse_errors.append(f"{command_name} does not support option {value}")
            elif value in unmodeled_options:
                parse_errors.append(f"{command_name} {value} is not modeled by the static backend")
            elif value == "-hierarchical":
                hierarchical = True
            elif value == "-regexp":
                regexp = True
            elif value == "-nocase":
                nocase = True
        elif len(value) >= 2 and value[0] == "-" and value[1].isalpha():
            parse_errors.append(f"{command_name} does not support option {value}")
        else:
            positional_count += 1
            nested = _parse_selector(raw_value, location, depth + 1, context=context)
            if nested is not None:
                nested_selectors.append(nested)
            try:
                word_dynamic = tcl_word_has_substitution(raw_value)
            except TclSyntaxError as error:
                word_dynamic = False
                parse_errors.append(f"{command_name} has malformed Tcl word: {error}")
            positional_dynamic = positional_dynamic or word_dynamic
            if word_dynamic:
                # The substitution result is unknown. Preserve bracket-aware
                # grouping for deterministic nested-query diagnostics rather
                # than pretending its source text is an evaluated Tcl list.
                if not pattern_retention_failed:
                    try:
                        remaining = MAX_TCL_LIST_ELEMENTS - len(patterns)
                        retain_patterns(split_words(value, max_words=remaining))
                    except TclSyntaxError:
                        reject_pattern_retention(
                            f"{command_name} selector pattern list exceeds {MAX_TCL_LIST_ELEMENTS} elements"
                        )
            elif command_name.startswith("get_"):
                if not pattern_retention_failed:
                    try:
                        remaining = MAX_TCL_LIST_ELEMENTS - len(patterns)
                        retain_patterns(split_tcl_list_preserving_backslashes(value, max_elements=remaining))
                    except TclSyntaxError as error:
                        if " elements" in str(error):
                            reject_pattern_retention(
                                f"{command_name} selector pattern list exceeds {MAX_TCL_LIST_ELEMENTS} elements"
                            )
                        else:
                            reject_pattern_retention(f"{command_name} has malformed Tcl pattern list: {error}")
            elif value:
                retain_patterns((value,))
        index += 1
    # OpenSTA's get_* commands accept zero or one positional Tcl argument.
    # That one word may itself be a Tcl list containing multiple patterns.
    # The four modeled -of_objects queries warn about and ignore positional
    # words instead, so retain their established effective semantics here.
    if command_name.startswith("all_") and command_name != "all_inputs" and positional_count:
        parse_errors.append(f"{command_name} does not accept positional patterns")
    elif command_name != "all_inputs" and of_objects_raw is None and positional_count > 1:
        parse_errors.append(
            f"{command_name} accepts at most one positional pattern-list argument; got {positional_count}"
        )
    # OpenSTA c821ad1 Sdc.tcl treats an omitted get_* pattern as "*", but an
    # explicitly supplied empty Tcl word is still a positional pattern and
    # must not be widened into an all-object collection.
    if not patterns and of_objects_raw is None and positional_count == 0 and not parse_errors:
        patterns = ["*"]
    # OpenSTA ignores positional patterns when -of_objects is present.  Those
    # ignored words must therefore not make an otherwise static selector look
    # Tcl-dynamic.  A dynamic nested source still makes the whole query
    # dynamic, because that collection determines the result.
    dynamic = (of_objects is None or of_objects.dynamic) if of_objects_raw is not None else positional_dynamic
    return Selector(
        command_name=command_name,
        kind=kind,
        patterns=tuple(patterns),
        raw=word,
        location=location,
        hierarchical=hierarchical,
        regexp=regexp,
        nocase=nocase,
        filter_expression=filter_expression,
        of_objects=of_objects,
        of_objects_raw=of_objects_raw,
        nested_selectors=tuple(nested_selectors),
        dynamic=dynamic,
        parse_error="; ".join(parse_errors) or None,
    )


def _is_keyword(value: str) -> bool:
    """Match OpenSTA ``is_keyword_arg`` without interpreting numbers."""

    return len(value) >= 2 and value[0] == "-" and value[1].isalpha()


def _decode_command_argument(parsed: ParsedCommand, raw: str) -> str:
    try:
        return decode_tcl_word(raw)
    except TclSyntaxError as error:
        message = f"{parsed.name} has malformed Tcl word: {error}"
        if message not in parsed.parse_errors:
            parsed.parse_errors.append(message)
        return raw


def _canonical_modeled_option(value: str, grammar: _CommandGrammar) -> tuple[str, str] | None:
    """Return ``(canonical spelling, arity)`` using OpenSTA's match order."""

    if value in grammar.value_options:
        return value, "value"
    if value in grammar.flag_options:
        return value, "flag"
    if value in grammar.repeated_value_options:
        return value, "value"
    if value in grammar.semantic_error_flags:
        return value, "flag"

    # parse_key_args searches keys before flags and takes the first prefix
    # match in declaration order. The later through/group parsers do not.
    for option in grammar.value_options:
        if option.startswith(value):
            return option, "value"
    for option in grammar.flag_options:
        if option.startswith(value):
            return option, "flag"
    return None


def _record_option(
    parsed: ParsedCommand,
    option: str,
    value: str,
    selector: Selector | None = None,
) -> None:
    parsed.options.setdefault(option, []).append(value)
    parsed.option_occurrences.append((option, value))
    parsed.option_selector_occurrences.append((option, value, selector))


def _parse_modeled_command(
    parsed: ParsedCommand,
    words: list[str],
    grammar: _CommandGrammar,
    context: _SelectorParseContext,
) -> None:
    index = 0
    while index < len(words):
        raw_word = words[index]
        selector = _parse_selector(raw_word, parsed.location, context=context)
        value = _decode_command_argument(parsed, raw_word)
        if _is_keyword(value):
            option = _canonical_modeled_option(value, grammar)
            if option is None:
                parsed.parse_errors.append(f"{parsed.name} does not support option {value}")
            else:
                canonical, arity = option
                if arity == "flag":
                    _record_option(parsed, canonical, "true")
                elif index + 1 >= len(words):
                    parsed.parse_errors.append(f"{parsed.name} {canonical} missing value")
                    _record_option(parsed, canonical, "")
                else:
                    index += 1
                    raw_operand = words[index]
                    operand_selector = _parse_selector(raw_operand, parsed.location, context=context)
                    operand = _decode_command_argument(parsed, raw_operand)
                    # Keep the source spelling for evaluated collections so
                    # selector.raw remains a stable join key in the engine.
                    # Non-selector values use their Tcl-decoded spelling.
                    selector_operand = (
                        operand_selector.raw
                        if operand_selector is not None and operand_selector.command_name == "<selector>"
                        else raw_operand
                    )
                    associated_selector = (
                        replace(operand_selector, option=canonical) if operand_selector is not None else None
                    )
                    _record_option(
                        parsed,
                        canonical,
                        selector_operand if operand_selector is not None else operand,
                        associated_selector,
                    )
                    if associated_selector is not None:
                        parsed.selectors.append(associated_selector)
                        if canonical not in _COLLECTION_SELECTOR_OPTIONS.get(parsed.name, frozenset()):
                            parsed.opaque_substitutions.append(raw_operand)
        else:
            positional_index = len(parsed.positionals)
            selector_word = selector.raw if selector is not None and selector.command_name == "<selector>" else raw_word
            positional_value = selector_word if selector is not None else value
            parsed.positionals.append(positional_value)
            parsed.positional_selector_occurrences.append((positional_value, selector))
            if selector is not None:
                parsed.selectors.append(selector)
                if _selector_positional_is_opaque(parsed.name, positional_index):
                    parsed.opaque_substitutions.append(raw_word)
        index += 1


def _parse_current_design(parsed: ParsedCommand, words: list[str], context: _SelectorParseContext) -> None:
    """Parse OpenSTA's direct one-argument context command.

    Unlike the constraint commands, ``current_design`` does not use
    ``parse_key_args``.  A literal design name beginning with ``-`` is
    therefore an operand, not an option.  Evaluated names remain opaque.
    """

    for raw_word in words:
        selector = _parse_selector(raw_word, parsed.location, context=context)
        value = _decode_command_argument(parsed, raw_word)
        selector_word = selector.raw if selector is not None and selector.command_name == "<selector>" else raw_word
        positional_value = selector_word if selector is not None else value
        parsed.positionals.append(positional_value)
        parsed.positional_selector_occurrences.append((positional_value, selector))
        if selector is not None:
            parsed.selectors.append(selector)
            parsed.opaque_substitutions.append(raw_word)


def _parse_generic_command(parsed: ParsedCommand, words: list[str], context: _SelectorParseContext) -> None:
    """Retain the broad parser for commands outside the modeled audit set."""

    index = 0
    while index < len(words):
        word = words[index]
        selector = _parse_selector(word, parsed.location, context=context)
        if selector:
            parsed.selectors.append(selector)
        if len(word) >= 2 and word[0] == "-" and word[1].isalpha():
            if word in FLAG_OPTIONS:
                _record_option(parsed, word, "true")
            elif index + 1 < len(words):
                index += 1
                value = words[index]
                nested = _parse_selector(value, parsed.location, context=context)
                associated_selector = replace(nested, option=word) if nested is not None else None
                _record_option(parsed, word, value, associated_selector)
                if associated_selector is not None:
                    parsed.selectors.append(associated_selector)
            else:
                _record_option(parsed, word, "")
        else:
            parsed.positionals.append(word)
            parsed.positional_selector_occurrences.append((word, selector))
        index += 1


def _parse_command(command: TclCommand, selector_budget: _SelectorParseBudget | None = None) -> ParsedCommand:
    parsed = ParsedCommand(tcl=command)
    context = _SelectorParseContext(selector_budget or _SelectorParseBudget())
    words = list(command.words[1:])
    if command.words:
        try:
            tcl_word_has_substitution(command.words[0])
        except TclSyntaxError as error:
            parsed.parse_errors.append(f"command name has malformed Tcl word: {error}")
    for word in words:
        try:
            active_substitution = tcl_word_has_substitution(word)
        except TclSyntaxError as error:
            message = f"{parsed.name} has malformed Tcl word: {error}"
            if message not in parsed.parse_errors:
                parsed.parse_errors.append(message)
            continue
        if active_substitution and _parse_selector(word, command.location, context=context) is None:
            parsed.opaque_substitutions.append(word)

    grammar = _COMMAND_GRAMMARS.get(command.name)
    if command.name == "current_design":
        _parse_current_design(parsed, words, context)
        if len(parsed.positionals) != 1:
            parsed.parse_errors.append(
                f"current_design requires exactly one literal design name; got {len(parsed.positionals)}"
            )
    elif grammar is None:
        _parse_generic_command(parsed, words, context)
    else:
        _parse_modeled_command(parsed, words, grammar, context)
        if command.name in {"set_false_path", "set_clock_groups"} and parsed.positionals:
            parsed.parse_errors.append(f"{command.name} accepts no positional operands; got {len(parsed.positionals)}")
    return parsed


def parse_sdc_text(text: str, path: str = "<memory>") -> SdcDocument:
    commands, issues = parse_tcl(text, path)
    selector_budget = _SelectorParseBudget()
    return SdcDocument(
        path=path,
        commands=[_parse_command(command, selector_budget) for command in commands],
        issues=issues,
    )


def parse_sdc(path: str | Path, *, max_bytes: int | None = None) -> SdcDocument:
    source = Path(path)
    source_path = str(source)
    if max_bytes is not None and max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")
    global_limit = tcl_parser.MAX_SDC_INPUT_BYTES
    limit = global_limit if max_bytes is None else min(max_bytes, global_limit)

    def rejected(message: str) -> SdcDocument:
        issue = TclParseIssue(message, SourceLocation(source_path, 1, 1))
        return SdcDocument(path=source_path, commands=[], issues=[issue])

    limit_message = (
        f"SDC source exceeds the {limit}-byte UTF-8 input limit"
        if max_bytes is None
        else (
            f"SDC source exceeds the remaining {limit}-byte portion of the {global_limit}-byte "
            "cumulative UTF-8 input limit for one constraint mode"
        )
    )
    if source.stat().st_size > limit:
        return rejected(limit_message)
    with source.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        return rejected(limit_message)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return rejected("SDC source is not valid UTF-8")
    document = parse_sdc_text(text, source_path)
    document.retained_source_bytes = len(raw)
    return document
