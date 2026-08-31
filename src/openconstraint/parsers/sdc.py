"""Static SDC command and object-query parsing."""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from pathlib import Path

from openconstraint.model import SourceLocation
from openconstraint.parsers.tcl import TclCommand, TclParseIssue, bracket_body, parse_tcl, split_words, unquote

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

_TCL_VARIABLE = re.compile(r"(?<!\\)\$(?:[A-Za-z_:][A-Za-z0-9_:]*|\{[^}]+\})")

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
class ParsedCommand:
    tcl: TclCommand
    options: dict[str, list[str]] = field(default_factory=dict)
    option_occurrences: list[tuple[str, str]] = field(default_factory=list)
    positionals: list[str] = field(default_factory=list)
    selectors: list[Selector] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.tcl.name

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


def _normalize_selector_option(command_name: str, word: str) -> str:
    """Apply Tcl word quoting and modeled OpenSTA option abbreviations."""

    # Leading/trailing whitespace inside a Tcl quoted or braced word is part
    # of the argument.  OpenSTA's parse_key_args therefore treats
    # ``{ -quiet }`` as a positional pattern, not the ``-quiet`` flag.  Do not
    # trim it here or a zero-match query can be widened to the implicit ``*``.
    value = unquote(word)
    if not (len(value) >= 2 and value[0] == "-" and value[1].isalpha()):
        return value
    options = _SELECTOR_FLAG_OPTIONS[command_name] | _SELECTOR_VALUE_OPTIONS[command_name]
    if value in options:
        return value
    matches = sorted(option for option in options if option.startswith(value))
    return matches[0] if len(matches) == 1 else value


def _parse_selector(word: str, location: SourceLocation) -> Selector | None:
    body = bracket_body(word)
    if body is None:
        return None
    words = list(split_words(body))
    if not words:
        return None
    command_name = unquote(words.pop(0))
    if command_name not in QUERY_KINDS:
        return None
    kind = QUERY_KINDS[command_name]
    hierarchical = False
    regexp = False
    nocase = False
    filter_expression: str | None = None
    of_objects: Selector | None = None
    of_objects_raw: str | None = None
    nested_selectors: list[Selector] = []
    patterns: list[str] = []
    positional_count = 0
    parse_errors: list[str] = []
    allowed_flags = _SELECTOR_FLAG_OPTIONS[command_name]
    allowed_values = _SELECTOR_VALUE_OPTIONS[command_name]
    unmodeled_options = _UNMODELED_SELECTOR_OPTIONS.get(command_name, frozenset())
    index = 0
    while index < len(words):
        raw_value = words[index]
        value = _normalize_selector_option(command_name, raw_value)
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
                nested = _parse_selector(operand, location)
                if nested is not None:
                    nested_selectors.append(nested)
                if value == "-of_objects":
                    # Tcl evaluates the operand before the outer command
                    # validates whether -of_objects is legal. Retain that
                    # query for independent auditing even if the option fails.
                    of_objects_raw = operand
                    of_objects = nested
                if supported_by_command and value in unmodeled_options:
                    parse_errors.append(f"{command_name} {value} is not modeled by the static backend")
                elif supported_by_command and value == "-filter":
                    filter_expression = unquote(operand)
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
            nested = _parse_selector(raw_value, location)
            if nested is not None:
                nested_selectors.append(nested)
            unpacked = unquote(raw_value).strip()
            if unpacked:
                patterns.extend(item for item in split_words(unpacked) if item)
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
    if of_objects_raw is not None:
        dynamic = of_objects is None or of_objects.dynamic
    else:
        dynamic = any(_TCL_VARIABLE.search(item) or re.search(r"\[[A-Za-z_][A-Za-z0-9_]*\s", item) for item in patterns)
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


def _parse_command(command: TclCommand) -> ParsedCommand:
    parsed = ParsedCommand(tcl=command)
    words = list(command.words[1:])
    index = 0
    while index < len(words):
        word = words[index]
        selector = _parse_selector(word, command.location)
        if selector:
            parsed.selectors.append(selector)
        if len(word) >= 2 and word[0] == "-" and word[1].isalpha():
            if word in FLAG_OPTIONS:
                parsed.options.setdefault(word, []).append("true")
                parsed.option_occurrences.append((word, "true"))
            elif index + 1 < len(words):
                index += 1
                value = words[index]
                parsed.options.setdefault(word, []).append(value)
                parsed.option_occurrences.append((word, value))
                nested = _parse_selector(value, command.location)
                if nested:
                    parsed.selectors.append(replace(nested, option=word))
            else:
                parsed.options.setdefault(word, []).append("")
                parsed.option_occurrences.append((word, ""))
        else:
            parsed.positionals.append(word)
        index += 1
    return parsed


def parse_sdc_text(text: str, path: str = "<memory>") -> SdcDocument:
    commands, issues = parse_tcl(text, path)
    return SdcDocument(path=path, commands=[_parse_command(command) for command in commands], issues=issues)


def parse_sdc(path: str | Path) -> SdcDocument:
    source = Path(path)
    return parse_sdc_text(source.read_text(encoding="utf-8"), str(source))
