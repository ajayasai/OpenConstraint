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
    dynamic: bool = False
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
    patterns: list[str] = []
    index = 0
    while index < len(words):
        value = words[index]
        if value == "-hierarchical":
            hierarchical = True
        elif value == "-regexp":
            regexp = True
        elif value == "-nocase":
            nocase = True
        elif value in ("-filter", "-of_objects") and index + 1 < len(words):
            index += 1
            if value == "-filter":
                filter_expression = unquote(words[index])
            else:
                of_objects_raw = words[index]
                of_objects = _parse_selector(words[index], location)
        elif value in ("-quiet",):
            pass
        else:
            unpacked = unquote(value).strip()
            if unpacked:
                patterns.extend(item for item in split_words(unpacked) if item)
        index += 1
    if not patterns and of_objects_raw is None:
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
        dynamic=dynamic,
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
