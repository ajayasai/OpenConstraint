"""Static SDC command and object-query parsing."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
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

FLAG_OPTIONS = {
    "-add",
    "-hierarchical",
    "-regexp",
    "-nocase",
    "-quiet",
    "-rise",
    "-fall",
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
    dynamic: bool = False


@dataclass(slots=True)
class ParsedCommand:
    tcl: TclCommand
    options: dict[str, list[str]] = field(default_factory=dict)
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
        elif value in ("-quiet",):
            pass
        else:
            unpacked = unquote(value).strip()
            if unpacked:
                patterns.extend(item for item in split_words(unpacked) if item)
        index += 1
    if command_name in {"all_inputs", "all_outputs", "all_clocks", "all_registers"} and not patterns:
        patterns = ["*"]
    dynamic = any("$" in item or re.search(r"\[[A-Za-z_][A-Za-z0-9_]*\s", item) for item in patterns)
    return Selector(
        kind=kind,
        patterns=tuple(patterns),
        raw=word,
        location=location,
        hierarchical=hierarchical,
        regexp=regexp,
        nocase=nocase,
        filter_expression=filter_expression,
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
        if word.startswith("-"):
            if word in FLAG_OPTIONS:
                parsed.options.setdefault(word, []).append("true")
            elif index + 1 < len(words):
                index += 1
                value = words[index]
                parsed.options.setdefault(word, []).append(value)
                nested = _parse_selector(value, command.location)
                if nested:
                    parsed.selectors.append(nested)
            else:
                parsed.options.setdefault(word, []).append("")
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
