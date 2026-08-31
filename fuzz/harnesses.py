"""Pure byte-oriented parser harnesses shared by Atheris and corpus tests."""

from __future__ import annotations

from openconstraint.parsers.liberty import MAX_LIBERTY_NODES, MAX_LIBERTY_WARNINGS, CellLibrary, parse_liberty_text
from openconstraint.parsers.sdc import parse_sdc_text
from openconstraint.parsers.tcl import parse_tcl, split_words
from openconstraint.parsers.verilog import (
    MAX_VERILOG_MODULES,
    MAX_VERILOG_WARNINGS,
    elaborate,
    parse_verilog_text,
)

MAX_INPUT_BYTES = 1 << 20


def _text(data: bytes) -> str | None:
    if len(data) > MAX_INPUT_BYTES:
        return None
    return data.decode("utf-8", errors="replace")


def fuzz_tcl_sdc(data: bytes) -> None:
    """Exercise Tcl tokenization and SDC semantic extraction together."""

    text = _text(data)
    if text is None:
        return
    commands, issues = parse_tcl(text, "<fuzz>")
    document = parse_sdc_text(text, "<fuzz>")
    if [command.tcl for command in document.commands] != commands:
        raise AssertionError("SDC and Tcl command streams diverged")
    if document.issues != issues:
        raise AssertionError("SDC and Tcl parse issues diverged")
    for command in commands:
        if not command.raw or not command.words or command.words != split_words(command.raw):
            raise AssertionError("Tcl command tokenization is internally inconsistent")


def fuzz_verilog(data: bytes) -> None:
    """Exercise the structural Verilog parser and deterministic output contract."""

    text = _text(data)
    if text is None:
        return
    parsed = parse_verilog_text(text)
    if parsed != parse_verilog_text(text):
        raise AssertionError("Verilog parsing is nondeterministic")
    if any(name != module.name for name, module in parsed.modules.items()):
        raise AssertionError("Verilog module index and definitions diverged")
    if len(parsed.modules) > MAX_VERILOG_MODULES:
        raise AssertionError("Verilog module retention exceeded the parser bound")
    if len(parsed.warnings) > MAX_VERILOG_WARNINGS + 1:
        raise AssertionError("Verilog warning retention exceeded its details plus summary bound")
    if parsed.modules:
        design = elaborate(parsed, CellLibrary())
        if any(name != instance.path for name, instance in design.instances.items()):
            raise AssertionError("elaborated instance index and paths diverged")


def fuzz_liberty(data: bytes) -> None:
    """Exercise the Liberty parser and deterministic cell-index contract."""

    text = _text(data)
    if text is None:
        return
    parsed = parse_liberty_text(text)
    if parsed != parse_liberty_text(text):
        raise AssertionError("Liberty parsing is nondeterministic")
    if any(name != cell.name for name, cell in parsed.cells.items()):
        raise AssertionError("Liberty cell index and specifications diverged")
    if len(parsed.cells) > MAX_LIBERTY_NODES:
        raise AssertionError("Liberty cell retention exceeded the parser node bound")
    if len(parsed.warnings) > MAX_LIBERTY_WARNINGS + 2:
        raise AssertionError("Liberty warning retention exceeded its details plus summary bounds")
