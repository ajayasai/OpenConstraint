"""Small, dependency-free Liberty parser for structural cell metadata.

The parser intentionally extracts only information needed by the static audit:
cell names, pin directions, sequential state expressions, clock pins, and
combinational input/output dependencies.  It accepts ordinary Liberty
group/attribute syntax and ignores unrelated content.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from openconstraint.parsers._text import strip_c_style_comments


@dataclass(slots=True)
class LibertyNode:
    kind: str
    args: tuple[str, ...] = ()
    attrs: dict[str, str] = field(default_factory=dict)
    children: list[LibertyNode] = field(default_factory=list)


@dataclass(slots=True)
class CellSpec:
    name: str
    pin_directions: dict[str, str]
    sequential: bool = False
    data_pins: set[str] = field(default_factory=set)
    clock_pins: set[str] = field(default_factory=set)
    combinational_dependencies: dict[str, set[str]] = field(default_factory=dict)


@dataclass(slots=True)
class CellLibrary:
    cells: dict[str, CellSpec] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def merge(self, other: CellLibrary) -> None:
        self.cells.update(other.cells)
        self.warnings.extend(other.warnings)


TOKEN_RE = re.compile(
    r"""
    (?P<space>\s+)
    |(?P<string>"(?:\\.|[^"\\])*")
    |(?P<punct>[(){}:;,])
    |(?P<atom>[^\s(){}:;,]+)
    """,
    re.DOTALL | re.VERBOSE,
)
MAX_GROUP_DEPTH = 256
MAX_LIBERTY_TOKENS = 750_000
MAX_LIBERTY_NODES = 120_000
MAX_LIBERTY_WARNINGS = 1_000
LIBERTY_TRUNCATION_WARNING = "Liberty retention limit reached; additional tokens, nodes, or warnings were omitted"


def _tokens(text: str) -> list[str]:
    return _tokenize(text)[0]


def _tokenize(text: str) -> tuple[list[str], bool]:
    without_comments = strip_c_style_comments(text)
    tokens: list[str] = []
    for match in TOKEN_RE.finditer(without_comments):
        if match.lastgroup == "space":
            continue
        if len(tokens) >= MAX_LIBERTY_TOKENS:
            return tokens, True
        tokens.append(match.group(0))
    return tokens, False


def _clean(token: str) -> str:
    token = token.strip()
    if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
        return token[1:-1].replace(r"\"", '"').replace(r"\\", "\\")
    return token


class _LibertyParser:
    def __init__(self, tokens: list[str], *, truncated: bool = False) -> None:
        self.tokens = tokens
        self.index = 0
        self.warnings: list[str] = []
        self.retained_nodes = 0
        self.truncated = truncated

    def warn(self, message: str) -> None:
        if len(self.warnings) < MAX_LIBERTY_WARNINGS:
            self.warnings.append(message)
        else:
            self.truncated = True
            self.index = len(self.tokens)

    def retain(self, nodes: list[LibertyNode], node: LibertyNode) -> None:
        if self.retained_nodes < MAX_LIBERTY_NODES:
            nodes.append(node)
            self.retained_nodes += 1
        else:
            self.truncated = True
            self.index = len(self.tokens)

    def peek(self) -> str | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def pop(self) -> str | None:
        value = self.peek()
        if value is not None:
            self.index += 1
        return value

    def _skip_group(self) -> None:
        depth = 1
        while self.peek() is not None and depth:
            token = self.pop()
            if token == "{":
                depth += 1
            elif token == "}":
                depth -= 1

    def parse(self, stop: str | None = None, depth: int = 0) -> list[LibertyNode]:
        nodes: list[LibertyNode] = []
        while self.peek() is not None and self.peek() != stop:
            key = self.pop()
            if key in {";", ",", ":", "(", ")", "{"}:
                self.warn(f"ignored unexpected token {key!r}")
                continue
            if key == "}":
                break
            if self.peek() == ":":
                self.pop()
                value_tokens: list[str] = []
                while self.peek() is not None and self.peek() not in {";", "}"}:
                    value_tokens.append(self.pop() or "")
                if self.peek() == ";":
                    self.pop()
                self.retain(
                    nodes,
                    LibertyNode("@attribute", (str(key),), {"value": " ".join(map(_clean, value_tokens))}),
                )
                continue
            args: list[str] = []
            if self.peek() == "(":
                self.pop()
                argument_depth = 1
                current: list[str] = []
                while self.peek() is not None and argument_depth:
                    token = self.pop()
                    if token == "(":
                        argument_depth += 1
                        current.append(token)
                    elif token == ")":
                        argument_depth -= 1
                        if argument_depth:
                            current.append(token)
                    elif token == "," and argument_depth == 1:
                        args.append(" ".join(map(_clean, current)).strip())
                        current = []
                    else:
                        current.append(token or "")
                if current or not args:
                    args.append(" ".join(map(_clean, current)).strip())
            if self.peek() == "{":
                self.pop()
                if depth >= MAX_GROUP_DEPTH:
                    self.warn(f"ignored group {key!r} nested beyond the parser limit of {MAX_GROUP_DEPTH}")
                    self._skip_group()
                    children = []
                else:
                    children = self.parse(stop="}", depth=depth + 1)
                    if self.peek() == "}":
                        self.pop()
                attrs: dict[str, str] = {}
                retained: list[LibertyNode] = []
                for child in children:
                    if child.kind == "@attribute" and child.args:
                        attrs[child.args[0]] = child.attrs.get("value", "")
                    else:
                        retained.append(child)
                self.retain(nodes, LibertyNode(str(key), tuple(args), attrs, retained))
            else:
                while self.peek() is not None and self.peek() not in {";", "}"}:
                    self.pop()
                if self.peek() == ";":
                    self.pop()
                self.retain(nodes, LibertyNode(str(key), tuple(args)))
        return nodes


def _walk(nodes: list[LibertyNode], kind: str) -> list[LibertyNode]:
    found: list[LibertyNode] = []
    for node in nodes:
        if node.kind == kind:
            found.append(node)
        found.extend(_walk(node.children, kind))
    return found


def _identifiers(expression: str) -> set[str]:
    ignored = {"and", "or", "not", "true", "false", "posedge", "negedge"}
    return {token for token in re.findall(r"[A-Za-z_][A-Za-z0-9_$]*", expression) if token.lower() not in ignored}


def _pin_tokens(expression: str) -> set[str]:
    ignored = {"and", "or", "not", "true", "false", "posedge", "negedge"}
    whitespace_tokens = {item.strip('{},"') for item in re.split(r"[\s,]+", expression) if item}
    expression_tokens = set(re.findall(r"[A-Za-z_][A-Za-z0-9_$]*(?:\[[^\]]+\])?", expression))
    return {item for item in whitespace_tokens | expression_tokens if item.lower() not in ignored}


def _pin_references(expression: str, candidates: set[str]) -> set[str]:
    """Return pin names referenced by a Liberty expression or related-pin list.

    Checking against the declared pin inventory avoids interpreting Liberty
    operators and internal state variables as cell pins.  Exact whitespace
    tokens cover escaped identifiers; identifier extraction covers ordinary
    Boolean functions and bus-bit spellings.
    """

    return _pin_tokens(expression) & candidates


def parse_liberty_text(text: str) -> CellLibrary:
    tokens, truncated = _tokenize(text)
    parser = _LibertyParser(tokens, truncated=truncated)
    roots = parser.parse()
    library = CellLibrary(warnings=parser.warnings)
    for cell_node in _walk(roots, "cell"):
        if not cell_node.args:
            continue
        name = cell_node.args[0]
        pin_directions: dict[str, str] = {}
        clock_pins: set[str] = set()
        pin_nodes = [child for child in cell_node.children if child.kind in {"pin", "bus"}]
        for pin_node in pin_nodes:
            if not pin_node.args:
                continue
            pin_name = pin_node.args[0]
            direction = pin_node.attrs.get("direction", "unknown").strip().lower()
            pin_directions[pin_name] = direction
            if pin_node.attrs.get("clock", "").strip().lower() == "true":
                clock_pins.add(pin_name)

        sequential_groups = [
            child for child in cell_node.children if child.kind in {"ff", "ff_bank", "latch", "latch_bank"}
        ]
        data_pins: set[str] = set()
        for group in sequential_groups:
            for key in ("next_state", "data_in"):
                data_pins.update(_identifiers(group.attrs.get(key, "")))
            for key in ("clocked_on", "clocked_on_also", "enable"):
                clock_pins.update(_identifiers(group.attrs.get(key, "")))
        data_pins.intersection_update(pin_directions)
        clock_pins.intersection_update(pin_directions)
        input_pins = {pin_name for pin_name, direction in pin_directions.items() if direction in {"input", "inout"}}
        combinational_dependencies: dict[str, set[str]] = {}
        if not sequential_groups:
            for pin_node in pin_nodes:
                if not pin_node.args:
                    continue
                output_name = pin_node.args[0]
                if pin_directions.get(output_name) not in {"output", "inout"}:
                    continue
                dependencies: set[str] = set()
                function = pin_node.attrs.get("function")
                if function is not None:
                    function_references = _pin_references(function, input_pins)
                    dependencies.update(function_references)
                    # Retain an explicitly constant function as a known output
                    # with no combinational input dependency, but do not treat
                    # an unrecognized identifier as a proven constant.
                    if function_references or not _pin_tokens(function):
                        combinational_dependencies[output_name] = dependencies
                for timing in (child for child in pin_node.children if child.kind == "timing"):
                    related_pin = timing.attrs.get("related_pin")
                    if related_pin is not None:
                        timing_references = _pin_references(related_pin, input_pins)
                        dependencies.update(timing_references)
                        if timing_references:
                            combinational_dependencies[output_name] = dependencies
        library.cells[name] = CellSpec(
            name=name,
            pin_directions=pin_directions,
            sequential=bool(sequential_groups),
            data_pins=data_pins,
            clock_pins=clock_pins,
            combinational_dependencies=combinational_dependencies,
        )
    if parser.truncated:
        library.warnings.append(LIBERTY_TRUNCATION_WARNING)
    if not library.cells:
        library.warnings.append("no cell groups were found in the Liberty input")
    return library


def parse_liberty(path: str | Path) -> CellLibrary:
    source = Path(path)
    return parse_liberty_text(source.read_text(encoding="utf-8", errors="replace"))
