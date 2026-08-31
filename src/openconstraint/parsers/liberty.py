"""Small, dependency-free Liberty parser for structural cell metadata.

The parser intentionally extracts only information needed by the static audit:
cell names, pin directions, sequential state expressions, and clock pins.  It
accepts ordinary Liberty group/attribute syntax and ignores unrelated content.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


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
    |(?P<block>/\*.*?\*/)
    |(?P<line>//[^\n]*)
    |(?P<string>"(?:\\.|[^"\\])*")
    |(?P<punct>[(){}:;,])
    |(?P<atom>[^\s(){}:;,]+)
    """,
    re.DOTALL | re.VERBOSE,
)


def _tokens(text: str) -> list[str]:
    return [match.group(0) for match in TOKEN_RE.finditer(text) if match.lastgroup not in {"space", "block", "line"}]


def _clean(token: str) -> str:
    token = token.strip()
    if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
        return token[1:-1].replace(r"\"", '"').replace(r"\\", "\\")
    return token


class _LibertyParser:
    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        self.index = 0
        self.warnings: list[str] = []

    def peek(self) -> str | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def pop(self) -> str | None:
        value = self.peek()
        if value is not None:
            self.index += 1
        return value

    def parse(self, stop: str | None = None) -> list[LibertyNode]:
        nodes: list[LibertyNode] = []
        while self.peek() is not None and self.peek() != stop:
            key = self.pop()
            if key in {";", ",", ":", "(", ")", "{"}:
                self.warnings.append(f"ignored unexpected token {key!r}")
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
                nodes.append(LibertyNode("@attribute", (str(key),), {"value": " ".join(map(_clean, value_tokens))}))
                continue
            args: list[str] = []
            if self.peek() == "(":
                self.pop()
                depth = 1
                current: list[str] = []
                while self.peek() is not None and depth:
                    token = self.pop()
                    if token == "(":
                        depth += 1
                        current.append(token)
                    elif token == ")":
                        depth -= 1
                        if depth:
                            current.append(token)
                    elif token == "," and depth == 1:
                        args.append(" ".join(map(_clean, current)).strip())
                        current = []
                    else:
                        current.append(token or "")
                if current or not args:
                    args.append(" ".join(map(_clean, current)).strip())
            if self.peek() == "{":
                self.pop()
                children = self.parse(stop="}")
                if self.peek() == "}":
                    self.pop()
                attrs: dict[str, str] = {}
                retained: list[LibertyNode] = []
                for child in children:
                    if child.kind == "@attribute" and child.args:
                        attrs[child.args[0]] = child.attrs.get("value", "")
                    else:
                        retained.append(child)
                nodes.append(LibertyNode(str(key), tuple(args), attrs, retained))
            else:
                while self.peek() is not None and self.peek() not in {";", "}"}:
                    self.pop()
                if self.peek() == ";":
                    self.pop()
                nodes.append(LibertyNode(str(key), tuple(args)))
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


def parse_liberty_text(text: str) -> CellLibrary:
    parser = _LibertyParser(_tokens(text))
    roots = parser.parse()
    library = CellLibrary(warnings=parser.warnings)
    for cell_node in _walk(roots, "cell"):
        if not cell_node.args:
            continue
        name = cell_node.args[0]
        pin_directions: dict[str, str] = {}
        clock_pins: set[str] = set()
        for pin_node in [child for child in cell_node.children if child.kind in {"pin", "bus"}]:
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
        library.cells[name] = CellSpec(
            name=name,
            pin_directions=pin_directions,
            sequential=bool(sequential_groups),
            data_pins=data_pins,
            clock_pins=clock_pins,
        )
    if not library.cells:
        library.warnings.append("no cell groups were found in the Liberty input")
    return library


def parse_liberty(path: str | Path) -> CellLibrary:
    source = Path(path)
    return parse_liberty_text(source.read_text(encoding="utf-8", errors="replace"))
