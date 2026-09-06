"""Small, bounded Tcl-expression interpreter. No Python/Tcl eval or host calls."""

from __future__ import annotations

import math
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

from openconstraint.engine import _tcl_integer
from openconstraint.parsers.tcl import decode_tcl_word

NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z", re.ASCII)
_NUMBER = re.compile(
    r"(?:0[xX][0-9a-fA-F]+|0[bB][01]+|0[oO][0-7]+|(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)", re.ASCII
)
_FLOAT = re.compile(r"[+-]?(?:[0-9]+\.[0-9]*|\.[0-9]+|[0-9]+[eE][+-]?[0-9]+)(?:[eE][+-]?[0-9]+)?\Z", re.ASCII)
_PREC = {
    "||": 1,
    "&&": 2,
    "==": 3,
    "!=": 3,
    "eq": 3,
    "ne": 3,
    "<": 4,
    "<=": 4,
    ">": 4,
    ">=": 4,
    "+": 5,
    "-": 5,
    "*": 6,
    "/": 6,
    "%": 6,
}


_Comparable = TypeVar("_Comparable", str, int, float)


def _compare(op: str, left: _Comparable, right: _Comparable) -> bool:
    if op == "==":
        return left == right
    if op == "!=":
        return left != right
    if op == "<":
        return left < right
    if op == "<=":
        return left <= right
    if op == ">":
        return left > right
    return left >= right


class ExpressionError(ValueError):
    """Unsupported, invalid, or resource-bounded expression."""


class NumberSyntaxError(ExpressionError):
    """A scalar is not numeric; string comparison can be used."""


class NumericLimitError(ExpressionError):
    """Never reinterpret a resource-bounded number as an ordinary string."""


def number(text: str) -> int | float:
    text = text.strip(" \t\n\r\v\f")
    if len(text) > 128:
        raise NumericLimitError("numeric operand exceeds 128 characters")
    integer = _tcl_integer(text)
    if integer is not None:
        if integer.bit_length() > 256:
            raise NumericLimitError("integer exceeds 256 bits")
        return integer
    if text.lower().lstrip("+-") in {"inf", "infinity", "nan"}:
        raise NumericLimitError("non-finite numbers are not modeled")
    if _FLOAT.fullmatch(text):
        value = float(text)
        if math.isfinite(value):
            return value
        raise NumericLimitError("non-finite arithmetic input")
    raise NumberSyntaxError(f"not a supported finite Tcl number: {text[:64]!r}")


def boolean(text: str) -> bool:
    try:
        return number(text) != 0
    except NumberSyntaxError:
        values = {"true": True, "false": False, "yes": True, "no": False, "on": True, "off": False}
        matches = {v for k, v in values.items() if text and k.startswith(text.lower())}
        if len(matches) == 1:
            return matches.pop()
        raise ExpressionError(f"not a Tcl Boolean: {text[:64]!r}") from None


def numeric_text(value: int | float) -> str:
    if isinstance(value, int):
        if value.bit_length() > 256:
            raise ExpressionError("integer result exceeds 256 bits")
        return str(value)
    if not math.isfinite(value):
        raise ExpressionError("non-finite arithmetic result")
    return re.sub(r"e([+-])0+(\d+)$", r"e\1\2", repr(value))


@dataclass(frozen=True)
class Node:
    op: str
    value: str = ""
    children: tuple[Node, ...] = ()


class Expression:
    """Pratt parser with lazy Boolean and conditional evaluation."""

    def __init__(self, text: str, resolve: Callable[[str], str], max_nodes: int = 512):
        if len(text) > 16_384:
            raise ExpressionError("expression exceeds 16384 characters")
        self.resolve = resolve
        self.tokens: list[tuple[str, str]] = []
        i = 0
        while i < len(text):
            if text[i] in " \t\r\n\v\f":
                i += 1
                continue
            start = i
            char = text[i]
            if char == "$":
                if text[i + 1 : i + 2] == "{":
                    end = text.find("}", i + 2)
                    if end < 0:
                        raise ExpressionError("unclosed expression variable")
                    name = text[i + 2 : end]
                    i = end + 1
                else:
                    match = re.match(r"[A-Za-z_][A-Za-z0-9_]*", text[i + 1 :])
                    if match is None:
                        raise ExpressionError("unsupported expression variable")
                    name = match.group(0)
                    i += 1 + len(name)
                if NAME.fullmatch(name) is None:
                    raise ExpressionError("array/namespace variables are not supported")
                self.tokens.append(("variable", name))
            elif char in '"{':
                quote = char
                depth = 1
                i += 1
                while i < len(text):
                    c = text[i]
                    if c == "\\":
                        i += 2
                        continue
                    if quote == "{" and c == "{":
                        depth += 1
                    if c == ("}" if quote == "{" else '"'):
                        depth -= 1
                        if depth == 0:
                            break
                    if quote == '"' and c in "$[":
                        raise ExpressionError("substitution inside expression strings is not supported")
                    i += 1
                if i >= len(text):
                    raise ExpressionError("unclosed expression string")
                i += 1
                self.tokens.append(("literal", decode_tcl_word(text[start:i])))
            elif match := _NUMBER.match(text, i):
                self.tokens.append(("number", match.group(0)))
                i = match.end()
            elif match := re.match(r"[A-Za-z_][A-Za-z0-9_]*", text[i:]):
                word = match.group(0)
                if word not in {"eq", "ne"}:
                    boolean(word)
                self.tokens.append(("op", word) if word in {"eq", "ne"} else ("boolean", word))
                i += len(word)
            else:
                op = text[i : i + 2]
                if op not in _PREC:
                    op = char
                if op not in _PREC and op not in {"!", "(", ")", "?", ":"}:
                    raise ExpressionError(f"unsupported expression operator at offset {i}")
                self.tokens.append(("op", op))
                i += len(op)
            if len(self.tokens) > max_nodes:
                raise ExpressionError("expression token limit exceeded")
        self.tokens.append(("end", ""))
        self.pos = 0
        self.root = self.parse(0, 0)
        if self.tokens[self.pos][0] != "end":
            raise ExpressionError("unexpected trailing expression tokens")

    def parse(self, minimum: int, depth: int) -> Node:
        if depth > 64:
            raise ExpressionError("expression nesting limit exceeded")
        kind, value = self.tokens[self.pos]
        self.pos += 1
        if kind in {"literal", "variable", "number", "boolean"}:
            node = Node(kind, value)
        elif value in {"+", "-", "!"}:
            node = Node("unary" + value, children=(self.parse(7, depth + 1),))
        elif value == "(":
            node = self.parse(0, depth + 1)
            if self.tokens[self.pos][1] != ")":
                raise ExpressionError("unclosed expression parentheses")
            self.pos += 1
        else:
            raise ExpressionError("expected expression operand")
        while True:
            op = self.tokens[self.pos][1]
            precedence = _PREC.get(op, -1)
            if precedence < minimum:
                break
            self.pos += 1
            node = Node(op, children=(node, self.parse(precedence + 1, depth + 1)))
        if minimum == 0 and self.tokens[self.pos][1] == "?":
            self.pos += 1
            yes = self.parse(0, depth + 1)
            if self.tokens[self.pos][1] != ":":
                raise ExpressionError("conditional expression needs ':'")
            self.pos += 1
            node = Node("?:", children=(node, yes, self.parse(0, depth + 1)))
        return node

    def result(self) -> str:
        raw = self.evaluate()
        try:
            return numeric_text(number(raw))
        except NumberSyntaxError:
            return raw

    def evaluate(self, node: Node | None = None, depth: int = 0) -> str:
        if depth > 64:
            raise ExpressionError("expression evaluation nesting limit exceeded")
        node = self.root if node is None else node
        op = node.op
        if op == "variable":
            return self.resolve(node.value)
        if op == "literal":
            return node.value
        if op == "number":
            number(node.value)
            return node.value
        if op == "boolean":
            boolean(node.value)
            return node.value
        a = self.evaluate(node.children[0], depth + 1)
        if op == "?:":
            return self.evaluate(node.children[1 if boolean(a) else 2], depth + 1)
        if op == "&&" and not boolean(a):
            return "0"
        if op == "||" and boolean(a):
            return "1"
        if op.startswith("unary"):
            if op == "unary!":
                return str(int(not boolean(a)))
            return numeric_text(number(a) if op == "unary+" else -number(a))
        b = self.evaluate(node.children[1], depth + 1)
        if op in {"&&", "||"}:
            return str(int(boolean(b)))
        if op in {"eq", "ne"}:
            return str(int((a == b) if op == "eq" else (a != b)))
        if op in {"==", "!=", "<", "<=", ">", ">="}:
            try:
                left: str | int | float = number(a)
                right: str | int | float = number(b)
            except NumberSyntaxError:
                left, right = a, b
            if isinstance(left, str) and isinstance(right, str):
                return str(int(_compare(op, left, right)))
            if not isinstance(left, str) and not isinstance(right, str):
                return str(int(_compare(op, left, right)))
            raise ExpressionError("inconsistent comparison operands")
        x, y = number(a), number(b)
        if op == "+":
            return numeric_text(x + y)
        if op == "-":
            return numeric_text(x - y)
        if op == "*":
            return numeric_text(x * y)
        if op in {"/", "%"} and y == 0:
            raise ExpressionError("division by zero")
        if op == "/":
            return numeric_text(x // y if isinstance(x, int) and isinstance(y, int) else x / y)
        if op == "%" and isinstance(x, int) and isinstance(y, int):
            return numeric_text(x % y)
        raise ExpressionError("remainder requires integer operands")
