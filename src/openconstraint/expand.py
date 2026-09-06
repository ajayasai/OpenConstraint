"""Bounded, non-host-executing Tcl expansion into the supported static SDC dialect.

Collections remain typed symbolic queries. Their cardinality or contents are
never guessed. Unsupported evaluation fails the whole expansion, not one line.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from hashlib import sha256
from importlib.resources import files
from pathlib import Path
from typing import Any

from openconstraint.expand_expr import NAME, Expression, ExpressionError, boolean, number, numeric_text
from openconstraint.functional import FunctionalInputError, read_functional_json
from openconstraint.parsers.sdc import (
    _COMMAND_GRAMMARS,
    _QUERY_COMMAND_ALIASES,
    _SELECTOR_VALUE_OPTIONS,
    MODELED_SDC_COMMANDS,
    QUERY_KINDS,
    _canonical_modeled_option,
    _normalize_selector_option,
    parse_sdc_text,
)
from openconstraint.parsers.tcl import (
    TclCommand,
    TclSyntaxError,
    _backslash_substitution,
    bracket_body,
    decode_tcl_word,
    parse_tcl,
    split_tcl_list,
    tcl_word_has_substitution,
)
from openconstraint.version import __version__

ALGORITHM = "bounded-symbolic-tcl-v1"
SCHEMA_VERSION = "1.0.0"
_QUERY_NAMES = frozenset(QUERY_KINDS) | {"get_port", "get_pin", "get_net", "get_clock", "get_cell"}
_BUILTINS = frozenset(
    {
        "set",
        "unset",
        "incr",
        "append",
        "list",
        "concat",
        "llength",
        "lindex",
        "lappend",
        "expr",
        "if",
        "foreach",
        "for",
        "while",
        "proc",
        "return",
        "break",
        "continue",
        "source",
    }
)
_RESERVED = _BUILTINS | _QUERY_NAMES | MODELED_SDC_COMMANDS
_SOURCE_ID = re.compile(r"[A-Za-z0-9_./-]{1,128}\Z", re.ASCII)


class ExpansionError(ValueError):
    """Expansion cannot preserve the semantics of the requested script."""


class ExpansionLimitError(ExpansionError):
    """A declared resource budget has been exhausted."""


@dataclass(frozen=True)
class ExpansionLimits:
    max_source_bytes: int = 2 * 1024 * 1024
    max_steps: int = 20_000
    max_iterations: int = 10_000
    max_commands: int = 10_000
    max_output_bytes: int = 4 * 1024 * 1024
    max_value_chars: int = 65_536
    max_live_chars: int = 2 * 1024 * 1024
    max_work_chars: int = 32 * 1024 * 1024
    max_depth: int = 32
    max_variables: int = 1024
    max_procedures: int = 128
    max_sources: int = 128
    max_list_elements: int = 4096

    def __post_init__(self) -> None:
        for name, descriptor in self.__dataclass_fields__.items():
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
            ceiling = descriptor.default
            if not isinstance(ceiling, int):
                raise TypeError("invalid implementation limit")
            if value > ceiling:
                raise ValueError(f"{name} may be lowered but not exceed the implementation ceiling")


@dataclass(frozen=True)
class Query:
    """A statically representable collection, not its unknown design members."""

    text: str
    clock_epoch: int | None
    context_epoch: int


@dataclass(frozen=True)
class TclList:
    """List content, with scalar coercion intentionally forbidden.

    Tcl may retain or regenerate a list's string representation depending on
    object history. Restricting typed lists to list-valued roles avoids guessing
    that representation in comparisons, concatenation, or scalar names.
    """

    elements: tuple[str, ...]


Value = str | Query | TclList


def quote(value: str) -> str:
    """Encode exactly one substitution-free Tcl word, including literal newlines."""
    if "\x00" in value or any(0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ExpansionError("NUL and Unicode surrogates are not supported")
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
    escaped = escaped.replace("[", "\\[").replace("]", "\\]")
    escaped = escaped.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return '"' + escaped + '"'


def _render(value: Value) -> str:
    if isinstance(value, Query):
        return value.text
    if isinstance(value, TclList):
        return quote(" ".join(quote(item) for item in value.elements))
    return quote(value)


def _scalar(value: Value) -> str:
    if isinstance(value, TclList):
        raise ExpansionError("generated list used as scalar; Tcl list string-representation coercion is not modeled")
    if isinstance(value, Query):
        raise ExpansionError(
            "design collection needs object resolution; scalar coercion or collection iteration is not supported"
        )
    return value


def _digest(value: object) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    ).hexdigest()


@dataclass(frozen=True)
class Origin:
    source: str
    enclosing_line: int
    operation: str
    iteration: int | None = None


@dataclass(frozen=True)
class Procedure:
    parameters: tuple[tuple[str, str | None], ...]
    variadic: bool
    body: str
    origin: Origin


class _Return(Exception):
    def __init__(self, value: Value):
        self.value = value


class _Break(Exception):
    pass


class _Continue(Exception):
    pass


class Expander:
    """A fresh interpreter instance for each explicit mode/configuration."""

    def __init__(self, sources: Mapping[str, str], defines: Mapping[str, str], limits: ExpansionLimits):
        self.limits = limits
        if not sources or len(sources) > limits.max_sources:
            raise ExpansionError("supply between one and max_sources explicit sources")
        self.sources = dict(sources)
        total_bytes = 0
        for alias, text in self.sources.items():
            if not isinstance(alias, str) or not _SOURCE_ID.fullmatch(alias):
                raise ExpansionError("invalid logical source ID")
            if not isinstance(text, str):
                raise ExpansionError("source text must be UTF-8 text")
            if len(text) > limits.max_source_bytes:
                raise ExpansionLimitError("source size limit exceeded")
            quote(text)  # Validate characters without interpreting any code.
            total_bytes += len(text.encode("utf-8"))
        if total_bytes > limits.max_source_bytes:
            raise ExpansionLimitError("aggregate source size limit exceeded")
        self.envs: list[dict[str, Value]] = [{}]
        self.procedures: dict[str, Procedure] = {}
        self.procedure_chars = 0
        self.stack: list[Origin] = []
        self.active_sources: list[str] = []
        self.used_sources: set[str] = set()
        self.clock_epoch = self.context_epoch = 0
        self.rows: list[dict[str, Any]] = []
        self.steps = self.iterations = self.output_bytes = self.work_chars = self.live_chars = self.depth = 0
        for name, value in defines.items():
            if not isinstance(value, str):
                raise ExpansionError("defines must be strings")
            self.assign(name, value)

    def work(self, characters: int) -> None:
        self.work_chars += characters
        if self.work_chars > self.limits.max_work_chars:
            raise ExpansionLimitError("max_work_chars exceeded")

    def value(self, value: Value) -> Value:
        size = len(value) if isinstance(value, str) else len(_render(value))
        if size > self.limits.max_value_chars:
            raise ExpansionLimitError("max_value_chars exceeded")
        self.work(size)
        return value

    def assign(self, name: str, value: Value) -> Value:
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise ExpansionError("only simple local variable names are supported (no arrays/namespaces)")
        value = self.value(value)
        env = self.envs[-1]
        if name not in env and len(env) >= self.limits.max_variables:
            raise ExpansionLimitError("max_variables exceeded")
        self.live_chars += len(_render(value)) - (len(_render(env[name])) if name in env else 0)
        if self.live_chars > self.limits.max_live_chars:
            raise ExpansionLimitError("max_live_chars exceeded")
        env[name] = value
        return value

    def lookup(self, name: str) -> Value:
        if not NAME.fullmatch(name):
            raise ExpansionError("array/namespace variables are not supported")
        if name not in self.envs[-1]:
            raise ExpansionError(f"undefined variable {name!r}")
        return self.envs[-1][name]

    def scalar_lookup(self, name: str) -> str:
        return _scalar(self.lookup(name))

    def words(self, value: Value) -> tuple[str, ...]:
        if isinstance(value, TclList):
            result = value.elements
            self.work(sum(len(item) for item in result))
        else:
            text = _scalar(value)
            self.work(len(text))
            result = split_tcl_list(text)
        if len(result) > self.limits.max_list_elements:
            raise ExpansionLimitError("max_list_elements exceeded")
        return result

    def expression(self, text: str) -> str:
        self.work(len(text))
        return Expression(text, self.scalar_lookup).result()

    def word(self, raw: str) -> Value:
        self.work(len(raw))
        if len(raw) > self.limits.max_value_chars:
            raise ExpansionLimitError("source word exceeds max_value_chars")
        if raw.startswith("{*}") and len(raw) > 3:
            raise ExpansionError("argument expansion {*} is not supported")
        if raw.startswith("{"):
            return self.value(decode_tcl_word(raw))
        text = raw[1:-1] if raw.startswith('"') and raw.endswith('"') else raw
        pieces: list[Value] = []
        literal: list[str] = []

        def flush() -> None:
            if literal:
                pieces.append("".join(literal))
                literal.clear()

        i = 0
        while i < len(text):
            char = text[i]
            if char == "\\":
                replacement, i = _backslash_substitution(text, i)
                literal.append(replacement)
                continue
            if char == "$":
                if text[i + 1 : i + 2] == "{":
                    end = text.find("}", i + 2)
                    if end < 0:
                        raise ExpansionError("unclosed variable substitution")
                    name = text[i + 2 : end]
                    i = end + 1
                else:
                    match = re.match(r"[A-Za-z0-9_:]+", text[i + 1 :])
                    if match is None:
                        literal.append("$")
                        i += 1
                        continue
                    name = match.group(0)
                    i += 1 + len(name)
                    if text[i : i + 1] == "(":
                        raise ExpansionError("array variables are not supported")
                flush()
                pieces.append(self.lookup(name))
                continue
            if char == "[":
                flush()
                end = text.find("]", i + 1)
                body = None
                while end >= 0:
                    self.work(end + 1 - i)
                    body = bracket_body(text[i : end + 1])
                    if body is not None:
                        break
                    end = text.find("]", end + 1)
                if body is None:
                    raise ExpansionError("unclosed command substitution")
                pieces.append(self.script(body, allow_emit=False))
                i = end + 1
                continue
            literal.append(char)
            i += 1
        flush()
        queries = [p for p in pieces if isinstance(p, (Query, TclList))]
        if queries:
            if len(queries) != 1 or any(p != "" for p in pieces if isinstance(p, str)):
                raise ExpansionError("a typed collection/list must occupy a whole Tcl word")
            return self.value(queries[0])
        return self.value("".join(_scalar(p) for p in pieces))

    def body(self, raw: str) -> str:
        if not raw.startswith("{") or raw.startswith("{*}"):
            raise ExpansionError("control/procedure bodies must be literal braced scripts")
        return decode_tcl_word(raw)

    def script(self, text: str, *, source: str | None = None, allow_emit: bool = True) -> Value:
        self.depth += 1
        try:
            if self.depth > self.limits.max_depth:
                raise ExpansionLimitError("max_depth exceeded")
            self.work(len(text))
            commands, issues = parse_tcl(text, source or "<expanded-body>")
            if issues:
                raise ExpansionError(issues[0].message)
            value: Value = ""
            for command in commands:
                self.steps += 1
                if self.steps > self.limits.max_steps:
                    raise ExpansionLimitError("max_steps exceeded")
                origin = (
                    Origin(source, command.location.line, command.name)
                    if source
                    else Origin(self.stack[-1].source, self.stack[-1].enclosing_line, command.name)
                )
                self.stack.append(origin)
                try:
                    value = self.command(command, allow_emit)
                except (ExpansionError, ExpressionError, TclSyntaxError) as error:
                    if isinstance(error, ExpansionError) and getattr(error, "located", False):
                        raise
                    wrapped = (
                        ExpansionLimitError(str(error))
                        if isinstance(error, ExpansionLimitError)
                        else ExpansionError(str(error))
                    )
                    wrapped.args = (f"{origin.source}:{origin.enclosing_line} ({origin.operation}): {error}",)
                    wrapped.located = True  # type: ignore[attr-defined]
                    raise wrapped from error
                finally:
                    self.stack.pop()
            return value
        finally:
            self.depth -= 1

    def source(self, alias: str, allow_emit: bool) -> Value:
        if alias not in self.sources:
            raise ExpansionError(f"source {alias!r} is not explicitly supplied; no filesystem search is performed")
        if alias in self.active_sources:
            raise ExpansionError("cyclic source inclusion")
        self.active_sources.append(alias)
        self.used_sources.add(alias)
        try:
            try:
                return self.script(self.sources[alias], source=alias, allow_emit=allow_emit)
            except _Return as returned:
                return returned.value
        finally:
            self.active_sources.pop()

    def tick(self) -> None:
        self.iterations += 1
        if self.iterations > self.limits.max_iterations:
            raise ExpansionLimitError("max_iterations exceeded")

    def loop_body(self, body: str, index: int, allow_emit: bool) -> bool:
        parent = self.stack[-1]
        self.stack.append(Origin(parent.source, parent.enclosing_line, "iteration", index))
        try:
            self.script(body, allow_emit=allow_emit)
        except _Break:
            return False
        except _Continue:
            pass
        finally:
            self.stack.pop()
        return True

    def check_list_roles(self, name: str, args: list[Value]) -> None:
        """A generated list may enter only fields with Tcl-list semantics."""
        list_options = {
            "-waveform",
            "-edges",
            "-edge_shift",
            "-from",
            "-to",
            "-through",
            "-rise_from",
            "-fall_from",
            "-rise_to",
            "-fall_to",
            "-rise_through",
            "-fall_through",
            "-source",
            "-master_clock",
            "-clock",
            "-group",
            "-of_objects",
        }
        expected: str | None = None
        positional = 0
        query_name = _QUERY_COMMAND_ALIASES.get(name, name)
        for arg in args:
            if expected is not None:
                if isinstance(arg, TclList) and expected not in list_options:
                    raise ExpansionError(f"generated list cannot supply scalar option {expected}")
                expected = None
                continue
            if isinstance(arg, str) and len(arg) >= 2 and arg[0] == "-" and arg[1].isalpha():
                if name in _COMMAND_GRAMMARS:
                    option = _canonical_modeled_option(arg, _COMMAND_GRAMMARS[name])
                    if option is not None and option[1] == "value":
                        expected = option[0]
                else:
                    canonical = _normalize_selector_option(query_name, quote(arg))
                    if canonical in _SELECTOR_VALUE_OPTIONS[query_name]:
                        expected = canonical
                continue
            if isinstance(arg, TclList):
                positional_lists = name in _QUERY_NAMES or name in {"create_clock", "create_generated_clock"}
                positional_lists = (
                    positional_lists or name in {"set_input_delay", "set_output_delay"} and positional > 0
                )
                if not positional_lists:
                    raise ExpansionError("generated list cannot supply a scalar positional operand")
            positional += 1

    def render(self, value: Value) -> str:
        if isinstance(value, Query) and (
            value.context_epoch != self.context_epoch
            or value.clock_epoch is not None
            and value.clock_epoch != self.clock_epoch
        ):
            raise ExpansionError(
                "symbolic query was captured before a clock/design mutation; deferred evaluation would change membership"
            )
        return _render(value)

    def condition_word(self, raw: str) -> str:
        if tcl_word_has_substitution(raw):
            raise ExpansionError("condition substitutions must be deferred inside a braced expression")
        return decode_tcl_word(raw)

    def command(self, command: TclCommand, allow_emit: bool) -> Value:
        if tcl_word_has_substitution(command.words[0]):
            raise ExpansionError("dynamic command names are not supported")
        name = command.name
        raw = command.words[1:]
        if name in {"if", "foreach", "for", "while", "proc"}:
            return self.control(name, raw, allow_emit)
        args = [self.word(w) for w in raw]
        if name in _QUERY_NAMES or name in MODELED_SDC_COMMANDS:
            self.check_list_roles(name, args)
            rendered = name + (" " + " ".join(self.render(v) for v in args) if args else "")
            self.value(rendered)
            if name in _QUERY_NAMES:
                # Resolve neither membership nor cardinality. Existing query parser
                # checks the symbolic expression as part of the emitted command.
                query = "[" + rendered + "]"
                checked = parse_sdc_text("set_false_path -from " + query, "<query>")
                if (
                    checked.issues
                    or not checked.commands
                    or any(sel.parse_error or sel.dynamic for sel in checked.commands[0].selectors)
                ):
                    raise ExpansionError("unsupported symbolic query")
                clock_dependent = name in {"get_clocks", "get_clock", "all_clocks"} or any(
                    isinstance(v, Query) and v.clock_epoch is not None for v in args
                )
                return Query(query, self.clock_epoch if clock_dependent else None, self.context_epoch)
            if not allow_emit:
                raise ExpansionError("SDC side effects in substitutions are not supported")
            doc = parse_sdc_text(rendered, "<normalized>")
            if len(doc.commands) != 1 or doc.issues:
                raise ExpansionError("generated SDC is not one statically parseable command")
            parsed = doc.commands[0]
            if (
                parsed.parse_errors
                or parsed.opaque_substitutions
                or any(s.parse_error or s.dynamic for s in parsed.selectors)
            ):
                raise ExpansionError("generated command or collection is outside the static SDC dialect")
            self.output_bytes += len(rendered.encode("utf-8")) + 1
            if self.output_bytes > self.limits.max_output_bytes or len(self.rows) >= self.limits.max_commands:
                raise ExpansionLimitError("normalized SDC output limit exceeded")
            row = {"index": len(self.rows), "sdc": rendered, "origin": [asdict(o) for o in self.stack]}
            self.work(len(json.dumps(row)))
            self.rows.append(row)
            if name in {"create_clock", "create_generated_clock"}:
                self.clock_epoch += 1
            if name == "current_design":
                self.context_epoch += 1
            return ""
        if name in self.procedures:
            return self.call(name, args, allow_emit)
        if name not in _BUILTINS:
            raise ExpansionError(
                f"unsupported command {name!r}; host commands and arbitrary Tcl execution are disabled"
            )
        if name == "set" and len(args) in {1, 2}:
            key = _scalar(args[0])
            return self.lookup(key) if len(args) == 1 else self.assign(key, args[1])
        if name == "unset" and args:
            for arg in args:
                key = _scalar(arg)
                old = self.lookup(key)
                self.live_chars -= len(_render(old))
                del self.envs[-1][key]
            return ""
        if name in {"incr", "append", "lappend"} and args:
            key = _scalar(args[0])
            if not NAME.fullmatch(key):
                raise ExpansionError("invalid variable name")
            old = self.envs[-1].get(key, "0" if name == "incr" else "")
            if name == "incr" and len(args) in {1, 2}:
                a, b = number(_scalar(old)), number(_scalar(args[1])) if len(args) == 2 else 1
                if not isinstance(a, int) or not isinstance(b, int):
                    raise ExpansionError("incr requires integer operands")
                return self.assign(key, numeric_text(a + b))
            if name == "append":
                return self.assign(key, _scalar(old) + "".join(_scalar(a) for a in args[1:]))
            if name == "lappend":
                if len(args) == 1:
                    self.words(old)
                    return self.assign(key, old)
                appended = [*self.words(old), *(_scalar(a) for a in args[1:])]
                return self.assign(key, self.make_list(appended))
        if name == "list":
            return self.make_list([_scalar(a) for a in args])
        if name == "concat":
            values: list[str] = []
            for arg in args:
                values.extend(self.words(arg))
                if len(values) > self.limits.max_list_elements:
                    raise ExpansionLimitError("max_list_elements exceeded")
            return self.make_list(values)
        if name == "llength" and len(args) == 1:
            return str(len(self.words(args[0])))
        if name == "lindex" and len(args) == 2:
            list_values = self.words(args[0])
            index_text = _scalar(args[1])
            if re.fullmatch(r"end(?:-[0-9]+)?", index_text):
                index = len(list_values) - 1 - (int(index_text[4:]) if len(index_text) > 3 else 0)
            else:
                numeric_index = number(index_text)
                if not isinstance(numeric_index, int):
                    raise ExpansionError("list index must be an integer")
                index = numeric_index
            return list_values[index] if 0 <= index < len(list_values) else ""
        if name == "expr" and len(args) == 1:
            return self.expression(_scalar(args[0]))
        if name == "source" and len(args) == 1:
            return self.source(_scalar(args[0]), allow_emit)
        if name == "return" and len(args) <= 1:
            raise _Return(args[0] if args else "")
        if name == "break" and not args:
            raise _Break()
        if name == "continue" and not args:
            raise _Continue()
        raise ExpansionError(f"unsupported arity/options for {name!r}")

    def make_list(self, values: Sequence[str]) -> TclList:
        if len(values) > self.limits.max_list_elements:
            raise ExpansionLimitError("max_list_elements exceeded")
        # Tcl list elements and command words use the same escaping for the
        # supported scalar alphabet. The whole list is later one command word.
        value = TclList(tuple(values))
        self.value(value)
        return value

    def control(self, name: str, raw: tuple[str, ...], allow_emit: bool) -> Value:
        if name == "proc" and len(raw) == 3:
            proc_name = _scalar(self.word(raw[0]))
            if not NAME.fullmatch(proc_name) or proc_name in _RESERVED:
                raise ExpansionError("procedure name must be simple and cannot shadow a builtin")
            parameters: list[tuple[str, str | None]] = []
            specs = self.words(self.word(raw[1]))
            variadic = bool(specs and specs[-1] == "args")
            for spec in specs[:-1] if variadic else specs:
                parts = self.words(spec)
                if len(parts) not in {1, 2} or not NAME.fullmatch(parts[0]) or parts[0] == "args":
                    raise ExpansionError("unsupported procedure argument")
                if any(p[0] == parts[0] for p in parameters):
                    raise ExpansionError("duplicate procedure parameter")
                parameters.append((parts[0], parts[1] if len(parts) == 2 else None))
            if variadic and any(p[0] == "args" for p in parameters):
                raise ExpansionError("duplicate args parameter")
            body = self.body(raw[2])
            self.procedure_chars += len(body) - (
                len(self.procedures[proc_name].body) if proc_name in self.procedures else 0
            )
            if self.procedure_chars > self.limits.max_live_chars:
                raise ExpansionLimitError("procedure-body retention limit exceeded")
            if proc_name not in self.procedures and len(self.procedures) >= self.limits.max_procedures:
                raise ExpansionLimitError("max_procedures exceeded")
            self.procedures[proc_name] = Procedure(tuple(parameters), variadic, body, self.stack[-1])
            return ""
        if name == "if":
            clauses: list[tuple[str | None, str]] = []
            i = 0
            while i < len(raw):
                if clauses:
                    keyword = decode_tcl_word(raw[i])
                    if keyword == "else" or keyword != "elseif" and i + 1 == len(raw):
                        if keyword == "else":
                            i += 1
                        if i + 1 != len(raw):
                            raise ExpansionError("invalid else clause")
                        clauses.append((None, self.body(raw[i])))
                        i += 1
                        break
                    if keyword != "elseif":
                        raise ExpansionError("unexpected if tail")
                    i += 1
                if i >= len(raw):
                    raise ExpansionError("missing if condition")
                test = self.condition_word(raw[i])
                i += 1
                if i < len(raw) and decode_tcl_word(raw[i]) == "then":
                    i += 1
                if i >= len(raw):
                    raise ExpansionError("missing if body")
                clauses.append((test, self.body(raw[i])))
                i += 1
            if not clauses:
                raise ExpansionError("missing if condition")
            for clause_test, body in clauses:
                if clause_test is None or boolean(self.expression(clause_test)):
                    return self.script(body, allow_emit=allow_emit)
            return ""
        if name == "foreach" and len(raw) >= 3 and len(raw) % 2 == 1:
            body = self.body(raw[-1])
            groups = []
            for i in range(0, len(raw) - 1, 2):
                names = self.words(self.word(raw[i]))
                if not names or any(not NAME.fullmatch(n) for n in names):
                    raise ExpansionError("foreach requires simple scalar variable names")
                values = self.words(self.word(raw[i + 1]))
                groups.append((names, values))
            count = max((len(v) + len(n) - 1) // len(n) for n, v in groups)
            for iteration in range(count):
                self.tick()
                for names, values in groups:
                    for j, variable in enumerate(names):
                        offset = iteration * len(names) + j
                        self.assign(variable, values[offset] if offset < len(values) else "")
                if not self.loop_body(body, iteration, allow_emit):
                    break
            return ""
        if name == "while" and len(raw) == 2 or name == "for" and len(raw) == 4:
            raw_words = list(raw)
            if name == "for":
                start, test, next_raw, body_raw = raw_words[0], raw_words[1], raw_words[2], raw_words[3]
                self.script(self.body(start), allow_emit=allow_emit)
                next_script = self.body(next_raw)
            else:
                test, body_raw = raw[0], raw[1]
                next_script = ""
            # Tcl substitutes the test word once, then expr evaluates it each iteration.
            condition = self.condition_word(test)
            body = self.body(body_raw)
            iteration = 0
            while boolean(self.expression(condition)):
                self.tick()
                if not self.loop_body(body, iteration, allow_emit):
                    break
                self.script(next_script, allow_emit=allow_emit)
                iteration += 1
            return ""
        raise ExpansionError(f"unsupported arity/options for {name!r}")

    def call(self, name: str, args: list[Value], allow_emit: bool) -> Value:
        proc = self.procedures[name]
        if not proc.variadic and len(args) > len(proc.parameters):
            raise ExpansionError("too many procedure arguments")
        self.envs.append({})
        self.stack.append(proc.origin)
        try:
            for i, (parameter, default) in enumerate(proc.parameters):
                if i >= len(args) and default is None:
                    raise ExpansionError("missing procedure argument")
                self.assign(parameter, args[i] if i < len(args) else str(default))
            if proc.variadic:
                self.assign("args", self.make_list([_scalar(a) for a in args[len(proc.parameters) :]]))
            try:
                return self.script(proc.body, allow_emit=allow_emit)
            except _Return as returned:
                return returned.value
            except (_Break, _Continue) as error:
                raise ExpansionError("break/continue cannot cross a procedure boundary") from error
        finally:
            self.live_chars -= sum(len(_render(v)) for v in self.envs.pop().values())
            self.stack.pop()


def expand_sdc(
    sources: Mapping[str, str],
    entries: Sequence[str],
    defines: Mapping[str, str] | None = None,
    limits: ExpansionLimits | None = None,
) -> dict[str, Any]:
    """Return a deterministic provenance pack only after complete successful expansion."""
    selected = limits or ExpansionLimits()
    if not entries or isinstance(entries, str) or len(entries) > selected.max_sources:
        raise ExpansionError("supply a nonempty, bounded sequence of logical entry source IDs")
    expander = Expander(sources, defines or {}, selected)
    try:
        for entry in entries:
            expander.source(entry, True)
    except (_Break, _Continue) as error:
        raise ExpansionError("break/continue outside a loop") from error
    if not expander.rows:
        raise ExpansionError("expansion produced no SDC commands")
    output = "\n".join(row["sdc"] for row in expander.rows) + "\n"
    # Recheck the entire emitted document against parser-wide retention bounds.
    document = parse_sdc_text(output, "<normalized>")
    if document.issues or len(document.commands) != len(expander.rows):
        raise ExpansionError("normalized document exceeds static-parser bounds")
    pack: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "algorithm": ALGORITHM,
        "tool_version": __version__,
        "status": "complete",
        "timing_signoff": False,
        "design_queries_executed": False,
        "entries": list(entries),
        "defines": dict(sorted((defines or {}).items())),
        "sources": [
            {"id": alias, "sha256": sha256(text.encode("utf-8")).hexdigest(), "used": alias in expander.used_sources}
            for alias, text in sorted(sources.items())
        ],
        "limits": asdict(selected),
        "metrics": {
            "steps": expander.steps,
            "iterations": expander.iterations,
            "emitted_commands": len(expander.rows),
            "work_chars": expander.work_chars,
        },
        "commands": expander.rows,
        "sdc": output,
        "sdc_sha256": sha256(output.encode("utf-8")).hexdigest(),
    }
    pack["digest"] = _digest(pack)
    if len(json.dumps(pack).encode()) > 16 * 1024 * 1024:
        raise ExpansionLimitError("provenance pack exceeds 16 MiB")
    return pack


def verify_expansion(expected: Mapping[str, Any], actual_sdc: str, current: Mapping[str, Any]) -> dict[str, Any]:
    """Verify exact artifact integrity and freshly recomputed expansion, not authenticity."""
    copy = dict(expected)
    digest = copy.pop("digest", None)
    integrity = isinstance(digest, str) and digest == _digest(copy)
    artifact = (
        expected.get("sdc") == actual_sdc and expected.get("sdc_sha256") == sha256(actual_sdc.encode()).hexdigest()
    )
    replay = expected == current
    return {
        "verified": bool(integrity and artifact and replay),
        "integrity": integrity,
        "sdc_matches": artifact,
        "replay_matches": replay,
        "timing_signoff": False,
    }


def _assignments(values: Sequence[str], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        key, sep, data = value.partition("=")
        if not sep or not key or key in result:
            raise ExpansionError(f"{label} requires unique NAME=VALUE arguments")
        result[key] = data
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("compile", "verify"):
        command = sub.add_parser(name)
        command.add_argument("--source", action="append", required=True, metavar="ID=PATH")
        command.add_argument("--entry", action="append", required=True, metavar="ID")
        command.add_argument("--define", action="append", default=[], metavar="NAME=VALUE")
        command.add_argument("--max-steps", type=int, default=ExpansionLimits().max_steps)
        command.add_argument("--max-iterations", type=int, default=ExpansionLimits().max_iterations)
        command.add_argument("--output" if name == "compile" else "--pack", type=Path, required=True)
    schema_parser = sub.add_parser("schema")
    schema_parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "schema":
            schema = (files("openconstraint.schemas") / "openconstraint-expansion.schema.json").read_text(
                encoding="utf-8"
            )
            if args.output is None:
                print(schema, end="")
            else:
                with args.output.open("x", encoding="utf-8", newline="\n") as stream:
                    stream.write(schema)
            return 0
        paths = _assignments(args.source, "--source")
        sources: dict[str, str] = {}
        limits = ExpansionLimits(max_steps=args.max_steps, max_iterations=args.max_iterations)
        if len(paths) > limits.max_sources:
            raise ExpansionLimitError("max_sources exceeded")
        retained = 0
        for alias, path in paths.items():
            with Path(path).open("rb") as stream:
                data = stream.read(limits.max_source_bytes - retained + 1)
            retained += len(data)
            if retained > limits.max_source_bytes:
                raise ExpansionLimitError("aggregate source bytes exceeded")
            sources[alias] = data.decode("utf-8")
        result = expand_sdc(sources, args.entry, _assignments(args.define, "--define"), limits)
        if args.command == "verify":
            expected = read_functional_json(args.pack / "provenance.json")
            with (args.pack / "normalized.sdc").open("rb") as stream:
                data = stream.read(limits.max_output_bytes + 1)
            if len(data) > limits.max_output_bytes:
                raise ExpansionLimitError("saved SDC exceeds output limit")
            verification = verify_expansion(expected, data.decode("utf-8"), result)
            print(json.dumps(verification, sort_keys=True))
            return 0 if verification["verified"] else 1
        # Do not write anything until every source has expanded successfully.
        # Existing directories/files/symlinks are refused, never overwritten.
        args.output.mkdir(parents=True, exist_ok=False)
        with (args.output / "normalized.sdc").open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(result["sdc"])
        with (args.output / "provenance.json").open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(result, stream, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False)
            stream.write("\n")
        print(
            json.dumps(
                {"status": "complete", "commands": len(result["commands"]), "digest": result["digest"]}, sort_keys=True
            )
        )
        return 0
    except (OSError, ValueError, UnicodeError, FunctionalInputError) as error:
        print(f"openconstraint-expand: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
