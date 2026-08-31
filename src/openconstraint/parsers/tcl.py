"""A deliberately non-executing Tcl/SDC lexer.

SDC files are Tcl programs.  OpenConstraint never evaluates them in its static
backend; this module only separates commands and words while respecting Tcl's
braces, quotes, brackets, comments, and continuation lines.
"""

from __future__ import annotations

from dataclasses import dataclass

from openconstraint.model import SourceLocation


@dataclass(frozen=True, slots=True)
class TclCommand:
    raw: str
    words: tuple[str, ...]
    location: SourceLocation

    @property
    def name(self) -> str:
        return unquote(self.words[0]) if self.words else ""


@dataclass(frozen=True, slots=True)
class TclParseIssue:
    message: str
    location: SourceLocation


def unquote(word: str) -> str:
    word = word.strip()
    if len(word) >= 2 and ((word[0] == "{" and word[-1] == "}") or (word[0] == '"' and word[-1] == '"')):
        return word[1:-1]
    return word


def _command_chunks(text: str) -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
    chunks: list[tuple[str, int]] = []
    issues: list[tuple[str, int]] = []
    buffer: list[str] = []
    line = 1
    start_line = 1
    brace_depth = 0
    bracket_depth = 0
    quote = False
    escaped = False
    comment = False
    at_word_start = True
    index = 0

    def flush() -> None:
        nonlocal buffer, start_line, at_word_start
        raw = "".join(buffer).strip()
        if raw:
            chunks.append((raw, start_line))
        buffer = []
        start_line = line
        at_word_start = True

    while index < len(text):
        char = text[index]
        if comment:
            if char == "\n":
                comment = False
                if brace_depth == 0 and bracket_depth == 0 and not quote:
                    flush()
                else:
                    buffer.append(char)
                line += 1
                start_line = line if not buffer else start_line
            index += 1
            continue

        if escaped:
            if char == "\n":
                buffer.append(" ")
                line += 1
            else:
                buffer.extend(("\\", char))
            escaped = False
            at_word_start = False
            index += 1
            continue

        if char == "\\":
            escaped = True
            index += 1
            continue

        if char == "#" and at_word_start and brace_depth == 0 and not quote:
            comment = True
            index += 1
            continue

        if char == '"' and brace_depth == 0:
            quote = not quote
            buffer.append(char)
            at_word_start = False
        elif not quote:
            if char == "{":
                brace_depth += 1
                buffer.append(char)
                at_word_start = False
            elif char == "}":
                brace_depth -= 1
                if brace_depth < 0:
                    issues.append(("unexpected closing brace", line))
                    brace_depth = 0
                buffer.append(char)
                at_word_start = False
            elif brace_depth == 0 and char == "[":
                bracket_depth += 1
                buffer.append(char)
                at_word_start = False
            elif brace_depth == 0 and char == "]":
                bracket_depth -= 1
                if bracket_depth < 0:
                    issues.append(("unexpected closing bracket", line))
                    bracket_depth = 0
                buffer.append(char)
                at_word_start = False
            elif brace_depth == 0 and bracket_depth == 0 and char in (";", "\n"):
                flush()
            else:
                buffer.append(char)
                at_word_start = char.isspace()
        else:
            buffer.append(char)

        if char == "\n":
            line += 1
            if not buffer:
                start_line = line
        index += 1

    if escaped:
        buffer.append("\\")
    flush()
    if quote:
        issues.append(("unterminated quoted word", line))
    if brace_depth:
        issues.append(("unterminated brace group", line))
    if bracket_depth:
        issues.append(("unterminated command substitution", line))
    return chunks, issues


def split_words(command: str) -> tuple[str, ...]:
    words: list[str] = []
    buffer: list[str] = []
    brace_depth = 0
    bracket_depth = 0
    quote = False
    escaped = False

    def flush() -> None:
        nonlocal buffer
        if buffer:
            words.append("".join(buffer))
            buffer = []

    for char in command:
        if escaped:
            buffer.extend(("\\", char))
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == '"' and brace_depth == 0:
            quote = not quote
            buffer.append(char)
            continue
        if not quote:
            if char == "{":
                brace_depth += 1
            elif char == "}":
                brace_depth = max(0, brace_depth - 1)
            elif brace_depth == 0 and char == "[":
                bracket_depth += 1
            elif brace_depth == 0 and char == "]":
                bracket_depth = max(0, bracket_depth - 1)
            elif char.isspace() and brace_depth == 0 and bracket_depth == 0:
                flush()
                continue
        buffer.append(char)
    if escaped:
        buffer.append("\\")
    flush()
    return tuple(words)


def parse_tcl(text: str, path: str) -> tuple[list[TclCommand], list[TclParseIssue]]:
    chunks, raw_issues = _command_chunks(text)
    commands = [
        TclCommand(raw=raw, words=split_words(raw), location=SourceLocation(path, line, 1))
        for raw, line in chunks
        if split_words(raw)
    ]
    issues = [TclParseIssue(message, SourceLocation(path, line, 1)) for message, line in raw_issues]
    return commands, issues


def bracket_body(word: str) -> str | None:
    """Return the body when *word* is exactly one bracket substitution."""

    candidate = unquote(word).strip()
    if not (candidate.startswith("[") and candidate.endswith("]")):
        return None
    depth = 0
    brace_depth = 0
    quote = False
    escaped = False
    for index, char in enumerate(candidate):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "{" and not quote:
            brace_depth += 1
        elif char == "}" and not quote and brace_depth:
            brace_depth -= 1
        elif brace_depth:
            continue
        elif char == '"':
            quote = not quote
        elif char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0 and index != len(candidate) - 1:
                return None
    return candidate[1:-1] if depth == 0 else None
