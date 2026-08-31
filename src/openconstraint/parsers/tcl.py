"""A deliberately non-executing Tcl/SDC lexer.

SDC files are Tcl programs.  OpenConstraint never evaluates them in its static
backend; this module only separates commands and words while respecting Tcl's
braces, quotes, brackets, comments, and continuation lines.
"""

from __future__ import annotations

from dataclasses import dataclass

from openconstraint.model import SourceLocation

MAX_TCL_COMMANDS = 50_000
MAX_TCL_PARSE_ISSUES = 1_000
MAX_TCL_LIST_ELEMENTS = 50_000
MAX_TCL_LIST_NESTING = 64
_TRUNCATION_MESSAGE = "Tcl retention limit reached; additional commands or parse issues were omitted"
_TCL_WHITESPACE = " \t\n\v\f\r"


@dataclass(frozen=True, slots=True)
class TclCommand:
    raw: str
    words: tuple[str, ...]
    location: SourceLocation

    @property
    def name(self) -> str:
        if not self.words:
            return ""
        try:
            return decode_tcl_word(self.words[0])
        except TclSyntaxError:
            # The lexer records grouping failures separately. Keeping an
            # undecodable command out of the modeled command set is safer
            # than interpreting its raw spelling as a different command.
            return ""


@dataclass(frozen=True, slots=True)
class TclParseIssue:
    message: str
    location: SourceLocation


def unquote(word: str) -> str:
    word = word.strip(_TCL_WHITESPACE)
    if len(word) >= 2 and ((word[0] == "{" and word[-1] == "}") or (word[0] == '"' and word[-1] == '"')):
        return word[1:-1]
    return word


class TclSyntaxError(ValueError):
    """A Tcl word or list cannot be decoded without evaluating Tcl."""


@dataclass(slots=True)
class _TclLexContext:
    """Lexical state for one command level (the file or one ``[...]``)."""

    brace_depth: int = 0
    quote: bool = False
    at_word_start: bool = True
    at_command_start: bool = True


def _backslash_substitution(text: str, index: int) -> tuple[str, int]:
    """Decode one Tcl backslash sequence and return its replacement/end."""

    if index + 1 >= len(text):
        return "\\", index + 1
    marker = text[index + 1]
    simple = {
        "a": "\a",
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
    }
    if marker in simple:
        return simple[marker], index + 2
    if marker == "\n":
        end = index + 2
        while end < len(text) and text[end] in " \t":
            end += 1
        return " ", end
    if marker in {"x", "u", "U"}:
        width = {"x": 2, "u": 4, "U": 8}[marker]
        end = index + 2
        while end < len(text) and end < index + 2 + width and text[end] in "0123456789abcdefABCDEF":
            end += 1
        if end == index + 2:
            return marker, end
        codepoint = int(text[index + 2 : end], 16)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise TclSyntaxError(f"invalid Tcl Unicode escape U+{codepoint:08X}")
        # OpenSTA's pinned Tcl 8.6 runtime uses the default three-byte Tcl
        # Unicode representation, where an eight-digit escape above the BMP
        # becomes U+FFFD.  Accepting it as a Python astral code point would
        # silently select a different object.  Keep the static subset portable
        # by failing closed instead.
        if marker == "U" and codepoint > 0xFFFF:
            raise TclSyntaxError(f"invalid Tcl Unicode escape U+{codepoint:08X}")
        try:
            return chr(codepoint), end
        except ValueError as error:
            raise TclSyntaxError(f"invalid Tcl Unicode escape U+{codepoint:08X}") from error
    if marker in "01234567":
        end = index + 2
        while end < len(text) and end < index + 4 and text[end] in "01234567":
            candidate = int(text[index + 1 : end + 1], 8)
            if candidate > 0xFF:
                break
            end += 1
        return chr(int(text[index + 1 : end], 8)), end
    return marker, index + 2


def _decode_backslashes(text: str) -> str:
    decoded: list[str] = []
    index = 0
    while index < len(text):
        if text[index] != "\\":
            if 0xD800 <= ord(text[index]) <= 0xDFFF:
                raise TclSyntaxError(f"invalid Unicode surrogate U+{ord(text[index]):08X}")
            decoded.append(text[index])
            index += 1
            continue
        replacement, index = _backslash_substitution(text, index)
        decoded.append(replacement)
    return "".join(decoded)


def _braced_word_end(word: str) -> int | None:
    depth = 0
    escaped = False
    for index, char in enumerate(word):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _quoted_word_end(word: str) -> int | None:
    escaped = False
    for index in range(1, len(word)):
        char = word[index]
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
        elif char == '"':
            return index
    return None


def decode_tcl_word(word: str) -> str:
    """Decode Tcl command-word quoting and backslashes without evaluation.

    Variable and command substitutions deliberately remain as source text;
    callers can use :func:`tcl_word_has_substitution` to fail closed. Braced
    words suppress backslash substitution, as they do in Tcl.
    """

    if not word:
        return ""
    if word[0] == "{":
        end = _braced_word_end(word)
        if end is None:
            raise TclSyntaxError("unmatched open brace in Tcl word")
        if end != len(word) - 1:
            raise TclSyntaxError("extra characters after close-brace in Tcl word")
        value = word[1:end]
        for char in value:
            if 0xD800 <= ord(char) <= 0xDFFF:
                raise TclSyntaxError(f"invalid Unicode surrogate U+{ord(char):08X}")
        return value
    if word[0] == '"':
        end = _quoted_word_end(word)
        if end is None:
            raise TclSyntaxError("unmatched quote in Tcl word")
        if end != len(word) - 1:
            raise TclSyntaxError("extra characters after close-quote in Tcl word")
        return _decode_backslashes(word[1:end])
    return _decode_backslashes(word)


def tcl_word_has_substitution(word: str) -> bool:
    """Return whether a command word contains active variable/command Tcl."""

    active = word.startswith("{*}") and len(word) > 3
    if not word or word[0] == "{":
        return active
    if word[0] == '"':
        end = _quoted_word_end(word)
        text = word[1:end] if end is not None else word[1:]
    else:
        text = word
    index = 0
    while index < len(text):
        char = text[index]
        if 0xD800 <= ord(char) <= 0xDFFF:
            raise TclSyntaxError(f"invalid Unicode surrogate U+{ord(char):08X}")
        if char == "\\":
            _, index = _backslash_substitution(text, index)
            continue
        if char == "[":
            active = True
        if char == "$":
            if index + 1 < len(text) and text[index + 1] == "{":
                closing = text.find("}", index + 2)
                if closing < 0:
                    raise TclSyntaxError("missing close-brace for Tcl variable name")
                active = True
            elif index + 1 < len(text) and (text[index + 1].isalnum() or text[index + 1] in "_:"):
                active = True
        index += 1
    return active


def split_tcl_list_preserving_backslashes(value: str) -> tuple[str, ...]:
    """Split the pattern list used by OpenSTA's ``get_*`` commands.

    OpenSTA doubles command-word backslashes before Tcl iterates the pattern
    list. This parser models that operation directly: backslashes cannot
    create list structure, remain single in bare/quoted elements, and remain
    doubled inside a nested braced list element. No Tcl code is evaluated.
    """

    elements: list[str] = []
    index = 0
    while index < len(value):
        while index < len(value) and value[index] in _TCL_WHITESPACE:
            index += 1
        if index >= len(value):
            break
        if value[index] == "{":
            index += 1
            depth = 1
            element: list[str] = []
            while index < len(value) and depth:
                char = value[index]
                if char == "\\":
                    element.append("\\\\")
                elif char == "{":
                    depth += 1
                    element.append(char)
                elif char == "}":
                    depth -= 1
                    if depth:
                        element.append(char)
                else:
                    element.append(char)
                index += 1
            if depth:
                raise TclSyntaxError("unmatched open brace in Tcl pattern list")
            if index < len(value) and value[index] not in _TCL_WHITESPACE:
                raise TclSyntaxError("extra characters after close-brace in Tcl pattern list")
            elements.append("".join(element))
            continue
        if value[index] == '"':
            index += 1
            element = []
            while index < len(value) and value[index] != '"':
                char = value[index]
                element.append("\\" if char == "\\" else char)
                index += 1
            if index >= len(value):
                raise TclSyntaxError("unmatched quote in Tcl pattern list")
            index += 1
            if index < len(value) and value[index] not in _TCL_WHITESPACE:
                raise TclSyntaxError("extra characters after close-quote in Tcl pattern list")
            elements.append("".join(element))
            continue
        element = []
        while index < len(value) and value[index] not in _TCL_WHITESPACE:
            char = value[index]
            element.append("\\" if char == "\\" else char)
            index += 1
        elements.append("".join(element))
    return tuple(elements)


def split_tcl_list(value: str) -> tuple[str, ...]:
    """Decode a Tcl list without evaluating commands or variables.

    Unlike :func:`split_tcl_list_preserving_backslashes`, which models the
    special pattern-list preparation in OpenSTA's ``get_*`` commands, this is
    a general Tcl-list decoder for already-decoded command operands.  Braced
    elements preserve their contents, quoted and bare elements perform Tcl
    backslash substitution, and malformed structure fails closed.
    """

    elements: list[str] = []
    index = 0
    while index < len(value):
        while index < len(value) and value[index] in _TCL_WHITESPACE:
            index += 1
        if index >= len(value):
            break
        if len(elements) >= MAX_TCL_LIST_ELEMENTS:
            raise TclSyntaxError(f"Tcl list exceeds {MAX_TCL_LIST_ELEMENTS} elements")

        if value[index] == "{":
            index += 1
            depth = 1
            element: list[str] = []
            while index < len(value) and depth:
                char = value[index]
                if 0xD800 <= ord(char) <= 0xDFFF:
                    raise TclSyntaxError(f"invalid Unicode surrogate U+{ord(char):08X}")
                if char == "\\":
                    # Backslashes suppress brace grouping inside a braced
                    # list element but otherwise remain literal.
                    element.append(char)
                    index += 1
                    if index < len(value):
                        escaped = value[index]
                        if 0xD800 <= ord(escaped) <= 0xDFFF:
                            raise TclSyntaxError(f"invalid Unicode surrogate U+{ord(escaped):08X}")
                        element.append(escaped)
                        index += 1
                    continue
                if char == "{":
                    depth += 1
                    if depth > MAX_TCL_LIST_NESTING:
                        raise TclSyntaxError(f"Tcl list exceeds nesting limit {MAX_TCL_LIST_NESTING}")
                    element.append(char)
                elif char == "}":
                    depth -= 1
                    if depth:
                        element.append(char)
                else:
                    element.append(char)
                index += 1
            if depth:
                raise TclSyntaxError("unmatched open brace in Tcl list")
            if index < len(value) and value[index] not in _TCL_WHITESPACE:
                raise TclSyntaxError("extra characters after close-brace in Tcl list")
            elements.append("".join(element))
            continue

        if value[index] == '"':
            index += 1
            element = []
            while index < len(value) and value[index] != '"':
                char = value[index]
                if 0xD800 <= ord(char) <= 0xDFFF:
                    raise TclSyntaxError(f"invalid Unicode surrogate U+{ord(char):08X}")
                if char == "\\":
                    replacement, index = _backslash_substitution(value, index)
                    element.append(replacement)
                else:
                    element.append(char)
                    index += 1
            if index >= len(value):
                raise TclSyntaxError("unmatched quote in Tcl list")
            index += 1
            if index < len(value) and value[index] not in _TCL_WHITESPACE:
                raise TclSyntaxError("extra characters after close-quote in Tcl list")
            elements.append("".join(element))
            continue

        element = []
        while index < len(value) and value[index] not in _TCL_WHITESPACE:
            char = value[index]
            if 0xD800 <= ord(char) <= 0xDFFF:
                raise TclSyntaxError(f"invalid Unicode surrogate U+{ord(char):08X}")
            if char == "\\":
                replacement, index = _backslash_substitution(value, index)
                element.append(replacement)
            else:
                element.append(char)
                index += 1
        elements.append("".join(element))
    return tuple(elements)


def _strip_command_whitespace(raw: str) -> str:
    """Trim command separators without dropping an escaped trailing space."""

    start = 0
    while start < len(raw) and raw[start] in _TCL_WHITESPACE:
        start += 1
    end = len(raw)
    while end > start and raw[end - 1] in _TCL_WHITESPACE:
        backslashes = 0
        cursor = end - 2
        while cursor >= start and raw[cursor] == "\\":
            backslashes += 1
            cursor -= 1
        if backslashes % 2:
            break
        end -= 1
    return raw[start:end]


def _command_chunks(text: str) -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
    chunks: list[tuple[str, int]] = []
    issues: list[tuple[str, int]] = []
    buffer: list[str] = []
    line = 1
    start_line = 1
    contexts = [_TclLexContext()]
    escaped = False
    comment = False
    index = 0
    truncation_line: int | None = None

    def record_issue(message: str, issue_line: int) -> None:
        nonlocal truncation_line
        if len(issues) < MAX_TCL_PARSE_ISSUES:
            issues.append((message, issue_line))
        elif truncation_line is None:
            truncation_line = issue_line

    def flush() -> None:
        nonlocal buffer, start_line, contexts, truncation_line
        raw = _strip_command_whitespace("".join(buffer))
        if raw:
            if len(chunks) < MAX_TCL_COMMANDS:
                chunks.append((raw, start_line))
            elif truncation_line is None:
                truncation_line = start_line
        buffer = []
        start_line = line
        contexts = [_TclLexContext()]

    while index < len(text):
        char = text[index]
        if comment:
            if char == "\\":
                # Tcl performs backslash-newline folding before recognizing
                # the physical end of a comment.  An odd run of backslashes
                # therefore continues the comment; an even run leaves the
                # newline active.
                run_end = index
                while run_end < len(text) and text[run_end] == "\\":
                    run_end += 1
                if (run_end - index) % 2 and run_end < len(text) and text[run_end] == "\n":
                    line += 1
                    index = run_end + 1
                    while index < len(text) and text[index] in " \t":
                        index += 1
                    continue
                index = run_end
                continue
            if char == "\n":
                comment = False
                if len(contexts) == 1:
                    flush()
                else:
                    buffer.append(char)
                    contexts[-1].at_word_start = True
                    contexts[-1].at_command_start = True
                line += 1
                start_line = line if not buffer else start_line
            index += 1
            continue

        if escaped:
            if char == "\n":
                buffer.append(" ")
                line += 1
                context = contexts[-1]
                if context.brace_depth == 0 and not context.quote:
                    context.at_word_start = True
                # Tcl replaces backslash-newline and every immediately
                # following space/tab with exactly one space, including in
                # quoted and braced words.
                index += 1
                while index < len(text) and text[index] in " \t":
                    index += 1
                escaped = False
                continue
            else:
                buffer.extend(("\\", char))
                contexts[-1].at_word_start = False
                contexts[-1].at_command_start = False
            escaped = False
            index += 1
            continue

        if char == "\\":
            escaped = True
            index += 1
            continue

        context = contexts[-1]
        if char == "#" and context.at_command_start and context.brace_depth == 0 and not context.quote:
            comment = True
            index += 1
            continue

        if context.brace_depth:
            buffer.append(char)
            if char == "{":
                context.brace_depth += 1
            elif char == "}":
                context.brace_depth -= 1
        elif context.quote:
            buffer.append(char)
            if char == '"':
                context.quote = False
            elif char == "[":
                contexts.append(_TclLexContext())
        elif char == "[":
            buffer.append(char)
            context.at_word_start = False
            context.at_command_start = False
            contexts.append(_TclLexContext())
        elif char == "]":
            if len(contexts) == 1:
                record_issue("unexpected closing bracket", line)
                buffer.append(char)
                context.at_word_start = False
                context.at_command_start = False
            else:
                buffer.append(char)
                contexts.pop()
        elif context.at_word_start and char == "{":
            context.brace_depth = 1
            context.at_word_start = False
            context.at_command_start = False
            buffer.append(char)
        elif context.at_word_start and char == '"':
            context.quote = True
            context.at_word_start = False
            context.at_command_start = False
            buffer.append(char)
        elif char in (";", "\n"):
            if len(contexts) == 1:
                flush()
            else:
                buffer.append(char)
                context.at_word_start = True
                context.at_command_start = True
        else:
            buffer.append(char)
            if char in _TCL_WHITESPACE:
                context.at_word_start = True
            else:
                context.at_word_start = False
                context.at_command_start = False

        if char == "\n":
            line += 1
            if not buffer:
                start_line = line
        index += 1

    if escaped:
        buffer.append("\\")
    unterminated_contexts = contexts
    flush()
    if any(context.quote for context in unterminated_contexts):
        record_issue("unterminated quoted word", line)
    if any(context.brace_depth for context in unterminated_contexts):
        record_issue("unterminated brace group", line)
    if len(unterminated_contexts) > 1:
        record_issue("unterminated command substitution", line)
    if truncation_line is not None:
        issues.append((_TRUNCATION_MESSAGE, truncation_line))
    return chunks, issues


def split_words(command: str) -> tuple[str, ...]:
    words: list[str] = []
    buffer: list[str] = []
    contexts = [_TclLexContext()]
    escaped = False

    def flush() -> None:
        nonlocal buffer
        if buffer:
            words.append("".join(buffer))
            buffer = []

    for char in command:
        context = contexts[-1]
        if escaped:
            buffer.extend(("\\", char))
            escaped = False
            context.at_word_start = False
            context.at_command_start = False
            continue
        if char == "\\":
            escaped = True
            continue
        if context.brace_depth:
            buffer.append(char)
            if char == "{":
                context.brace_depth += 1
            elif char == "}":
                context.brace_depth -= 1
            continue
        if context.quote:
            buffer.append(char)
            if char == '"':
                context.quote = False
            elif char == "[":
                contexts.append(_TclLexContext())
            continue
        if char == "[":
            buffer.append(char)
            context.at_word_start = False
            context.at_command_start = False
            contexts.append(_TclLexContext())
            continue
        if char == "]" and len(contexts) > 1:
            buffer.append(char)
            contexts.pop()
            continue
        if context.at_word_start and char == "{":
            context.brace_depth = 1
            context.at_word_start = False
            context.at_command_start = False
            buffer.append(char)
            continue
        if context.at_word_start and char == '"':
            context.quote = True
            context.at_word_start = False
            context.at_command_start = False
            buffer.append(char)
            continue
        if char in (";", "\n") and len(contexts) > 1:
            buffer.append(char)
            context.at_word_start = True
            context.at_command_start = True
            continue
        if char in _TCL_WHITESPACE:
            if len(contexts) == 1:
                flush()
                context.at_word_start = True
            else:
                buffer.append(char)
                context.at_word_start = True
            continue
        buffer.append(char)
        context.at_word_start = False
        context.at_command_start = False
    if escaped:
        buffer.append("\\")
    flush()
    return tuple(words)


def parse_tcl(text: str, path: str) -> tuple[list[TclCommand], list[TclParseIssue]]:
    chunks, raw_issues = _command_chunks(text)
    commands: list[TclCommand] = []
    for raw, line in chunks:
        words = split_words(raw)
        if words:
            commands.append(TclCommand(raw=raw, words=words, location=SourceLocation(path, line, 1)))
    issues = [TclParseIssue(message, SourceLocation(path, line, 1)) for message, line in raw_issues]
    return commands, issues


def bracket_body(word: str) -> str | None:
    """Return the body when *word* is exactly one bracket substitution."""

    stripped = word.strip(_TCL_WHITESPACE)
    # Tcl performs command substitution inside quoted words, but braces make
    # bracket text literal. Do not turn a brace-suppressed command into an
    # executable selector in the static model.
    if len(stripped) >= 2 and stripped[0] == "{" and stripped[-1] == "}":
        return None
    candidate = unquote(stripped).strip(_TCL_WHITESPACE)
    if not (candidate.startswith("[") and candidate.endswith("]")):
        return None
    contexts = [_TclLexContext()]
    escaped = False
    comment = False
    for index in range(1, len(candidate)):
        char = candidate[index]
        context = contexts[-1]
        if comment:
            if char == "\n":
                comment = False
                context.at_word_start = True
                context.at_command_start = True
            continue
        if escaped:
            escaped = False
            context.at_word_start = False
            context.at_command_start = False
            continue
        if char == "\\":
            escaped = True
            continue
        if context.brace_depth:
            if char == "{":
                context.brace_depth += 1
            elif char == "}":
                context.brace_depth -= 1
            continue
        if context.quote:
            if char == '"':
                context.quote = False
            elif char == "[":
                contexts.append(_TclLexContext())
            continue
        if char == "#" and context.at_command_start:
            comment = True
        elif char == "[":
            context.at_word_start = False
            context.at_command_start = False
            contexts.append(_TclLexContext())
        elif char == "]":
            if len(contexts) == 1:
                return candidate[1:index] if index == len(candidate) - 1 else None
            contexts.pop()
        elif context.at_word_start and char == "{":
            context.brace_depth = 1
            context.at_word_start = False
            context.at_command_start = False
        elif context.at_word_start and char == '"':
            context.quote = True
            context.at_word_start = False
            context.at_command_start = False
        elif char in (";", "\n"):
            context.at_word_start = True
            context.at_command_start = True
        elif char in _TCL_WHITESPACE:
            context.at_word_start = True
        else:
            context.at_word_start = False
            context.at_command_start = False
    return None
