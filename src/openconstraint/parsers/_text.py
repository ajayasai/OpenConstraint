"""Linear-time text preprocessing shared by structural parsers."""

from __future__ import annotations


def strip_c_style_comments(text: str) -> str:
    """Replace C-style comments with spaces while preserving length/newlines."""

    characters = list(text)
    index = 0
    quoted = False
    escaped = False
    while index < len(characters):
        character = characters[index]
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
            index += 1
            continue
        if character == '"':
            quoted = True
            index += 1
            continue
        if index + 1 >= len(characters) or character != "/":
            index += 1
            continue
        following = characters[index + 1]
        if following == "/":
            characters[index] = characters[index + 1] = " "
            index += 2
            while index < len(characters) and characters[index] != "\n":
                characters[index] = " "
                index += 1
            continue
        if following == "*":
            characters[index] = characters[index + 1] = " "
            index += 2
            while index < len(characters):
                if index + 1 < len(characters) and characters[index] == "*" and characters[index + 1] == "/":
                    characters[index] = characters[index + 1] = " "
                    index += 2
                    break
                if characters[index] != "\n":
                    characters[index] = " "
                index += 1
            continue
        index += 1
    return "".join(characters)
