"""Atheris launcher for the Liberty parser."""

from __future__ import annotations

import sys

import atheris

atheris.enabled_hooks.add("RegEx")
with atheris.instrument_imports():
    from fuzz.harnesses import fuzz_liberty


def main() -> None:
    atheris.Setup(sys.argv, fuzz_liberty)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
