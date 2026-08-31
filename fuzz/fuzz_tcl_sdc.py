"""Atheris launcher for the Tcl and SDC parsers."""

from __future__ import annotations

import sys

import atheris

atheris.enabled_hooks.add("RegEx")
with atheris.instrument_imports():
    from fuzz.harnesses import fuzz_tcl_sdc


def main() -> None:
    atheris.Setup(sys.argv, fuzz_tcl_sdc)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
