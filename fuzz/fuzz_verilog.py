"""Atheris launcher for the structural Verilog parser."""

from __future__ import annotations

import sys

import atheris

# Atheris 3.1's experimental RegEx hook does not preserve the ``pos``
# argument accepted by compiled-pattern ``search``/``match`` methods.  The
# Verilog parser deliberately uses those APIs while scanning modules, so rely
# on Atheris's bytecode instrumentation for this target instead.
with atheris.instrument_imports():
    from fuzz.harnesses import fuzz_verilog


def main() -> None:
    atheris.Setup(sys.argv, fuzz_verilog)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
