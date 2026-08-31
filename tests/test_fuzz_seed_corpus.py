from __future__ import annotations

import importlib.util
import sys
from collections.abc import Callable
from contextlib import nullcontext
from pathlib import Path
from types import ModuleType

import pytest

from fuzz.harnesses import fuzz_liberty, fuzz_tcl_sdc, fuzz_verilog

CORPUS_ROOT = Path(__file__).parents[1] / "fuzz" / "corpus"


@pytest.mark.parametrize(
    ("corpus_name", "harness"),
    [
        ("tcl_sdc", fuzz_tcl_sdc),
        ("verilog", fuzz_verilog),
        ("liberty", fuzz_liberty),
    ],
)
def test_seed_corpus_is_nonempty_and_parser_safe(corpus_name: str, harness: Callable[[bytes], None]) -> None:
    seeds = sorted(path for path in (CORPUS_ROOT / corpus_name).iterdir() if path.is_file())

    assert seeds
    for seed in seeds:
        harness(seed.read_bytes())


def test_verilog_launcher_avoids_incompatible_atheris_regex_hook(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Atheris 3.1 RegEx proxy rejects Pattern.search(text, pos)."""

    fake_atheris = ModuleType("atheris")
    fake_atheris.instrument_imports = nullcontext  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "atheris", fake_atheris)

    launcher = CORPUS_ROOT.parent / "fuzz_verilog.py"
    spec = importlib.util.spec_from_file_location("fuzz._verilog_launcher_test", launcher)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
