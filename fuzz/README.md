# Parser fuzzing

OpenConstraint has two complementary parser-fuzzing layers:

- `tests/test_parser_properties.py` uses Hypothesis in the ordinary cross-platform test suite. It checks arbitrary Unicode text up to 4,096 characters and generates valid Tcl/SDC, Verilog, and Liberty structures with semantic assertions.
- The launchers in this directory use Atheris/libFuzzer for coverage-guided, long-running arbitrary-byte mutation. Their seed corpora contain valid, nested, escaped, and deliberately malformed examples. The same pure harnesses are replayed by `tests/test_fuzz_seed_corpus.py` on every test run.
- Parser-token dictionaries keep mutations reaching meaningful grammar branches instead of spending most runs on immediately rejected noise.

Each native target accepts at most 1 MiB per input. The parsers also impose the
documented command, token, node, expansion, depth, and elaboration limits, while
the CI runner applies a 10-second per-input timeout and 1 GiB RSS ceiling. These
are regression guards, not a substitute for OS isolation around hostile files.

No corpus may contain a proprietary netlist, SDC file, Liberty model, PDK excerpt, or vendor log. Reduce every regression to a minimal synthetic input before committing it.

## Run the property tests

```console
python -m pip install -e ".[dev]"
pytest tests/test_parser_properties.py tests/test_fuzz_seed_corpus.py
```

## Run Atheris

Atheris supports CPython on Linux for this project. Install the dedicated extra, then run each target from the repository root:

```console
python -m pip install -e ".[fuzz]"
python -m fuzz.fuzz_tcl_sdc fuzz/corpus/tcl_sdc -dict=fuzz/dictionaries/tcl_sdc.dict -max_len=1048576 -max_total_time=3600
python -m fuzz.fuzz_verilog fuzz/corpus/verilog -dict=fuzz/dictionaries/verilog.dict -max_len=1048576 -max_total_time=3600
python -m fuzz.fuzz_liberty fuzz/corpus/liberty -dict=fuzz/dictionaries/liberty.dict -max_len=1048576 -max_total_time=3600
```

The Tcl/SDC and Liberty launchers opt into Atheris's experimental regular-expression hook. The Verilog launcher intentionally uses bytecode instrumentation alone because Atheris 3.1's regular-expression proxy does not support the `pos` argument used by compiled-pattern `search` and `match` calls.

A crash is written as a reproducer in the current directory. Minimize it before adding it to the relevant corpus:

```console
python -m fuzz.fuzz_tcl_sdc -minimize_crash=1 -exact_artifact_path=minimized.sdc crash-input
```

Use `-atheris_runs=N` instead of libFuzzer's `-runs=N` when collecting Python coverage, as recommended by Atheris.
