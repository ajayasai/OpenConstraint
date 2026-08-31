# Getting started

## Requirements

- Python 3.11 or newer.
- A gate-level or structural Verilog netlist in the supported subset.
- One or more Liberty files containing the referenced leaf cells.
- One or more SDC files.

OpenSTA is not required and is never invoked by default. The optional
`--opensta` path is documented separately and must be used only with trusted
inputs.

## Install a source checkout

```console
git clone https://github.com/ajayasai/OpenConstraint.git
cd OpenConstraint
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
openconstraint --version
```

## Run the synthetic demo

```console
openconstraint demo --output-dir openconstraint-demo-report
```

The command copies a small, permissively licensed synthetic design to
`openconstraint-demo-report/inputs/` and writes all four report formats beside
it. The demo exits nonzero if it develops an error or falls below 100% modeled
structural coverage, making it a useful installation smoke test.

## Audit one constraint mode

```console
openconstraint audit \
  --verilog path/to/top.v \
  --liberty path/to/standard_cells.lib \
  --sdc path/to/functional.sdc \
  --top top \
  --format html \
  --output build/openconstraint.html
```

Repeat `--verilog`, `--liberty`, or `--sdc` to combine files. `--top` can be
omitted when hierarchy has one unambiguous root; specifying it is safer in CI.

## Audit several modes

```console
openconstraint audit \
  --verilog path/to/top.v \
  --liberty path/to/standard_cells.lib \
  --mode functional=constraints/common.sdc \
  --mode functional=constraints/functional.sdc \
  --mode scan=constraints/common.sdc \
  --mode scan=constraints/scan.sdc \
  --format all \
  --output build/openconstraint
```

Repeating the same mode name combines its SDC files in command-line order. Do
not combine `--sdc` and `--mode` in one invocation.

## Interpret the result

Start with errors, then warnings. Notes identify reviewable conditions such as
an implicit 50% primary-clock waveform. Inspect component denominators before
using the aggregate coverage score; a non-applicable category is omitted, not
counted as missing.

A clean report means no implemented static rule fired for the modeled subset.
It does not mean that every SDC construct was understood or that timing intent
is correct. Review `OC1003`, `OC1004`, parser warnings, and the
[compatibility document](compatibility.md).

## Optional trusted OpenSTA validation

If OpenSTA is separately installed and every Verilog, Liberty, and SDC input is
trusted to execute with your permissions:

```console
openconstraint audit \
  --verilog path/to/top.v \
  --liberty path/to/standard_cells.lib \
  --sdc path/to/functional.sdc \
  --top top \
  --opensta \
  --opensta-timeout 120 \
  --format json \
  --output build/openconstraint.json
```

Use `--opensta-bin /absolute/path/to/sta` when discovery on `PATH` is not
appropriate. Read [opensta-validation.md](opensta-validation.md) and the
[security model](security-model.md) first.
