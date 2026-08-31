# Opt-in OpenSTA validation

OpenConstraint's default audit is static and never executes Tcl. `--opensta` is
an explicit second layer for inputs already trusted to execute in a separately
installed OpenSTA process.

```console
openconstraint audit \
  --verilog design.v \
  --liberty cells.lib \
  --sdc constraints.sdc \
  --top top \
  --opensta \
  --opensta-bin /opt/opensta/bin/sta \
  --opensta-timeout 120 \
  --format json \
  --output openconstraint.json
```

If `--opensta-bin` is omitted, OpenConstraint searches `PATH` for `sta` and then
`opensta`. The version query and each mode must finish within the positive,
finite timeout.

## What runs

OpenConstraint first completes its static audit. It then queries the executable
version and starts one process per mode using an argument vector—not a shell.
Each process uses a temporary generated driver that:

1. disables OpenSTA's continue-on-error behavior;
2. reads every supplied Liberty file;
3. reads every supplied Verilog file and links the selected top;
4. executes that mode's SDC files in their supplied order;
5. runs `check_setup -verbose`;
6. writes a timestamp-free effective SDC.

The process starts with `-no_init`, `-no_splash`, and `-exit`. OpenConstraint
captures stdout/stderr, return status, duration, timeout state, executable
version, and SHA-256 of the effective SDC. Temporary scripts and effective SDC
files are removed after the mode result is captured.

## Failure semantics

A timeout, nonzero return, unsuccessful `check_setup`, or missing effective SDC
emits error [OC6001](rules/OC6001.md). The report is still written and normal
severity gating applies. Failure to discover or start the requested executable
is an operational/input error.

## Security boundary

OpenSTA evaluates SDC as Tcl. `shell=False`, quoting, `-no_init`, and a timeout
protect the adapter's generated command path; they do not make hostile SDC safe.
Use only trusted constraints, a trusted pinned executable, a non-privileged
sandbox, read-only inputs, resource limits, and restricted network/filesystem
access. Never add `--opensta` to a workflow that runs untrusted fork content.

Captured stdout/stderr and constraint hashes become part of the JSON/SARIF/HTML
result data and may be confidential.

## Interpretation

Successful validation means that the installed OpenSTA version loaded the
supplied design/constraints, passed the adapter's `check_setup` condition, and
wrote an effective SDC. It does not calculate or certify path timing through
OpenConstraint, formally prove exceptions, or establish equivalence with a
commercial sign-off flow.
