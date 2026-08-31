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

For a successful mode, the in-memory effective SDC is then audited by the same
non-executing static rule pipeline used for input SDC. This can expose issues in
objects or constraints produced after OpenSTA evaluates trusted Tcl. A finding
whose rule, message, and evidence are not already present is merged into the
active mode and top-level diagnostics with an `<opensta-effective:MODE>` source
location. OpenSTA's writer emits a `current_design` prologue; the static parser
accepts that context directive only when it has one literal operand equal to
the elaborated top. Dynamic, missing, extra, or mismatched design contexts fail
closed.

The report's per-mode `effective_audit` object records effective coverage,
total and newly merged diagnostic counts, normalized static/effective semantic
SHA-256 values, and `semantic_match`. That comparison covers modeled clocks,
exceptions, canonical active I/O-delay state, and coverage. Raw I/O-delay
command history remains in the normal report and is not hashed as active state.
For semantic comparison, a valid primary clock without `-waveform` uses its SDC
default `{0, period/2}`; the normal report still records `waveform: null` and
`waveform_explicit: false`, preserving the authored constraint provenance.
The original static mode remains the primary model; its clocks, exceptions, and
coverage are not replaced, and cross-mode rules are not rerun over effective
snapshots.

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
wrote an effective SDC. `semantic_match` means only that the two snapshots are
equal under OpenConstraint's documented static subset. The effective SDC can
still contain syntax or semantics outside that subset. Exception and active
I/O-delay records are canonically ordered, so representational list order alone
does not cause a mismatch; command order still matters when it changes active
overwrite, merge, or reset semantics.
A clock redefinition's object-generation effects and `unset_input_delay` /
`unset_output_delay` are not in the active I/O replay subset.
A mismatch is a review signal rather than proof that either representation is
wrong. Validation does not calculate or certify path timing through
OpenConstraint, formally prove exceptions, or establish equivalence with a
commercial sign-off flow.

The public source-pinned integration job also executes focused compatibility
assertions directly in OpenSTA c821ad1. They verify omitted versus explicitly
empty `get_*` patterns, Tcl quoting/whitespace, backslash-produced wildcards and
options, nested Tcl-list pattern words, singular query aliases, and modeled
option abbreviations. They also cover patternless and brace-suppressed
`-of_objects`, exact direction-filter properties/vocabulary, malformed option
operands and filters, selector positional arity, regular-expression rejection,
hierarchical pin-local names, multiplicity-sensitive singleton operands, and
primary/generated-clock target arity before the effective-SDC round trip runs.
The fixture additionally pins regexp exact-lookup routing and Tcl-ARE
divergence cases, current-scope wildcard depth, literal-list cardinality,
OpenSTA's warning-versus-error behavior for literal resolution, and invalid
extra multicycle operands. It also pins one-pass numeric decoding and the
warning-and-apply behavior of stray `set_false_path`/`set_clock_groups`
positionals. OpenConstraint's stricter all-or-nothing and no-warning-state
policies are tested separately and documented as intentional safety
divergences.
