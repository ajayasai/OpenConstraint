# Boolean influence evidence (experimental)

`openconstraint-functional` checks **Boolean source-to-target influence** in a
flat, technology-mapped Yosys JSON netlist. This is a separate evidence layer
from structural SDC auditing. It does not consume SDC, generate false-path
exceptions, calculate delays, or certify timing signoff.

## Meaning of a result

The explicitly selected model is `zero_delay_arbitrary_state`. Combinational
cells are ideal Boolean functions. Q outputs of supported flip-flops are
independent, arbitrary state inputs; the analysis never infers reset-reachable
states, clock relationships, or next-state behavior.

For each obligation, two copies of the target cone share the same side inputs
and state. Only the specified sources may differ. The question is whether any
allowed source perturbation changes at least one target.

| Status | What it establishes |
| --- | --- |
| `independent` | No perturbation changes the targets in the declared Boolean model under the supplied assumptions. |
| `dependent` | Two concrete assignments differ only at permitted sources and produce different target values. |
| `inconsistent_assumptions` | Assumptions conflict, or fix a source under test. No independence claim is accepted. |
| `unsupported` | The model or obligation cannot be interpreted safely, or the requested solver is unavailable. |
| `bounded` | A work limit or solver resource limit prevents a decision. This is not a pass. |

**Boolean independence is not a timing false-path proof.** For example,
reconvergent signals may cancel in zero-delay Boolean logic yet exhibit
physical glitches when path delays differ. Likewise, a Boolean dependence does
not alone refute an SDC exception whose validity depends on a clock schedule
or temporal protocol. Every result therefore contains `timing_signoff: false`.

## Install and run the conformance example

The exhaustive backend needs no additional runtime dependency:

```console
python -m pip install -e .
openconstraint-functional analyze \
  --netlist examples/functional/netlist.json \
  --spec examples/functional/checks.json \
  --backend enumerate --output boolean-result.json
```

The example intentionally returns **exit code 1**: the disabled-mode obligation
is independent, while the enabled-mode obligation is dependent. Inspect the
reported assignments; do not suppress failures blindly with `|| true` in CI.
The committed netlist is an explicitly hand-written conformance fixture.

For the optional SAT/SMT backend:

```console
python -m pip install -e '.[formal]'
openconstraint-functional analyze \
  --netlist examples/functional/netlist.json \
  --spec examples/functional/checks.json \
  --backend z3 --output boolean-z3.json
openconstraint-functional verify \
  --netlist examples/functional/netlist.json \
  --spec examples/functional/checks.json \
  --report boolean-z3.json --backend enumerate
```

Verification defaults to the independent exhaustive implementation. It
recomputes the decisions and concretely evaluates stored counterexamples;
it does not trust a saved status or an integrity hash alone. A successfully
reproduced dependence returns `verified: true` with `all_independent: false`.
Thus **verified means reproduced, not that all obligations passed**.

The optional solver dependency is `z3-solver>=5.1,<6`; the exact solver version
is recorded in each report. Pin it in your environment for repeated experiments.
Same-version runs use a fixed solver seed, but no cross-version identity of
SAT witnesses or timeout outcomes is promised. Replay compares decisions and
validates stored witnesses rather than requiring two solvers to choose the
same satisfying assignment.

## Use a real synthesis output

In a separately controlled build stage with Yosys installed:

```console
mkdir -p build
yosys -p 'read_verilog examples/functional/design.v; hierarchy -check -top top; proc; flatten; opt; techmap; opt; write_json build/functional.json'
openconstraint-functional analyze \
  --netlist build/functional.json --spec examples/functional/checks.json \
  --backend z3 --output build/functional-result.json
```

The dedicated functional CI workflow runs this flow on repository-owned RTL,
records `yosys -V` and the Z3 version, compares both backends, and preserves the
netlist, decisions, replay results, and logs. This tests an actual synthesis
output in addition to the hand-written primitive fixtures. The installed Yosys
version is recorded, not represented as a checksum-pinned reference engine.

The checker reads JSON only. It never launches Yosys, evaluates RTL, executes
Tcl, or downloads a solver on behalf of an input file.

## Obligation format

```json
{
  "schema_version": "1.0.0",
  "model": "zero_delay_arbitrary_state",
  "top": "top",
  "checks": [{
    "id": "disabled-mode",
    "sources": ["a"],
    "targets": ["out"],
    "assumptions": [{"signal": "enable", "value": 0}]
  }]
}
```

Signal references may be scalar net names, numeric Yosys bit IDs, or
`{"net": "bus", "bit": 0}`. **The bit field indexes the JSON `bits` array**,
not the original HDL declaration's numeric subscript. Yosys `offset` and `upto`
are presentation metadata; use the emitted array when selecting a bus bit.
Aliases resolve to the same signal ID and cannot conceal contradictory
assumptions.

Sources must be primary inputs or supported DFF Q boundaries. Assumptions may
fix other primary inputs or DFF Q boundaries to integer `0` or `1`; they may
not constrain internal target logic or fix a source under test. Sources are
varied jointly, while all other inputs are held identical across the two
worlds. Target constants and sources absent from a target cone are supported.

Check IDs must be unique. Unknown specification fields are rejected, including
unsupported edge qualifiers and `through` scopes. There is no silent mapping
from a Boolean obligation to a more specific SDC timing exception.

## Supported and rejected logic

Supported single-bit cells are `$_BUF_`, `$_NOT_`, `$_AND_`, `$_NAND_`,
`$_OR_`, `$_NOR_`, `$_XOR_`, `$_XNOR_`, `$_ANDNOT_`, `$_ORNOT_`, `$_MUX_`,
and `$_NMUX_`. `$_DFF_P_` and `$_DFF_N_` provide arbitrary Q state boundaries,
not sequential proof semantics.

Unknown cells, unexpected primitive parameters/ports, blackboxes, whiteboxes,
unlowered processes, memories, latches, X/Z values, inout ports, undriven used
signals, multiple drivers, and combinational cycles fail closed. Unsupported
logic anywhere in the selected model invalidates it rather than being silently
blackboxed. Flatten, lower, and technology-map the design before checking it;
unsupported constructs still require an explicit model extension and tests.

## Limits, provenance, and output safety

Both front ends and solvers have explicit limits. Defaults are 50,000 cells,
200,000 signal IDs, 256 obligations, and 1,000,000 aggregate cone gate/variable
work units. The exhaustive backend allows at most 18 free cone inputs and
5,000,000 estimated evaluation work units per obligation, with a hard cap of
24 configurable free inputs. Z3 has a 10,000 ms per-obligation solver timeout
and a 1,000,000 resource-unit limit. These are algorithm bounds, not operating
system memory/process isolation; constrain the enclosing CI job as well.

Relevant target cones are memoized only during the current call. Nothing is
loaded from an untrusted persisted cache, and a new analysis rebuilds its
model. Unrelated logic is excluded from the solver cone but not from input
validation or provenance hashing.

JSON input is limited to 16 MiB per file and 128 levels of nesting. Duplicate
keys, non-finite constants, invalid UTF-8, and malformed data are rejected.
Output files are created exclusively: an existing file, including a link to
an input, is never overwritten. Use a fresh output path for each invocation.

Reports bind the complete canonical netlist and obligation specification,
model, algorithm, backend/version, resource limits, statuses, and concrete
witnesses to SHA-256 digests. Hashes detect accidental alteration; they are
**not signatures or proof of authenticity**. Independent replay is required
for an evidence claim. The verifier refuses to call an unsupported or bounded
outcome a verified decision, even when that outcome is reproducible.

| Command | Exit 0 | Exit 1 | Exit 2 |
| --- | --- | --- | --- |
| `analyze` | Every obligation is independent | At least one dependence or non-decision | Invalid input or operational error |
| `verify` | All stored decisions reproduced | Mismatch, invalid witness, or non-decision | Invalid input or operational error |

Export strict Draft 2020-12 schemas with:

```console
openconstraint-functional schema --kind spec --output functional-spec.schema.json
openconstraint-functional schema --kind result --output functional-result.schema.json
```

## Validation and remaining work

Tests include hand-written truth tables, independent concrete evaluation of
solver assignments, exhaustive-vs-Z3 checks over generated acyclic circuits,
contradictory assumptions, resource exhaustion, unsupported logic, aliasing,
JSON safety, and altered artifacts. Differential agreement is useful evidence,
not independent verification of the entire JSON frontend, which both backends
share. The independent primitive truth-table tests and real-Yosys CI address
parts of that shared trust boundary.

Delay-aware path sensitization, sequential reachability, multicycle temporal
properties, automatic SDC binding, hierarchy transformation, broad Tcl
execution, and industrial-scale commercial comparisons remain separate work.
This module is an implemented first Boolean evidence layer, not completion of
[the full functional exception backend](../ROADMAP.md).

Primary format and solver references:
[Yosys JSON format](https://yosyshq.readthedocs.io/projects/yosys/en/v0.52/cmd/write_json.html)
and [Z3 Python guide](https://microsoft.github.io/z3guide/programming/Z3%20Python/Introduction/).
