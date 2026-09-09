# Hierarchy-aware formal front ends (experimental)

The Boolean and single-clock sequential checkers now accept **already
elaborated and techmapped hierarchical Yosys JSON** directly. Every instance
gets a separate wire namespace; explicit port connections join those namespaces.
This removes the requirement to run a separate flattening tool before these
checks. It does not add an RTL parser, infer clocks or reset assumptions, promote
SDC, demote timing constraints, or establish physical timing equivalence.

## Run the supplied example

Install the feature branch with `python -m pip install -e '.[formal]'`.
The repository includes a hand-authored hierarchical conformance netlist:

```console
openconstraint-sequential analyze \
  --netlist examples/hierarchy/netlist.json \
  --spec examples/hierarchy/checks.json \
  --backend z3 --output hierarchical-result.json

openconstraint-sequential verify \
  --netlist examples/hierarchy/netlist.json \
  --spec examples/hierarchy/checks.json \
  --report hierarchical-result.json --backend enumerate
```

The first command intentionally exits **1**: one property is proven and the
negative control has a counterexample. Successful replay exits **0**, with
`verified: true` and `passed: false`. Existing output files are refused. The
Boolean checker accepts the same input with `examples/hierarchy/functional-checks.json`.
Its register outputs still have arbitrary-state semantics; it is not a sequential proof.

## Export from a real HDL front end

Use a separately installed Yosys to resolve source-language constructs and
parameters and lower logic to supported single-bit primitives. For this
repository-owned fixture:

```console
yosys -p 'read_verilog examples/hierarchy/design.v; hierarchy -check -top top; proc; techmap; opt_clean; write_json hierarchical.json'
```

No `flatten` command is needed before OpenConstraint. The Python elaborator
does not execute HDL, invoke a process, access a network, or read paths named
by input metadata. Source paths in attributes are retained as data only.

Yosys's `hierarchy` pass resolves parameterized module variants. Instance
parameter overrides remaining in JSON are rejected: this tool must not pretend
to synthesize a different parameter value by merely copying a module body.
Specialized modules with empty instance parameters and descriptive
`parameter_default_values` are supported. The input JSON's already elaborated
body is authoritative; no parameter expression is evaluated here.

## Inspect the connectivity and origin map

```console
openconstraint-hierarchy compile \
  --netlist examples/hierarchy/netlist.json --top top --output hierarchy-pack

openconstraint-hierarchy verify \
  --netlist examples/hierarchy/netlist.json --top top --pack hierarchy-pack

openconstraint-hierarchy schema --output hierarchy.schema.json
```

The new directory contains `netlist.json` and `hierarchy.json`. The latter
includes the flattened netlist, module-instance paths and attributes, leaf-cell
origins, named signal bit mappings, the top-bit alias map, counts, limits,
unused-module names and content digests. Verify reconstructs **all** bindings
and metadata from the caller-selected original input and checks both files.
Rehashing fabricated origins or edited wiring does not pass reconstruction.

The digest covers canonical JSON, not original whitespace or key order. Every
supplied module, even an unused one, remains source-digest-bound. Unused modules
are listed but are not expanded or treated as part of the selected design.
Hashes are integrity identities, not signatures or proof of authorship. A valid
hierarchy pack is not a functional or timing proof; both remain explicit false
claims in its contract. Automatic formal analysis binds the original hierarchical
JSON in its existing report identity and deterministically re-elaborates on replay.

## Names and bit identity

Top-level names are unchanged. A child signal is named with slash-prefixed,
JSON-pointer-escaped path components: `/left/capture/q`. A literal `/` inside a
component becomes `~1`; a literal `~` becomes `~0`. Thus the instance named
`left/capture` is not confused with two nested instances `left` then `capture`.
Top names that collide with a generated child name cause an error, not a merge.
The same collision protection applies to cell names.

Use a named reference, or `{ "net": "/left/capture/q", "bit": 0 }` for a bus.
`bit` is the position in the Yosys `bits` array, not a Verilog declared index.
Bus order, slices, reversals, and constants follow the explicit arrays. No
implicit extension, truncation, endian guessing, or missing-port padding occurs.

Top numeric IDs are preserved where possible. Aliased top IDs canonicalize to
the smallest member; constants remain `"0"` or `"1"`. New internal wire IDs are
allocated above all original top IDs. A removed numeric alias is not reassigned
as an unrelated wire. For portable hierarchical properties, prefer names and
consult `top_bit_map`; a module-local numeric ID is never a hierarchical reference.

## What is rejected

Recursive hierarchy, blackboxes, whiteboxes, unknown/unmapped leaf primitives,
memories, processes, inout ports, X/Z constants, unresolved instance parameters,
missing/extra ports, width mismatches, contradictory constants, conflicting
aliases, shorted primary inputs, multiple drivers, and undriven consumed signals
all fail closed. Module definitions cannot override the meaning of internal
primitive names. An empty unconnected net alias may remain in provenance but
cannot be used as a driven signal in a proof.

Supported leaf interfaces are the Boolean checker's twelve gate primitives and
the sequential checker's forty-six synchronous flip-flop/reset/enable variants.
This is an interface/connectivity allowlist. The selected checker still enforces
its own model: for example, asynchronous resets, mixed clocks, latches and hidden
initial-state attributes are not newly accepted. Net `init` attributes are retained
so the sequential checker can reject hidden initial-state assumptions rather
than losing them during flattening. `keep_hierarchy` is an optimization hint,
not an added behavioral assumption, and is retained in instance provenance.

The elaborator validates connectivity, not absence of combinational loops or
correctness of any timing exception. The downstream Boolean/sequential loader
continues to reject unsupported functional models. The structural Verilog/Liberty
audit front end is unchanged by this feature.

## Bounds and reproducibility

Defaults: 16 MiB canonical input, 20,000 expanded module instances including the
top, 100,000 leaf cells, 400,000 instance-local wires, 2,000,000 charged alias and
connection bit entries, hierarchy depth 64, 4,096 characters per expanded name,
and 64 MiB evidence. Proof loaders further cap expansion using their existing
cell/bit limits. Repeated module definitions are parsed once per elaboration;
state and wire instances are never shared between instantiations.

Repeated metadata is charged conservatively before retaining output records;
final output size is also checked. The flattened netlist is capped at 16 MiB so
it can be read by the existing proof CLIs. Limits may be lowered, not raised
above implementation ceilings. These are algorithmic bounds, not a host CPU/RSS
sandbox. Source changes invalidate replay; there is no stale persistent cache.

Compilation finishes before creating output. Existing directories/files/links
are refused. A later I/O failure may leave an incomplete directory; it is never
reported as successful. Exit codes: **0** completed compilation/matching replay,
**1** well-formed replay mismatch, **2** unsupported/malformed/bounded input or
operational error. Malformed saved JSON is an error, never a matching artifact.

## Independent controls

`tests/test_hierarchy.py` checks repeated local bit IDs, vector wiring, constants,
aliases, recursive definitions, all supported register interfaces, hidden init
attributes, resource bounds, source corruption, namespace collisions, no-clobber,
and both proof engines. One hundred seeded nested Boolean circuits are compared
with an independent recursive module evaluator that does not use union-find.

The dedicated workflow requires actual Yosys and compares the hierarchical
export, OpenConstraint's flattening, and Yosys's native flattening. Both proof
backends must agree on positive and negative controls and replay their reports.
It also checks 128 sixteen-cycle input sequences against separately written RTL
equations and requires native Yosys SAT proof/falsification controls over six
steps. Those bounded native checks are not a separate unbounded proof. The
small fixture includes repeated and nested modules and two parameter widths;
it does not establish full language support or industrial-scale superiority.

Run the full reference control with:

```console
python examples/hierarchy/validate.py --yosys --output build/hierarchy-validation
python benchmarks/hierarchy.py --sizes 1000,5000 --output hierarchy-scale.json
```

Without `--yosys`, the validation script uses the hand-authored JSON and explicitly
reports `real_yosys: false`; no native comparison is implied. The benchmark is
repeat-instance connectivity elaboration and artifact replay, not solver scale,
process RSS, chip timing performance, or a commercial product comparison.

## References

- [Yosys JSON output format](https://yosyshq.readthedocs.io/projects/yosys/en/stable/cmd/write_json.html)
- [Yosys hierarchy processing](https://yosyshq.readthedocs.io/projects/yosys/en/0.40/cmd/hierarchy.html)
- [Yosys native flattening](https://yosyshq.readthedocs.io/projects/yosys/en/v0.57/cmd/index_passes_hierarchy.html)
