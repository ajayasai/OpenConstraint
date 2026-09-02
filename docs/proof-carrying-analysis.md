# Proof-carrying structural exception analysis

`openconstraint-prove` adds a replayable path-analysis layer to the ordinary
OpenConstraint audit. It answers a narrower question than functional formal
verification:

> Does a directed path exist in the complete modeled structural graph for the
> resolved `-from` / ordered `-through` / `-to` scope of this exception?

The command never executes Tcl, never labels a path *functionally false*, and
never substitutes for STA or formal signoff. Its advantage is that every result
is accompanied by public, deterministic evidence that another machine can
replay.

## Install and run

From a source checkout:

```console
python -m pip install -e .
openconstraint-prove analyze \
  --verilog build/top.v \
  --liberty pdk/cells.lib \
  --sdc constraints/top.sdc \
  --top top \
  --format all \
  --output build/openconstraint-proof
```

The output directory contains:

- `openconstraint-proof.json` — replayable per-exception certificates;
- `openconstraint-proof.txt` — concise human-readable witnesses and reasons;
- `openconstraint-repair.json` — deterministic, review-required repair actions;
- `openconstraint-repair.sdc` — inert, line-by-line commented SDC templates with explicit placeholders.

For named modes, repeat `--mode NAME=FILE` in file order:

```console
openconstraint-prove analyze \
  --verilog build/top.v \
  --liberty pdk/cells.lib \
  --mode functional=constraints/common.sdc \
  --mode functional=constraints/functional.sdc \
  --mode scan=constraints/common.sdc \
  --mode scan=constraints/scan.sdc \
  --top top \
  --output build/proof
```

## Proof statuses

| Status | Meaning |
| --- | --- |
| `witnessed` | A directed structural path satisfying every ordered through group was found. The shortest deterministic witness is retained. |
| `vacuous` | Exhaustive bounded search completed and found no matching structural path. On a trusted model this is strong evidence that the exception is ineffective at this implementation stage. |
| `unresolved` | The design/SDC model is incomplete, the exception scope is unresolved, or its timing-node expansion is empty. No proof claim is made. |
| `bounded` | The explicit search-state or graph-edge limit was reached. No absence claim is made. |

A false-path witness proves only that the exception cuts a structurally real
path. It does **not** prove that the path is functionally false. A vacuity
certificate proves absence only in the modeled structural graph and only when
the model is trusted.

## Graph and clock semantics

The canonical graph contains typed port, net, and pin nodes. Directed edges are
created from input ports and output pins into nets, from nets into input pins
and output ports, and across modeled combinational Liberty arcs. Sequential
state is a boundary: the graph does not create a data arc from a sequential
input to a sequential output.

A clock used in an exception endpoint is expanded to the sequential instances
whose clock pins it reaches. In a `-from` scope those instances contribute
output pins; in a `-to` scope they contribute modeled sequential data pins.
The analyzer reconstructs the selector kind from the accepted raw command, so
`[get_clocks clk]` cannot be confused with `[get_ports clk]` when both namespaces
contain the same name. An untyped literal that collides across namespaces is
reported as `unresolved` rather than guessed. Unspecified `-from` and `-to`
scopes expand to all structural timing startpoints and endpoints respectively.

Ordered `-through` groups are tracked in the search state, so
`-through A -through B` is not treated as the unordered set `{A, B}`.

## Replay verification

Commit a proof pack with a release or CI artifact, then replay it against the
same inputs:

```console
openconstraint-prove verify \
  --verilog build/top.v \
  --liberty pdk/cells.lib \
  --sdc constraints/top.sdc \
  --top top \
  --proof reviewed/openconstraint-proof.json
```

Verification first checks the exact internal digest of each certificate and
proof pack, then compares a path-independent replay identity:

- the canonical structural-graph digest;
- selector-kind-aware normalized exception identities;
- every path-independent per-exception certificate identifier;
- the semantic `replay_digest`.

`pack_digest` protects the exact serialized artifact, including display paths.
`replay_digest` excludes filesystem-path metadata, so byte-identical inputs can
be replayed from a different checkout or CI workspace. Parser-warning text is
retained in the exact pack; its count, trusted state, graph, exceptions, and
conclusions participate in replay identity.

It exits `0` for a verified semantic replay, `1` for a mismatch, and `2` for
invalid inputs or operational errors.

## CI gates and resource bounds

By default, proof findings do not fail a job. A project may opt into one gate:

```console
openconstraint-prove analyze ... --fail-on vacuous
openconstraint-prove analyze ... --fail-on unresolved
openconstraint-prove analyze ... --fail-on bounded
```

Resource limits are explicit and deterministic:

```console
--max-graph-edges 5000000
--max-search-states 1000000
--max-witness-nodes 256
```

Crossing a graph limit is an input/operational failure. Crossing a search-state
limit produces a `bounded` certificate rather than an unsound absence claim.
Long witnesses retain deterministic head and tail segments plus the omitted
node count.

## Repair-plan safety

The repair planner never modifies an SDC file automatically. It can:

- suggest similar names for unmatched object queries;
- emit complete min/max by rise/fall I/O-delay templates;
- emit a clock-period template while refusing to guess a period;
- propose the common multicycle setup `N` / hold `N-1` companion for review;
- identify structurally vacuous exceptions for removal or narrowing;
- group overlap and unconstrained-endpoint remediation work.

Every line in `openconstraint-repair.sdc` is prefixed with `# PROPOSED:`. The generated file is therefore inert even when a source diagnostic or exception contains multiple lines; a timing owner must review and deliberately uncomment a command before it can affect a flow.

Every numeric timing value that cannot be proven from the inputs remains an
angle-bracket placeholder. The JSON safety contract publishes both the placeholder regular expression and the exact sorted token set used by that plan, so consumers can reject partially substituted templates deterministically. Similar-name and multicycle suggestions are evidence,
not designer intent, and require review by a timing owner.

## Machine-readable contracts

Export the bundled Draft 2020-12 schemas with:

```console
openconstraint-prove schema --kind proof --output openconstraint-proof.schema.json
openconstraint-prove schema --kind repair --output openconstraint-repair.schema.json
```

Both outputs are timestamp-free. Exact `pack_digest` values remain stable
when serialized metadata, including source paths, is identical. Semantic
`replay_digest` values remain stable for byte-identical inputs replayed from
different checkout roots.

## What this closes—and what remains

This layer closes an important gap between simple scope-overlap lint and
reviewable structural exception validation: it produces concrete paths for
real scopes and replayable exhaustive-search certificates for vacuous scopes.
It also makes repair recommendations machine-readable without silently guessing
timing intent.

Functional false-path proof, sequential sensitization, RTL property generation,
hierarchical promotion/demotion, timing budgeting, full Tcl execution, and
signoff-quality constraint generation remain separate capabilities. They must
be added with equally explicit proof and safety contracts rather than hidden
behind an overall superiority claim.
