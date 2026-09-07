# Structural false-path change analysis (experimental)

The question answered is deliberately precise:

> On this same structural design, does either SDC snapshot select a complete
> structural path that the other snapshot does not select as a false path?

This compares **unions of path scopes**, not SDC lines, exception counts, or
just launch/capture pairs. The result does not establish whether those paths
are functionally false, whether clock timing is unchanged, or whether the two
files are equivalent for timing signoff.

## Why this differs from a textual diff

Suppose data reaches result through two parallel branches. Replacing an
exception through only the left branch with a broad data-to-result exception
selects the right branch too, despite identical launch/capture endpoints.
The tool returns the right-hand path as a concrete newly selected cut.

Conversely, replacing one broad exception with two exceptions that together
cover both branches preserves the selected structural path language. The tool
reports `equivalent_structural_cuts`, even though all the exception records
changed. Reordering or duplicating a declaration also preserves that language.
A newly added scope that has no structural route contributes no paths; that
vacuity is not a proof that the exception is functionally justified.

## Try the supplied examples

Install from this feature branch with `python -m pip install -e .`. Use a new
output filename for each command; existing files, directories and links are
refused. No parent directory is created implicitly.

```console
openconstraint-cut-compare compare \
  --verilog examples/cutcompare/design.v --liberty examples/cutcompare/cells.lib \
  --top top --before examples/cutcompare/before.sdc \
  --after examples/cutcompare/after.sdc --output cut-change.json
```

Expected exit **1**: both setup and hold gain a structural cut. Each result
contains a shortest complete port/net/pin witness through `u_right/A`, the
matching candidate rule indices, and an empty matching-baseline list.

```console
openconstraint-cut-compare compare \
  --verilog examples/cutcompare/design.v --liberty examples/cutcompare/cells.lib \
  --top top --before examples/cutcompare/after.sdc \
  --after examples/cutcompare/equivalent.sdc --output cut-equivalent.json
```

Expected exit **0**: the two specific branch exceptions cover exactly the same
structural walks as the broad exception.

For parameterized inputs, first use [bounded SDC expansion](sdc-expansion.md)
for each snapshot/mode. Compare the two `normalized.sdc` files, keeping their
separate expansion provenance. Compare one design and one explicit mode pair
per invocation; this command does not map objects between netlist revisions.

## Supported comparison contract

The structural graph has typed port/net/pin nodes and directed connectivity and
combinational dependency edges. Sequential D-to-Q state is not crossed.
Source endpoints are input/inout ports and register output/inout pins. Capture
endpoints are output/inout ports and register data pins. An explicitly selected
from/to object must expand wholly to the appropriate endpoint set; an internal
combinational from/to pin is rejected, not silently reinterpreted.

`set_false_path` supports unqualified `-from`, ordered `-through`, and `-to`
scopes, plus `-setup` and `-hold`. Missing from/to scopes use the full endpoint
universe. Typed port, pin, cell, register, net-through, all-input/all-output and
unambiguous literal collections use the existing static resolver. Cells expand
to endpoint pins or, for through scopes, their pins. Names are case-sensitive;
input source locations are retained as side-relative line numbers.

Each through group means one matching graph-node occurrence. Consecutive groups
must consume distinct occurrences, even when their collections overlap. The
language is **finite directed walks**, so a loop may appear in a witness on a
cyclic combinational graph. This is an exact graph-language contract, not a
claim about physically sensitizable timing paths. Zero-edge walks are possible
when an inout port is both a source and a target.

The following do **not** receive an approximation or an equivalence verdict:

- Clock-tagged `get_clocks`/`all_clocks` exception endpoints and literal clock
  endpoints. Expanding two different clock tags to the same register pin would
  lose timing-domain identity, so this version refuses it.
- Rise/fall-qualified exceptions, `-reset_path`, `set_clock_groups`, other timing
  exception kinds, case analysis, disable-timing, and unmodeled commands.
- Dynamic Tcl, malformed commands, partially unmatched queries, ambiguous
  objects, or a structural model with parser/elaboration warnings.

Primary/generated clock definitions, valid input/output delays and a matching
`current_design` assertion may coexist with the compared exceptions. They are
syntax/audit checked but their **timing values are outside the comparison**.
Two files with different periods can have equivalent structural cuts. Missing
clock coverage alone does not prevent structural comparison; run the ordinary
`openconstraint audit` separately to enforce timing-coverage policy. Every
report explicitly records `timing_equivalence: false`, `timing_signoff: false`
and `functional_exception_validity: false`.

## Algorithm and correctness argument

For a particular source node, each exception has either a disabled state (the
source was outside its from collection) or a progress index: the length of the
longest prefix of its through groups matched so far. Processing one graph node
can advance that index by at most one. Greedy prefix advancement recognizes
exactly the ordered-subsequence language: consuming the earliest available
occurrence never removes a later opportunity to complete the suffix.

A product state consists of the current graph node and the progress vector for
**every exception in both snapshots**. At each capture node, one union accepts
when any enabled exception has completed its through groups and matches the
target. After-only acceptance is a newly selected cut; before-only acceptance
is a removed cut. Separate searches retain setup and hold distinctions.

Two path prefixes may merge only when this complete product state is identical.
Their possible accepting suffixes are then identical, including both unions'
negative conditions. The algorithm therefore need not enumerate all structural
paths. Breadth-first traversal with sorted sources/adjacency returns a shortest
witness for each observed direction, with deterministic tie-breaking.

A finite product-state traversal that exhausts its queue proves absence of that
direction's difference on this graph. If witnesses for both directions are
found, their existence is established without further search. A resource limit
makes every not-yet-established direction `bounded`, never `absent`. Already
found witnesses may survive as partial evidence, but the overall result remains
incomplete. Each emitted witness is also checked for real edges and independently
matched using a set-of-prefixes algorithm rather than the search's greedy state.

Worst-case product-state growth can still be exponential in the number of
ordered scopes. There is no general linear-time or industrial-scale claim.

## Resource ceilings and outcomes

All limits can be lowered, not raised beyond implementation ceilings:

| Resource | Default ceiling |
| --- | ---: |
| Combined UTF-8 SDC bytes | 2 MiB |
| Combined top-level SDC commands | 1,024 |
| Graph nodes / edges | 200,000 / 500,000 |
| Combined false-path declarations | 128 |
| Through groups per declaration | 32 |
| Expanded selector-node entries | 500,000 |
| Charged product states / progress cells | 100,000 / 2,000,000 |
| Charged search/matcher work units | 5,000,000 |
| Complete witness nodes | 4,096 |

The counters are deterministic charged work, not elapsed-time or operating
system RSS limits. Existing parser/elaborator limits still apply. For untrusted
large workloads also impose operating-system CPU/memory limits; this tool is
not an OS sandbox. If output writing fails, an incomplete file may remain, but
no successful completion is reported and replay cannot validate malformed JSON.

Default `compare` exit codes: **0** for equivalent structural cuts, **1** for a
completed comparison with a change, **2** for unknown semantics, resource bounds
or operational errors. `--fail-on new-cut` permits removals but rejects additions;
`--fail-on never` permits completed differences for reporting only. Neither
option permits unresolved/bounded comparisons to pass.

## Replay and schema

```console
openconstraint-cut-compare verify \
  --verilog examples/cutcompare/design.v --liberty examples/cutcompare/cells.lib \
  --top top --before examples/cutcompare/before.sdc \
  --after examples/cutcompare/after.sdc --report cut-change.json

openconstraint-cut-compare schema --output cut-comparison.schema.json
```

Replay rebuilds from the caller's design, exact SDC bytes and selected limits,
then compares the complete canonical report. It does not trust a report's status,
witness, counters, hash or purported instructions. Modifying metadata and
rehashing it cannot substitute for fresh reconstruction. Duplicate JSON keys
are rejected. JSON booleans and numbers are not considered interchangeable.

SDC comments and line endings are byte-bound; relocating identical files is
allowed. Design identity binds the rebuilt structural graph, top name and
endpoint universe, **not the original Verilog/Liberty file bytes or delay
values**. A source edit that changes none of these structural facts does not
invalidate this structural replay. Hashes do not authenticate an author.

`verify` exits 0 for an exactly reproduced report, 1 for mismatch and 2 for
operational/malformed-input errors. Reproducing a bounded/unresolved report is
an integrity check, not a proof: its output still says `complete: false`.
Use the `compare` status/policy gate, not replay success alone, to approve a cut
comparison. Custom limits must be supplied again explicitly when replaying.

## Validation and reproducible scale fixture

`tests/test_cutcompare.py` contains deterministic unit/adversarial cases and
200 seeded small acyclic graphs. An independent exhaustive enumerator lists
paths and tests all ordered occurrence combinations; its results are compared
with both directions, both senses, and the shortest returned witnesses. It
shares the existing parser/structural graph with production, so it independently
checks the comparison algorithm, not native STA interpretation.

```console
python -m pytest tests/test_cutcompare.py
python benchmarks/cutcompare.py --layers 45 --output cut-scale.json
```

The layered fixture has 45 independent two-way reconvergences and therefore
2^45 source-to-output structural routes, but only hundreds of graph nodes.
It is designed to expose path-enumeration blowups, **not** to imitate a
multi-billion-instance SoC. The report records graph size, charged work,
tracemalloc-instrumented wall time and Python allocation peak. No proprietary
tool performance, native STA equivalence or superiority is inferred from it.
