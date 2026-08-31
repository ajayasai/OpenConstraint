# Public-design benchmark harness

This directory defines reproducible compatibility and scale measurements over
publicly available designs. Upstream RTL/netlists, Liberty files, and SDC files
are **not vendored**. A manifest records the immutable upstream URL, exact byte
size, SHA-256 digest, logical filename, SPDX identifier, license URL, and an
attribution notice for every artifact.

The committed corpus uses the official OpenROAD 26Q3 SKY130HD test inputs at
commit `a9147cf3aebe65e058bb3fa89c1f9e524488dbb8`: AES, Ibex, JPEG, and their
shared standard-cell Liberty model. The combined fetched size is about 23.7 MB;
selecting one case fetches only that design's netlist/SDC plus the shared
library. The corpus intentionally excludes Nangate45 because the available
Liberty file carries a legacy restriction header whose provenance conflicts
with the surrounding platform license.

### Upstream-static and coverage-reference modes

Each upstream SDC invokes OpenROAD's custom `set_all_input_output_delays`
procedure. OpenConstraint's safe static backend does not execute project Tcl,
so the `upstream-static` mode reports 60% structural coverage and missing I/O
delays at that parser boundary. Those diagnostics do **not** mean the upstream
flow omitted its delays.

The same case also has a `coverage-reference` mode that appends a small,
checked-in SDC overlay under [`overlays/`](overlays/). It applies the helper's
documented 20%-of-period values to explicit non-clock input patterns and
`all_outputs`, producing a 100% OpenConstraint coverage reference. This is
deliberately **not** described as collection-equivalent or sign-off SDC: the
patterns are reviewed static surrogates for a project Tcl helper, not an
execution of that helper. Keeping both modes in one case avoids reparsing the
large design and makes the static Tcl boundary explicit without claiming
formal semantic equivalence.

## Reproduce a run

Populate the content-addressed cache while network access is allowed:

```console
openconstraint benchmark fetch \
  --manifest benchmarks/manifest.json \
  --cache-dir .benchmark-cache \
  --output benchmark-fetch.json
```

Then disconnect the network and reproduce the semantic result:

```console
openconstraint benchmark run \
  --manifest benchmarks/manifest.json \
  --cache-dir .benchmark-cache \
  --offline \
  --baseline benchmarks/baseline.json \
  --output benchmark-result.json
```

The run exits 1 if any case errors or differs from its semantic baseline. Use
repeatable `--dataset ID` and `--case DATASET/CASE` selectors for focused runs.
An unknown selector is an error rather than an accidental empty pass.

## Cache and acquisition contract

The cache has two content-addressed layers:

```text
artifacts/<sha256>.blob     exact downloaded bytes
sources/<sha256>/<config>/  safely materialized inputs
```

Every cache use rechecks the blob size and SHA-256. The materialization key also
binds archive type, raw filename, strip prefix, and expansion limit. Before
reuse, a second SHA-256 fingerprint verifies every materialized directory,
regular-file path, byte size, and file digest; links, junctions, special files,
additions, removals, and edits force reconstruction. `--offline` never opens the
network, fails if the exact blob is absent, and can safely rebuild a missing or
damaged materialization from that blob. Online acquisition uses HTTPS, caps the
download at the pinned byte count, rejects a redirect away from HTTPS, downloads
to a temporary file, and publishes it atomically only after verification.
Fetch, run, and baseline outputs may not resolve to the cache directory or any
path beneath it. An early check covers the declared and resolved cache and its
fixed `artifacts` and `sources` layers before manifest loading. After selection,
the checker additionally protects the exact required blobs, digest roots, and
materialization roots without walking the cache tree. Same-entry versus
hard-link disambiguation, when needed, probes at most 4,096 sibling names. The
selected cache root is then created and the checker runs again before any
acquisition or analysis. This makes case- and Unicode-normalization aliases
observable even when a suite-only selection needs no artifact. A final check
runs after acquisition or analysis, immediately before report publication. With
stable, trusted cache and output-parent directories, these checks prevent a
report from replacing selected cache state. Reports are then published by
atomic same-directory replacement, which prevents an output hard-linked from
outside the cache from truncating the cached inode. The checks do not defend
against a concurrent process that can replace an ancestor between the final
validation and replacement; do not use cache or output parents writable by
other users.

The 12.8 MB Liberty blob exceeds GitHub's direct raw-file limit, so its immutable
Contents API URL is fetched with GitHub's documented raw media type. The other,
smaller commit-pinned inputs use `raw.githubusercontent.com`; both paths still
pass through the same exact size and SHA-256 verification.

`OPENCONSTRAINT_GITHUB_TOKEN` can supply an optional least-privilege bearer
token for `api.github.com` only. The benchmark workflow uses its read-only
repository token to avoid shared-runner API rate limits. The token is never
sent to other hosts, and authenticated redirects are rejected rather than
forwarding credentials. Local public fetches work without a token subject to
GitHub's unauthenticated rate limit.

Raw-file artifacts use `"archive": "none"` and a normalized `filename`.
ZIP, gzip-compressed tar, and xz-compressed tar artifacts are supported for
future corpora. Archive extraction rejects absolute/traversal paths, duplicate
members, cross-platform path aliases, Windows device names, file/directory
conflicts, links, devices, encrypted ZIP members, excessive entry counts, and
an unpacked size above the manifest limit.

The cache is data, not executable code. OpenConstraint's default static backend
continues to parse SDC without evaluating Tcl. Do not enable `audit --opensta`
for an upstream corpus unless its inputs have separately been reviewed as
trusted executable Tcl.

## Input references

Each case input uses `ORIGIN:PATH` syntax. `suite:...` is relative to the
manifest directory and is intended for small OpenConstraint-authored overlays.
Any other origin is an artifact ID from the same dataset. Both forms are
resolved beneath their declared roots and must name regular files.

Every `suite:` input must also appear exactly once in top-level `suite_files`
with its byte size and SHA-256. Runtime resolution verifies both before parsing.
The `manifest_sha256` field is SHA-256 over the parsed manifest serialized as
UTF-8 JSON with sorted object keys and compact separators; it therefore binds
the declared suite-file digests without claiming to hash external bytes
directly. Whitespace-only reformatting of the manifest does not change it.

Each dataset can declare multiple artifacts. This lets a design netlist, SDC,
and shared Liberty library remain independently pinned and licensed without
downloading a repository archive.

## Metrics and baselines

Result JSON separates two classes of evidence:

- **Semantic evidence**: elaborated design counts and normalized warnings; a
  SHA-256 over every port, net, instance, pin, driver/load relationship, and
  connectivity record; exact clock definitions and exception topology; every
  coverage component; and normalized diagnostic messages, locations, and
  evidence. These deterministic fields are baseline-gated, so a same-count
  connectivity or object-resolution regression still fails.
- **Observational metrics**: input bytes, analysis wall time, and peak traced
  Python allocation. Analysis timing and memory begin before Liberty parsing
  and include Liberty/Verilog ingestion, elaboration, SDC parsing, and audit;
  verified-cache acquisition and input-reference checks are excluded. These are
  recorded for scale tracking but deliberately not used as a default pass/fail
  threshold because shared runners are noisy. Result metadata records Python
  version/implementation, operating system/release, machine architecture,
  available processor text, and logical CPU count so observations are not
  presented without their runtime context; it never records a hostname or user.
  Wall time is measured while `tracemalloc` is active, so it is an instrumented
  compatibility/scale observation rather than an uninstrumented throughput
  claim. Compare results only under like-for-like runtime conditions.

Create a new semantic baseline only after reviewing an intentional change:

```console
openconstraint benchmark baseline \
  --manifest benchmarks/manifest.json \
  --cache-dir .benchmark-cache \
  --offline \
  --output benchmarks/baseline.json
```

Baseline JSON contains no timestamp, path, timing, memory, or host metadata. It
is bound to the canonical manifest SHA-256, so source, checked-in overlay, or
configuration changes require an explicit baseline review.

Schemas under [`schemas/`](schemas/) define the strict Draft 2020-12 manifest,
baseline, and result formats. Runtime loading performs the same critical checks
without adding a JSON Schema dependency to the OpenConstraint package.

## Licensing policy

An SPDX identifier and upstream license URL are mandatory per artifact. A
manifest is provenance, not a legal conclusion; maintainers must still review
nonstandard or mixed upstream licensing before adding a case. Keep third-party
bytes out of Git, prefer canonical project-hosted immutable URLs, and never use
a mutable branch URL even when a digest would detect drift.
