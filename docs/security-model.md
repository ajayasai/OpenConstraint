# Security model

## Summary

OpenConstraint treats Verilog, Liberty, and SDC content as untrusted text. The
default static backend parses but does not execute those files. In particular,
it never passes SDC to a Tcl interpreter.

This substantially reduces risk compared with evaluating an arbitrary SDC
program, but it does not make hostile input risk-free. v0.3.0-beta bounds
pathological Verilog bus expansion, Liberty group nesting, and structural
hierarchy depth, but it does not impose a general file-size, memory, or runtime
quota.

## Assets to protect

- The machine and account running the audit.
- Source constraints, netlists, libraries, and their identifying path names.
- CI credentials and repository write permissions.
- Integrity of diagnostics, coverage scores, and generated reports.
- Availability of local and CI runners.

## Trust boundaries

### Input files

All input bytes and object names are untrusted. The readers open only paths
explicitly supplied on the command line. SDC `source`, file access, environment
lookups, Tcl variables, and command substitutions are not evaluated.

### Output paths

The user chooses output paths. Before reading controls or writing output,
`audit` resolves every report and generated-baseline destination and rejects
overlap with any Verilog, Liberty, SDC, waiver, or baseline input. It can still
overwrite an unrelated named output. `schema` can overwrite its named file;
`demo` and `--format all` create directories and overwrite their known output
names. Do not point them at sensitive files or shared untrusted paths.

### Reports

JSON and SARIF can contain source paths, object names, raw exception text, and
evidence samples. Treat reports as design data before uploading them to a public
CI artifact or code-scanning service.

With `--opensta`, the report additionally contains the OpenSTA version,
per-mode return status, duration, effective-SDC SHA-256, and captured
stdout/stderr. Tool output can reveal paths, object names, constraint text, and
environment details; review it before sharing.

The HTML reporter escapes text, embeds data using JSON encoding that neutralizes
closing-script sequences, uses `textContent` for graph labels, includes no
external scripts or styles, and makes no network requests. Browser and local-file
security still apply; open reports with an up-to-date browser.

### Optional OpenSTA process

`--opensta` is an explicit trust-boundary change. It executes every supplied SDC
file as Tcl in a separately installed OpenSTA process with the runner's account,
filesystem, environment, and network permissions. Only use it when all input
files and the chosen executable are trusted.

The adapter starts one process per mode with `shell=False`, disables OpenSTA user
init/splash loading, quotes generated driver values, captures stdout/stderr, and
uses a positive finite timeout (120 seconds by default). These controls reduce
accidental coupling and command-line injection; they do not sandbox the Tcl that
OpenSTA intentionally evaluates. Apply OS/container isolation and resource
limits. A timeout of the direct process is not a substitute for controlling
descendant processes an SDC could create.

## Tcl/SDC handling

The lexer understands enough Tcl grouping to identify SDC commands and nested
object queries. It preserves dynamic syntax as data. A query containing a Tcl
variable or unsupported nested expression produces `OC1003` or `OC1004`; it is
not substituted or executed.

This guarantee applies to OpenConstraint's built-in static backend. It does not
make the same SDC safe to load into another Tcl-based EDA tool, including the
explicit `--opensta` path.

## Availability risks

A hostile file can attempt to consume CPU or memory through extreme size,
identifier count, regular-expression cost, or structure. Targeted parser limits
cap Tcl retention at 50,000 commands and 1,000 detailed issues; Liberty
retention at 750,000 tokens, 120,000 nodes, and 1,000 detailed warnings; bus
expansion at 65,536 bits; expanded names at 131,072 per parsed Verilog file;
Verilog connections at 65,536 per instance; structural statements at 200,000;
parsed Verilog modules at 10,000; detailed Verilog warnings at 1,000;
Liberty/hierarchy depth at 256 levels; and elaborated structural objects at
262,144. A deterministic summary warning records cardinality truncation, and
design-level error `OC0002` prevents the resulting partial model from passing
the default severity gate.
These are defense-in-depth controls, not a sandbox or a complete resource
budget. For untrusted inputs:

- run untrusted audits in a disposable container or restricted CI job;
- set OS/container CPU, memory, file-size, and wall-clock limits;
- mount inputs read-only and use a dedicated output directory;
- use a non-privileged account with no secrets or network credentials;
- avoid running pull-request artifacts in a privileged release workflow.

Hypothesis properties and committed corpus replay run in the ordinary CI suite.
Separate Atheris/libFuzzer jobs continuously mutate all three parser surfaces
with finite per-input and workflow timeouts; any crash reproducer is retained as
a short-lived CI artifact for minimization and regression testing.

## CI guidance

Repository workflows use read-only permissions by default and pin Actions to
immutable commits. Optional PyPI publishing is isolated behind the `pypi`
GitHub environment and OIDC trusted publishing. The tag-only GitHub Release job
receives a scoped `contents: write` token and no package credential. Fork pull
requests must never receive release credentials.

## Non-goals and non-guarantees

- A clean audit is not evidence that the input is safe to execute elsewhere.
- Parser safety does not prove timing or functional correctness.
- Apache-2.0 does not provide a warranty or security certification.
- The project cannot protect confidential data after a user uploads it to a
  public issue or public CI artifact.

## Vulnerability reporting

Report suspected command execution, path traversal, report injection, denial of
service, dependency compromise, or policy bypass privately according to
[SECURITY.md](../SECURITY.md).
