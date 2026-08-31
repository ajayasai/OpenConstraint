# Labeled semantic accuracy benchmark

This suite measures whether OpenConstraint emits the reviewed diagnostic rule
IDs for deterministic SDC mutations. It complements the large public-design
regression suite: the public-design suite measures compatibility and stable
behavior at scale, while this suite supplies explicit defect labels for
precision and recall.

It is deliberately not a timing-signoff, formal-verification, industrial-PPA,
or vendor-comparison benchmark. A perfect score means only that the current
checker classified these checked-in mutations exactly as reviewed.

## Truth-set design

[`truth-set.json`](truth-set.json) embeds a small project-authored Verilog,
Liberty, and fully constrained SDC fixture under Apache-2.0. Keeping the fixture
inside the versioned truth set makes its canonical SHA-256 bind the source,
audit options, mutation operations, expected labels, and thresholds together.
No proprietary design or vendor output is used.

Each case starts from the same clean SDC and applies ordered operations:

- `replace` requires an exact anchor and expected occurrence count. A stale or
  ambiguous anchor is an input error rather than a silently changed mutation.
- `append` adds reviewed SDC text with normalized final-newline handling.
- `mutant-only` audits one mutated mode.
- `reference-and-mutant` audits the clean and mutated modes together, allowing
  clock and exception drift labels to be tested.

The truth set includes a clean control plus isolated and intentionally
cascading defects. When one mutation legitimately produces several findings,
all expected rule-ID occurrence counts are recorded. The result lists tested
and untested catalog IDs so the score cannot imply coverage of rules absent
from the truth set. The current SDC mutation layer intentionally leaves the
structural-model and external-OpenSTA integration rules outside its scope.

The committed suite currently contains 31 cases and 58 reviewed diagnostic
occurrences. It covers every catalog rule except `OC0002` and `OC6001`:
`OC0002` requires a structural Verilog/Liberty/elaboration mutation, while
`OC6001` requires an external process failure. Those behaviors have dedicated
test and integration layers rather than synthetic SDC truth labels.

## Metrics

Expected and observed diagnostics are compared as multisets of rule IDs for
every case. For each rule occurrence:

- true positive (`TP`): an observed occurrence up to the expected count;
- false positive (`FP`): an observed occurrence beyond the expected count;
- false negative (`FN`): an expected occurrence that was not observed.

The aggregate metrics pool occurrences across all cases:

```text
precision = TP / (TP + FP)
recall    = TP / (TP + FN)
F1        = 2 * precision * recall / (precision + recall)
```

An empty denominator is scored as `1.0`: producing no findings for a clean
case is correct, as is having no missed labels when no labels were expected.
`false_pass_rate` is the fraction of defect-bearing cases that produced zero
diagnostics at all. A wrong diagnostic on a defective case is not a literal
false pass; it is still exposed through both FP and FN counts. The result also
records `cases_with_misses` and per-case exact matching.

The checked-in thresholds require precision `1.0`, recall `1.0`, and false-pass
rate `0.0`. A threshold failure exits with status 1; malformed truth data or a
stale mutation exits with status 2.

## Reproduce

From a source checkout with OpenConstraint installed:

```console
python -m openconstraint.accuracy \
  --truth-set benchmarks/accuracy/truth-set.json \
  --output accuracy-result.json
```

The output contains no timestamp, duration, hostname, temporary path, or random
seed, so identical code and truth data produce byte-identical JSON. Validate the
inputs and output against the closed-shape Draft 2020-12 schemas:

```console
python - <<'PY'
import json
from pathlib import Path
from jsonschema import Draft202012Validator

root = Path("benchmarks/accuracy")
for instance_path, schema_path in (
    (root / "truth-set.json", root / "schemas/truth-set.schema.json"),
    (Path("accuracy-result.json"), root / "schemas/result.schema.json"),
):
    instance = json.loads(instance_path.read_text(encoding="utf-8"))
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(instance)
PY
```

Schema validation checks the versioned document structure and value domains.
The loader also performs semantic checks that JSON Schema cannot express as a
field projection, including unique case IDs, unique expected rule IDs, catalog
membership, and the presence of both clean and defect-bearing cases.

CI performs the same schema validation, enforces the thresholds, publishes a
job-summary scorecard, and retains the result JSON as an artifact.

## Adding or changing cases

1. State one concrete defect and why each expected rule occurrence follows.
2. Prefer an exact replacement over broad textual rewriting.
3. Run the suite and inspect every additional diagnostic; record legitimate
   cascades rather than suppressing them.
4. Keep a clean control and verify the result is deterministic across two runs.
5. Treat a truth-label change like a test-oracle change: review it separately
   from checker implementation when practical.

Precision and recall here are only as credible as the reviewed labels. The
small fixture does not reproduce real design prevalence, synthesis naming,
full Tcl execution, analog timing, formal path feasibility, or multi-million
gate capacity. Those require separate corpora and independent validation.
