# Adoption controls

OpenConstraint can distinguish newly introduced diagnostics from reviewed
legacy findings without deleting evidence from the report. Two controls serve
different purposes:

- a **diagnostic baseline** snapshots existing findings while a team adopts the
  tool; and
- a **waiver** records an explicit decision to accept one finding, with a
  required reason and an optional expiry date.

Both formats are versioned JSON, use exact `openconstraint/v1` diagnostic
fingerprints, reject unknown fields and duplicate keys, and are intended to be
reviewed in version control. Controls do not change structural coverage.

## Establish a baseline

Generate the baseline from the raw, uncontrolled result:

```console
openconstraint audit \
  --verilog netlist/top.v \
  --liberty liberty/cells.lib \
  --sdc constraints/top.sdc \
  --top top \
  --write-baseline constraints/openconstraint-baseline.json \
  --format json \
  --output reports/openconstraint.json \
  --fail-on never
```

`--write-baseline` is deliberately incompatible with `--waivers` and with
loading another baseline. It writes all raw findings, then applies the ordinary
severity and coverage exit policy. Use `--fail-on never` for a first-time
snapshot if existing findings would otherwise fail the command.

The generated file is timestamp-free and sorted by fingerprint. It records the
producer version, top module, complete diagnostic identity, and portable source
path suffix used by the fingerprint algorithm. A baseline may only be loaded
for the same top-module name.

Use it on subsequent runs:

```console
openconstraint audit \
  --verilog netlist/top.v \
  --liberty liberty/cells.lib \
  --sdc constraints/top.sdc \
  --top top \
  --baseline constraints/openconstraint-baseline.json \
  --strict-controls \
  --fail-on warning
```

Matching baseline findings remain visible as controlled findings, but they do
not contribute to active diagnostic counts or the severity gate. A diagnostic
not in the baseline is active and is marked `new` in SARIF when a baseline is
loaded. A baseline entry that no longer matches is **stale**; it normally
remains report metadata so a cleanup can be reviewed. `--strict-controls`
makes any stale baseline entry fail the quality policy with exit code 1.

Fingerprint identity includes rule ID, mode, portable path suffix, source line,
and message. Moving or materially changing a finding therefore makes it new;
the old entry becomes stale. Severity and full snapshot metadata must also
match, so a severity upgrade cannot be hidden by an older baseline.

## Review and add a waiver

A waiver targets one exact fingerprint. It cannot suppress a rule, mode, path
glob, or arbitrary group of findings. Copy the fingerprint, rule, severity,
and mode from the JSON, SARIF, HTML, or text report and add a review reason:

```json
{
  "schema_version": "1.0.0",
  "kind": "openconstraint-waivers",
  "waivers": [
    {
      "id": "SOC-142-clock-group",
      "fingerprint": "0123456789abcdefabcd",
      "rule_id": "OC1002",
      "severity": "warning",
      "mode": "functional",
      "reason": "The integration specification requires this reviewed port group; tracked by SOC-142.",
      "expires": "2027-03-31"
    }
  ]
}
```

`reason` is mandatory. `expires` is optional and uses the ISO `YYYY-MM-DD`
calendar format. A waiver remains valid through its expiry date; an already
expired waiver, evaluated by the UTC calendar date, is an input error (exit
code 2), not a silently reactivated finding. Waiver IDs and fingerprints must
be unique across every loaded file.

Load one or more waiver files:

```console
openconstraint audit \
  --verilog netlist/top.v \
  --liberty liberty/cells.lib \
  --sdc constraints/top.sdc \
  --waivers policy/team-waivers.json \
  --waivers policy/project-waivers.json \
  --strict-controls \
  --fail-on warning
```

An unused waiver is reported. With `--strict-controls`, any unused waiver fails
the quality policy so fixed or moved findings cannot leave invisible policy
debt. A fingerprint cannot appear in both a baseline and a waiver; ambiguous
control ownership is rejected as an input error.

## Report and audit trail

The JSON report's `summary.adoption` records:

- raw, active, waived, and baselined diagnostic counts;
- unused-waiver and stale-baseline counts;
- every controlled diagnostic and its disposition;
- waiver ID, reason, expiry, and source path where applicable; and
- the path, schema version, and SHA-256 of every loaded control file, plus the
  baseline producer version.

Active diagnostics remain in the normal top-level and per-mode arrays.
Controlled diagnostics move to the disposition records, so machine gates see
only active findings without erasing review evidence. Text and HTML render both
sets. SARIF emits accepted external suppressions for waivers and
`baselineState: unchanged` for baselined findings.

Control files and reports may reveal source paths, design messages, and review
reasons. Apply the same confidentiality policy used for other audit artifacts.

## Schemas and validation limits

Export the exact schemas shipped with the installed version:

```console
openconstraint schema --kind waivers --output openconstraint-waivers.schema.json
openconstraint schema --kind baseline --output openconstraint-diagnostic-baseline.schema.json
openconstraint schema --kind report --output openconstraint-report.schema.json
```

Runtime validation does not depend on `jsonschema`: it rejects malformed UTF-8
or JSON, non-finite numbers, duplicate JSON keys, unknown fields, invalid
fingerprints and dates, duplicate controls, and metadata mismatches. Each
control file is limited to 8 MiB; each waiver or baseline array is limited to
100,000 entries.
