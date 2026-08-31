# CLI reference

## `openconstraint audit`

```text
openconstraint audit --verilog FILE [--verilog FILE ...]
                     --liberty FILE [--liberty FILE ...]
                     (--sdc FILE [--sdc FILE ...] |
                      --mode NAME=FILE [--mode NAME=FILE ...])
                     [--top MODULE]
                     [--format text|json|sarif|html|all]
                     [--output PATH]
                     [--fail-on error|warning|never]
                     [--min-coverage PERCENT]
                     [--broad-match-count COUNT]
                     [--broad-match-ratio RATIO]
                     [--no-implicit-waveform-note]
                     [--waivers FILE ...]
                     [--baseline FILE | --write-baseline FILE]
                     [--strict-controls]
                     [--opensta]
                     [--opensta-bin PATH]
                     [--opensta-timeout SECONDS]
```

| Option | Meaning |
| --- | --- |
| `--verilog FILE` | Structural Verilog input; repeatable and required. |
| `--liberty FILE` | Liberty input; repeatable and required. |
| `--sdc FILE` | SDC in a single mode named `default`; repeatable. |
| `--mode NAME=FILE` | Named-mode SDC; repeat a name to append files to that mode. |
| `--top MODULE` | Top module. If omitted, the parser chooses the only uninstantiated module or its first parsed module when ambiguous. Specify it for reproducibility. |
| `--format` | `text` by default. `all` writes every format to a directory. |
| `--output PATH` | `-` means stdout. With `--format all`, this must be a directory path and cannot be `-`. Every resolved report destination is rejected if it overlaps a Verilog, Liberty, SDC, waiver, baseline, or explicitly selected OpenSTA executable input. |
| `--fail-on` | Lowest diagnostic severity that fails the quality gate. Default: `error`. `never` disables severity failure. |
| `--min-coverage PERCENT` | Fail if any audited mode is below the finite 0–100 threshold. |
| `--broad-match-count COUNT` | Nonnegative absolute wildcard threshold. Default: 50 matches. |
| `--broad-match-ratio RATIO` | Finite 0–1 fractional wildcard threshold. Default: 0.8. |
| `--no-implicit-waveform-note` | Suppress `OC2002` notes for valid implicit primary-clock waveforms. |
| `--waivers FILE` | Apply a versioned exact-fingerprint waiver file; repeatable. Each waiver requires rule, severity, mode, and reason metadata and may have an expiry date. |
| `--baseline FILE` | Load a reviewed diagnostic baseline. Matching legacy findings remain in disposition evidence but are removed from active severity counts. |
| `--write-baseline FILE` | Write a deterministic baseline of raw findings. Cannot be combined with loaded controls or stdout, and cannot overlap any audit input or report destination. Ordinary quality gates still apply. |
| `--strict-controls` | Fail with exit 1 when a waiver is unused or a baseline entry is stale. Requires `--waivers` or `--baseline`. |
| `--opensta` | Explicitly execute trusted inputs in a separately installed OpenSTA process after the static audit. Off by default. |
| `--opensta-bin PATH` | Executable path/name. With `--opensta`, defaults to discovering `sta` then `opensta` on `PATH`. |
| `--opensta-timeout SECONDS` | Positive finite timeout for the version query and each mode process. Default: 120. |

A wildcard is broad when the object universe has at least five members and the
query meets either configured threshold. `all_inputs`, `all_outputs`, and
`all_clocks` are excluded from this warning.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Audit completed and the selected severity/coverage policy passed. |
| 1 | Audit completed, but a diagnostic or minimum-coverage policy failed. |
| 2 | Invalid arguments, unreadable input, decoding failure, or modeled input error. |

The report is written before the quality-policy exit code is calculated. This
allows CI to upload SARIF or HTML even when findings fail the gate.

Malformed, expired, ambiguous, or metadata-mismatched controls are input errors
and exit 2. Stale/unused controls are reportable policy state and only fail when
`--strict-controls` is selected. See [adoption controls](adoption-controls.md)
for the formats, precedence, and recommended review flow.

An OpenSTA mode timeout, nonzero exit, failed `check_setup`, or missing effective
SDC emits error OC6001 and therefore normally exits 1 after writing the report.
Failure to locate or start the explicitly requested executable is an input or
operational error rather than a clean static result.

## `openconstraint rules`

List the installed stable diagnostic catalog:

```console
openconstraint rules
openconstraint rules --json
```

## `openconstraint schema`

Print or copy the report, waiver, or diagnostic-baseline JSON Schema:

```console
openconstraint schema
openconstraint schema --output openconstraint-report.schema.json
openconstraint schema --kind waivers --output openconstraint-waivers.schema.json
openconstraint schema --kind baseline --output openconstraint-diagnostic-baseline.schema.json
```

## `openconstraint demo`

Copy the bundled synthetic inputs and generate all reports:

```console
openconstraint demo --output-dir openconstraint-demo-report
```

The destination is created if needed. Existing same-named demo inputs and
reports may be overwritten; choose the path deliberately.

## `openconstraint benchmark`

Acquire checksum-pinned public inputs, run selected cases, or create a reviewed
semantic baseline:

```console
openconstraint benchmark fetch --manifest FILE [--cache-dir DIR] [--offline]
openconstraint benchmark run --manifest FILE [--cache-dir DIR] [--offline] [--baseline FILE]
openconstraint benchmark baseline --manifest FILE [--cache-dir DIR] [--offline] --output FILE
```

All actions accept repeatable `--dataset ID` and `--case DATASET/CASE`
selectors. Fetch and run write JSON to stdout by default; `--output FILE`
redirects it. Run exits 1 for a case error or semantic-baseline mismatch and 2
for invalid metadata, cache integrity failures, or unreadable inputs. A
resolved output path may not overlap the manifest, a loaded baseline, or a
declared local suite input.

The default cache is `.cache/openconstraint/benchmarks` below the user's home
directory. For strict reproduction, fetch into an explicit cache and rerun with
`--offline`. See [`benchmarks/README.md`](../benchmarks/README.md) for the
manifest, security, licensing, and metric contracts.
