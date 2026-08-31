# Diagnostic rule reference

Diagnostic IDs are stable user-facing identifiers. Before 1.0, rule algorithms
may be refined, but an ID is not silently reused for a different meaning.
`openconstraint rules --json` prints the catalog shipped with an installation.

| ID | Default | Name | Category |
| --- | --- | --- | --- |
| [OC0001](OC0001.md) | error | malformed-sdc | Loading |
| [OC0002](OC0002.md) | error | incomplete-structural-model | Loading |
| [OC1001](OC1001.md) | error | zero-object-query | Queries |
| [OC1002](OC1002.md) | warning | dangerously-broad-query | Queries |
| [OC1003](OC1003.md) | warning | dynamic-query | Queries |
| [OC1004](OC1004.md) | warning | unsupported-query | Queries |
| [OC2001](OC2001.md) | error | invalid-clock-period | Clocks |
| [OC2002](OC2002.md) | note | implicit-clock-waveform | Clocks |
| [OC2003](OC2003.md) | error | clock-redefined | Clocks |
| [OC2004](OC2004.md) | warning | multiple-active-clocks | Clocks |
| [OC2005](OC2005.md) | error | invalid-clock-waveform | Clocks |
| [OC2006](OC2006.md) | error | invalid-clock-definition | Clocks |
| [OC2010](OC2010.md) | error | generated-clock-source-missing | Generated clocks |
| [OC2011](OC2011.md) | error | generated-clock-master-invalid | Generated clocks |
| [OC2012](OC2012.md) | error | invalid-generated-clock-transform | Generated clocks |
| [OC2101](OC2101.md) | error | unconstrained-endpoint | Coverage |
| [OC3001](OC3001.md) | warning | input-delay-missing | I/O |
| [OC3002](OC3002.md) | warning | output-delay-missing | I/O |
| [OC3010](OC3010.md) | error | invalid-io-delay | I/O |
| [OC3011](OC3011.md) | error | io-delay-clock-reference | I/O |
| [OC3012](OC3012.md) | error | io-delay-direction | I/O |
| [OC3013](OC3013.md) | warning | io-delay-min-max-incomplete | I/O |
| [OC3014](OC3014.md) | warning | io-delay-overwritten | I/O |
| [OC4001](OC4001.md) | warning | overlapping-exception | Exceptions |
| [OC4002](OC4002.md) | error | invalid-exception-definition | Exceptions |
| [OC4010](OC4010.md) | error | invalid-multicycle | Exceptions |
| [OC4011](OC4011.md) | warning | multicycle-setup-hold-pair | Exceptions |
| [OC4012](OC4012.md) | error | conflicting-multicycle | Exceptions |
| [OC5001](OC5001.md) | note | mode-clock-drift | Modes |
| [OC5002](OC5002.md) | note | mode-exception-drift | Modes |
| [OC6001](OC6001.md) | error | opensta-validation-failed | OpenSTA |

Default severity describes the catalog entry. A rule may emit a different
severity when its evidence is more or less dangerous; those cases are called
out on the rule page. CLI gating uses the emitted severity.

## Interpreting a finding

Each finding contains a source location or a synthetic location such as
`<design>`, an explanation of risk, a remediation, mode, deterministic
fingerprint, and structured evidence. A finding proves that the documented
static condition was observed. It does not prove that the design will fail
timing or that the suggested change is correct for the interface protocol.

False positives, false negatives, and missing syntax support are first-class
bugs. Use the dedicated issue forms and attach only synthetic or redacted data.
