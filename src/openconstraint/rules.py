"""Stable diagnostic catalog exposed by the CLI and SARIF reporter."""

from __future__ import annotations

from dataclasses import dataclass

from openconstraint.model import Severity


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    name: str
    default_severity: Severity
    summary: str
    category: str


RULES = {
    rule.rule_id: rule
    for rule in (
        Rule("OC0001", "malformed-sdc", Severity.ERROR, "The Tcl/SDC structure is malformed.", "loading"),
        Rule("OC1001", "zero-object-query", Severity.ERROR, "An SDC object query matches nothing.", "queries"),
        Rule(
            "OC1002",
            "dangerously-broad-query",
            Severity.WARNING,
            "A wildcard query covers a risky share of its object universe.",
            "queries",
        ),
        Rule(
            "OC1003",
            "dynamic-query",
            Severity.WARNING,
            "A Tcl-dynamic query cannot be proven by the safe static backend.",
            "queries",
        ),
        Rule(
            "OC1004",
            "unsupported-query",
            Severity.WARNING,
            "A query feature is outside the deterministic static subset.",
            "queries",
        ),
        Rule("OC2001", "invalid-clock-period", Severity.ERROR, "A clock has no valid positive period.", "clocks"),
        Rule(
            "OC2002",
            "implicit-clock-waveform",
            Severity.NOTE,
            "A primary clock uses the valid implicit 50% waveform.",
            "clocks",
        ),
        Rule(
            "OC2003",
            "clock-redefined",
            Severity.ERROR,
            "A clock is redefined without a clean additive merge.",
            "clocks",
        ),
        Rule(
            "OC2004",
            "multiple-active-clocks",
            Severity.WARNING,
            "A sequential clock pin receives multiple clocks.",
            "clocks",
        ),
        Rule(
            "OC2010",
            "generated-clock-source-missing",
            Severity.ERROR,
            "A generated clock source resolves to nothing.",
            "generated clocks",
        ),
        Rule(
            "OC2011",
            "generated-clock-master-invalid",
            Severity.ERROR,
            "A generated-clock source is unrelated to the selected master.",
            "generated clocks",
        ),
        Rule(
            "OC2101",
            "unconstrained-endpoint",
            Severity.ERROR,
            "One or more sequential endpoints have no reachable clock.",
            "coverage",
        ),
        Rule("OC3001", "input-delay-missing", Severity.WARNING, "A non-clock input is missing an input delay.", "I/O"),
        Rule("OC3002", "output-delay-missing", Severity.WARNING, "An output is missing an output delay.", "I/O"),
        Rule(
            "OC4001",
            "overlapping-exception",
            Severity.WARNING,
            "Timing exceptions overlap or shadow one another.",
            "exceptions",
        ),
        Rule("OC5001", "mode-clock-drift", Severity.NOTE, "A clock definition differs across modes.", "modes"),
        Rule("OC5002", "mode-exception-drift", Severity.NOTE, "Exception topology differs across modes.", "modes"),
        Rule(
            "OC6001",
            "opensta-validation-failed",
            Severity.ERROR,
            "The explicitly requested OpenSTA validation did not complete cleanly.",
            "OpenSTA",
        ),
    )
}
