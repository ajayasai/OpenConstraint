"""Compact deterministic terminal report."""

from __future__ import annotations

from openconstraint.model import AuditResult


def render_text(result: AuditResult) -> str:
    lines = [
        f"OpenConstraint {result.tool_version} — {result.design['top']}",
        (
            f"Design: {result.design['ports']} ports, {result.design['instances']} cells, "
            f"{result.design['sequential_endpoints']} sequential endpoints"
        ),
        "",
    ]
    for mode in result.modes:
        lines.append(f"Mode {mode.name}: {mode.coverage.score:.2f}% structural coverage (grade {mode.coverage.grade})")
        for component in mode.coverage.components:
            percent = "n/a" if component.percentage is None else f"{component.percentage:.2f}%"
            lines.append(f"  {component.label:<30} {component.covered:>5}/{component.total:<5} {percent:>8}")
        lines.append("")
    if result.diagnostics:
        for finding in result.diagnostics:
            location = f"{finding.location.path}:{finding.location.line}:{finding.location.column}"
            lines.append(
                f"{finding.severity.value.upper():7} {finding.rule_id} [{finding.mode}] {location} — {finding.message}"
            )
            lines.append(f"         Fix: {finding.suggestion}")
    else:
        lines.append("No findings.")
    lines.extend(
        (
            "",
            (
                f"Summary: {result.summary['errors']} error(s), {result.summary['warnings']} warning(s), "
                f"{result.summary['notes']} note(s)"
            ),
            "Structural coverage measures modeled obligations; it does not prove functional false paths or sign-off correctness.",
        )
    )
    return "\n".join(lines) + "\n"
