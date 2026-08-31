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
    adoption = result.summary.get("adoption")
    if isinstance(adoption, dict):
        lines.append(
            "Adoption controls: "
            f"{adoption['active_diagnostic_count']} active of {adoption['raw_diagnostic_count']} raw; "
            f"{adoption['waived_count']} waived, {adoption['baselined_count']} baselined"
        )
        baseline_source = adoption.get("baseline_source")
        if isinstance(baseline_source, dict):
            producer = adoption.get("baseline_generated_by_version")
            producer_text = f", producer OpenConstraint {producer}" if producer else ""
            lines.append(f"  Baseline: {baseline_source['path']} (sha256 {baseline_source['sha256']}{producer_text})")
        waiver_sources = adoption.get("waiver_sources")
        if isinstance(waiver_sources, list):
            for source in waiver_sources:
                if isinstance(source, dict):
                    lines.append(f"  Waivers: {source['path']} (sha256 {source['sha256']})")
        if adoption.get("strict_failure") is True:
            lines.append(
                "  STRICT CONTROL FAILURE: "
                f"{adoption['unused_waiver_count']} unused waiver(s), "
                f"{adoption['stale_baseline_count']} stale baseline entry/entries"
            )
        lines.append("")
    if result.diagnostics:
        for finding in result.diagnostics:
            location = f"{finding.location.path}:{finding.location.line}:{finding.location.column}"
            lines.append(
                f"{finding.severity.value.upper():7} {finding.rule_id} [{finding.mode}] {location} — {finding.message}"
            )
            lines.append(f"         Fix: {finding.suggestion}")
            lines.append(f"         Fingerprint: {finding.fingerprint}")
    else:
        lines.append("No active findings." if isinstance(adoption, dict) else "No findings.")
    if isinstance(adoption, dict) and adoption.get("dispositions"):
        lines.extend(("", "Controlled findings:"))
        for disposition in adoption["dispositions"]:
            finding = disposition["diagnostic"]
            location = finding["location"]
            detail = f" via {disposition['source_path']}"
            if disposition["status"] == "waived":
                expiry = f", expires {disposition['expires']}" if disposition["expires"] else ""
                detail = (
                    f" by {disposition['waiver_id']} ({disposition['reason']}{expiry}) via {disposition['source_path']}"
                )
            lines.append(
                f"  {str(disposition['status']).upper():10} {finding['rule_id']} [{finding['mode']}] "
                f"{location['path']}:{location['line']} — {finding['message']}"
            )
            lines.append(f"             {finding['fingerprint']}{detail}")
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
