"""SARIF 2.1.0 output for GitHub code scanning and other CI consumers."""

from __future__ import annotations

import json
from pathlib import Path

from openconstraint.model import AuditResult, Severity
from openconstraint.rules import RULES

LEVELS = {Severity.ERROR: "error", Severity.WARNING: "warning", Severity.NOTE: "note"}


def _uri(path: str) -> str:
    if path.startswith("<"):
        return f"openconstraint://{path.strip('<>').replace(' ', '-')}"
    candidate = Path(path)
    if not candidate.is_absolute():
        return candidate.as_posix()
    try:
        return candidate.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return candidate.resolve().as_uri()


def render_sarif(result: AuditResult, *, indent: int = 2) -> str:
    used_rule_ids = sorted({finding.rule_id for finding in result.diagnostics})
    rules = []
    for rule_id in used_rule_ids:
        rule = RULES.get(rule_id)
        rules.append(
            {
                "id": rule_id,
                "name": rule.name if rule else rule_id.lower(),
                "shortDescription": {"text": rule.summary if rule else rule_id},
                "helpUri": f"https://github.com/ajayasai/OpenConstraint/blob/main/docs/rules/{rule_id}.md",
                "defaultConfiguration": {"level": LEVELS.get(rule.default_severity, "warning") if rule else "warning"},
                "properties": {"category": rule.category if rule else "other", "precision": "high"},
            }
        )
    results = []
    for finding in result.diagnostics:
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": LEVELS[finding.severity],
                "message": {"text": f"[{finding.mode}] {finding.message}\n\n{finding.suggestion}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _uri(finding.location.path)},
                            "region": {
                                "startLine": max(1, finding.location.line),
                                "startColumn": max(1, finding.location.column),
                            },
                        }
                    }
                ],
                "partialFingerprints": {"openconstraint/v1": finding.fingerprint},
                "properties": {
                    "mode": finding.mode,
                    "rationale": finding.rationale,
                    "evidence": finding.evidence,
                },
            }
        )
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OpenConstraint",
                        "version": result.tool_version,
                        "informationUri": "https://github.com/ajayasai/OpenConstraint",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {"summary": result.summary, "design": result.design},
            }
        ],
    }
    return json.dumps(payload, indent=indent, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
