"""SARIF 2.1.0 output for GitHub code scanning and other CI consumers."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from openconstraint.adoption import disposition_diagnostics
from openconstraint.model import AuditResult, Severity
from openconstraint.rules import RULES

LEVELS = {Severity.ERROR: "error", Severity.WARNING: "warning", Severity.NOTE: "note"}
LEVEL_VALUES = {severity.value: level for severity, level in LEVELS.items()}


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


def _result(finding: Mapping[str, Any]) -> dict[str, Any]:
    location = finding["location"]
    return {
        "ruleId": finding["rule_id"],
        "level": LEVEL_VALUES[str(finding["severity"])],
        "message": {"text": f"[{finding['mode']}] {finding['message']}\n\n{finding['suggestion']}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(str(location["path"]))},
                    "region": {
                        "startLine": max(1, int(location["line"])),
                        "startColumn": max(1, int(location["column"])),
                    },
                }
            }
        ],
        "partialFingerprints": {"openconstraint/v1": finding["fingerprint"]},
        "properties": {
            "mode": finding["mode"],
            "rationale": finding["rationale"],
            "evidence": finding["evidence"],
        },
    }


def render_sarif(result: AuditResult, *, indent: int = 2) -> str:
    dispositions = disposition_diagnostics(result)
    controlled_findings = [item["diagnostic"] for item in dispositions if isinstance(item.get("diagnostic"), dict)]
    used_rule_ids = sorted(
        {finding.rule_id for finding in result.diagnostics}
        | {str(finding["rule_id"]) for finding in controlled_findings}
    )
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
                "properties": {"category": rule.category if rule else "other"},
            }
        )
    adoption = result.summary.get("adoption")
    has_baseline = isinstance(adoption, dict) and adoption.get("baseline_source") is not None
    results: list[dict[str, Any]] = []
    for active_finding in result.diagnostics:
        item = _result(active_finding.to_dict())
        if has_baseline:
            item["baselineState"] = "new"
        results.append(item)
    for disposition in dispositions:
        controlled_finding = disposition.get("diagnostic")
        if not isinstance(controlled_finding, dict):
            continue
        item = _result(controlled_finding)
        item["properties"]["adoptionStatus"] = disposition.get("status")
        item["properties"]["controlSource"] = disposition.get("source_path")
        if disposition.get("status") == "baselined":
            item["baselineState"] = "unchanged"
        else:
            item["suppressions"] = [
                {
                    "kind": "external",
                    "status": "accepted",
                    "justification": (
                        f"{disposition.get('waiver_id')}: {disposition.get('reason')}"
                        + (f" (expires {disposition['expires']})" if disposition.get("expires") else "")
                    ),
                }
            ]
        results.append(item)
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
