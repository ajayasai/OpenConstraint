"""Versioned JSON report."""

from __future__ import annotations

import json

from openconstraint.model import AuditResult


def render_json(result: AuditResult, *, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
