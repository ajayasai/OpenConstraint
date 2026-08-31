"""Versioned diagnostic baselines and reviewable exact-fingerprint waivers."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from openconstraint.model import AuditResult, Diagnostic, Severity

WAIVER_SCHEMA_VERSION = "1.0.0"
BASELINE_SCHEMA_VERSION = "1.0.0"
FINGERPRINT_ALGORITHM = "openconstraint/v1"
MAX_CONTROL_BYTES = 8 * 1024 * 1024
MAX_WAIVERS = 100_000
MAX_BASELINE_DIAGNOSTICS = 100_000

_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{20}$")
_RULE_ID_RE = re.compile(r"^OC[0-9]{4}$")
_WAIVER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")


@dataclass(frozen=True, slots=True)
class ControlSource:
    """Content provenance for one loaded control document."""

    path: str
    sha256: str
    schema_version: str

    def to_dict(self) -> dict[str, str]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True, slots=True)
class Waiver:
    """One reviewed suppression bound to an exact diagnostic identity."""

    waiver_id: str
    fingerprint: str
    rule_id: str
    severity: Severity
    mode: str
    reason: str
    expires: date | None
    source: ControlSource

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.waiver_id,
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "mode": self.mode,
            "reason": self.reason,
            "expires": self.expires.isoformat() if self.expires is not None else None,
            "source_path": self.source.path,
        }


@dataclass(frozen=True, slots=True)
class WaiverSet:
    """Validated waivers merged from one or more ordered source files."""

    entries: Mapping[str, Waiver]
    sources: tuple[ControlSource, ...]


@dataclass(frozen=True, slots=True)
class BaselineDiagnostic:
    """Review snapshot for one baselined diagnostic."""

    fingerprint: str
    rule_id: str
    severity: Severity
    mode: str
    message: str
    path: str
    line: int
    column: int

    def to_dict(self) -> dict[str, object]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "mode": self.mode,
            "message": self.message,
            "location": {"path": self.path, "line": self.line, "column": self.column},
        }


@dataclass(frozen=True, slots=True)
class DiagnosticBaseline:
    """Validated baseline bound to one top-level design name."""

    design_top: str
    generated_by_version: str
    entries: Mapping[str, BaselineDiagnostic]
    source: ControlSource


def _portable_path(path: str) -> str:
    source_path = path.replace("\\", "/")
    if not source_path.startswith("<"):
        source_path = "/".join(part for part in source_path.split("/") if part)[-240:]
        source_path = "/".join(source_path.split("/")[-4:])
    return source_path


def _diagnostic_identity(finding: Diagnostic) -> BaselineDiagnostic:
    return BaselineDiagnostic(
        fingerprint=finding.fingerprint,
        rule_id=finding.rule_id,
        severity=finding.severity,
        mode=finding.mode,
        message=finding.message,
        path=_portable_path(finding.location.path),
        line=finding.location.line,
        column=finding.location.column,
    )


def _fingerprint(rule_id: str, mode: str, path: str, line: int, message: str) -> str:
    payload = "\x1f".join((rule_id, mode, _portable_path(path), str(line), message))
    return sha256(payload.encode("utf-8")).hexdigest()[:20]


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r} is not allowed")


def _object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _control_path(path: str | Path) -> str:
    return str(Path(path)).replace("\\", "/")


def _load_json(path: str | Path, label: str) -> tuple[dict[str, object], bytes]:
    source = Path(path)
    size = source.stat().st_size
    if size > MAX_CONTROL_BYTES:
        raise ValueError(f"{label} exceeds the {MAX_CONTROL_BYTES}-byte control-file limit")
    with source.open("rb") as stream:
        raw = stream.read(MAX_CONTROL_BYTES + 1)
    if len(raw) > MAX_CONTROL_BYTES:
        raise ValueError(f"{label} exceeds the {MAX_CONTROL_BYTES}-byte control-file limit")
    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            parse_constant=_reject_constant,
            object_pairs_hook=_object_without_duplicates,
        )
    except (json.JSONDecodeError, RecursionError, UnicodeError) as error:
        raise ValueError(f"invalid {label} JSON: {error}") from error
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} must be a JSON object")
    return parsed, raw


def _known_keys(value: Mapping[str, object], expected: set[str], label: str) -> None:
    unknown = sorted(set(value) - expected)
    if unknown:
        raise ValueError(f"{label} contains unknown field(s): {', '.join(unknown)}")


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _array(value: object, label: str, limit: int) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    if len(value) > limit:
        raise ValueError(f"{label} exceeds the {limit}-entry limit")
    return value


def _string(value: object, label: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{label} must be a nonempty string without surrounding whitespace")
    if len(value) > maximum:
        raise ValueError(f"{label} exceeds {maximum} characters")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _severity(value: object, label: str) -> Severity:
    try:
        return Severity(_string(value, label, maximum=16))
    except ValueError as error:
        raise ValueError(f"{label} must be one of error, warning, or note") from error


def _source(path: str | Path, raw: bytes, schema_version: str) -> ControlSource:
    return ControlSource(_control_path(path), sha256(raw).hexdigest(), schema_version)


def load_waivers(paths: Sequence[str | Path], *, today: date | None = None) -> WaiverSet:
    """Load strict waiver files and reject expired or ambiguous entries."""

    effective_date = today or datetime.now(UTC).date()
    entries: dict[str, Waiver] = {}
    ids: dict[str, str] = {}
    sources: list[ControlSource] = []
    for path in paths:
        root, raw = _load_json(path, "waiver file")
        _known_keys(root, {"schema_version", "kind", "waivers"}, "waiver file")
        if root.get("schema_version") != WAIVER_SCHEMA_VERSION:
            raise ValueError(f"unsupported waiver schema_version in {_control_path(path)}")
        if root.get("kind") != "openconstraint-waivers":
            raise ValueError(f"invalid waiver kind in {_control_path(path)}")
        source = _source(path, raw, WAIVER_SCHEMA_VERSION)
        sources.append(source)
        for index, item in enumerate(_array(root.get("waivers"), "waivers", MAX_WAIVERS)):
            label = f"waivers[{index}]"
            record = _mapping(item, label)
            _known_keys(
                record,
                {"id", "fingerprint", "rule_id", "severity", "mode", "reason", "expires"},
                label,
            )
            waiver_id = _string(record.get("id"), f"{label}.id", maximum=128)
            if not _WAIVER_ID_RE.fullmatch(waiver_id):
                raise ValueError(f"{label}.id has an invalid format")
            fingerprint = _string(record.get("fingerprint"), f"{label}.fingerprint", maximum=20)
            if not _FINGERPRINT_RE.fullmatch(fingerprint):
                raise ValueError(f"{label}.fingerprint must be 20 lowercase hexadecimal characters")
            rule_id = _string(record.get("rule_id"), f"{label}.rule_id", maximum=6)
            if not _RULE_ID_RE.fullmatch(rule_id):
                raise ValueError(f"{label}.rule_id must use the OCdddd form")
            mode = _string(record.get("mode"), f"{label}.mode", maximum=256)
            reason = _string(record.get("reason"), f"{label}.reason", maximum=4096)
            expires: date | None = None
            if "expires" in record:
                raw_expiry = _string(record["expires"], f"{label}.expires", maximum=10)
                if not _DATE_RE.fullmatch(raw_expiry):
                    raise ValueError(f"{label}.expires must use YYYY-MM-DD")
                try:
                    expires = date.fromisoformat(raw_expiry)
                except ValueError as error:
                    raise ValueError(f"{label}.expires is not a valid calendar date") from error
                if expires < effective_date:
                    raise ValueError(
                        f"waiver {waiver_id!r} expired on {expires.isoformat()} "
                        f"(effective date {effective_date.isoformat()})"
                    )
            if waiver_id in ids:
                raise ValueError(f"duplicate waiver id {waiver_id!r} in {source.path} and {ids[waiver_id]}")
            if fingerprint in entries:
                raise ValueError(
                    f"duplicate waiver fingerprint {fingerprint!r} in {source.path} "
                    f"and {entries[fingerprint].source.path}"
                )
            waiver = Waiver(
                waiver_id,
                fingerprint,
                rule_id,
                _severity(record.get("severity"), f"{label}.severity"),
                mode,
                reason,
                expires,
                source,
            )
            ids[waiver_id] = source.path
            entries[fingerprint] = waiver
    return WaiverSet(entries, tuple(sources))


def baseline_from_result(result: AuditResult) -> dict[str, object]:
    """Create a deterministic, timestamp-free snapshot of raw diagnostics."""

    if "adoption" in result.summary:
        raise ValueError("cannot create a diagnostic baseline from an already controlled result")
    entries: dict[str, BaselineDiagnostic] = {}
    for finding in result.diagnostics:
        identity = _diagnostic_identity(finding)
        previous = entries.get(identity.fingerprint)
        if previous is not None and previous != identity:
            raise ValueError(f"diagnostic fingerprint collision for {identity.fingerprint}")
        entries[identity.fingerprint] = identity
    return {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "kind": "openconstraint-diagnostic-baseline",
        "fingerprint_algorithm": FINGERPRINT_ALGORITHM,
        "generated_by": {"name": "OpenConstraint", "version": result.tool_version},
        "design": {"top": str(result.design["top"])},
        "diagnostics": [entries[key].to_dict() for key in sorted(entries)],
    }


def render_baseline(value: Mapping[str, object]) -> str:
    """Render a baseline in the canonical human-reviewable JSON form."""

    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"


def load_diagnostic_baseline(path: str | Path) -> DiagnosticBaseline:
    """Load and fully validate a diagnostic baseline."""

    root, raw = _load_json(path, "diagnostic baseline")
    _known_keys(
        root,
        {"schema_version", "kind", "fingerprint_algorithm", "generated_by", "design", "diagnostics"},
        "diagnostic baseline",
    )
    if root.get("schema_version") != BASELINE_SCHEMA_VERSION:
        raise ValueError("unsupported diagnostic baseline schema_version")
    if root.get("kind") != "openconstraint-diagnostic-baseline":
        raise ValueError("invalid diagnostic baseline kind")
    if root.get("fingerprint_algorithm") != FINGERPRINT_ALGORITHM:
        raise ValueError("unsupported diagnostic baseline fingerprint_algorithm")
    generated_by = _mapping(root.get("generated_by"), "diagnostic baseline.generated_by")
    _known_keys(generated_by, {"name", "version"}, "diagnostic baseline.generated_by")
    if generated_by.get("name") != "OpenConstraint":
        raise ValueError("diagnostic baseline.generated_by.name must be OpenConstraint")
    generated_by_version = _string(generated_by.get("version"), "diagnostic baseline.generated_by.version")
    design = _mapping(root.get("design"), "diagnostic baseline.design")
    _known_keys(design, {"top"}, "diagnostic baseline.design")
    design_top = _string(design.get("top"), "diagnostic baseline.design.top")
    entries: dict[str, BaselineDiagnostic] = {}
    for index, item in enumerate(
        _array(root.get("diagnostics"), "diagnostic baseline.diagnostics", MAX_BASELINE_DIAGNOSTICS)
    ):
        label = f"diagnostic baseline.diagnostics[{index}]"
        record = _mapping(item, label)
        _known_keys(record, {"fingerprint", "rule_id", "severity", "mode", "message", "location"}, label)
        fingerprint = _string(record.get("fingerprint"), f"{label}.fingerprint", maximum=20)
        if not _FINGERPRINT_RE.fullmatch(fingerprint):
            raise ValueError(f"{label}.fingerprint must be 20 lowercase hexadecimal characters")
        rule_id = _string(record.get("rule_id"), f"{label}.rule_id", maximum=6)
        if not _RULE_ID_RE.fullmatch(rule_id):
            raise ValueError(f"{label}.rule_id must use the OCdddd form")
        mode = _string(record.get("mode"), f"{label}.mode", maximum=256)
        message = _string(record.get("message"), f"{label}.message", maximum=16384)
        location = _mapping(record.get("location"), f"{label}.location")
        _known_keys(location, {"path", "line", "column"}, f"{label}.location")
        source_path = _string(location.get("path"), f"{label}.location.path", maximum=4096)
        line = _integer(location.get("line"), f"{label}.location.line")
        column = _integer(location.get("column"), f"{label}.location.column")
        if fingerprint != _fingerprint(rule_id, mode, source_path, line, message):
            raise ValueError(f"{label}.fingerprint does not match its diagnostic identity")
        if fingerprint in entries:
            raise ValueError(f"duplicate diagnostic baseline fingerprint {fingerprint!r}")
        entries[fingerprint] = BaselineDiagnostic(
            fingerprint,
            rule_id,
            _severity(record.get("severity"), f"{label}.severity"),
            mode,
            message,
            source_path,
            line,
            column,
        )
    return DiagnosticBaseline(
        design_top,
        generated_by_version,
        entries,
        _source(path, raw, BASELINE_SCHEMA_VERSION),
    )


def _identity_matches(current: BaselineDiagnostic, expected: BaselineDiagnostic) -> bool:
    return current == expected


def _disposition(
    finding: Diagnostic,
    status: str,
    source: ControlSource,
    waiver: Waiver | None = None,
) -> dict[str, object]:
    return {
        "status": status,
        "diagnostic": finding.to_dict(),
        "source_path": source.path,
        "waiver_id": waiver.waiver_id if waiver is not None else None,
        "reason": waiver.reason if waiver is not None else None,
        "expires": waiver.expires.isoformat() if waiver is not None and waiver.expires is not None else None,
    }


def apply_adoption_controls(
    result: AuditResult,
    *,
    waivers: WaiverSet | None = None,
    baseline: DiagnosticBaseline | None = None,
    strict: bool = False,
) -> None:
    """Apply controls to an audit result and attach complete report provenance."""

    if "adoption" in result.summary:
        raise ValueError("adoption controls have already been applied to this result")
    if waivers is None and baseline is None:
        raise ValueError("at least one waiver set or diagnostic baseline is required")
    if baseline is not None and baseline.design_top != str(result.design["top"]):
        raise ValueError(
            f"diagnostic baseline top {baseline.design_top!r} does not match audited top {result.design['top']!r}"
        )
    waiver_entries = waivers.entries if waivers is not None else {}
    baseline_entries = baseline.entries if baseline is not None else {}
    overlap = sorted(set(waiver_entries) & set(baseline_entries))
    if overlap:
        sample = ", ".join(overlap[:5])
        raise ValueError(f"diagnostics cannot be both waived and baselined: {sample}")

    active: list[Diagnostic] = []
    dispositions: list[dict[str, object]] = []
    matched_waivers: set[str] = set()
    matched_baseline: set[str] = set()
    waived_count = 0
    baselined_count = 0
    for finding in result.diagnostics:
        fingerprint = finding.fingerprint
        waiver = waiver_entries.get(fingerprint)
        if waiver is not None:
            if waiver.rule_id != finding.rule_id or waiver.severity != finding.severity or waiver.mode != finding.mode:
                raise ValueError(f"waiver {waiver.waiver_id!r} metadata does not match diagnostic {fingerprint}")
            matched_waivers.add(fingerprint)
            waived_count += 1
            dispositions.append(_disposition(finding, "waived", waiver.source, waiver))
            continue
        expected = baseline_entries.get(fingerprint)
        if expected is not None:
            if not _identity_matches(_diagnostic_identity(finding), expected):
                raise ValueError(f"diagnostic baseline metadata does not match diagnostic {fingerprint}")
            if baseline is None:  # pragma: no cover - guarded by baseline_entries construction
                raise AssertionError("baseline entry without baseline source")
            matched_baseline.add(fingerprint)
            baselined_count += 1
            dispositions.append(_disposition(finding, "baselined", baseline.source))
            continue
        active.append(finding)

    controlled_fingerprints = matched_waivers | matched_baseline
    result.diagnostics = active
    for mode in result.modes:
        mode.diagnostics = [item for item in mode.diagnostics if item.fingerprint not in controlled_fingerprints]

    counts = {severity: sum(item.severity == severity for item in active) for severity in Severity}
    result.summary["diagnostic_count"] = len(active)
    result.summary["errors"] = counts[Severity.ERROR]
    result.summary["warnings"] = counts[Severity.WARNING]
    result.summary["notes"] = counts[Severity.NOTE]

    unused_waivers = [waiver_entries[key].to_dict() for key in sorted(set(waiver_entries) - matched_waivers)]
    stale_baseline = [baseline_entries[key].to_dict() for key in sorted(set(baseline_entries) - matched_baseline)]
    strict_failure = strict and bool(unused_waivers or stale_baseline)
    dispositions.sort(key=lambda item: str(_mapping(item["diagnostic"], "diagnostic")["fingerprint"]))
    result.summary["adoption"] = {
        "fingerprint_algorithm": FINGERPRINT_ALGORITHM,
        "raw_diagnostic_count": len(active) + waived_count + baselined_count,
        "active_diagnostic_count": len(active),
        "waived_count": waived_count,
        "baselined_count": baselined_count,
        "unused_waiver_count": len(unused_waivers),
        "stale_baseline_count": len(stale_baseline),
        "strict": strict,
        "strict_failure": strict_failure,
        "waiver_sources": [source.to_dict() for source in (waivers.sources if waivers is not None else ())],
        "baseline_source": baseline.source.to_dict() if baseline is not None else None,
        "baseline_generated_by_version": baseline.generated_by_version if baseline is not None else None,
        "dispositions": dispositions,
        "unused_waivers": unused_waivers,
        "stale_baseline_diagnostics": stale_baseline,
    }


def adoption_strict_failure(result: AuditResult) -> bool:
    """Return whether strict stale-control policy failed for this result."""

    adoption = result.summary.get("adoption")
    return isinstance(adoption, dict) and adoption.get("strict_failure") is True


def disposition_diagnostics(result: AuditResult) -> list[Mapping[str, Any]]:
    """Expose typed-enough disposition records to human and SARIF reporters."""

    adoption = result.summary.get("adoption")
    if not isinstance(adoption, dict):
        return []
    dispositions = adoption.get("dispositions")
    if not isinstance(dispositions, list):
        return []
    return [item for item in dispositions if isinstance(item, dict)]
