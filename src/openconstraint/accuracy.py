"""Deterministic truth-set benchmark for rule-level semantic accuracy.

This module intentionally measures only whether OpenConstraint emits the
reviewed rule IDs for small, synthetic SDC mutations.  It is not a timing,
formal-verification, or vendor-comparison benchmark.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

from openconstraint.engine import AuditOptions, ModeInput, audit
from openconstraint.parsers.liberty import parse_liberty_text
from openconstraint.parsers.verilog import elaborate, parse_verilog_text
from openconstraint.rules import RULES
from openconstraint.version import __version__

TRUTH_SCHEMA_VERSION = "1.0.0"
RESULT_SCHEMA_VERSION = "1.0.0"
_ID_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_MAX_JSON_BYTES = 64 * 1024 * 1024
_MAX_JSON_DEPTH = 256
_MAX_JSON_NODES = 1_000_000


class AccuracyError(ValueError):
    """Raised when a truth set or mutation is invalid."""


class _Score(TypedDict):
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    exact_match: bool
    false_pass: bool


@dataclass(frozen=True, slots=True)
class Fixture:
    fixture_id: str
    description: str
    top: str
    verilog: str
    liberty: str
    sdc: str
    license_spdx: str
    provenance: str


@dataclass(frozen=True, slots=True)
class Mutation:
    kind: str
    text: str = ""
    match: str = ""
    replacement: str = ""
    count: int = 0


@dataclass(frozen=True, slots=True)
class AccuracyCase:
    case_id: str
    description: str
    execution: str
    mutations: tuple[Mutation, ...]
    expected: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class Thresholds:
    minimum_precision: float
    minimum_recall: float
    maximum_false_pass_rate: float


@dataclass(frozen=True, slots=True)
class TruthSet:
    path: Path
    digest: str
    suite_id: str
    suite_name: str
    description: str
    fixture: Fixture
    options: AuditOptions
    thresholds: Thresholds
    cases: tuple[AccuracyCase, ...]


def _reject_constant(value: str) -> None:
    raise AccuracyError(f"non-finite JSON number {value!r} is not allowed")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AccuracyError(f"duplicate JSON key {key!r} is not allowed")
        result[key] = value
    return result


def _validate_json_shape(value: object, label: str) -> None:
    """Bound nested/container traversal before schema-specific validation."""

    stack: list[tuple[object, int]] = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES:
            raise AccuracyError(f"{label} exceeds the JSON node limit of {_MAX_JSON_NODES}")
        if depth > _MAX_JSON_DEPTH:
            raise AccuracyError(f"{label} exceeds the JSON nesting limit of {_MAX_JSON_DEPTH}")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)


def _load_json(path: Path, label: str) -> object:
    try:
        size = path.stat().st_size
        if size > _MAX_JSON_BYTES:
            raise AccuracyError(f"{label} exceeds the JSON size limit of {_MAX_JSON_BYTES} bytes")
        value = json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=_reject_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except AccuracyError:
        raise
    except json.JSONDecodeError as error:
        raise AccuracyError(f"invalid {label} JSON: {error}") from error
    except RecursionError as error:
        raise AccuracyError(f"{label} exceeds the JSON nesting limit of {_MAX_JSON_DEPTH}") from error
    except ValueError as error:
        raise AccuracyError(f"invalid {label} JSON: {error}") from error
    _validate_json_shape(value, label)
    return value


def _object(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise AccuracyError(f"{context} must be an object")
    return value


def _array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise AccuracyError(f"{context} must be an array")
    return value


def _string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise AccuracyError(f"{context} must be a nonempty string")
    return value


def _known_keys(value: Mapping[str, object], allowed: set[str], context: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise AccuracyError(f"{context} has unknown key(s): {', '.join(unknown)}")


def _identifier(value: object, context: str) -> str:
    result = _string(value, context)
    if _ID_RE.fullmatch(result) is None:
        raise AccuracyError(f"{context} must be a lowercase kebab-case identifier")
    return result


def _ratio(value: object, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AccuracyError(f"{context} must be a number from 0 through 1")
    result = float(value)
    if not math.isfinite(result) or not 0.0 <= result <= 1.0:
        raise AccuracyError(f"{context} must be a finite number from 0 through 1")
    return result


def _nonnegative_integer(value: object, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AccuracyError(f"{context} must be a nonnegative integer")
    return value


def _canonical_digest(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _parse_fixture(value: object) -> Fixture:
    item = _object(value, "fixture")
    _known_keys(
        item,
        {"id", "description", "top", "verilog", "liberty", "sdc", "license"},
        "fixture",
    )
    license_value = _object(item.get("license"), "fixture.license")
    _known_keys(license_value, {"spdx", "provenance"}, "fixture.license")
    return Fixture(
        fixture_id=_identifier(item.get("id"), "fixture.id"),
        description=_string(item.get("description"), "fixture.description"),
        top=_string(item.get("top"), "fixture.top"),
        verilog=_string(item.get("verilog"), "fixture.verilog"),
        liberty=_string(item.get("liberty"), "fixture.liberty"),
        sdc=_string(item.get("sdc"), "fixture.sdc"),
        license_spdx=_string(license_value.get("spdx"), "fixture.license.spdx"),
        provenance=_string(license_value.get("provenance"), "fixture.license.provenance"),
    )


def _parse_options(value: object) -> AuditOptions:
    item = _object(value, "options")
    _known_keys(
        item,
        {"broad_match_count", "broad_match_ratio", "broad_match_min_universe", "report_implicit_waveform"},
        "options",
    )
    report_waveform = item.get("report_implicit_waveform")
    if not isinstance(report_waveform, bool):
        raise AccuracyError("options.report_implicit_waveform must be a boolean")
    return AuditOptions(
        broad_match_count=_nonnegative_integer(item.get("broad_match_count"), "options.broad_match_count"),
        broad_match_ratio=_ratio(item.get("broad_match_ratio"), "options.broad_match_ratio"),
        broad_match_min_universe=_nonnegative_integer(
            item.get("broad_match_min_universe"), "options.broad_match_min_universe"
        ),
        report_implicit_waveform=report_waveform,
    )


def _parse_thresholds(value: object) -> Thresholds:
    item = _object(value, "thresholds")
    _known_keys(item, {"minimum_precision", "minimum_recall", "maximum_false_pass_rate"}, "thresholds")
    return Thresholds(
        minimum_precision=_ratio(item.get("minimum_precision"), "thresholds.minimum_precision"),
        minimum_recall=_ratio(item.get("minimum_recall"), "thresholds.minimum_recall"),
        maximum_false_pass_rate=_ratio(item.get("maximum_false_pass_rate"), "thresholds.maximum_false_pass_rate"),
    )


def _parse_mutation(value: object, context: str) -> Mutation:
    item = _object(value, context)
    kind = _string(item.get("kind"), f"{context}.kind")
    if kind == "append":
        _known_keys(item, {"kind", "text"}, context)
        return Mutation(kind=kind, text=_string(item.get("text"), f"{context}.text"))
    if kind == "replace":
        _known_keys(item, {"kind", "match", "replacement", "count"}, context)
        match = _string(item.get("match"), f"{context}.match")
        replacement = item.get("replacement")
        if not isinstance(replacement, str):
            raise AccuracyError(f"{context}.replacement must be a string")
        count = _nonnegative_integer(item.get("count"), f"{context}.count")
        if count == 0:
            raise AccuracyError(f"{context}.count must be positive")
        return Mutation(kind=kind, match=match, replacement=replacement, count=count)
    raise AccuracyError(f"{context}.kind must be 'append' or 'replace'")


def _parse_expected(value: object, context: str) -> tuple[tuple[str, int], ...]:
    labels: list[tuple[str, int]] = []
    seen: set[str] = set()
    for index, raw in enumerate(_array(value, context)):
        item_context = f"{context}[{index}]"
        item = _object(raw, item_context)
        _known_keys(item, {"rule_id", "count"}, item_context)
        rule_id = _string(item.get("rule_id"), f"{item_context}.rule_id")
        if rule_id not in RULES:
            raise AccuracyError(f"{item_context}.rule_id names unknown rule {rule_id!r}")
        if rule_id in seen:
            raise AccuracyError(f"{context} repeats rule {rule_id!r}")
        seen.add(rule_id)
        count = _nonnegative_integer(item.get("count"), f"{item_context}.count")
        if count == 0:
            raise AccuracyError(f"{item_context}.count must be positive")
        labels.append((rule_id, count))
    return tuple(sorted(labels))


def _parse_case(value: object, index: int) -> AccuracyCase:
    context = f"cases[{index}]"
    item = _object(value, context)
    _known_keys(item, {"id", "description", "execution", "mutations", "expected"}, context)
    execution = _string(item.get("execution"), f"{context}.execution")
    if execution not in {"mutant-only", "reference-and-mutant"}:
        raise AccuracyError(f"{context}.execution has an unsupported value")
    mutations = tuple(
        _parse_mutation(mutation, f"{context}.mutations[{mutation_index}]")
        for mutation_index, mutation in enumerate(_array(item.get("mutations"), f"{context}.mutations"))
    )
    expected = _parse_expected(item.get("expected"), f"{context}.expected")
    if expected and not mutations:
        raise AccuracyError(f"{context} expects defects but applies no mutation")
    return AccuracyCase(
        case_id=_identifier(item.get("id"), f"{context}.id"),
        description=_string(item.get("description"), f"{context}.description"),
        execution=execution,
        mutations=mutations,
        expected=expected,
    )


def load_truth_set(path: str | Path) -> TruthSet:
    """Load and strictly validate one versioned semantic truth set."""

    source = Path(path)
    payload = _load_json(source, "truth-set")
    root = _object(payload, "truth set")
    _known_keys(root, {"schema_version", "suite", "fixture", "options", "thresholds", "cases"}, "truth set")
    if root.get("schema_version") != TRUTH_SCHEMA_VERSION:
        raise AccuracyError(f"unsupported truth-set schema {root.get('schema_version')!r}")
    suite = _object(root.get("suite"), "suite")
    _known_keys(suite, {"id", "name", "description"}, "suite")
    cases = tuple(_parse_case(value, index) for index, value in enumerate(_array(root.get("cases"), "cases")))
    if not cases:
        raise AccuracyError("cases must not be empty")
    case_ids = [case.case_id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise AccuracyError("case IDs must be unique")
    if not any(case.expected for case in cases) or not any(not case.expected for case in cases):
        raise AccuracyError("truth set must include both defect-bearing and clean-control cases")
    return TruthSet(
        path=source.resolve(),
        digest=_canonical_digest(payload),
        suite_id=_identifier(suite.get("id"), "suite.id"),
        suite_name=_string(suite.get("name"), "suite.name"),
        description=_string(suite.get("description"), "suite.description"),
        fixture=_parse_fixture(root.get("fixture")),
        options=_parse_options(root.get("options")),
        thresholds=_parse_thresholds(root.get("thresholds")),
        cases=cases,
    )


def apply_mutations(base_sdc: str, mutations: Sequence[Mutation]) -> str:
    """Apply exact, ordered mutations and reject stale mutation anchors."""

    result = base_sdc
    for index, mutation in enumerate(mutations):
        if mutation.kind == "append":
            if result and not result.endswith("\n"):
                result += "\n"
            result += mutation.text
            if not result.endswith("\n"):
                result += "\n"
            continue
        if mutation.kind != "replace":
            raise AccuracyError(f"mutation {index} has unsupported kind {mutation.kind!r}")
        occurrences = result.count(mutation.match)
        if occurrences != mutation.count:
            raise AccuracyError(
                f"mutation {index} expected {mutation.count} occurrence(s) of its anchor, found {occurrences}"
            )
        result = result.replace(mutation.match, mutation.replacement, mutation.count)
    return result


def _ratio_or_identity(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 1.0


def _labels(counter: Mapping[str, int]) -> list[dict[str, object]]:
    return [{"rule_id": rule_id, "count": counter[rule_id]} for rule_id in sorted(counter) if counter[rule_id]]


def _rates(true_positives: int, false_positives: int, false_negatives: int) -> tuple[float, float, float]:
    precision = _ratio_or_identity(true_positives, true_positives + false_positives)
    recall = _ratio_or_identity(true_positives, true_positives + false_negatives)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return precision, recall, f1


def score_counts(expected: Mapping[str, int], observed: Mapping[str, int]) -> _Score:
    """Score two rule-ID multisets using occurrence-level classification."""

    rule_ids = set(expected) | set(observed)
    true_positives = sum(min(expected.get(rule_id, 0), observed.get(rule_id, 0)) for rule_id in rule_ids)
    false_positives = sum(max(observed.get(rule_id, 0) - expected.get(rule_id, 0), 0) for rule_id in rule_ids)
    false_negatives = sum(max(expected.get(rule_id, 0) - observed.get(rule_id, 0), 0) for rule_id in rule_ids)
    precision, recall, f1 = _rates(true_positives, false_positives, false_negatives)
    expected_total = sum(expected.values())
    observed_total = sum(observed.values())
    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "exact_match": false_positives == 0 and false_negatives == 0,
        "false_pass": expected_total > 0 and observed_total == 0,
    }


def run_accuracy_suite(truth: TruthSet) -> dict[str, object]:
    """Run all deterministic mutations and return a machine-readable scorecard."""

    try:
        parsed_verilog = parse_verilog_text(truth.fixture.verilog)
        library = parse_liberty_text(truth.fixture.liberty)
        design = elaborate(parsed_verilog, library, truth.fixture.top)
    except ValueError as error:
        raise AccuracyError(f"accuracy fixture could not be parsed or elaborated: {error}") from error
    if design.warnings:
        raise AccuracyError(f"accuracy fixture produced structural warning(s): {'; '.join(design.warnings)}")

    case_results: list[dict[str, object]] = []
    aggregate_true_positives = 0
    aggregate_false_positives = 0
    aggregate_false_negatives = 0
    false_pass_cases = 0
    cases_with_misses = 0
    exact_match_cases = 0
    tested_rules: set[str] = set()

    with tempfile.TemporaryDirectory(prefix="openconstraint-accuracy-") as temporary:
        temporary_root = Path(temporary)
        reference_path = temporary_root / "reference.sdc"
        reference_path.write_text(truth.fixture.sdc, encoding="utf-8", newline="\n")
        for case in truth.cases:
            mutated_sdc = apply_mutations(truth.fixture.sdc, case.mutations)
            mutated_path = temporary_root / f"{case.case_id}.sdc"
            mutated_path.write_text(mutated_sdc, encoding="utf-8", newline="\n")
            modes = [ModeInput("mutant", [str(mutated_path)])]
            if case.execution == "reference-and-mutant":
                modes.insert(0, ModeInput("reference", [str(reference_path)]))
            result = audit(design, modes, truth.options)
            expected = Counter(dict(case.expected))
            observed = Counter(finding.rule_id for finding in result.diagnostics)
            score = score_counts(expected, observed)
            aggregate_true_positives += score["true_positives"]
            aggregate_false_positives += score["false_positives"]
            aggregate_false_negatives += score["false_negatives"]
            tested_rules.update(expected)
            false_pass_cases += int(bool(score["false_pass"]))
            cases_with_misses += int(score["false_negatives"] > 0)
            exact_match_cases += int(bool(score["exact_match"]))
            case_results.append(
                {
                    "id": case.case_id,
                    "description": case.description,
                    "execution": case.execution,
                    "mutated_sdc_sha256": hashlib.sha256(mutated_sdc.encode("utf-8")).hexdigest(),
                    "expected": _labels(expected),
                    "observed": _labels(observed),
                    "score": score,
                }
            )

    defect_cases = sum(bool(case.expected) for case in truth.cases)
    false_pass_rate = _ratio_or_identity(false_pass_cases, defect_cases)
    precision, recall, f1 = _rates(
        aggregate_true_positives,
        aggregate_false_positives,
        aggregate_false_negatives,
    )
    passed = (
        precision >= truth.thresholds.minimum_precision
        and recall >= truth.thresholds.minimum_recall
        and false_pass_rate <= truth.thresholds.maximum_false_pass_rate
    )
    thresholds = {
        "minimum_precision": truth.thresholds.minimum_precision,
        "minimum_recall": truth.thresholds.minimum_recall,
        "maximum_false_pass_rate": truth.thresholds.maximum_false_pass_rate,
    }
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "tool": {"name": "OpenConstraint", "version": __version__},
        "suite": {
            "id": truth.suite_id,
            "name": truth.suite_name,
            "truth_set_sha256": truth.digest,
        },
        "fixture": {
            "id": truth.fixture.fixture_id,
            "description": truth.fixture.description,
            "top": truth.fixture.top,
            "license": {"spdx": truth.fixture.license_spdx, "provenance": truth.fixture.provenance},
        },
        "summary": {
            "passed": passed,
            "case_count": len(truth.cases),
            "defect_case_count": defect_cases,
            "clean_case_count": len(truth.cases) - defect_cases,
            "exact_match_case_count": exact_match_cases,
            "cases_with_misses": cases_with_misses,
            "false_pass_cases": false_pass_cases,
            "false_pass_rate": false_pass_rate,
            "true_positives": aggregate_true_positives,
            "false_positives": aggregate_false_positives,
            "false_negatives": aggregate_false_negatives,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "tested_rule_ids": sorted(tested_rules),
            "untested_rule_ids": sorted(set(RULES) - tested_rules),
            "thresholds": thresholds,
        },
        "cases": case_results,
    }


def render_accuracy_json(result: Mapping[str, object]) -> str:
    """Render stable UTF-8 JSON without host or timing metadata."""

    return json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m openconstraint.accuracy",
        description="Run the deterministic rule-level semantic accuracy truth set.",
    )
    parser.add_argument("--truth-set", required=True, metavar="FILE")
    parser.add_argument("--output", default="-", metavar="FILE")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        output: Path | None = None
        if arguments.output != "-":
            truth_path = Path(arguments.truth_set).resolve()
            output = Path(arguments.output).resolve()
            if output == truth_path:
                raise AccuracyError("--output must not resolve to --truth-set")
        result = run_accuracy_suite(load_truth_set(arguments.truth_set))
        rendered = render_accuracy_json(result)
        if output is None:
            sys.stdout.write(rendered)
        else:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered, encoding="utf-8", newline="\n")
        summary = _object(result.get("summary"), "accuracy result summary")
        return 0 if summary.get("passed") is True else 1
    except (AccuracyError, OSError, UnicodeError) as error:
        parser.exit(2, f"openconstraint accuracy: input error: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
