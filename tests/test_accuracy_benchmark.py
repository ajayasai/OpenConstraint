from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import openconstraint.accuracy as accuracy
from openconstraint.accuracy import (
    RESULT_SCHEMA_VERSION,
    TRUTH_SCHEMA_VERSION,
    AccuracyError,
    Mutation,
    apply_mutations,
    load_truth_set,
    main,
    render_accuracy_json,
    run_accuracy_suite,
    score_counts,
)

ROOT = Path(__file__).parents[1]
TRUTH_PATH = ROOT / "benchmarks" / "accuracy" / "truth-set.json"
TRUTH_SCHEMA_PATH = ROOT / "benchmarks" / "accuracy" / "schemas" / "truth-set.schema.json"
RESULT_SCHEMA_PATH = ROOT / "benchmarks" / "accuracy" / "schemas" / "result.schema.json"


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_committed_truth_set_and_result_match_versioned_schemas() -> None:
    truth_payload = _json(TRUTH_PATH)
    truth_schema = _json(TRUTH_SCHEMA_PATH)
    result_schema = _json(RESULT_SCHEMA_PATH)
    Draft202012Validator.check_schema(truth_schema)
    Draft202012Validator.check_schema(result_schema)
    Draft202012Validator(truth_schema).validate(truth_payload)

    truth = load_truth_set(TRUTH_PATH)
    first = run_accuracy_suite(truth)
    second = run_accuracy_suite(truth)
    Draft202012Validator(result_schema).validate(first)

    assert truth_payload["schema_version"] == TRUTH_SCHEMA_VERSION
    assert first["schema_version"] == RESULT_SCHEMA_VERSION
    assert first == second
    assert render_accuracy_json(first) == render_accuracy_json(second)


def test_committed_truth_set_has_perfect_reviewed_rule_classification() -> None:
    result = run_accuracy_suite(load_truth_set(TRUTH_PATH))
    summary = result["summary"]

    assert summary == {
        "passed": True,
        "case_count": 35,
        "defect_case_count": 34,
        "clean_case_count": 1,
        "exact_match_case_count": 35,
        "cases_with_misses": 0,
        "false_pass_cases": 0,
        "false_pass_rate": 0.0,
        "true_positives": 67,
        "false_positives": 0,
        "false_negatives": 0,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
        "tested_rule_ids": [
            "OC0001",
            "OC0003",
            "OC1001",
            "OC1002",
            "OC1003",
            "OC1004",
            "OC2001",
            "OC2002",
            "OC2003",
            "OC2004",
            "OC2005",
            "OC2006",
            "OC2010",
            "OC2011",
            "OC2012",
            "OC2101",
            "OC3001",
            "OC3002",
            "OC3010",
            "OC3011",
            "OC3012",
            "OC3013",
            "OC3014",
            "OC4001",
            "OC4002",
            "OC4010",
            "OC4011",
            "OC4012",
            "OC5001",
            "OC5002",
        ],
        "untested_rule_ids": ["OC0002", "OC6001"],
        "thresholds": {
            "minimum_precision": 1.0,
            "minimum_recall": 1.0,
            "maximum_false_pass_rate": 0.0,
        },
    }
    assert all(case["score"]["exact_match"] for case in result["cases"])


def test_occurrence_scoring_counts_extra_missing_and_matching_labels() -> None:
    score = score_counts(
        {"OC1001": 2, "OC2001": 1},
        {"OC1001": 1, "OC2002": 2},
    )

    assert score == {
        "true_positives": 1,
        "false_positives": 2,
        "false_negatives": 2,
        "precision": 1 / 3,
        "recall": 1 / 3,
        "f1": 1 / 3,
        "exact_match": False,
        "false_pass": False,
    }
    assert score_counts({}, {}) == {
        "true_positives": 0,
        "false_positives": 0,
        "false_negatives": 0,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
        "exact_match": True,
        "false_pass": False,
    }
    assert score_counts({"OC1001": 1}, {})["false_pass"] is True


def test_exact_mutations_reject_stale_anchors() -> None:
    assert apply_mutations("clock 10\n", [Mutation("replace", match="10", replacement="8", count=1)]) == "clock 8\n"
    assert apply_mutations("clock 10", [Mutation("append", text="next")]) == "clock 10\nnext\n"

    with pytest.raises(AccuracyError, match="expected 2 occurrence"):
        apply_mutations("clock 10\n", [Mutation("replace", match="10", replacement="8", count=2)])
    with pytest.raises(AccuracyError, match="unsupported kind"):
        apply_mutations("clock 10\n", [Mutation("delete")])


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda payload: payload.update(schema_version="2.0.0"), "unsupported truth-set schema"),
        (lambda payload: payload["cases"][1]["expected"][0].update(rule_id="OC9999"), "unknown rule"),
        (lambda payload: payload["cases"][1].update(id="clean-control"), "case IDs must be unique"),
        (lambda payload: payload.update(extra=True), "unknown key"),
    ],
)
def test_truth_loader_rejects_unversioned_or_ambiguous_truth(tmp_path: Path, change, message: str) -> None:
    payload = _json(TRUTH_PATH)
    change(payload)
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(AccuracyError, match=message):
        load_truth_set(path)


def test_truth_digest_ignores_json_whitespace(tmp_path: Path) -> None:
    payload = _json(TRUTH_PATH)
    reformatted = tmp_path / "reformatted.json"
    reformatted.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")

    assert load_truth_set(reformatted).digest == load_truth_set(TRUTH_PATH).digest


def test_aggregate_metrics_preserve_case_identity(tmp_path: Path) -> None:
    payload = _json(TRUTH_PATH)
    cases = {case["id"]: case for case in payload["cases"]}
    cases["zero-object-query"]["expected"][0]["rule_id"] = "OC1002"
    cases["dangerously-broad-query"]["expected"][0]["rule_id"] = "OC1001"
    path = tmp_path / "cross-case-swap.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    result = run_accuracy_suite(load_truth_set(path))
    summary = result["summary"]
    assert summary["passed"] is False
    assert summary["true_positives"] == 65
    assert summary["false_positives"] == 2
    assert summary["false_negatives"] == 2


def test_truth_loader_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_version":"1.0.0","schema_version":"1.0.0"}', encoding="utf-8")

    with pytest.raises(AccuracyError, match="duplicate JSON key 'schema_version'"):
        load_truth_set(path)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_truth_loader_rejects_nonfinite_json_numbers(tmp_path: Path, constant: str) -> None:
    path = tmp_path / "nonfinite.json"
    path.write_text(f'{{"schema_version":{constant}}}', encoding="utf-8")

    with pytest.raises(AccuracyError, match="non-finite JSON number"):
        load_truth_set(path)


def test_truth_loader_rejects_oversize_input_before_reading(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "oversize.json"
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(accuracy, "_MAX_JSON_BYTES", 1)

    with pytest.raises(AccuracyError, match="JSON size limit of 1 byte"):
        load_truth_set(path)


def test_truth_loader_bounds_json_node_count(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "too-many-nodes.json"
    path.write_text('{"items":[1]}', encoding="utf-8")
    monkeypatch.setattr(accuracy, "_MAX_JSON_NODES", 2)

    with pytest.raises(AccuracyError, match="JSON node limit of 2"):
        load_truth_set(path)


def test_truth_loader_wraps_json_integer_safety_limit(tmp_path: Path) -> None:
    path = tmp_path / "overlong-integer.json"
    path.write_text('{"schema_version":' + "1" * 5000 + "}", encoding="utf-8")

    with pytest.raises(AccuracyError, match="invalid truth-set JSON"):
        load_truth_set(path)


def test_cli_reports_deep_json_as_clean_input_error(tmp_path: Path, capsys) -> None:
    path = tmp_path / "deep.json"
    path.write_text("[" * 2000 + "0" + "]" * 2000, encoding="utf-8")

    with pytest.raises(SystemExit) as raised:
        main(["--truth-set", str(path)])

    captured = capsys.readouterr()
    assert raised.value.code == 2
    assert "JSON nesting limit" in captured.err
    assert "Traceback" not in captured.err


def test_cli_rejects_output_truth_collision_without_modifying_input(tmp_path: Path, capsys) -> None:
    truth_path = tmp_path / "truth.json"
    truth_path.write_bytes(TRUTH_PATH.read_bytes())
    original = truth_path.read_bytes()

    with pytest.raises(SystemExit) as raised:
        main(["--truth-set", str(truth_path), "--output", str(truth_path.resolve())])

    captured = capsys.readouterr()
    assert raised.value.code == 2
    assert "--output must not resolve to --truth-set" in captured.err
    assert "Traceback" not in captured.err
    assert truth_path.read_bytes() == original


def test_cli_classifies_invalid_embedded_design_as_input_error(tmp_path: Path, capsys) -> None:
    payload = _json(TRUTH_PATH)
    payload["fixture"]["verilog"] = "this is not verilog"
    truth_path = tmp_path / "invalid-fixture.json"
    truth_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SystemExit) as raised:
        main(["--truth-set", str(truth_path)])

    assert raised.value.code == 2
    assert "fixture could not be parsed or elaborated" in capsys.readouterr().err


def test_cli_writes_result_and_fails_when_a_reviewed_label_is_missed(tmp_path: Path) -> None:
    payload = _json(TRUTH_PATH)
    payload["cases"][1]["expected"][0]["count"] = 2
    truth_path = tmp_path / "truth.json"
    truth_path.write_text(json.dumps(payload), encoding="utf-8")
    output = tmp_path / "result.json"

    assert main(["--truth-set", str(truth_path), "--output", str(output)]) == 1
    result = _json(output)
    assert result["summary"]["passed"] is False
    assert result["summary"]["false_negatives"] == 1
    Draft202012Validator(_json(RESULT_SCHEMA_PATH)).validate(result)
