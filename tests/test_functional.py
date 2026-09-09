"""Independent Boolean oracles, adversarial inputs, and artifact replay tests."""

from __future__ import annotations

import copy
import importlib.util
import json
import random
from itertools import product

import pytest
from jsonschema import Draft202012Validator

from openconstraint.functional import (
    GATE_PORTS,
    MODEL,
    FunctionalInputError,
    FunctionalLimitError,
    FunctionalLimits,
    Gate,
    LogicModel,
    _digest,
    _evaluate,
    _z3_expression,
    analyze_functional,
    main,
    read_functional_json,
    verify_functional,
)

HAS_Z3 = importlib.util.find_spec("z3") is not None
requires_z3 = pytest.mark.skipif(not HAS_Z3, reason="optional Z3 solver not installed")


def netlist(kind="$_AND_"):
    inputs = {"a": [2], "b": [3], "sel": [4]}
    ports = {n: {"direction": "input", "bits": b} for n, b in inputs.items()}
    ports["out"] = {"direction": "output", "bits": [5]}
    connection = {p: [dict(A=2, B=3, S=4)[p]] for p in GATE_PORTS[kind]}
    connection["Y"] = [5]
    return {
        "modules": {
            "top": {
                "ports": ports,
                "netnames": {n: {"bits": p["bits"]} for n, p in ports.items()},
                "cells": {"g": {"type": kind, "connections": connection}},
            }
        }
    }


def spec(*, sources=None, targets=None, assumptions=None):
    return {
        "schema_version": "1.0.0",
        "model": MODEL,
        "top": "top",
        "checks": [
            {
                "id": "check",
                "sources": sources or ["a"],
                "targets": targets or ["out"],
                "assumptions": assumptions or [],
            }
        ],
    }


def decision(n=None, s=None, backend="enumerate", **kwargs):
    return analyze_functional(n or netlist(), s or spec(), backend=backend, **kwargs)["checks"][0]


@pytest.mark.parametrize(
    "kind,expected",
    [
        ("$_BUF_", [0, 1]),
        ("$_NOT_", [1, 0]),
        ("$_AND_", [0, 0, 0, 1]),
        ("$_NAND_", [1, 1, 1, 0]),
        ("$_OR_", [0, 1, 1, 1]),
        ("$_NOR_", [1, 0, 0, 0]),
        ("$_XOR_", [0, 1, 1, 0]),
        ("$_XNOR_", [1, 0, 0, 1]),
        ("$_ANDNOT_", [0, 0, 1, 0]),
        ("$_ORNOT_", [1, 0, 1, 1]),
        ("$_MUX_", [0, 0, 0, 1, 1, 0, 1, 1]),
        ("$_NMUX_", [1, 1, 1, 0, 0, 1, 0, 0]),
    ],
)
def test_gate_against_handwritten_truth_table(kind, expected):
    gate = Gate("test", kind, tuple(range(2, 2 + len(GATE_PORTS[kind]))), 9)
    observed = []
    for values in product((False, True), repeat=len(gate.inputs)):
        observed.append(int(_evaluate((gate,), dict(zip(gate.inputs, values, strict=True)), (9,))[0]))
    assert observed == expected


@requires_z3
@pytest.mark.parametrize("kind", GATE_PORTS)
def test_smt_gate_matches_independent_truth_evaluator(kind):
    import z3

    gate = Gate("test", kind, tuple(range(2, 2 + len(GATE_PORTS[kind]))), 9)
    for values in product((False, True), repeat=len(gate.inputs)):
        concrete = _evaluate((gate,), dict(zip(gate.inputs, values, strict=True)), (9,))[0]
        expression = _z3_expression(z3, kind, [z3.BoolVal(v) for v in values])
        assert z3.is_true(z3.simplify(expression)) is concrete


@pytest.mark.parametrize("backend", ["enumerate", pytest.param("z3", marks=requires_z3)])
def test_mode_assumptions_and_counterexample(backend):
    blocked = spec(assumptions=[{"signal": "b", "value": 0}])
    enabled = spec(assumptions=[{"signal": "b", "value": 1}])
    assert decision(s=blocked, backend=backend)["status"] == "independent"
    assert decision(s=enabled, backend=backend)["status"] == "dependent"
    n = netlist()
    report = analyze_functional(n, enabled, backend=backend)
    assert report["timing_signoff"] is False
    checked = verify_functional(report, n, enabled, backend="enumerate")
    assert checked["verified"] is True
    assert checked["all_independent"] is False
    assert checked["timing_signoff"] is False


@pytest.mark.parametrize("backend", ["enumerate", pytest.param("z3", marks=requires_z3)])
def test_reconvergent_cancellation_is_not_timing_signoff(backend):
    n = netlist("$_XOR_")
    n["modules"]["top"]["cells"]["g"]["connections"]["B"] = [2]
    report = analyze_functional(n, spec(), backend=backend)
    assert report["checks"][0]["status"] == "independent"
    assert report["model"] == MODEL and report["timing_signoff"] is False


def test_bit_references_aliases_bus_indices_and_constants():
    n = netlist()
    n["modules"]["top"]["netnames"]["bus"] = {"bits": [2, 3], "offset": 5, "upto": 1}
    n["modules"]["top"]["netnames"]["one"] = {"bits": ["1"]}
    assert decision(n, spec(sources=[{"net": "bus", "bit": 0}]))["status"] == "dependent"
    assert decision(n, spec(sources=[2]))["status"] == "dependent"
    assert decision(n, spec(targets=["one"]))["status"] == "independent"
    for bad in ["bus", {"net": "bus", "bit": 2}, {"net": "bus", "bit": True}, True, "missing", 999]:
        assert decision(n, spec(sources=[bad]))["status"] == "unsupported"


@pytest.mark.parametrize("case", ["duplicate_alias", "source_fixed", "internal_assumption", "constant_source"])
def test_unsafe_assumptions_never_produce_a_proof(case):
    n = netlist()
    s = spec()
    if case == "duplicate_alias":
        n["modules"]["top"]["netnames"]["alias"] = {"bits": [3]}
        s["checks"][0]["assumptions"] = [{"signal": "b", "value": 0}, {"signal": "alias", "value": 1}]
    elif case == "source_fixed":
        s["checks"][0]["assumptions"] = [{"signal": "a", "value": 0}]
    elif case == "internal_assumption":
        s["checks"][0]["assumptions"] = [{"signal": "out", "value": 0}]
    else:
        n["modules"]["top"]["netnames"]["zero"] = {"bits": ["0"]}
        s["checks"][0]["sources"] = ["zero"]
    result = decision(n, s)
    assert result["status"] in {"inconsistent_assumptions", "unsupported"}
    report = analyze_functional(n, s, backend="enumerate")
    assert not verify_functional(report, n, s)["verified"]


@pytest.mark.parametrize(
    "case",
    [
        "x",
        "z",
        "unknown_cell",
        "latch",
        "memory",
        "blackbox",
        "inout",
        "multi_driver",
        "constant_output",
        "undriven",
        "loop",
        "width",
        "direction",
        "parameters",
        "alias_conflict",
    ],
)
def test_incomplete_or_unsupported_models_fail_closed(case):
    n = netlist()
    m = n["modules"]["top"]
    g = m["cells"]["g"]
    if case in {"x", "z"}:
        g["connections"]["B"] = [case]
    elif case == "unknown_cell":
        g["type"] = "vendor_cell"
    elif case == "latch":
        g["type"] = "$_DLATCH_P_"
    elif case == "memory":
        m["memories"] = {"ram": {}}
    elif case == "blackbox":
        m["attributes"] = {"blackbox": "00001"}
    elif case == "inout":
        m["ports"]["b"]["direction"] = "inout"
    elif case == "multi_driver":
        m["cells"]["second"] = copy.deepcopy(g)
    elif case == "constant_output":
        g["connections"]["Y"] = ["0"]
    elif case == "undriven":
        g["connections"]["B"] = [999]
    elif case == "loop":
        g["connections"]["B"] = [5]
    elif case == "width":
        g["connections"]["A"] = [2, 3]
    elif case == "direction":
        g["port_directions"] = {"A": "output", "B": "input", "Y": "output"}
    elif case == "parameters":
        g["parameters"] = {"unexpected": "1"}
    else:
        m["netnames"]["a"]["bits"] = [3]
    assert decision(n)["status"] == "unsupported"


def test_flipflops_are_explicit_arbitrary_state_boundaries():
    n = netlist("$_BUF_")
    m = n["modules"]["top"]
    m["cells"]["ff"] = {"type": "$_DFF_P_", "connections": {"C": [4], "D": [2], "Q": [6]}}
    m["netnames"]["q"] = {"bits": [6]}
    m["cells"]["g"]["connections"]["A"] = [6]
    assert decision(n, spec(sources=["q"]))["status"] == "dependent"
    assert decision(n, spec(sources=["a"]))["status"] == "independent"
    m["cells"]["ff"]["connections"]["Q"] = [2]
    assert decision(n)["status"] == "unsupported"


def test_unused_cones_are_not_solved_and_target_cones_are_cached(monkeypatch):
    n = netlist()
    m = n["modules"]["top"]
    for index in range(100):
        m["cells"][f"unused{index}"] = {"type": "$_NOT_", "connections": {"A": [2], "Y": [10 + index]}}
    s = spec()
    s["checks"].append(s["checks"][0] | {"id": "second"})
    calls = []
    original = LogicModel.cone

    def tracked(self, targets):
        calls.append(targets)
        return original(self, targets)

    monkeypatch.setattr(LogicModel, "cone", tracked)
    result = analyze_functional(n, s, backend="enumerate")
    assert len(calls) == 1
    assert all(c["cone_gates"] == 1 for c in result["checks"])
    analyze_functional(n, s, backend="enumerate")
    assert len(calls) == 2


def test_deterministic_limits_never_become_independence():
    assert decision(limits=FunctionalLimits(max_enum_inputs=1))["status"] == "bounded"
    assert decision(limits=FunctionalLimits(max_enum_work=1))["status"] == "bounded"
    assert decision(limits=FunctionalLimits(max_total_gate_work=1))["status"] == "bounded"
    assert decision(limits=FunctionalLimits(max_bits=1))["status"] == "bounded"
    n = netlist()
    n["modules"]["top"]["cells"]["g2"] = {"type": "$_BUF_", "connections": {"A": [2], "Y": [9]}}
    assert decision(n, limits=FunctionalLimits(max_gates=1))["status"] == "bounded"
    s = spec()
    s["checks"].append(s["checks"][0] | {"id": "second"})
    with pytest.raises(FunctionalLimitError):
        analyze_functional(n, s, limits=FunctionalLimits(max_checks=1))


@requires_z3
def test_real_solver_resource_exhaustion_is_not_a_pass():
    report = analyze_functional(netlist(), spec(), limits=FunctionalLimits(solver_rlimit=1))
    assert report["checks"][0]["status"] == "bounded"
    assert not verify_functional(report, netlist(), spec())["verified"]


@pytest.mark.parametrize(
    "key,value", [("max_gates", 0), ("max_bits", True), ("solver_timeout_ms", 2**32), ("max_enum_inputs", 25)]
)
def test_limit_contract(key, value):
    with pytest.raises(ValueError):
        FunctionalLimits(**{key: value})


@pytest.mark.parametrize("change", ["through", "empty", "duplicate", "model", "assumption_bool"])
def test_specification_rejects_implicit_or_unsupported_semantics(change):
    s = spec()
    if change == "through":
        s["checks"][0]["through"] = ["out"]
    elif change == "empty":
        s["checks"] = []
    elif change == "duplicate":
        s["checks"] *= 2
    elif change == "model":
        s["model"] = "timing_signoff"
    else:
        s["checks"][0]["assumptions"] = [{"signal": "b", "value": True}]
    with pytest.raises(FunctionalInputError):
        analyze_functional(netlist(), s, backend="enumerate")


def test_tampered_rehashed_reports_and_witnesses_fail_replay():
    n = netlist()
    s = spec()
    original = analyze_functional(n, s, backend="enumerate")
    assert verify_functional(original, n, s)["verified"]
    for field, value in [("status", "independent"), ("query_digest", "0" * 64), ("counterexample", None)]:
        tampered = copy.deepcopy(original)
        tampered["checks"][0][field] = value
        tampered["report_digest"] = _digest({k: v for k, v in tampered.items() if k != "report_digest"})
        assert not verify_functional(tampered, n, s)["verified"]
    tampered = copy.deepcopy(original)
    tampered["checks"][0]["counterexample"]["left"]["inputs"]["999"] = 1
    tampered["report_digest"] = _digest({k: v for k, v in tampered.items() if k != "report_digest"})
    assert not verify_functional(tampered, n, s)["verified"]
    tampered = copy.deepcopy(original)
    tampered["checks"] = []
    assert not verify_functional(tampered, n, s)["verified"]
    changed = netlist("$_OR_")
    assert not verify_functional(original, changed, s)["verified"]


@requires_z3
@pytest.mark.parametrize("seed", range(32))
def test_generated_dags_differentially_agree_with_exhaustive_backend(seed):
    rng = random.Random(seed)
    n = netlist()
    m = n["modules"]["top"]
    m["cells"] = {}
    available = [2, 3, 4, "0", "1"]
    for index in range(8):
        kind = rng.choice(list(GATE_PORTS))
        output = 10 + index
        connections = {p: [rng.choice(available)] for p in GATE_PORTS[kind]}
        connections["Y"] = [output]
        m["cells"][f"g{index}"] = {"type": kind, "connections": connections}
        available.append(output)
    m["ports"]["out"]["bits"] = [17]
    m["netnames"]["out"]["bits"] = [17]
    s = spec(sources=rng.sample(["a", "b", "sel"], rng.randint(1, 3)))
    reference = analyze_functional(n, s, backend="enumerate")
    solver = analyze_functional(n, s, backend="z3")
    assert solver["checks"][0]["status"] == reference["checks"][0]["status"]
    assert verify_functional(solver, n, s, backend="enumerate")["verified"]
    assert verify_functional(reference, n, s, backend="z3")["verified"]


def test_solver_is_optional_and_missing_dependency_fails_closed(monkeypatch):
    import openconstraint.functional as f

    def unavailable(name):
        raise ImportError("missing")

    monkeypatch.setattr(f.importlib, "import_module", unavailable)
    report = f.analyze_functional(netlist(), spec())
    assert report["checks"][0]["status"] == "unsupported"
    assert "not installed" in report["checks"][0]["reason"]


@pytest.mark.parametrize("raw", ['{"a":1,"a":2}', '{"a":NaN}', '{"a":1e999}', "[]", "\ud800"])
def test_json_input_rejects_ambiguous_or_nonfinite_data(tmp_path, raw):
    path = tmp_path / "input.json"
    path.write_bytes(raw.encode("utf-8", errors="surrogatepass"))
    with pytest.raises((ValueError, UnicodeError)):
        read_functional_json(path)


def test_json_size_and_nesting_limits(tmp_path, monkeypatch):
    import openconstraint.functional as f

    path = tmp_path / "input.json"
    path.write_text('{"a":123456}')
    monkeypatch.setattr(f, "MAX_JSON_BYTES", 5)
    with pytest.raises(FunctionalLimitError):
        read_functional_json(path)
    monkeypatch.setattr(f, "MAX_JSON_BYTES", 100_000)
    path.write_text("[" * 5000 + "0" + "]" * 5000)
    with pytest.raises(FunctionalLimitError):
        read_functional_json(path)


def test_cli_roundtrip_and_no_input_overwrite(tmp_path, capsys):
    n = tmp_path / "netlist.json"
    s = tmp_path / "spec.json"
    r = tmp_path / "report.json"
    n.write_text(json.dumps(netlist()))
    s.write_text(json.dumps(spec()))
    common = ["--netlist", str(n), "--spec", str(s), "--backend", "enumerate"]
    assert main(["analyze", *common, "--output", str(r)]) == 1
    assert main(["verify", *common, "--report", str(r)]) == 0
    assert json.loads(capsys.readouterr().out)["verified"]
    before = n.read_bytes()
    assert main(["analyze", *common, "--output", str(n)]) == 2
    assert n.read_bytes() == before
    s.write_text(json.dumps(spec(assumptions=[{"signal": "b", "value": 0}])))
    assert main(["analyze", *common]) == 0
    assert json.loads(capsys.readouterr().out)["checks"][0]["status"] == "independent"


def test_schemas_validate_generated_artifacts(tmp_path):
    for kind in ("spec", "result"):
        output = tmp_path / f"{kind}.json"
        assert main(["schema", "--kind", kind, "--output", str(output)]) == 0
        schema = json.loads(output.read_text())
        Draft202012Validator.check_schema(schema)
        value = spec() if kind == "spec" else analyze_functional(netlist(), spec(), backend="enumerate")
        Draft202012Validator(schema).validate(value)


def test_unlowered_processes_are_rejected():
    n = netlist()
    n["modules"]["top"]["processes"] = {"unlowered": {}}
    result = analyze_functional(n, spec(), backend="enumerate")
    assert result["checks"][0]["status"] == "unsupported"


def test_result_schema_rejects_false_signoff_and_missing_counterexample():
    from importlib.resources import files

    schema = json.loads((files("openconstraint.schemas") / "openconstraint-functional-result.schema.json").read_text())
    validator = Draft202012Validator(schema)
    report = analyze_functional(netlist(), spec(), backend="enumerate")
    assert validator.is_valid(report)
    report["timing_signoff"] = True
    assert not validator.is_valid(report)
    report["timing_signoff"] = False
    report["checks"][0]["counterexample"] = None
    assert not validator.is_valid(report)


@pytest.mark.parametrize("mutation", ["tool", "version", "backend", "limit", "summary", "count", "reason", "extra"])
def test_rehashed_invalid_report_metadata_is_not_verified(mutation):
    from openconstraint.functional import _digest

    n, s = netlist(), spec()
    result = analyze_functional(n, s, backend="enumerate")
    if mutation == "tool":
        result["tool"]["name"] = "not-openconstraint"
    elif mutation == "version":
        result["tool"]["version"] = ""
    elif mutation == "backend":
        result["backend"]["name"] = "nonexistent"
    elif mutation == "limit":
        result["limits"]["max_gates"] = True
    elif mutation == "summary":
        result["summary"]["dependent"] = True
    elif mutation == "count":
        result["checks"][0]["cone_gates"] = True
    elif mutation == "reason":
        result["checks"][0]["reason"] = ""
    else:
        result["silicon_signoff"] = True
    result["report_digest"] = _digest({k: v for k, v in result.items() if k != "report_digest"})
    assert not verify_functional(result, n, s)["verified"]
