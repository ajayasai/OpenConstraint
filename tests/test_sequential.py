from __future__ import annotations

import copy
import importlib.util
import json
from hashlib import sha256
from importlib.resources import files
from itertools import product

import pytest
from jsonschema import Draft202012Validator

from openconstraint.functional import FunctionalInputError, _digest
from openconstraint.sequential import (
    _contract,
    analyze_sequential,
    validate_invariant,
    verify_sequential,
)
from openconstraint.sequential_cli import main, render_vcd
from openconstraint.sequential_model import (
    MODEL,
    Budget,
    SequentialLimits,
    build_machine,
    load_synchronous_model,
)

HAS_Z3 = importlib.util.find_spec("z3") is not None
WITH_Z3 = pytest.mark.skipif(not HAS_Z3, reason="optional Z3 solver not installed")


def cell(kind, **conn):
    return {"type": kind, "connections": {name: [bit] for name, bit in conn.items()}}


def ports(**entries):
    return {name: {"direction": direction, "bits": [bit]} for name, (direction, bit) in entries.items()}


def toggler():
    return {
        "modules": {
            "top": {
                "ports": ports(clk=("input", 2), reset=("input", 3), event=("output", 4)),
                "cells": {"inv": cell("$_NOT_", A=4, Y=5), "ff": cell("$_SDFF_PP0_", C=2, R=3, D=5, Q=4)},
            }
        }
    }


def spec(*checks, **extra):
    return {
        "schema_version": "1.0.0",
        "model": MODEL,
        "top": "top",
        "clock": "clk",
        "edge": "posedge",
        "prefix": [[{"signal": "reset", "value": 1}]],
        "checks": list(checks),
        **extra,
    }


def spacing(cycles=2, ident="spacing"):
    return {"id": ident, "kind": "min_spacing", "event": "event", "cycles": cycles}


def forbidden(signal="event", value=1, ident="forbidden"):
    return {"id": ident, "kind": "forbid", "forbid": [{"signal": signal, "value": value}]}


def seal(report):
    report["report_digest"] = _digest({k: v for k, v in report.items() if k != "report_digest"})
    return report


@pytest.mark.parametrize("backend", ["enumerate", pytest.param("z3", marks=WITH_Z3)])
def test_spacing_proof_violation_and_independent_replay(backend):
    n, s = toggler(), spec(spacing(2, "two"), spacing(3, "three"))
    report = analyze_sequential(n, s, backend=backend)
    good, bad = report["checks"]
    assert good["status"] == "proven" and good["activation"] == "witnessed"
    assert bad["status"] == "counterexample"
    assert bad["checked_depth"] == 3
    assert bad["counterexample"][0]["inputs"] == [1]  # Reset prefix must be replayed.
    assert good["proof"]["kind"] == ("k_induction" if backend == "z3" else "reachable_invariant")
    assert report["passed"] is False and report["timing_signoff"] is False
    assert verify_sequential(report, n, s) == {
        "verified": True,
        "passed": False,
        "timing_signoff": False,
        "replay_backend": "enumerate",
        "errors": [],
    }
    schema = json.loads((files("openconstraint.schemas") / "openconstraint-sequential-result.schema.json").read_text())
    Draft202012Validator(schema).validate(report)


def test_finite_invariant_checker_verifies_initiation_closure_safety():
    n, s = toggler(), spec(spacing())
    r = analyze_sequential(n, s, backend="enumerate")
    assert r["passed"] is True
    model = load_synchronous_model(n, "top", "clk", "posedge", SequentialLimits())
    machine, contract = build_machine(model, s["checks"][0], SequentialLimits()), _contract(model, s)
    proof = r["checks"][0]["proof"]
    assert validate_invariant(machine, contract, proof, Budget(SequentialLimits()))
    for bad in [
        None,
        {},
        {"kind": "k_induction", "k": 1},
        {"kind": "reachable_invariant", "states": []},
        {"kind": "reachable_invariant", "states": ["00"]},
        {"kind": "reachable_invariant", "states": ["01", "10"]},
        {"kind": "reachable_invariant", "states": ["00", "01", "10", "11"]},
        {"kind": "reachable_invariant", "states": ["xxx"]},
        {"kind": "reachable_invariant", "states": ["00", "00"]},
    ]:
        assert not validate_invariant(machine, contract, bad, Budget(SequentialLimits()))
    for states in [["00"], ["01", "10"], ["00", "01", "10", "11"]]:
        tampered = copy.deepcopy(r)
        tampered["checks"][0]["proof"]["states"] = states
        assert not verify_sequential(seal(tampered), n, s)["verified"]


@pytest.mark.parametrize("backend", ["enumerate", pytest.param("z3", marks=WITH_Z3)])
def test_event_vacuity_never_passes_ci(backend):
    n = toggler()
    n["modules"]["top"]["cells"]["ff"] = cell("$_DFF_P_", C=2, D="0", Q=4)
    s = spec(spacing(), initial=[{"signal": "event", "value": 0}], prefix=[])
    r = analyze_sequential(n, s, backend=backend)
    assert r["checks"][0]["status"] == "proven"
    assert r["checks"][0]["activation"] in {"unreachable", "not_witnessed"}
    assert r["passed"] is False
    v = verify_sequential(r, n, s)
    assert v["verified"] is True and v["passed"] is False


def test_reset_prefix_is_a_transition_not_a_guessed_initial_state():
    n = toggler()
    n["modules"]["top"]["cells"]["ff"] = cell("$_SDFF_PP0_", C=2, R=3, D=4, Q=4)
    no_reset = spec(forbidden(), prefix=[])
    reset = spec(forbidden())
    assert analyze_sequential(n, no_reset, backend="enumerate")["checks"][0]["status"] == "counterexample"
    assert analyze_sequential(n, reset, backend="enumerate")["passed"] is True
    bad = spec(forbidden(), assumptions=[{"signal": "reset", "value": 0}])
    report = analyze_sequential(n, bad, backend="enumerate")
    assert report["checks"][0]["status"] == "inconsistent_assumptions"
    assert not report["passed"]


@WITH_Z3
def test_two_step_induction_requires_a_checked_base_case():
    n = {
        "modules": {
            "top": {
                "ports": ports(clk=("input", 2), a=("output", 4), b=("output", 5)),
                "cells": {"a": cell("$_DFF_P_", C=2, D="0", Q=4), "b": cell("$_DFF_P_", C=2, D=4, Q=5)},
            }
        }
    }
    s = spec(forbidden("b"), prefix=[], initial=[{"signal": "a", "value": 0}, {"signal": "b", "value": 0}])
    r = analyze_sequential(n, s, backend="z3")
    assert r["passed"] and r["checks"][0]["proof"] == {"kind": "k_induction", "k": 2}
    assert verify_sequential(r, n, s)["verified"]
    assert verify_sequential(r, n, s, backend="z3")["verified"]
    shallow = analyze_sequential(n, s, backend="z3", limits=SequentialLimits(max_depth=1))
    assert shallow["checks"][0]["status"] == "bounded" and not shallow["passed"]
    assert not verify_sequential(shallow, n, s)["verified"]
    # Removing the initial contract must expose the base-case counterexample,
    # even though the exact same induction obligation is valid.
    s["initial"] = []
    r = analyze_sequential(n, s, backend="z3")
    assert r["checks"][0]["status"] == "counterexample" and r["checks"][0]["checked_depth"] == 0


PRIMITIVES = []
for c in "PN":
    PRIMITIVES += [(f"$_DFF_{c}_", c, None, None, None, None)]
    for e in "PN":
        PRIMITIVES += [(f"$_DFFE_{c}{e}_", c, e, None, None, None)]
    for r in "PN":
        for v in (0, 1):
            PRIMITIVES += [(f"$_SDFF_{c}{r}{v}_", c, None, r, v, True)]
            for e in "PN":
                for prefix, priority in [("SDFFE", True), ("SDFFCE", False)]:
                    PRIMITIVES += [(f"$_{prefix}_{c}{r}{v}{e}_", c, e, r, v, priority)]


@pytest.mark.parametrize("primitive,c,e,r,v,priority", PRIMITIVES)
def test_all_synchronous_cell_polarities_and_priorities(primitive, c, e, r, v, priority):
    conn = {"C": 2, "D": 3, "Q": 6} | ({"E": 4} if e else {}) | ({"R": 5} if r else {})
    n = {
        "modules": {
            "top": {
                "ports": ports(clk=("input", 2), d=("input", 3), en=("input", 4), rst=("input", 5), q=("output", 6)),
                "cells": {"ff": cell(primitive, **conn)},
            }
        }
    }
    model = load_synchronous_model(n, "top", "clk", "posedge" if c == "P" else "negedge", SequentialLimits())
    machine = build_machine(model, forbidden("q"), SequentialLimits())
    for old, data, enable, reset in product((False, True), repeat=4):
        active_en = e is None or enable == (e == "P")
        active_reset = r is not None and reset == (r == "P")
        # Independent procedural truth table, not the lowering implementation.
        if priority and active_reset:
            expected = bool(v)
        elif active_en:
            expected = bool(v) if active_reset else data
        else:
            expected = old
        world = {b: {3: data, 4: enable, 5: reset}[b] for b in machine.inputs}
        following, _, _ = machine.step((old,), world)
        assert following == (expected,), primitive


def test_sequential_cone_reduction_removes_unrelated_state():
    n = toggler()
    for i in range(1000):
        n["modules"]["top"]["cells"][f"unrelated{i}"] = cell("$_DFF_P_", C=2, D=3, Q=100 + i)
    report = analyze_sequential(n, spec(spacing()), backend="enumerate")
    assert report["passed"]
    assert report["checks"][0]["cone"] == {"state_bits": [4], "input_bits": [3], "history_bits": 1, "gate_count": 2}


@pytest.mark.parametrize(
    "mutation",
    [
        "async",
        "unknown",
        "process",
        "memory",
        "blackbox",
        "init",
        "derived_clock",
        "mixed_edge",
        "clock_data",
        "clock_D",
        "bad_direction",
        "bad_ports",
        "bad_width",
        "parameters",
        "duplicate_driver",
        "no_type",
    ],
)
def test_unsupported_model_is_fail_closed(mutation):
    n = toggler()
    m = n["modules"]["top"]
    if mutation == "async":
        m["cells"]["ff"]["type"] = "$_DFF_PP0_"
    elif mutation == "unknown":
        m["cells"]["ff"]["type"] = "CUSTOM"
    elif mutation == "process":
        m["processes"] = {"p": {}}
    elif mutation == "memory":
        m["memories"] = {"mem": {}}
    elif mutation == "blackbox":
        m["attributes"] = {"blackbox": 1}
    elif mutation == "init":
        m["netnames"] = {"event": {"bits": [4], "attributes": {"init": "0"}}}
    elif mutation == "derived_clock":
        m["cells"]["ff"]["connections"]["C"] = [5]
    elif mutation == "mixed_edge":
        m["cells"]["ff"]["type"] = "$_SDFF_NP0_"
    elif mutation == "clock_data":
        m["cells"]["inv"]["connections"]["A"] = [2]
    elif mutation == "clock_D":
        m["cells"]["ff"]["connections"]["D"] = [2]
    elif mutation == "bad_direction":
        m["cells"]["ff"]["port_directions"] = {"C": "output"}
    elif mutation == "bad_ports":
        del m["cells"]["ff"]["connections"]["R"]
    elif mutation == "bad_width":
        m["cells"]["ff"]["connections"]["D"] = [5, 3]
    elif mutation == "parameters":
        m["cells"]["ff"]["parameters"] = {"P": 1}
    elif mutation == "duplicate_driver":
        m["cells"]["ff2"] = copy.deepcopy(m["cells"]["ff"])
    else:
        m["cells"]["ff"]["type"] = 0
    result = analyze_sequential(n, spec(spacing()), backend="enumerate")
    assert result["checks"][0]["status"] == "unsupported"
    assert not result["passed"]


@pytest.mark.parametrize(
    "limits",
    [
        SequentialLimits(max_cells=1),
        SequentialLimits(max_bits=1),
        SequentialLimits(max_state_bits=1),
        SequentialLimits(max_states=1),
        SequentialLimits(max_work=1),
    ],
)
def test_explicit_work_limits_never_prove_absence(limits):
    n, s = toggler(), spec(spacing())
    report = analyze_sequential(n, s, backend="enumerate", limits=limits)
    assert report["checks"][0]["status"] == "bounded" and not report["passed"]
    assert not verify_sequential(report, n, s)["verified"]


@WITH_Z3
def test_solver_limits_and_missing_solver(monkeypatch):
    import openconstraint.sequential as seq

    n, s = toggler(), spec(spacing())
    for limits in [SequentialLimits(max_solver_calls=1), SequentialLimits(solver_rlimit=1)]:
        report = analyze_sequential(n, s, backend="z3", limits=limits)
        assert report["checks"][0]["status"] == "bounded"

    def missing(_):
        raise ImportError("no optional solver")

    monkeypatch.setattr(seq.importlib, "import_module", missing)
    assert analyze_sequential(n, s, backend="z3")["checks"][0]["status"] == "unsupported"


@pytest.mark.parametrize(
    "key,value",
    [
        ("max_work", 0),
        ("max_states", True),
        ("max_cells", 1.5),
        ("max_enum_free_bits", 25),
        ("max_prefix", 257),
        ("max_depth", 257),
        ("max_history", 257),
        ("max_state_bits", 65537),
        ("solver_timeout_ms", 2**32),
        ("solver_rlimit", 2**32),
    ],
)
def test_invalid_limits(key, value):
    with pytest.raises(ValueError):
        SequentialLimits(**{key: value})


@pytest.mark.parametrize(
    "key,value",
    [
        ("schema_version", "2"),
        ("model", "zero_delay_arbitrary_state"),
        ("top", False),
        ("checks", []),
        ("checks", [spacing(), spacing()]),
        ("prefix", {}),
        ("initial", None),
        ("prefix", [False]),
        ("extra", 0),
    ],
)
def test_invalid_specification(key, value):
    s = spec(spacing())
    s[key] = value
    with pytest.raises((FunctionalInputError, TypeError)):
        analyze_sequential(toggler(), s, backend="enumerate")


@pytest.mark.parametrize(
    "field,assignment",
    [
        ("initial", {"signal": "reset", "value": 1}),
        ("assumptions", {"signal": "event", "value": 0}),
        ("initial", {"signal": "clk", "value": 0}),
        ("assumptions", {"signal": "reset", "value": True}),
        ("assumptions", {"signal": "missing", "value": 0}),
    ],
)
def test_invalid_assumption_domains(field, assignment):
    s = spec(spacing())
    s[field] = [assignment]
    assert analyze_sequential(toggler(), s, backend="enumerate")["checks"][0]["status"] == "unsupported"


def test_alias_conflicts_cannot_manufacture_a_proof():
    n = toggler()
    n["modules"]["top"]["netnames"] = {"alias": {"bits": [3]}}
    s = spec(spacing(), prefix=[], assumptions=[{"signal": "reset", "value": 0}, {"signal": "alias", "value": 1}])
    assert analyze_sequential(n, s, backend="enumerate")["checks"][0]["status"] == "inconsistent_assumptions"
    check = forbidden()
    check["forbid"].append({"signal": "event", "value": 0})
    assert analyze_sequential(n, spec(check), backend="enumerate")["checks"][0]["status"] == "inconsistent_assumptions"


def bound_spec(raw):
    s = spec(spacing())
    s["checks"][0]["binding"] = {"source": "functional", "sha256": sha256(raw).hexdigest(), "command_index": 1}
    return s


def test_sdc_binding_is_exact_explicit_and_stale_safe():
    raw = b"create_clock -name core -period 10 [get_ports clk]\nset_multicycle_path 2 -setup -from [get_ports d] -to [get_ports q]\n"
    n, s = toggler(), bound_spec(raw)
    r = analyze_sequential(n, s, backend="enumerate", sdc_sources={"functional": raw})
    assert r["passed"]
    assert r["checks"][0]["binding"]["role"] == "review_property_link"
    assert r["checks"][0]["binding"]["exception_validated"] is False
    assert verify_sequential(r, n, s, sdc_sources={"functional": raw})["verified"]
    for sources in [{}, {"functional": raw + b"#changed\n"}]:
        changed = analyze_sequential(n, s, backend="enumerate", sdc_sources=sources)
        assert changed["checks"][0]["status"] == "unsupported" and not changed["passed"]
        assert not verify_sequential(r, n, s, sdc_sources=sources)["verified"]
    s["checks"][0]["binding"]["command_index"] = 0
    assert not analyze_sequential(n, s, backend="enumerate", sdc_sources={"functional": raw})["passed"]


@pytest.mark.parametrize(
    "suffix", [b"\nexec touch not-allowed\n", b"\nset_false_path -from $dynamic\n", b"\ncreate_clock {\n", b"\xff"]
)
def test_bound_sdc_with_unsupported_commands_is_rejected(suffix):
    raw = (
        b"create_clock -period 10 [get_ports clk]\nset_multicycle_path 2 -setup -from [get_ports d] -to [get_ports q]\n"
        + suffix
    )
    r = analyze_sequential(toggler(), bound_spec(raw), backend="enumerate", sdc_sources={"functional": raw})
    assert not r["passed"] and r["checks"][0]["status"] == "unsupported"


@pytest.mark.parametrize("where", ["inputs", "state", "observed"])
def test_counterexample_corruption_is_rejected_even_with_recomputed_hash(where):
    n, s = toggler(), spec(spacing(3))
    r = analyze_sequential(n, s, backend="enumerate")
    r["checks"][0]["counterexample"][0][where][0] ^= 1
    seal(r)
    assert not verify_sequential(r, n, s)["verified"]
    with pytest.raises(FunctionalInputError):
        render_vcd(r, n, s, "spacing")


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_frame",
        "extra_frame_key",
        "bool_value",
        "empty_trace",
        "missing_trace",
        "wrong_scope",
        "wrong_binding",
        "wrong_summary",
        "wrong_pass",
        "wrong_digest",
        "wrong_model",
        "fake_activation",
        "extra_top",
        "invalid_status",
    ],
)
def test_saved_report_mutations_fail_closed(mutation):
    n, s = toggler(), spec(spacing(3))
    r = analyze_sequential(n, s, backend="enumerate")
    c = r["checks"][0]
    if mutation == "missing_frame":
        c["counterexample"].pop(0)
    elif mutation == "extra_frame_key":
        c["counterexample"][0]["extra"] = 1
    elif mutation == "bool_value":
        c["counterexample"][0]["inputs"][0] = True
    elif mutation == "empty_trace":
        c["counterexample"] = []
    elif mutation == "missing_trace":
        c["counterexample"] = None
    elif mutation == "wrong_scope":
        c["cone"]["state_bits"] = [99]
    elif mutation == "wrong_binding":
        c["binding"] = {}
    elif mutation == "wrong_summary":
        r["summary"] = {"counterexample": 2}
    elif mutation == "wrong_pass":
        r["passed"] = True
    elif mutation == "wrong_digest":
        r["netlist_digest"] = "0" * 64
    elif mutation == "wrong_model":
        r["model"] = "all_clock_signoff"
    elif mutation == "fake_activation":
        c["activation_witness"] = []
    elif mutation == "extra_top":
        r["extra"] = True
    else:
        c["status"] = "proven"
    assert not verify_sequential(seal(r), n, s)["verified"]


def test_trace_waveforms_are_deterministic_and_do_not_embed_untrusted_names():
    n, s = toggler(), spec(spacing(3))
    r = analyze_sequential(n, s, backend="enumerate")
    text = render_vcd(r, n, s, "spacing")
    assert text == render_vcd(r, n, s, "spacing")
    assert "$timescale 1 ns $end" in text and "state_bit_4" in text
    assert "#4\n" in text and "NOT physical timing" in text
    with pytest.raises(FunctionalInputError):
        render_vcd(r, n, s, "missing")
    r["report_digest"] = "f" * 64
    with pytest.raises(FunctionalInputError):
        render_vcd(r, n, s, "spacing")


def test_cli_analyze_verify_waveform_schema_and_exclusive_outputs(tmp_path, capsys):
    n, s = toggler(), spec(spacing(3))
    netlist, spec_path = tmp_path / "net.json", tmp_path / "spec.json"
    netlist.write_text(json.dumps(n))
    spec_path.write_text(json.dumps(s))
    args = ["--netlist", str(netlist), "--spec", str(spec_path)]
    report = tmp_path / "report.json"
    assert main(["analyze", *args, "--backend", "enumerate", "--output", str(report)]) == 1
    assert main(["verify", *args, "--report", str(report)]) == 0
    assert json.loads(capsys.readouterr().out)["verified"] is True
    assert main(["analyze", *args, "--backend", "enumerate", "--output", str(report)]) == 2
    assert main(["analyze", *args, "--backend", "enumerate", "--output", str(netlist)]) == 2
    assert json.loads(netlist.read_text()) == n
    wave = tmp_path / "wave.vcd"
    assert main(["witness", *args, "--report", str(report), "--check", "spacing", "--output", str(wave)]) == 0
    for kind in ["spec", "result"]:
        target = tmp_path / (kind + "-schema.json")
        assert main(["schema", "--kind", kind, "--output", str(target)]) == 0
        schema = json.loads(target.read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(s if kind == "spec" else json.loads(report.read_text()))
    bad = tmp_path / "bad.json"
    bad.write_text('{"modules":{},"modules":{}}')
    assert main(["analyze", "--netlist", str(bad), "--spec", str(spec_path)]) == 2


def test_cli_bound_sdc_index_and_identity(tmp_path, capsys):
    raw = (
        b"create_clock -period 10 [get_ports clk]\nset_multicycle_path 2 -setup -from [get_ports d] -to [get_ports q]\n"
    )
    source = tmp_path / "test.sdc"
    source.write_bytes(raw)
    assert main(["sdc-index", "--sdc", str(source), "--source-id", "functional"]) == 0
    index = json.loads(capsys.readouterr().out)
    assert index["bindings"][0]["command_index"] == 1
    n, s = toggler(), bound_spec(raw)
    net, sp = tmp_path / "net.json", tmp_path / "spec.json"
    net.write_text(json.dumps(n))
    sp.write_text(json.dumps(s))
    args = ["--netlist", str(net), "--spec", str(sp), "--backend", "enumerate"]
    assert main(["analyze", *args, "--sdc", "functional=" + str(source)]) == 0
    assert json.loads(capsys.readouterr().out)["passed"]
    assert main(["analyze", *args, "--sdc", "bad"]) == 2
    assert main(["analyze", *args, "--sdc", "functional=" + str(source), "--sdc", "functional=" + str(source)]) == 2


@WITH_Z3
@pytest.mark.parametrize("seed", range(20))
def test_seeded_sequential_networks_differentially(seed):
    import random

    rng = random.Random(seed)
    state_bits = list(range(10, 14))
    n = {
        "modules": {
            "top": {
                "ports": ports(clk=("input", 2), data=("input", 3)),
                "cells": {},
                "netnames": {f"q{i}": {"bits": [bit]} for i, bit in enumerate(state_bits)},
            }
        }
    }
    cells = n["modules"]["top"]["cells"]
    available = [3, *state_bits, "0", "1"]
    for i in range(8):
        out = 20 + i
        kind = rng.choice(["$_AND_", "$_OR_", "$_XOR_"])
        cells[f"g{i}"] = cell(kind, A=rng.choice(available), B=rng.choice(available), Y=out)
        available.append(out)
    for i, q in enumerate(state_bits):
        cells[f"ff{i}"] = cell("$_DFF_P_", C=2, D=rng.choice(available), Q=q)
    check = {
        "id": "bad",
        "kind": "forbid",
        "forbid": [{"signal": "q0", "value": rng.randrange(2)}, {"signal": "q1", "value": rng.randrange(2)}],
    }
    s = spec(check, prefix=[], initial=[{"signal": f"q{i}", "value": 0} for i in range(4)])
    enum = analyze_sequential(n, s, backend="enumerate")
    smt = analyze_sequential(n, s, backend="z3")
    status = enum["checks"][0]["status"]
    assert status in {"proven", "counterexample"}
    assert smt["checks"][0]["status"] == status or smt["checks"][0]["status"] == "bounded"
    assert verify_sequential(enum, n, s)["verified"]
    if smt["checks"][0]["status"] != "bounded":
        assert verify_sequential(smt, n, s)["verified"]
