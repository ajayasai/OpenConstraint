"""Hierarchy binding, source replay, integration, and independent logic controls."""

from __future__ import annotations

import copy
import importlib.util
import json
import random
from dataclasses import asdict
from itertools import product

import pytest
from jsonschema import Draft202012Validator

from openconstraint.functional import (
    FunctionalInputError,
    FunctionalLimitError,
    FunctionalLimits,
    _evaluate,
    analyze_functional,
    load_logic_model,
    verify_functional,
)
from openconstraint.hierarchy import (
    CONTRACT,
    HierarchyInputError,
    HierarchyLimitError,
    HierarchyLimits,
    digest,
    elaborate_hierarchy,
    flatten_if_needed,
    hierarchical_name,
    verify_hierarchy,
)
from openconstraint.hierarchy_cli import main
from openconstraint.sequential import analyze_sequential, verify_sequential
from openconstraint.sequential_model import MODEL, SequentialLimits, load_synchronous_model

WITH_Z3 = pytest.mark.skipif(importlib.util.find_spec("z3") is None, reason="optional Z3 solver not installed")


def port(direction, *bits, **metadata):
    return {"direction": direction, "bits": list(bits), **metadata}


def cell(kind, **conns):
    return {
        "type": kind,
        "connections": {name: value if isinstance(value, list) else [value] for name, value in conns.items()},
    }


def module(ports=None, cells=None, nets=None, **extra):
    return {"ports": ports or {}, "cells": cells or {}, "netnames": nets or {}, **extra}


def two_instances():
    return {
        "modules": {
            "top": module(
                {"a": port("input", 2), "b": port("input", 3), "x": port("output", 4), "y": port("output", 5)},
                {"left": cell("invert", a=2, y=4), "right": cell("invert", a=3, y=5)},
            ),
            "invert": module({"a": port("input", 2), "y": port("output", 3)}, {"g": cell("$_NOT_", A=2, Y=3)}),
        }
    }


def evaluate(netlist, inputs, targets):
    model = load_logic_model(netlist, "top", FunctionalLimits())
    gates, _ = model.cone(tuple(model.resolve(n) for n in targets))
    values = {model.resolve(name): bool(value) for name, value in inputs.items()}
    return _evaluate(gates, values, tuple(model.resolve(n) for n in targets))


def bool_spec(source="a", target="x"):
    return {
        "schema_version": "1.0.0",
        "model": "zero_delay_arbitrary_state",
        "top": "top",
        "checks": [{"id": "influence", "sources": [source], "targets": [target], "assumptions": []}],
    }


def hierarchical_counter():
    child = module(
        {"clk": port("input", 2), "reset": port("input", 3), "event": port("output", 4)},
        {"inv": cell("$_NOT_", A=4, Y=5), "ff": cell("$_SDFF_PP0_", C=2, D=5, R=3, Q=4)},
    )
    top = module(child["ports"], {"counter": cell("child", clk=2, reset=3, event=4)})
    return {"modules": {"top": top, "child": child}}


def seq_spec():
    return {
        "schema_version": "1.0.0",
        "model": MODEL,
        "top": "top",
        "clock": "clk",
        "edge": "posedge",
        "prefix": [[{"signal": "reset", "value": 1}]],
        "checks": [
            {"id": "good", "kind": "min_spacing", "event": "/counter/event", "cycles": 2},
            {"id": "bad", "kind": "min_spacing", "event": "event", "cycles": 3},
        ],
    }


def test_repeated_modules_are_distinct_with_identical_local_ids():
    n = two_instances()
    saved = copy.deepcopy(n)
    pack = elaborate_hierarchy(n, "top")
    assert n == saved
    assert set(pack["netlist"]["modules"]["top"]["cells"]) == {"/left/g", "/right/g"}
    assert pack["provenance"]["counts"]["instances"] == 3
    for a, b in product((0, 1), repeat=2):
        assert evaluate(n, {"a": a, "b": b}, ["x", "y", "/left/y", "/right/y"]) == (not a, not b, not a, not b)
    assert verify_hierarchy(pack, n, "top")
    assert pack["contract"] == CONTRACT


@pytest.mark.parametrize("backend", ["enumerate", pytest.param("z3", marks=WITH_Z3)])
@pytest.mark.parametrize(
    "source,target,expected",
    [
        ("a", "x", "dependent"),
        ("b", "x", "independent"),
        ("a", "/right/y", "independent"),
        ("b", "/right/y", "dependent"),
    ],
)
def test_functional_engine_automatically_consumes_hierarchy(backend, source, target, expected):
    n, spec = two_instances(), bool_spec(source, target)
    r = analyze_functional(n, spec, backend=backend)
    assert r["checks"][0]["status"] == expected
    assert verify_functional(r, n, spec, backend="enumerate")["verified"]


@pytest.mark.parametrize("backend", ["enumerate", pytest.param("z3", marks=WITH_Z3)])
def test_reset_aware_proof_and_counterexample_replay_from_hierarchy(backend):
    n, spec = hierarchical_counter(), seq_spec()
    r = analyze_sequential(n, spec, backend=backend)
    assert [c["status"] for c in r["checks"]] == ["proven", "counterexample"]
    assert r["checks"][0]["activation"] == "witnessed"
    assert verify_sequential(r, n, spec, backend="enumerate")["verified"]


def test_bufferless_ports_and_constant_outputs_bind_by_alias_not_cell_count():
    n = {
        "modules": {
            "top": module(
                {"i": port("input", 10), "o": port("output", 20), "zero": port("output", 21)},
                {"wire": cell("wire", i=10, o=20, zero=21)},
            ),
            "wire": module({"i": port("input", 2), "o": port("output", 2), "zero": port("output", "0")}),
        }
    }
    p = elaborate_hierarchy(n, "top")
    assert p["netlist"]["modules"]["top"]["ports"]["o"]["bits"] == [10]
    assert p["netlist"]["modules"]["top"]["ports"]["zero"]["bits"] == ["0"]
    assert evaluate(n, {"i": 1}, ["o", "zero"]) == (True, False)
    assert p["provenance"]["counts"]["leaf_cells"] == 0
    with pytest.raises(FunctionalInputError):
        load_logic_model(n, "top", FunctionalLimits()).resolve(20)  # Canonicalized ID is not guessed.


def test_vector_slices_offsets_concatenations_and_constant_inputs():
    child = module({"i": port("input", 2, 3, 4, offset=7, upto=1), "o": port("output", 4, 3, 2, signed=1)})
    n = {
        "modules": {
            "top": module(
                {"a": port("input", 7, 8), "out": port("output", 10, 11, 12)},
                {"u": cell("reverse", i=[7, "1", 8], o=[10, 11, 12])},
            ),
            "reverse": child,
        }
    }
    p = elaborate_hierarchy(n, "top")
    assert p["netlist"]["modules"]["top"]["ports"]["out"]["bits"] == [8, "1", 7]
    assert p["netlist"]["modules"]["top"]["netnames"]["/u/i"]["bits"] == [7, "1", 8]


def test_alias_ids_zero_and_one_are_not_binary_constants():
    n = {
        "modules": {
            "top": module({"a": port("input", 0), "x": port("output", 1)}, {"u": cell("inv", a=0, y=1)}),
            "inv": two_instances()["modules"]["invert"],
        }
    }
    assert evaluate(n, {"a": 0}, ["x"]) == (True,)
    assert evaluate(n, {"a": 1}, ["x"]) == (False,)


def test_inputs_outputs_and_port_aliases_have_one_driver():
    n = two_instances()
    n["modules"]["top"]["cells"]["right"]["connections"]["y"] = [4]
    with pytest.raises(HierarchyInputError, match="multiply driven"):
        elaborate_hierarchy(n, "top")
    n = two_instances()
    n["modules"]["top"]["cells"]["left"]["connections"]["y"] = [2]
    with pytest.raises(HierarchyInputError, match="multiply driven"):
        elaborate_hierarchy(n, "top")


@pytest.mark.parametrize(
    "child_ports,bindings,reason",
    [
        ({"a": port("input", 2), "b": port("input", 2)}, {"a": [2], "b": [3]}, "shorts"),
        ({"o": port("output", "0")}, {"o": [2]}, "ties an input"),
        ({"o": port("output", "0")}, {"o": ["1"]}, "contradictory"),
    ],
)
def test_short_circuits_and_contradictory_constants_are_rejected(child_ports, bindings, reason):
    n = {
        "modules": {
            "top": module(
                {"a": port("input", 2), "b": port("input", 3)}, {"u": {"type": "child", "connections": bindings}}
            ),
            "child": module(child_ports),
        }
    }
    with pytest.raises(HierarchyInputError, match=reason):
        elaborate_hierarchy(n, "top")


@pytest.mark.parametrize(
    "mutation,match",
    [
        (lambda n: n["modules"]["top"]["cells"]["left"]["connections"].update(a=[2, 3]), "width mismatch"),
        (lambda n: n["modules"]["top"]["cells"]["left"]["connections"].pop("a"), "missing/extra"),
        (lambda n: n["modules"]["top"]["cells"]["left"]["connections"].update(extra=[2]), "missing/extra"),
        (lambda n: n["modules"]["top"]["cells"]["left"].update(parameters={"WIDTH": 3}), "parameters"),
        (
            lambda n: n["modules"]["top"]["cells"]["left"].update(port_directions={"a": "output", "y": "input"}),
            "directions",
        ),
        (lambda n: n["modules"]["invert"].update(attributes={"blackbox": "1"}), "blackbox"),
        (lambda n: n["modules"]["invert"].update(attributes={"whitebox": "1"}), "whitebox"),
        (lambda n: n["modules"]["invert"].update(memories={"memory": {}}), "memories"),
        (lambda n: n["modules"]["invert"].update(processes={"process": {}}), "processes"),
        (lambda n: n["modules"]["invert"]["ports"]["a"].update(direction="inout"), "inout"),
        (lambda n: n["modules"]["invert"]["ports"]["a"].update(bits=["0"]), "input port"),
        (lambda n: n["modules"]["invert"]["ports"]["a"].update(bits=["x"]), "X/Z"),
        (lambda n: n["modules"]["invert"]["cells"]["g"].update(type="$_DFF_PP0_"), "unknown/unmapped"),
        (lambda n: n["modules"]["invert"]["cells"]["g"].update(type="missing_module"), "unknown/unmapped"),
        (lambda n: n["modules"]["invert"]["cells"]["g"].update(parameters={"A": 1}), "parameters"),
        (
            lambda n: n["modules"]["invert"]["cells"]["g"].update(port_directions={"A": "output", "Y": "input"}),
            "directions",
        ),
        (lambda n: n["modules"]["invert"]["cells"]["g"]["connections"].update(A=[]), "nonempty"),
        (lambda n: n["modules"]["invert"]["cells"]["g"]["connections"].update(A=[2, 2]), "single-bit"),
        (lambda n: n["modules"]["invert"]["cells"]["g"]["connections"].update(A=[True]), "wire IDs"),
        (lambda n: n["modules"]["invert"]["cells"]["g"]["connections"].update(A=[-1]), "wire IDs"),
        (lambda n: n["modules"]["invert"]["cells"]["g"]["connections"].update(A=[2**32]), "wire IDs"),
        (lambda n: n["modules"]["invert"]["cells"]["g"]["connections"].update(A=[99]), "undriven"),
        (lambda n: n["modules"]["invert"]["netnames"].update(a={"bits": [8]}), "conflicting"),
        (lambda n: n["modules"]["invert"].update(future_behavior=True), "unsupported fields"),
        (lambda n: n["modules"]["invert"].update(ports=[]), "object"),
        (lambda n: n["modules"]["invert"]["cells"]["g"].update(type=None), "type"),
        (lambda n: n["modules"].update({"$_NOT_": module()}), "shadow"),
    ],
)
def test_fail_closed_hierarchy_validation(mutation, match):
    n = two_instances()
    mutation(n)
    with pytest.raises(HierarchyInputError, match=match):
        elaborate_hierarchy(n, "top")
    with pytest.raises(FunctionalInputError):
        load_logic_model(n, "top", FunctionalLimits())


def chain(depth):
    modules = {"m0": module({"i": port("input", 2), "o": port("output", 2)})}
    for index in range(1, depth + 1):
        modules[f"m{index}"] = module(
            {"i": port("input", 2), "o": port("output", 3)}, {"u": cell(f"m{index - 1}", i=2, o=3)}
        )
    return {"modules": modules}


def test_repeated_definitions_are_not_recursive_but_ancestral_cycles_are():
    n = two_instances()
    n["modules"]["invert"]["cells"] = {"recursive": cell("invert", a=2, y=3)}
    with pytest.raises(HierarchyInputError, match="recursive"):
        elaborate_hierarchy(n, "top")
    p = elaborate_hierarchy(chain(12), "m12")
    assert p["provenance"]["counts"]["instances"] == 13
    assert p["netlist"]["modules"]["m12"]["ports"]["o"]["bits"] == [2]
    with pytest.raises(HierarchyLimitError, match="depth"):
        elaborate_hierarchy(chain(12), "m12", limits=HierarchyLimits(max_depth=11))


@pytest.mark.parametrize(
    "field,value",
    [
        ("max_instances", 2),
        ("max_leaf_cells", 1),
        ("max_wires", 5),
        ("max_alias_bits", 10),
        ("max_source_bytes", 10),
        ("max_output_bytes", 200),
        ("max_name_chars", 5),
    ],
)
def test_every_expansion_budget_is_enforced(field, value):
    with pytest.raises(HierarchyLimitError):
        elaborate_hierarchy(two_instances(), "top", limits=HierarchyLimits(**{field: value}))


@pytest.mark.parametrize("field", asdict(HierarchyLimits()))
@pytest.mark.parametrize("value", [0, -1, True, 1.5, 2**40])
def test_limits_are_strict_non_booleans_below_ceilings(field, value):
    with pytest.raises(ValueError):
        HierarchyLimits(**{field: value})


def test_frontend_limits_apply_to_expanded_cells_not_just_top_instances():
    n = two_instances()
    # Three levels with two instances at each level and one leaf primitive.
    for level in range(4):
        n["modules"][f"level{level}"] = module(
            n["modules"]["top"]["ports"], copy.deepcopy(n["modules"]["top"]["cells"])
        )
    with pytest.raises(FunctionalLimitError):
        load_logic_model(n, "top", FunctionalLimits(max_gates=1))
    with pytest.raises(HierarchyLimitError):
        flatten_if_needed(n, "top", max_cells=1, max_bits=100)


def test_qualified_names_escape_literal_separators_and_tildes():
    n = two_instances()
    n["modules"]["top"]["cells"]["a/b~c"] = n["modules"]["top"]["cells"].pop("left")
    p = elaborate_hierarchy(n, "top")
    assert "/a~1b~0c/a" in p["netlist"]["modules"]["top"]["netnames"]
    assert hierarchical_name(("a/b",), "q") != hierarchical_name(("a", "b"), "q")
    n["modules"]["top"]["netnames"]["/a~1b~0c/a"] = {"bits": [2]}
    with pytest.raises(HierarchyInputError, match="collision"):
        elaborate_hierarchy(n, "top")


def test_init_attributes_survive_and_sequential_engine_still_rejects_hidden_initial_state():
    n = hierarchical_counter()
    n["modules"]["child"]["netnames"]["event"] = {"bits": [4], "attributes": {"init": "0", "src": "fixture.v:2"}}
    p = elaborate_hierarchy(n, "top")
    assert p["netlist"]["modules"]["top"]["netnames"]["/counter/event"]["attributes"]["init"] == "0"
    with pytest.raises(FunctionalInputError, match="init"):
        load_synchronous_model(n, "top", "clk", "posedge", SequentialLimits())


def test_returned_metadata_does_not_alias_input_and_unreachable_modules_remain_bound():
    n = two_instances()
    n["modules"]["invert"]["attributes"] = {"src": "leaf.v:1"}
    n["modules"]["unused"] = {"arbitrary": "not evaluated"}
    p = elaborate_hierarchy(n, "top")
    assert p["provenance"]["unused_modules"] == ["unused"]
    p["provenance"]["instances"][1]["attributes"]["src"] = "changed"
    assert n["modules"]["invert"]["attributes"]["src"] == "leaf.v:1"
    p = elaborate_hierarchy(n, "top")
    n["modules"]["unused"]["arbitrary"] = "edited"
    assert not verify_hierarchy(p, n, "top")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p.update(extra="fabricated"),
        lambda p: p["provenance"]["instances"][1].update(module="different"),
        lambda p: p["provenance"]["cells"][0].update(path=["right", "g"]),
        lambda p: p["provenance"]["signals"][0].update(bits=[True]),
        lambda p: p["netlist"]["modules"]["top"]["cells"]["/left/g"]["connections"].update(A=[3]),
        lambda p: p["contract"].update(functional_property_proof=True),
        lambda p: p["limits"].update(max_instances=19999),
        lambda p: p["provenance"]["counts"].update(instances=3.0),
    ],
)
def test_rehashed_tampering_never_matches_reconstruction(mutation):
    n = two_instances()
    p = elaborate_hierarchy(n, "top")
    mutation(p)
    p["netlist_digest"] = digest(p["netlist"])
    p["pack_digest"] = digest({k: v for k, v in p.items() if k != "pack_digest"})
    assert not verify_hierarchy(p, n, "top")


def test_json_key_order_irrelevant_but_limits_and_top_are_bound():
    n = two_instances()
    p = elaborate_hierarchy(n, "top")
    reordered = {"modules": dict(reversed(list(n["modules"].items())))}
    assert elaborate_hierarchy(reordered, "top") == p
    assert not verify_hierarchy(p, n, "top", limits=HierarchyLimits(max_instances=500))
    with pytest.raises(HierarchyInputError):
        elaborate_hierarchy(n, "missing")
    with pytest.raises(HierarchyInputError):
        elaborate_hierarchy(n, "")


def test_cli_roundtrip_schema_and_no_clobber(tmp_path, capsys):
    source, out = tmp_path / "input.json", tmp_path / "pack"
    source.write_text(json.dumps(two_instances()))
    arguments = ["--netlist", str(source), "--top", "top"]
    assert main(["compile", *arguments, "--output", str(out)]) == 0
    assert main(["verify", *arguments, "--pack", str(out)]) == 0
    p = json.loads((out / "hierarchy.json").read_text())
    schema_path = tmp_path / "schema.json"
    assert main(["schema", "--output", str(schema_path)]) == 0
    schema = json.loads(schema_path.read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(p)
    assert main(["compile", *arguments, "--output", str(out)]) == 2
    assert main(["schema", "--output", str(schema_path)]) == 2
    flat_path = out / "netlist.json"
    flat_path.write_text("{}")
    assert main(["verify", *arguments, "--pack", str(out)]) == 1
    flat_path.write_text('{"a":0,"a":1}')
    assert main(["verify", *arguments, "--pack", str(out)]) == 2
    assert main(["schema"]) == 0
    assert '"$schema"' in capsys.readouterr().out


@pytest.mark.parametrize("seed", range(100))
def test_random_nested_logic_matches_independent_recursive_evaluation(seed):
    """Oracle recursively evaluates module calls; it does not use union-find."""
    rng = random.Random(seed)
    modules = {
        "leaf": module(
            {"a": port("input", 2), "b": port("input", 3), "o": port("output", 4)},
            {"gate": cell("$_XOR_", A=2, B=3, Y=4)},
        )
    }
    previous = "leaf"
    for level in range(rng.randint(1, 5)):
        child_name = f"m{level}"
        swap = rng.choice([False, True])
        modules[child_name] = module(
            {"a": port("input", 2), "b": port("input", 3), "o": port("output", 6)},
            {
                "first": cell(previous, a=3 if swap else 2, b=rng.choice([2, 3, "0", "1"]), o=4),
                "second": cell(previous, a=4, b=3, o=5),
                "gate": cell(rng.choice(["$_AND_", "$_OR_", "$_XOR_"]), A=5, B=2, Y=6),
            },
        )
        previous = child_name
    modules["top"] = module(
        {"a": port("input", 2), "b": port("input", 3), "o": port("output", 4)}, {"u": cell(previous, a=2, b=3, o=4)}
    )
    n = {"modules": modules}

    def oracle(name, a, b):
        definition = modules[name]
        values = {2: bool(a), 3: bool(b), "0": False, "1": True}
        pending = list(definition["cells"].values())
        while pending:
            for c in pending[:]:
                co = c["connections"]
                ikeys, output = ("AB", "Y") if c["type"].startswith("$_") else ("ab", "o")
                if not all(co[k][0] in values for k in ikeys):
                    continue
                x, y = (values[co[k][0]] for k in ikeys)
                if c["type"] == "$_XOR_":
                    result = x != y
                elif c["type"] == "$_AND_":
                    result = x and y
                elif c["type"] == "$_OR_":
                    result = x or y
                else:
                    result = oracle(c["type"], x, y)
                values[co[output][0]] = result
                pending.remove(c)
        return values[definition["ports"]["o"]["bits"][0]]

    p = elaborate_hierarchy(n, "top")
    for a, b in product((0, 1), repeat=2):
        assert evaluate(p["netlist"], {"a": a, "b": b}, ["o"])[0] == oracle("top", a, b)


def test_parent_instance_attributes_are_retained_without_changing_behavior():
    n = two_instances()
    n["modules"]["top"]["cells"]["left"]["attributes"] = {"src": "top.v:5", "keep_hierarchy": "1"}
    p = elaborate_hierarchy(n, "top")
    left = next(i for i in p["provenance"]["instances"] if i["path"] == ["left"])
    assert left["instance_attributes"]["src"] == "top.v:5"
    assert evaluate(n, {"a": 0, "b": 1}, ["x", "y"]) == (True, False)


def test_cell_namespace_collision_is_not_silently_merged():
    n = two_instances()
    n["modules"]["top"]["cells"]["/left/g"] = cell("$_NOT_", A=2, Y=100)
    with pytest.raises(HierarchyInputError, match="collision"):
        elaborate_hierarchy(n, "top")


def test_bit_id_exhaustion_is_not_emitted_as_unreplayable_output():
    n = two_instances()
    n["modules"]["top"]["netnames"]["high"] = {"bits": [2**31 - 1]}
    n["modules"]["invert"]["netnames"]["unused"] = {"bits": [99]}
    with pytest.raises(HierarchyLimitError, match="namespace"):
        elaborate_hierarchy(n, "top")


@pytest.mark.parametrize("bad", [[], None, 1, True, {"modules": []}, {"models": {}, "modules": {}}])
def test_bad_top_level_inputs(bad):
    with pytest.raises(HierarchyInputError):
        elaborate_hierarchy(bad, "top")


def test_invalid_input_never_creates_destination_and_file_link_are_refused(tmp_path):
    n = two_instances()
    n["modules"]["invert"]["cells"]["g"]["connections"]["A"] = ["z"]
    src, dest = tmp_path / "source.json", tmp_path / "pack"
    src.write_text(json.dumps(n))
    args = ["compile", "--netlist", str(src), "--top", "top", "--output", str(dest)]
    assert main(args) == 2 and not dest.exists()
    src.write_text(json.dumps(two_instances()))
    dest.write_text("preserve me")
    assert main(args) == 2 and dest.read_text() == "preserve me"
    dest.unlink()
    try:
        dest.symlink_to(src)
    except OSError:
        return  # Windows without symlink permission still exercises file no-clobber.
    assert main(args) == 2 and dest.is_symlink()


PRIMITIVES = [f"$_DFF_{c}_" for c in "PN"]
PRIMITIVES += [f"$_DFFE_{c}{e}_" for c in "PN" for e in "PN"]
PRIMITIVES += [f"$_SDFF_{c}{r}{v}_" for c in "PN" for r in "PN" for v in "01"]
PRIMITIVES += [
    f"$_{k}_{c}{r}{v}{e}_" for k in ["SDFFE", "SDFFCE"] for c in "PN" for r in "PN" for v in "01" for e in "PN"
]


@pytest.mark.parametrize("kind", PRIMITIVES)
def test_all_supported_sequential_interfaces_survive_hierarchy_against_truth_table(kind):
    family, code = kind[2:-1].split("_")
    cp = code[0]
    ep = code[-1] if family in {"DFFE", "SDFFE", "SDFFCE"} else None
    rp = code[1] if family.startswith("SDFF") else None
    rv = code[2] == "1" if rp else False
    ports = {
        "clk": port("input", 2),
        "d": port("input", 3),
        "e": port("input", 4),
        "r": port("input", 5),
        "q": port("output", 6),
    }
    conns = {"C": 2, "D": 3, "Q": 6}
    if ep:
        conns["E"] = 4
    if rp:
        conns["R"] = 5
    n = {
        "modules": {
            "top": module(ports, {"u": cell("ff", clk=2, d=3, e=4, r=5, q=6)}),
            "ff": module(ports, {"ff": cell(kind, **conns)}),
        }
    }
    model = load_synchronous_model(n, "top", "clk", "posedge" if cp == "P" else "negedge", SequentialLimits())
    qbit = model.resolve("q")
    for q, d, e, r in product((False, True), repeat=4):
        enabled = ep is None or e == (ep == "P")
        reset = rp is not None and r == (rp == "P")
        value = d if enabled else q
        if reset and (family != "SDFFCE" or enabled):
            value = rv
        values = {qbit: q, model.resolve("d"): d, model.resolve("e"): e, model.resolve("r"): r}
        actual = _evaluate(model.logic.gates, values, (model.next_state[qbit],))[0]
        assert actual == value


@pytest.mark.parametrize(
    "category,key",
    [("ports", "signed"), ("ports", "upto"), ("ports", "offset"), ("netnames", "hide_name"), ("cells", "hide_name")],
)
@pytest.mark.parametrize("value", [True, 0.5, "0", 2**40])
def test_malformed_metadata_cannot_generate_schema_invalid_packs(category, key, value):
    n = two_instances()
    target = n["modules"]["invert"][category]
    if category == "netnames":
        target["a"] = {"bits": [2]}
    name = "g" if category == "cells" else "a"
    target[name][key] = value
    with pytest.raises(HierarchyInputError, match="metadata"):
        elaborate_hierarchy(n, "top")
