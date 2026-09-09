from __future__ import annotations

import copy
import itertools
import json
import random
from dataclasses import asdict
from importlib.resources import files

import pytest
from jsonschema import Draft202012Validator

from openconstraint.cutcompare import ComparisonLimits, compare_structural_cuts, verify_comparison
from openconstraint.cutcompare_cli import main
from openconstraint.proof import GraphNode, build_structural_graph

LIBRARY = """library (test) {
 cell (BUF) {pin (A) {direction : input;} pin (Y) {direction : output; function : "A";}}
 cell (OR2) {pin (A) {direction : input;} pin (B) {direction : input;} pin (Y) {direction : output; function : "A|B";}}
 cell (DFF) {ff (IQ, IQN) {clocked_on : "CK"; next_state : "D";}
 pin (CK) {direction : input; clock : true;} pin (D) {direction : input;} pin (Q) {direction : output;}}
}"""
DIAMOND = """module top(input data, input spare, output result, output extra);
 wire l,r,j;
 BUF u_left (.A(data),.Y(l)); BUF u_right (.A(data),.Y(r));
 OR2 u_join (.A(l),.B(r),.Y(j)); BUF u_out (.A(j),.Y(result));
 BUF u_extra (.A(spare),.Y(extra)); endmodule"""
BROAD = "set_false_path -from [get_ports data] -to [get_ports result]"
LEFT = "set_false_path -from [get_ports data] -through [get_pins u_left/A] -to [get_ports result]"
RIGHT = LEFT.replace("u_left/A", "u_right/A")
EXTRA = "set_false_path -from [get_ports spare] -to [get_ports extra]"


@pytest.fixture
def diamond(design_factory):
    return design_factory(verilog=DIAMOND, liberty=LIBRARY)


def statuses(report, sense="setup"):
    return tuple(report["checks"][sense][d]["status"] for d in ("new_cuts", "removed_cuts"))


def test_same_endpoints_do_not_hide_new_branch(diamond):
    report = compare_structural_cuts(diamond, LEFT, BROAD)
    assert report["status"] == "different_structural_cuts"
    assert statuses(report) == ("witnessed", "absent")
    witness = report["checks"]["setup"]["new_cuts"]
    assert {"kind": "pin", "name": "u_right/A"} in witness["witness"]
    assert {"kind": "pin", "name": "u_left/A"} not in witness["witness"]
    assert witness["matched_before"] == [] and witness["matched_after"] == [0]
    assert report["contract"]["timing_equivalence"] is False


@pytest.mark.parametrize(
    "before,after",
    [
        (BROAD, LEFT + "\n" + RIGHT),
        (LEFT + "\n" + RIGHT, BROAD),
        (LEFT + "\n" + RIGHT, RIGHT + "\n" + LEFT),
        (LEFT, LEFT + "\n" + LEFT),
        (BROAD, BROAD.replace("-from [get_ports data]", "")),
        ("", "set_false_path -from [get_ports spare] -to [get_ports result]"),
        ("", ""),
        (BROAD, "# comment\n" + BROAD),
        (BROAD, BROAD.replace("data", "{data}")),
        (LEFT + "\n" + RIGHT, LEFT.replace("u_left/A", "{u_left/A u_right/A}")),
        (BROAD, BROAD.replace("-from [get_ports data]", "-from [all_inputs]")),
        (BROAD, BROAD.replace("-to [get_ports result]", "-to [all_outputs]")),
    ],
)
def test_equivalent_rewrites_and_vacuous_scopes(diamond, before, after):
    report = compare_structural_cuts(diamond, before, after)
    assert report["reason"] is None
    assert report["status"] == "equivalent_structural_cuts"
    assert report["complete"] is True
    assert statuses(report) == statuses(report, "hold") == ("absent", "absent")


@pytest.mark.parametrize("sense", ["setup", "hold"])
def test_setup_hold_kept_distinct(diamond, sense):
    restricted = BROAD.replace("set_false_path", "set_false_path -" + sense)
    report = compare_structural_cuts(diamond, restricted, BROAD)
    other = "hold" if sense == "setup" else "setup"
    assert statuses(report, sense) == ("absent", "absent")
    assert statuses(report, other) == ("witnessed", "absent")


def test_both_directions_have_different_witnesses(diamond):
    report = compare_structural_cuts(diamond, LEFT, RIGHT)
    assert statuses(report) == ("witnessed", "witnessed")
    assert report["checks"]["setup"]["new_cuts"]["witness"] != report["checks"]["setup"]["removed_cuts"]["witness"]
    report = compare_structural_cuts(diamond, BROAD, "")
    assert statuses(report) == ("absent", "witnessed")


def test_through_order_and_distinct_occurrences(diamond):
    ordered = LEFT.replace("-to", "-through [get_pins u_out/A] -to")
    reverse = LEFT.replace("u_left/A", "u_out/A").replace("-to", "-through [get_pins u_left/A] -to")
    assert statuses(compare_structural_cuts(diamond, reverse, ordered)) == ("witnessed", "absent")
    repeated = LEFT.replace("-to", "-through [get_pins u_left/A] -to")
    assert compare_structural_cuts(diamond, "", repeated)["status"] == "equivalent_structural_cuts"
    # One occurrence in two overlapping groups must not consume both groups.
    overlap = LEFT.replace("u_left/A", "{u_left/A u_right/A}").replace("-to", "-through [get_pins u_left/A] -to")
    assert compare_structural_cuts(diamond, "", overlap)["status"] == "equivalent_structural_cuts"


@pytest.mark.parametrize(
    "text",
    [
        BROAD.replace("data", "{data absent}"),
        BROAD.replace("data", "absent"),
        BROAD.replace("-from", "-rise_from"),
        BROAD.replace("-to", "-fall_to"),
        LEFT.replace("-through", "-rise_through"),
        LEFT.replace("-through", "-fall_through"),
        BROAD.replace("set_false_path", "set_false_path -rise"),
        BROAD.replace("set_false_path", "set_false_path -fall"),
        BROAD.replace("set_false_path", "set_false_path -rise -fall"),
        BROAD.replace("set_false_path", "set_false_path -reset_path"),
        BROAD + "\nset_case_analysis 0 [get_ports data]",
        BROAD + "\nset_disable_timing [get_cells u_left]",
        BROAD + "\nset_clock_groups -asynchronous -group a -group b",
        BROAD + "\nset_multicycle_path 2 -from [get_ports data] -to [get_ports result]",
        BROAD + "\nset_max_delay 2 -from [get_ports data] -to [get_ports result]",
        "set name data; " + BROAD,
        "source hidden.sdc",
        "set_false_path -from [get_ports data",
        "set_false_path -from $objects -to [get_ports result]",
        "set_false_path -from [get_pins u_left/Y] -to [get_ports result]",
        "set_false_path -from [get_ports data] -to [get_pins u_left/A]",
        "set_false_path -from [get_cells u_left] -to [get_ports result]",
        "set_false_path -from [get_ports data] -to [get_cells u_out]",
        "set_false_path -from data -to result",  # ambiguous net/port? ports accepted below; clocks test covers collision
        "current_design wrong_top",
        "create_clock -period -1 [get_ports data]",
        "create_clock -name c -period 10 [get_ports data]\nset_false_path -from [get_clocks c] -to [get_ports result]",
        "create_clock -name c -period 10 [get_ports data]\nset_false_path -from c -to [get_ports result]",
    ],
)
def test_unknown_semantics_cannot_be_equivalent(diamond, text):
    # Bare port names can be unambiguous under the published literal contract.
    if text == "set_false_path -from data -to result":
        assert compare_structural_cuts(diamond, BROAD, text)["status"] == "equivalent_structural_cuts"
        return
    report = compare_structural_cuts(diamond, text, text)
    assert report["status"] == "unresolved", report
    assert report["complete"] is False
    assert statuses(report) == ("unresolved", "unresolved")


def test_clock_io_values_are_explicitly_outside_cut_equivalence(diamond):
    context = "create_clock -name c -period 10 [get_ports data]\nset_input_delay 1 -clock c [get_ports spare]\n"
    report = compare_structural_cuts(diamond, context + BROAD, context.replace("period 10", "period 20") + BROAD)
    assert report["status"] == "equivalent_structural_cuts"
    assert report["source_hashes"]["before"] != report["source_hashes"]["after"]
    assert report["contract"]["timing_equivalence"] is False


def test_dff_boundary_and_cell_selection(design_factory):
    design = design_factory(liberty=LIBRARY)
    text = "set_false_path -from [get_cells u_ff] -to [get_ports result]"
    report = compare_structural_cuts(design, "", text)
    assert report["status"] == "different_structural_cuts", report["reason"]
    assert report["checks"]["setup"]["new_cuts"]["witness"][0] == {"kind": "pin", "name": "u_ff/Q"}
    # No combinational path crosses DFF state from its D pin to Q.
    assert (
        compare_structural_cuts(design, "", "set_false_path -from [get_ports data] -to [get_ports result]")["status"]
        == "equivalent_structural_cuts"
    )
    assert (
        compare_structural_cuts(design, "", "set_false_path -from [get_ports data] -to [get_cells u_ff]")["status"]
        == "different_structural_cuts"
    )


def test_net_and_cell_through_scopes(diamond):
    for scope in ("[get_nets l]", "[get_cells u_left]", "u_left", "l"):
        text = LEFT.replace("[get_pins u_left/A]", scope)
        assert compare_structural_cuts(diamond, LEFT, text)["status"] == "equivalent_structural_cuts"


def test_warnings_gate_even_empty_comparison(diamond):
    diamond.warnings.append("unsupported design")
    assert compare_structural_cuts(diamond, "", "")["status"] == "unresolved"


@pytest.mark.parametrize("field", list(asdict(ComparisonLimits())))
@pytest.mark.parametrize("value", [0, -1, True, 1.5, "2", 10**9])
def test_limit_validation(field, value):
    with pytest.raises(ValueError):
        ComparisonLimits(**{field: value})


@pytest.mark.parametrize("field", list(asdict(ComparisonLimits())))
def test_every_resource_ceiling_fails_closed(diamond, field):
    before, after = LEFT, BROAD
    if field == "max_through_groups":
        before = LEFT.replace("-to", "-through [get_pins u_out/A] -to")
    report = compare_structural_cuts(diamond, before, after, limits=ComparisonLimits(**{field: 1}))
    assert report["status"] == "bounded", (field, report)
    assert report["complete"] is False
    assert "max_" in report["reason"]


def test_byte_limits_and_non_utf8(diamond):
    assert (
        compare_structural_cuts(diamond, "#é", "", limits=ComparisonLimits(max_source_bytes=2))["status"] == "bounded"
    )
    assert (
        compare_structural_cuts(diamond, "#a", "#b", limits=ComparisonLimits(max_source_bytes=3))["status"] == "bounded"
    )
    assert compare_structural_cuts(diamond, "\ud800", "")["status"] == "unresolved"


def test_replay_binds_exact_source_graph_and_limits(diamond):
    report = compare_structural_cuts(diamond, LEFT, BROAD)
    assert verify_comparison(diamond, LEFT, BROAD, report)["verified"] is True
    assert verify_comparison(diamond, LEFT + "\n# edited", BROAD, report)["verified"] is False
    assert (
        verify_comparison(diamond, LEFT, BROAD, report, limits=ComparisonLimits(max_states=99999))["verified"] is False
    )
    diamond.combinational_arcs["u_left/A"] = set()
    assert verify_comparison(diamond, LEFT, BROAD, report)["verified"] is False


@pytest.mark.parametrize(
    "mutation", ["status", "witness", "matched", "source", "extra", "bool", "nan", "contract", "digest"]
)
def test_tampering_and_rehashing_do_not_pass(diamond, mutation):
    report = compare_structural_cuts(diamond, LEFT, BROAD)
    if mutation == "status":
        report["status"] = "equivalent_structural_cuts"
    elif mutation == "witness":
        report["checks"]["setup"]["new_cuts"]["witness"][0]["name"] = "spare"
    elif mutation == "matched":
        report["checks"]["setup"]["new_cuts"]["matched_before"] = [0]
    elif mutation == "source":
        report["source_hashes"]["before"] = "0" * 64
    elif mutation == "extra":
        report["instructions"] = "source attacker.sdc"
    elif mutation == "bool":
        report["complete"] = 1
    elif mutation == "nan":
        report["work"]["steps"] = float("nan")
    elif mutation == "contract":
        report["contract"]["timing_equivalence"] = True
    else:
        report["report_digest"] = "0" * 64
    if mutation not in ("digest", "nan"):
        from hashlib import sha256

        payload = {k: v for k, v in report.items() if k != "report_digest"}
        report["report_digest"] = sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()
    assert verify_comparison(diamond, LEFT, BROAD, report)["verified"] is False


def test_bounded_report_replay_does_not_assert_equivalence(diamond):
    limits = ComparisonLimits(max_states=1)
    report = compare_structural_cuts(diamond, LEFT, BROAD, limits=limits)
    replay = verify_comparison(diamond, LEFT, BROAD, report, limits=limits)
    assert replay["verified"] is True and replay["complete"] is False
    assert replay["comparison_status"] == "bounded"


def _paths(graph, sources, targets):
    # Independent exhaustive oracle used only on small, acyclic fixtures.
    def walk(path):
        if path[-1] in targets:
            yield tuple(path)
        for target in graph.adjacency[path[-1]]:
            assert target not in path, "oracle fixtures must be acyclic"
            yield from walk([*path, target])

    for source in sorted(sources):
        yield from walk([source])


def _oracle_matches(spec, path, sense):
    source, target, groups, senses = spec
    if sense not in senses or path[0].name not in source or path[-1].name not in target:
        return False
    # Enumerate ordered occurrence choices, not the production greedy DFA.
    return any(
        all(
            path[position].kind == "pin" and path[position].name in group
            for position, group in zip(positions, groups, strict=True)
        )
        for positions in itertools.combinations(range(len(path)), len(groups))
    )


def _sdc(specs):
    commands = []
    for source, target, groups, senses in specs:
        sense_option = "" if len(senses) == 2 else " -" + next(iter(senses))
        through = "".join(" -through [get_pins {" + " ".join(sorted(group)) + "}]" for group in groups)
        commands.append(
            "set_false_path"
            + sense_option
            + " -from [get_ports {"
            + " ".join(sorted(source))
            + "}]"
            + through
            + " -to [get_ports {"
            + " ".join(sorted(target))
            + "}]"
        )
    return "\n".join(commands)


@pytest.mark.parametrize("seed", range(200))
def test_random_dags_match_independent_enumeration(design_factory, seed):
    rng = random.Random(seed)
    nets = ["data", "spare"]
    rows = []
    pins = []
    for i in range(rng.randint(2, 7)):
        a, b = rng.choice(nets), rng.choice(nets)
        rows.append(f"OR2 g{i} (.A({a}),.B({b}),.Y(n{i}));")
        nets.append(f"n{i}")
        pins.extend([f"g{i}/A", f"g{i}/B", f"g{i}/Y"])
    v = "module top(input data,input spare,output result,output extra); wire " + ",".join(nets[2:]) + ";"
    v += "".join(rows) + f"BUF out (.A({nets[-1]}),.Y(result)); BUF other (.A({rng.choice(nets)}),.Y(extra)); endmodule"
    design = design_factory(verilog=v, liberty=LIBRARY)
    assert not design.warnings

    def specs():
        return [
            (
                frozenset(rng.sample(["data", "spare"], rng.randint(1, 2))),
                frozenset(rng.sample(["result", "extra"], rng.randint(1, 2))),
                tuple(frozenset(rng.sample(pins, rng.randint(1, 2))) for _ in range(rng.randint(0, 3))),
                rng.choice([frozenset({"setup"}), frozenset({"hold"}), frozenset({"setup", "hold"})]),
            )
            for _ in range(rng.randint(0, 4))
        ]

    left, right = specs(), specs()
    if seed % 5 == 0:
        right = list(reversed(left)) + left[:1]
    report = compare_structural_cuts(design, _sdc(left), _sdc(right))
    assert report["complete"], report["reason"]
    graph = build_structural_graph(design)
    paths = list(
        _paths(
            graph,
            {GraphNode("port", n) for n in ("data", "spare")},
            {GraphNode("port", n) for n in ("result", "extra")},
        )
    )
    for sense in ("setup", "hold"):
        left_paths = {path for path in paths if any(_oracle_matches(s, path, sense) for s in left)}
        right_paths = {path for path in paths if any(_oracle_matches(s, path, sense) for s in right)}
        for direction, difference in [
            ("new_cuts", right_paths - left_paths),
            ("removed_cuts", left_paths - right_paths),
        ]:
            outcome = report["checks"][sense][direction]
            assert outcome["status"] == ("witnessed" if difference else "absent")
            if difference:
                witness = tuple(GraphNode(**node) for node in outcome["witness"])
                assert witness in difference
                assert len(witness) == min(map(len, difference))
    assert compare_structural_cuts(design, _sdc(left), _sdc(right)) == report


def layered_design(layers=45):
    rows, nets = [], []
    for i in range(layers):
        source = "data" if i == 0 else f"j{i - 1}"
        nets.extend([f"l{i}", f"r{i}", f"j{i}"])
        rows.extend(
            [
                f"BUF left{i} (.A({source}),.Y(l{i}));",
                f"BUF right{i} (.A({source}),.Y(r{i}));",
                f"OR2 join{i} (.A(l{i}),.B(r{i}),.Y(j{i}));",
            ]
        )
    return (
        "module top(input data, output result); wire "
        + ",".join(nets)
        + ";"
        + "".join(rows)
        + f"BUF out (.A(j{layers - 1}),.Y(result)); endmodule"
    )


def test_exponentially_many_paths_use_small_product(design_factory):
    layers = 45
    design = design_factory(verilog=layered_design(layers), liberty=LIBRARY)
    split = "\n".join(BROAD.replace("-to", f"-through [get_pins {branch}0/A] -to") for branch in ("left", "right"))
    report = compare_structural_cuts(design, BROAD, split)
    assert report["status"] == "equivalent_structural_cuts"
    assert report["work"]["states"] < 5000
    assert report["work"]["steps"] < 100000
    graph = build_structural_graph(design)
    memo = {}

    def count(node):
        if node in memo:
            return memo[node]
        result = int(node == GraphNode("port", "result")) + sum(count(n) for n in graph.adjacency[node])
        memo[node] = result
        return result

    assert count(GraphNode("port", "data")) == 2**layers


def test_cycles_terminate_with_walk_semantics(design_factory):
    v = """module top(input data, output result); wire x,y;
    OR2 merge (.A(data),.B(y),.Y(x)); BUF loop (.A(x),.Y(y)); BUF out (.A(x),.Y(result)); endmodule"""
    design = design_factory(verilog=v, liberty=LIBRARY)
    text = BROAD.replace("-to", "-through [get_pins loop/A] -through [get_pins loop/A] -to")
    report = compare_structural_cuts(design, "", text)
    assert report["status"] == "different_structural_cuts"
    path = report["checks"]["setup"]["new_cuts"]["witness"]
    assert path.count({"kind": "pin", "name": "loop/A"}) == 2


@pytest.fixture
def cli_inputs(tmp_path):
    for name, text in [("design.v", DIAMOND), ("cells.lib", LIBRARY), ("before.sdc", LEFT), ("after.sdc", BROAD)]:
        (tmp_path / name).write_text(text, encoding="utf-8")
    return [
        "--verilog",
        str(tmp_path / "design.v"),
        "--liberty",
        str(tmp_path / "cells.lib"),
        "--top",
        "top",
        "--before",
        str(tmp_path / "before.sdc"),
        "--after",
        str(tmp_path / "after.sdc"),
    ]


@pytest.mark.parametrize("policy,exitcode", [("change", 1), ("new-cut", 1), ("never", 0)])
def test_cli_policies_replay_and_schema(cli_inputs, tmp_path, capsys, policy, exitcode):
    report_path = tmp_path / "result.json"
    assert main(["compare", *cli_inputs, "--fail-on", policy, "--output", str(report_path)]) == exitcode
    assert main(["verify", *cli_inputs, "--report", str(report_path)]) == 0
    assert json.loads(capsys.readouterr().out)["verified"] is True
    report = json.loads(report_path.read_text())
    schema = json.loads(files("openconstraint.schemas").joinpath("cut-comparison.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(report)
    assert main(["schema"]) == 0
    assert json.loads(capsys.readouterr().out) == schema


def test_cli_fresh_outputs_and_stale_replay(cli_inputs, tmp_path, capsys):
    report_path = tmp_path / "result.json"
    assert main(["compare", *cli_inputs, "--output", str(report_path)]) == 1
    original = report_path.read_bytes()
    assert main(["compare", *cli_inputs, "--output", str(report_path)]) == 2
    assert report_path.read_bytes() == original
    (tmp_path / "after.sdc").write_text(LEFT)
    assert main(["verify", *cli_inputs, "--report", str(report_path)]) == 1
    assert main(["compare", *cli_inputs]) == 0
    assert main(["compare", *cli_inputs, "--output", str(tmp_path / "before.sdc")]) == 2
    assert (tmp_path / "before.sdc").read_text() == LEFT
    assert main(["compare", *cli_inputs, "--output", str(tmp_path)]) == 2


def test_cli_new_cut_policy_allows_only_removals(cli_inputs, tmp_path, capsys):
    (tmp_path / "before.sdc").write_text(BROAD)
    (tmp_path / "after.sdc").write_text(LEFT)
    assert main(["compare", *cli_inputs, "--fail-on", "new-cut"]) == 0
    assert main(["compare", *cli_inputs, "--fail-on", "change"]) == 1
    assert main(["compare", *cli_inputs, "--fail-on", "never", "--max-states", "1"]) == 2


@pytest.mark.parametrize("payload", ["[]", "{", '{"status":"x","status":"y"}', '{"work":NaN}'])
def test_cli_bad_evidence(cli_inputs, tmp_path, capsys, payload):
    report_path = tmp_path / "bad.json"
    report_path.write_text(payload)
    assert main(["verify", *cli_inputs, "--report", str(report_path)]) in (1, 2)


def test_cli_rejects_bad_limits_bytes_missing_files_and_links(cli_inputs, tmp_path, capsys):
    assert main(["compare", *cli_inputs, "--max-states", "0"]) == 2
    assert main(["compare", *cli_inputs, "--max-source-bytes", "1"]) == 2
    link = tmp_path / "output-link.json"
    try:
        link.symlink_to(tmp_path / "missing.json")
    except OSError:
        pytest.skip("symlink creation unavailable")
    assert main(["compare", *cli_inputs, "--output", str(link)]) == 2
    assert not (tmp_path / "missing.json").exists()
    (tmp_path / "after.sdc").write_bytes(b"\xff")
    assert main(["compare", *cli_inputs]) == 2
    (tmp_path / "after.sdc").unlink()
    assert main(["compare", *cli_inputs]) == 2


def test_schema_validates_noncomplete_reports_and_refuses_added_fields(diamond):
    schema = json.loads(files("openconstraint.schemas").joinpath("cut-comparison.schema.json").read_text())
    validator = Draft202012Validator(schema)
    reports = [
        compare_structural_cuts(diamond, "", ""),
        compare_structural_cuts(diamond, "exec something", ""),
        compare_structural_cuts(diamond, LEFT, BROAD, limits=ComparisonLimits(max_states=1)),
    ]
    for report in reports:
        validator.validate(report)
        tampered = copy.deepcopy(report)
        tampered["complete"] = 1
        assert not validator.is_valid(tampered)
        tampered = copy.deepcopy(report)
        tampered["unused"] = True
        assert not validator.is_valid(tampered)
