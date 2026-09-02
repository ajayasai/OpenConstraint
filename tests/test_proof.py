from __future__ import annotations

import json
import re
from importlib.resources import files
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from openconstraint.proof import (
    ProofLimitError,
    ProofLimits,
    ProofStatus,
    analyze_proofs,
    build_repair_plan,
    build_structural_graph,
    main,
    render_proof_text,
    render_repair_sdc,
    verify_proof_pack,
)

COMBINATIONAL = r"""
module top(input data, input spare, output result);
  wire mid;
  BUF u_first (.A(data), .Y(mid));
  BUF u_second (.A(mid), .Y(result));
endmodule
"""


def _proof(pack: dict[str, object], index: int = 0) -> dict[str, object]:
    modes = pack["modes"]
    assert isinstance(modes, list)
    mode = modes[0]
    assert isinstance(mode, dict)
    proofs = mode["proofs"]
    assert isinstance(proofs, list)
    item = proofs[index]
    assert isinstance(item, dict)
    return item


def test_structural_graph_is_canonical_and_bounded(design_factory) -> None:
    design = design_factory(verilog=COMBINATIONAL)
    first = build_structural_graph(design)
    second = build_structural_graph(design)
    assert first.digest == second.digest
    assert first.edge_count > 0
    assert any(node.name == "u_first/A" for node in first.nodes)
    with pytest.raises(ProofLimitError):
        build_structural_graph(design, ProofLimits(max_graph_edges=1))


def test_proves_existing_and_vacuous_paths(audit_factory, design_factory) -> None:
    sdc = r"""
set_false_path -from [get_ports data] -through [get_cells u_first] -to [get_ports result]
set_false_path -from [get_ports spare] -to [get_ports result]
"""
    design = design_factory(verilog=COMBINATIONAL)
    result = audit_factory(sdc, verilog=COMBINATIONAL)
    pack = analyze_proofs(design, result)
    assert _proof(pack, 0)["status"] == ProofStatus.WITNESSED.value
    assert _proof(pack, 0)["witness_node_count"] >= 5
    assert _proof(pack, 1)["status"] == ProofStatus.VACUOUS.value
    assert pack["summary"] == {
        "bounded": 0,
        "unresolved": 0,
        "vacuous": 1,
        "witnessed": 1,
    }
    assert pack["pack_digest"]
    assert "witness:" in render_proof_text(pack)


def test_ordered_through_scopes_are_enforced(audit_factory, design_factory) -> None:
    sdc = r"""
set_false_path -from [get_ports data] -through [get_cells u_second] -through [get_cells u_first] -to [get_ports result]
set_false_path -from [get_ports data] -through [get_cells u_first] -through [get_cells u_second] -to [get_ports result]
"""
    design = design_factory(verilog=COMBINATIONAL)
    result = audit_factory(sdc, verilog=COMBINATIONAL)
    pack = analyze_proofs(design, result)
    assert _proof(pack, 0)["status"] == ProofStatus.VACUOUS.value
    assert _proof(pack, 1)["status"] == ProofStatus.WITNESSED.value


def test_search_limit_and_witness_truncation(audit_factory, design_factory) -> None:
    sdc = "set_false_path -from [get_ports data] -to [get_ports result]"
    design = design_factory(verilog=COMBINATIONAL)
    result = audit_factory(sdc, verilog=COMBINATIONAL)
    bounded = analyze_proofs(design, result, ProofLimits(max_search_states=1))
    assert _proof(bounded)["status"] == ProofStatus.BOUNDED.value
    truncated = analyze_proofs(design, result, ProofLimits(max_witness_nodes=2))
    assert _proof(truncated)["status"] == ProofStatus.WITNESSED.value
    assert _proof(truncated)["witness_omitted_nodes"] > 0
    assert len(_proof(truncated)["witness"]) == 2
    one_node = analyze_proofs(design, result, ProofLimits(max_witness_nodes=1))
    assert len(_proof(one_node)["witness"]) == 1


def test_incomplete_model_and_unresolvable_scope_do_not_claim_proof(audit_factory, design_factory) -> None:
    design = design_factory(verilog=COMBINATIONAL)
    result = audit_factory(
        "set_false_path -from [get_ports missing] -to [get_ports result]",
        verilog=COMBINATIONAL,
    )
    unresolved = analyze_proofs(design, result)
    assert _proof(unresolved)["status"] == ProofStatus.UNRESOLVED.value

    clean = audit_factory(
        "set_false_path -from [get_ports data] -to [get_ports result]",
        verilog=COMBINATIONAL,
    )
    design.warnings.append("injected incomplete model")
    untrusted = analyze_proofs(design, clean)
    assert _proof(untrusted)["status"] == ProofStatus.UNRESOLVED.value
    modes = untrusted["modes"]
    assert isinstance(modes, list) and modes[0]["trusted_model"] is False


def test_clock_scope_maps_to_clocked_launch_points(audit_factory, design_factory) -> None:
    sdc = r"""
create_clock -name core -period 10 [get_ports clk]
set_false_path -from [get_clocks core] -to [get_ports result]
"""
    design = design_factory()
    result = audit_factory(sdc)
    pack = analyze_proofs(design, result)
    proof = _proof(pack)
    assert proof["status"] == ProofStatus.WITNESSED.value
    witness = proof["witness"]
    assert isinstance(witness, list)
    assert witness[0]["name"] == "u_ff/Q"


def test_selector_kinds_disambiguate_clock_and_port_name_collision(audit_factory, design_factory) -> None:
    sdc = r"""
create_clock -name clk -period 10 [get_ports clk]
set_false_path -from [get_clocks clk] -to [get_ports result]
set_false_path -from [get_ports clk] -to [get_ports result]
set_false_path -from clk -to result
"""
    design = design_factory()
    result = audit_factory(sdc)
    pack = analyze_proofs(design, result)

    clock_proof = _proof(pack, 0)
    assert clock_proof["scope_kinds"]["from"] == "clocks"
    assert clock_proof["status"] == ProofStatus.WITNESSED.value
    assert clock_proof["witness"][0]["name"] == "u_ff/Q"

    port_proof = _proof(pack, 1)
    assert port_proof["scope_kinds"]["from"] == "ports"
    assert port_proof["status"] == ProofStatus.VACUOUS.value

    literal_proof = _proof(pack, 2)
    assert literal_proof["scope_kinds"]["from"] == "literal"
    assert literal_proof["status"] == ProofStatus.UNRESOLVED.value
    assert "collide across object namespaces" in literal_proof["reason"]


def test_repair_plan_suggests_names_and_complete_io_matrix(audit_factory, design_factory) -> None:
    sdc = r"""
create_clock -name core -period 10 [get_ports clk]
set_false_path -from [get_ports datta] -to [get_ports result]
"""
    design = design_factory()
    result = audit_factory(sdc)
    pack = analyze_proofs(design, result)
    plan = build_repair_plan(design, result, pack)
    actions = plan["actions"]
    assert isinstance(actions, list)
    query = next(item for item in actions if item["kind"] == "repair_object_query")
    suggestions = query["source"]["suggestions"]["datta"]
    assert suggestions[0]["candidate"] == "data"
    input_action = next(item for item in actions if item["kind"] == "complete_input_delay_matrix")
    assert len(input_action["sdc_template"]) == 4
    assert "-clock core" in input_action["sdc_template"][0]
    rendered = render_repair_sdc(plan)
    assert "REVIEW REQUIRED" in rendered
    assert "<MIN_RISE>" in rendered
    assert "# PROPOSED: set_input_delay" in rendered
    assert not any(line.startswith(("set_", "create_")) for line in rendered.splitlines())
    safety = plan["safety"]
    assert isinstance(safety, dict)
    placeholder_pattern = safety["placeholder_pattern"]
    assert isinstance(placeholder_pattern, str)
    expected_tokens = sorted(
        {
            match.group(0)
            for action in actions
            for template in action["sdc_template"]
            for match in re.finditer(placeholder_pattern, template)
        }
    )
    assert safety["placeholder_tokens"] == expected_tokens
    assert "<MIN_RISE>" in expected_tokens
    assert "<CLOCK>" not in expected_tokens


def test_repair_plan_publishes_clock_placeholder_without_unique_clock(audit_factory, design_factory) -> None:
    sdc = "set_false_path -from [get_ports data] -to [get_ports result]"
    design = design_factory()
    result = audit_factory(sdc)
    pack = analyze_proofs(design, result)
    plan = build_repair_plan(design, result, pack)
    safety = plan["safety"]
    assert isinstance(safety, dict)
    placeholder_tokens = safety["placeholder_tokens"]
    assert isinstance(placeholder_tokens, list)
    assert "<CLOCK>" in placeholder_tokens


def test_repair_plan_includes_structural_model_failure(audit_factory, design_factory) -> None:
    incomplete_verilog = r"""
module top(input data, output result);
  UNKNOWN_CELL u_missing (.A(data), .Y(result));
endmodule
"""
    design = design_factory(verilog=incomplete_verilog)
    result = audit_factory(
        "set_false_path -from [get_ports data] -to [get_ports result]",
        verilog=incomplete_verilog,
    )
    assert any(diagnostic.rule_id == "OC0002" for diagnostic in result.diagnostics)
    pack = analyze_proofs(design, result)
    plan = build_repair_plan(design, result, pack)
    actions = plan["actions"]
    assert isinstance(actions, list)
    action = next(item for item in actions if item["kind"] == "restore_static_model_completeness")
    assert action["source"]["rule_id"] == "OC0002"


def test_rendered_repair_sdc_comments_every_untrusted_line() -> None:
    plan = {
        "plan_digest": "example",
        "actions": [
            {
                "id": "OCRP-EXAMPLE",
                "confidence": "high",
                "title": "Adversarial multiline proposal",
                "review": "Do not execute without review.",
                "sdc_template": ["set_false_path -from [get_ports data]\nexec touch /tmp/not-allowed"],
            }
        ],
    }
    rendered = render_repair_sdc(plan)
    assert "# PROPOSED: set_false_path -from [get_ports data]" in rendered
    assert "# PROPOSED: exec touch /tmp/not-allowed" in rendered
    assert "\nexec touch /tmp/not-allowed" not in rendered


def test_repair_plan_adds_multicycle_hold_template(audit_factory, design_factory) -> None:
    sdc = r"""
create_clock -name core -period 10 [get_ports clk]
set_multicycle_path 3 -setup -from [get_ports data] -to [get_ports result]
"""
    design = design_factory()
    result = audit_factory(sdc)
    pack = analyze_proofs(design, result)
    plan = build_repair_plan(design, result, pack)
    actions = plan["actions"]
    assert isinstance(actions, list)
    action = next(item for item in actions if item["kind"] == "pair_multicycle_hold")
    assert action["sdc_template"]
    assert "set_multicycle_path 2" in action["sdc_template"][0]
    assert "-hold" in action["sdc_template"][0]
    assert any(item["kind"] == "remove_or_narrow_vacuous_exception" for item in actions)


def test_clock_period_and_unconstrained_endpoint_repairs(audit_factory, design_factory) -> None:
    sdc = "create_clock -name broken [get_ports clk]"
    design = design_factory()
    result = audit_factory(sdc)
    pack = analyze_proofs(design, result)
    plan = build_repair_plan(design, result, pack)
    actions = plan["actions"]
    assert isinstance(actions, list)
    clock = next(item for item in actions if item["kind"] == "repair_clock_period")
    assert "-period <PERIOD>" in clock["sdc_template"][0]
    assert any(item["kind"] == "connect_unconstrained_endpoints" for item in actions)


def test_proof_pack_verification_detects_tampering(audit_factory, design_factory) -> None:
    sdc = "set_false_path -from [get_ports data] -to [get_ports result]"
    design = design_factory(verilog=COMBINATIONAL)
    result = audit_factory(sdc, verilog=COMBINATIONAL)
    pack = analyze_proofs(design, result)
    assert verify_proof_pack(pack, pack)["verified"] is True
    tampered = json.loads(json.dumps(pack))
    tampered["model"]["graph_digest"] = "0" * 64
    verification = verify_proof_pack(tampered, pack)
    assert verification["verified"] is False
    assert verification["graph_digest_matches"] is False
    assert verification["expected_pack_integrity"] is False

    tampered_certificate = json.loads(json.dumps(pack))
    tampered_certificate["modes"][0]["proofs"][0]["witness"] = []
    tampered_certificate["pack_digest"] = pack["pack_digest"]
    verification = verify_proof_pack(tampered_certificate, pack)
    assert verification["verified"] is False
    assert verification["invalid_expected_certificates"]


def test_replay_identity_is_independent_of_checkout_paths(project_files, tmp_path: Path) -> None:
    verilog, liberty, sdc = project_files(
        verilog=COMBINATIONAL,
        sdc="set_false_path -from [get_ports data] -to [get_ports result]",
    )
    relocated = tmp_path / "relocated"
    relocated.mkdir()
    relocated_verilog = relocated / verilog.name
    relocated_liberty = relocated / liberty.name
    relocated_sdc = relocated / sdc.name
    for source, target in (
        (verilog, relocated_verilog),
        (liberty, relocated_liberty),
        (sdc, relocated_sdc),
    ):
        target.write_bytes(source.read_bytes())

    original_output = tmp_path / "original-proof"
    relocated_output = tmp_path / "relocated-proof"
    for output, selected_verilog, selected_liberty, selected_sdc in (
        (original_output, verilog, liberty, sdc),
        (relocated_output, relocated_verilog, relocated_liberty, relocated_sdc),
    ):
        assert (
            main(
                [
                    "analyze",
                    "--verilog",
                    str(selected_verilog),
                    "--liberty",
                    str(selected_liberty),
                    "--sdc",
                    str(selected_sdc),
                    "--top",
                    "top",
                    "--format",
                    "all",
                    "--output",
                    str(output),
                ]
            )
            == 0
        )

    original = json.loads((original_output / "openconstraint-proof.json").read_text(encoding="utf-8"))
    replayed = json.loads((relocated_output / "openconstraint-proof.json").read_text(encoding="utf-8"))
    assert original["pack_digest"] != replayed["pack_digest"]
    assert original["replay_digest"] == replayed["replay_digest"]
    verification = verify_proof_pack(original, replayed)
    assert verification["verified"] is True
    assert verification["pack_digest_matches"] is False
    assert verification["replay_digest_matches"] is True


def test_cli_writes_all_artifacts_and_can_verify(project_files, tmp_path: Path) -> None:
    verilog, liberty, sdc = project_files(
        verilog=COMBINATIONAL,
        sdc="set_false_path -from [get_ports data] -to [get_ports result]",
    )
    output = tmp_path / "proof"
    common = [
        "--verilog",
        str(verilog),
        "--liberty",
        str(liberty),
        "--sdc",
        str(sdc),
        "--top",
        "top",
    ]
    assert main(["analyze", *common, "--format", "all", "--output", str(output)]) == 0
    expected = {
        "openconstraint-proof.json",
        "openconstraint-proof.txt",
        "openconstraint-repair.json",
        "openconstraint-repair.sdc",
    }
    assert {path.name for path in output.iterdir()} == expected
    assert (
        main(
            [
                "verify",
                *common,
                "--proof",
                str(output / "openconstraint-proof.json"),
                "--output",
                str(tmp_path / "verification.json"),
            ]
        )
        == 0
    )
    verification = json.loads((tmp_path / "verification.json").read_text(encoding="utf-8"))
    assert verification["verified"] is True


def test_cli_formats_gates_and_invalid_inputs(project_files, tmp_path: Path, capsys) -> None:
    verilog, liberty, sdc = project_files(
        verilog=COMBINATIONAL,
        sdc="set_false_path -from [get_ports spare] -to [get_ports result]",
    )
    common = [
        "--verilog",
        str(verilog),
        "--liberty",
        str(liberty),
        "--sdc",
        str(sdc),
        "--top",
        "top",
    ]
    json_path = tmp_path / "bundle.json"
    text_path = tmp_path / "proof.txt"
    assert main(["analyze", *common, "--format", "json", "--output", str(json_path)]) == 0
    assert "proof" in json.loads(json_path.read_text(encoding="utf-8"))
    assert main(["analyze", *common, "--format", "text", "--output", str(text_path)]) == 0
    assert "VACUOUS" in text_path.read_text(encoding="utf-8")
    assert main(["analyze", *common, "--fail-on", "vacuous", "--output", str(tmp_path / "gate")]) == 1
    assert (
        main(
            [
                "analyze",
                "--verilog",
                str(verilog),
                "--liberty",
                str(liberty),
                "--mode",
                "broken",
                "--output",
                str(tmp_path / "bad"),
            ]
        )
        == 2
    )
    assert "invalid --mode" in capsys.readouterr().err


def test_cli_refuses_to_overwrite_an_input(project_files, capsys) -> None:
    verilog, liberty, sdc = project_files(
        verilog=COMBINATIONAL,
        sdc="set_false_path -from [get_ports data] -to [get_ports result]",
    )
    assert (
        main(
            [
                "analyze",
                "--verilog",
                str(verilog),
                "--liberty",
                str(liberty),
                "--sdc",
                str(sdc),
                "--top",
                "top",
                "--format",
                "json",
                "--output",
                str(sdc),
            ]
        )
        == 2
    )
    assert "must not overlap input path" in capsys.readouterr().err


def test_proof_and_repair_outputs_validate_against_bundled_schemas(audit_factory, design_factory) -> None:
    sdc = "set_false_path -from [get_ports data] -to [get_ports result]"
    design = design_factory(verilog=COMBINATIONAL)
    result = audit_factory(sdc, verilog=COMBINATIONAL)
    pack = analyze_proofs(design, result)
    plan = build_repair_plan(design, result, pack)
    schema_root = files("openconstraint.schemas")
    proof_schema = json.loads((schema_root / "openconstraint-proof.schema.json").read_text(encoding="utf-8"))
    repair_schema = json.loads((schema_root / "openconstraint-repair.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(proof_schema)
    Draft202012Validator.check_schema(repair_schema)
    Draft202012Validator(proof_schema).validate(pack)
    Draft202012Validator(repair_schema).validate(plan)


def test_cli_exports_bundled_schemas(tmp_path: Path) -> None:
    proof_path = tmp_path / "proof.schema.json"
    repair_path = tmp_path / "repair.schema.json"
    assert main(["schema", "--kind", "proof", "--output", str(proof_path)]) == 0
    assert main(["schema", "--kind", "repair", "--output", str(repair_path)]) == 0
    proof_schema = json.loads(proof_path.read_text(encoding="utf-8"))
    repair_schema = json.loads(repair_path.read_text(encoding="utf-8"))
    assert proof_schema["title"] == "OpenConstraint proof pack"
    assert repair_schema["title"] == "OpenConstraint repair plan"


def test_invalid_proof_limits_are_rejected() -> None:
    with pytest.raises(ValueError):
        ProofLimits(max_search_states=0)
