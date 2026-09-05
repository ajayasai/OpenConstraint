"""Regression tests that reparse and re-audit review-only repair proposals."""

from __future__ import annotations

import pytest

from openconstraint.engine import _propagate_clock
from openconstraint.model import Instance, Pin, Port
from openconstraint.parsers.sdc import parse_sdc_text
from openconstraint.proof import _sdc_collection, analyze_proofs, build_repair_plan, render_repair_sdc
from openconstraint.query import resolve_selector


def test_io_matrix_roundtrip_uses_one_collection_argument(audit_factory, design_factory):
    sdc = "create_clock -name {core clock} -period 10 [get_ports clk]"
    design = design_factory()
    result = audit_factory(sdc)
    plan = build_repair_plan(design, result, analyze_proofs(design, result))
    commands = []
    for action in plan["actions"]:
        if action["kind"] in {"complete_input_delay_matrix", "complete_output_delay_matrix"}:
            for template in action["sdc_template"]:
                for token in ("<MIN_RISE>", "<MIN_FALL>", "<MAX_RISE>", "<MAX_FALL>"):
                    template = template.replace(token, "1")
                commands.append(template)
    repaired = audit_factory(sdc + "\n" + "\n".join(commands))
    assert not any(
        d.rule_id in {"OC0001", "OC0003", "OC1001", "OC1004", "OC3001", "OC3002", "OC3010", "OC3011", "OC3013"}
        for d in repaired.diagnostics
    )


@pytest.mark.parametrize("name", ["with space", "data[0]", "literal$var", "a;b", "unicode_λ"])
def test_collection_quotes_and_resolves_exact_names(design_factory, name):
    design = design_factory()
    design.ports[name] = Port(name, "input", name)
    design.nets.add(name)
    raw = _sdc_collection(design, ["data", name])
    parsed = parse_sdc_text("set_false_path -from " + raw).commands[0]
    assert not parsed.parse_errors
    query = resolve_selector(parsed.selectors[0], design, {})
    assert query.error is None
    assert query.matches == {"data", name}
    assert query.match_count == 2


@pytest.mark.parametrize("name", ["*", "dat?", "-quiet", 'a"b', "a\\b", "a{b}", "a\nb"])
def test_unrepresentable_exact_collection_is_an_explicit_placeholder(design_factory, name):
    design = design_factory()
    design.ports[name] = Port(name, "input", name)
    assert _sdc_collection(design, [name]) == "<OBJECT_COLLECTION>"


@pytest.mark.parametrize("field", ["id", "confidence", "title", "review", "sdc_template", "plan_digest"])
def test_every_untrusted_metadata_line_is_inert(field):
    action = dict(id="id", confidence="high", title="title", review="review", sdc_template=["set x 1"])
    plan = dict(plan_digest="hash", actions=[action])
    payload = "first\nset ::escaped 1\rset ::escaped 2\r\nset ::escaped 3"
    if field == "plan_digest":
        plan[field] = payload
    elif field == "sdc_template":
        action[field] = [payload]
    else:
        action[field] = payload
    rendered = render_repair_sdc(plan)
    assert all(not line or line.startswith("#") for line in rendered.splitlines())
    # The project's non-executing Tcl lexer sees zero executable commands.
    parsed = parse_sdc_text(rendered)
    assert not parsed.issues and not parsed.commands


@pytest.mark.parametrize("connected", [True, False])
def test_direct_combinational_clock_pin_propagates_to_sequential_sink(design_factory, connected):
    design = design_factory()
    pins = {
        "A": Pin("u_clk/A", "u_clk", "A", "input", "clk2" if connected else None),
        "Y": Pin("u_clk/Y", "u_clk", "Y", "output", "clk"),
    }
    design.instances["u_clk"] = Instance("u_clk", "BUF", pins)
    design.pins.update({p.path: p for p in pins.values()})
    design.combinational_arcs["u_clk/A"] = {"u_clk/Y"}
    if connected:
        design.loads.setdefault("clk2", set()).add("u_clk/A")
    nets, reached = _propagate_clock(design, {"u_clk/A"})
    assert "clk" in nets
    assert {"u_clk/A", "u_clk/Y", "u_ff/CK"} <= reached


@pytest.mark.parametrize("phase", ["", "-setup", "-setup -hold", "-s"])
@pytest.mark.parametrize("operand", ["3", "{3}", "0x3"])
def test_multicycle_pair_reaudit_and_option_values_remain_unchanged(audit_factory, design_factory, phase, operand):
    sdc = "create_clock -name core -period 10 [get_ports clk]\n"
    command = f"set_multicycle_path {phase} -from [get_ports data] -comment {{do not change -setup}} -to [get_ports result] {operand}"
    result = audit_factory(sdc + command)
    design = design_factory()
    plan = build_repair_plan(design, result, analyze_proofs(design, result))
    action = next(a for a in plan["actions"] if a["kind"] == "pair_multicycle_hold")
    assert len(action["sdc_template"]) == 2
    for raw in action["sdc_template"]:
        parsed = parse_sdc_text(raw).commands[0]
        assert parsed.option("-comment") == "do not change -setup"
    repaired = audit_factory(sdc + "\n".join(action["sdc_template"]))
    assert not any(d.rule_id in {"OC0001", "OC4010", "OC4011", "OC4012", "OC4001"} for d in repaired.diagnostics)


def test_clock_reachability_cache_is_per_mode_and_per_analysis(audit_factory, design_factory, monkeypatch):
    import openconstraint.proof as p

    header = "create_clock -name core -period 10 [get_ports clk]\n"
    exceptions = "\n".join(
        f"set_false_path -comment {{example {i}}} -from [get_clocks core] -to [get_ports result]" for i in range(40)
    )
    result = audit_factory([("first", header + exceptions), ("second", header + exceptions)])
    design = design_factory()
    original = p._propagate_clock
    calls = []

    def counted(design, targets):
        calls.append(frozenset(targets))
        return original(design, targets)

    monkeypatch.setattr(p, "_propagate_clock", counted)
    first = p.analyze_proofs(design, result)
    assert len(calls) == 2  # Forty queries in each mode, one propagation per mode.
    assert first["summary"]["witnessed"] == 80
    assert p.analyze_proofs(design, result) == first
    assert len(calls) == 4  # No stale reuse between runs.


def test_untrusted_mode_without_exceptions_fails_inconclusive_gate(audit_factory, design_factory):
    from openconstraint.proof import _gate

    result = audit_factory("set ignored_dynamic 1")
    pack = analyze_proofs(design_factory(), result)
    assert not any(pack["summary"].values())
    assert pack["modes"][0]["trusted_model"] is False
    assert _gate(pack, "never") == 0
    for gate in ("unresolved", "inconclusive", "any"):
        assert _gate(pack, gate) == 1
    with pytest.raises(ValueError):
        _gate(pack, "typo")


@pytest.mark.parametrize("status", ["bounded", "unresolved", "vacuous", "witnessed"])
def test_compound_proof_gates(status):
    from openconstraint.proof import _gate

    pack = {"modes": [{"trusted_model": True}], "summary": {status: 1}}
    assert _gate(pack, "inconclusive") == int(status in {"bounded", "unresolved"})
    assert _gate(pack, "any") == int(status != "witnessed")
    assert _gate(pack, "never") == 0
