from __future__ import annotations

import copy
import json
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from openconstraint.expand import (
    ExpansionError,
    ExpansionLimits,
    _digest,
    expand_sdc,
    main,
    quote,
    verify_expansion,
)
from openconstraint.expand_expr import Expression, ExpressionError
from openconstraint.parsers.sdc import parse_sdc_text
from openconstraint.parsers.tcl import decode_tcl_word, parse_tcl, tcl_word_has_substitution

CLOCK = "create_clock -name core -period 10 [get_ports clk]"


def expand(text, **kwargs):
    return expand_sdc({"main": text}, ["main"], **kwargs)


def test_parameterized_sdc_reaches_audit_and_proof(audit_factory, design_factory):
    from openconstraint.proof import analyze_proofs

    script = r"""
set period 10
set input_ports [get_ports {clk2 data spare}]
proc make_clock {name port period} {
 create_clock -name $name -period $period [get_ports $port]
}
make_clock core clk $period
foreach {direction delay} {input 1 output 2} {
 if {$direction eq "input"} {
  set_input_delay $delay -clock core $input_ports
 } else {
  set_output_delay $delay -clock core [all_outputs]
 }
}
set_false_path -from [get_clocks core] -to [get_ports result]
"""
    pack = expand(script)
    audited = audit_factory(pack["sdc"])
    assert audited.modes[0].coverage.score == 100
    assert not [d for d in audited.diagnostics if d.severity == "error"]
    proved = analyze_proofs(design_factory(), audited)
    assert proved["summary"]["witnessed"] == 1
    assert pack["design_queries_executed"] is False
    assert pack["timing_signoff"] is False
    assert pack["metrics"]["iterations"] == 2
    assert [row["index"] for row in pack["commands"]] == list(range(4))


def test_modes_and_explicit_includes_have_replayable_provenance():
    sources = {
        "main": 'source common.sdc\nif {$MODE eq "scan"} {set p 40} else {set p 10}\nclockit $p',
        "common.sdc": "proc clockit {p} {create_clock -period $p [get_ports clk]}",
        "unused": "exec should_not_be_executed",
    }
    a = expand_sdc(sources, ["main"], {"MODE": "scan"})
    b = expand_sdc(sources, ["main"], {"MODE": "functional"})
    assert a["sdc"] != b["sdc"]
    assert a == expand_sdc(dict(reversed(list(sources.items()))), ["main"], {"MODE": "scan"})
    assert any(o["source"] == "common.sdc" for o in a["commands"][0]["origin"])
    assert next(s for s in a["sources"] if s["id"] == "unused")["used"] is False
    assert verify_expansion(a, a["sdc"], a)["verified"]
    sources["common.sdc"] += "\n# reviewed"
    changed = expand_sdc(sources, ["main"], {"MODE": "scan"})
    assert changed["sdc"] == a["sdc"]
    assert not verify_expansion(a, a["sdc"], changed)["verified"]


def test_provenance_and_sdc_tampering_fail_recomputed_verification():
    pack = expand(CLOCK)
    edited = copy.deepcopy(pack)
    edited["commands"][0]["origin"][0]["enclosing_line"] = 999
    edited.pop("digest")
    edited["digest"] = _digest(edited)
    assert not verify_expansion(edited, pack["sdc"], pack)["verified"]
    assert not verify_expansion(pack, pack["sdc"].replace("10", "20"), pack)["verified"]
    edited = copy.deepcopy(pack)
    edited["digest"] = "a" * 64
    assert not verify_expansion(edited, pack["sdc"], pack)["integrity"]


@pytest.mark.parametrize(
    "script",
    [
        "exec touch forbidden",
        "eval {create_clock -period 10 [get_ports clk]}",
        "open /etc/passwd",
        "socket example.org 80",
        "load thing",
        "package require x",
        "source /etc/passwd",
        "set x $env(HOME)",
        "set x $::env",
        "set x ${env(HOME)}",
        "set cmd create_clock; $cmd -period 10 [get_ports clk]",
        "set ps [get_ports *]; foreach p $ps {create_clock -period 10 $p}",
        "set ps [get_ports *]; set n [llength $ps]",
        'set ps [get_ports *]; set n "prefix$ps"',
        "set ps [get_ports *]; set n [list $ps]",
        "set q [get_ports -nonsense x]",
        "set q [get_cells -hsc : x]",
        "if $MODE {create_clock -period 10 [get_ports clk]}",
        "set body {create_clock -period 10 [get_ports clk]}; while {1} $body",
        "proc set {} {return 0}",
        "proc p {x x} {return $x}",
        "set x [create_clock -period 10 [get_ports clk]]",
        "set x [exec malicious]",
        "set x ${unclosed",
        "foreach p [get_ports *] {}",
        "create_clock {*}{-period 10 clk}",
        "break",
        "continue",
        "if {1} {set x 1} garbage garbage",
        "proc bad {} {break}; foreach p {a} {bad}",
        "proc bad {} {continue}; foreach p {a} {bad}",
        "proc p {a} {return $a}; p",
        "proc p {} {return}; p 1",
        "create_clock -period [get_ports data] [get_ports clk]",
        "set unsupported 1; while {[exec malicious]} {}",
    ],
)
def test_unsupported_inputs_fail_whole_expansion(script):
    with pytest.raises(ExpansionError):
        expand(CLOCK + "\n" + script)


@pytest.mark.parametrize(
    "capture,mutation",
    [
        ("set c [get_clocks *]", "create_clock -name extra -period 20 [get_ports clk2]"),
        ("set c [all_clocks]", "create_clock -name extra -period 20 [get_ports clk2]"),
        ("set c [get_ports clk]", "current_design top"),
    ],
)
def test_deferred_query_mutation_is_not_silently_reordered(capture, mutation):
    with pytest.raises(ExpansionError, match="captured before"):
        expand(CLOCK + f"\n{capture}\n{mutation}\nset_false_path -from $c -to [get_ports result]")


def test_same_epoch_clock_query_can_be_reused_and_unused_stale_query_does_not_matter():
    pack = expand(
        CLOCK
        + """
set c [get_clocks core]
set_false_path -from $c -to [get_ports result]
set_false_path -from $c -to [get_ports data]
create_clock -name extra -period 30 [get_ports clk2]
"""
    )
    assert len(pack["commands"]) == 4


@pytest.mark.parametrize(
    "text",
    [
        "",
        "simple",
        "core clock",
        "a[b]",
        "{braces}",
        "dollar$and;semicolon",
        'a"quoted"word',
        "back\\slash",
        "embedded\nnewline",
        "\t\r",
        "#comment",
        "தமிழ்",
    ],
)
def test_generated_scalar_words_round_trip_without_active_substitutions(text):
    encoded = quote(text)
    assert decode_tcl_word(encoded) == text
    assert not tcl_word_has_substitution(encoded)
    commands, issues = parse_tcl("set x " + encoded, "<test>")
    assert not issues and len(commands) == 1 and len(commands[0].words) == 3


@pytest.mark.parametrize(
    "field,script",
    [
        ("max_steps", "while {1} {incr i}"),
        ("max_iterations", "while {1} {}"),
        ("max_commands", "foreach p {a b c} {create_clock -period 10 [get_ports $p]}"),
        ("max_value_chars", "set x abcdefghijklmnopqrstuvwxyz"),
        ("max_variables", "set a 1; set b 2; set c 3"),
        ("max_procedures", "proc a {} {}; proc b {} {}; proc c {} {}"),
        ("max_list_elements", "set x [list a b c]"),
        ("max_output_bytes", CLOCK),
        ("max_source_bytes", CLOCK),
        ("max_work_chars", CLOCK),
        ("max_live_chars", "set a 12345"),
        ("max_depth", "proc recurse {} {recurse}; recurse"),
    ],
)
def test_explicit_resource_bounds(field, script):
    with pytest.raises(ExpansionError):
        expand(script, limits=replace(ExpansionLimits(), **{field: 2}))


@pytest.mark.parametrize("value", [0, -1, True, 1.5, 20_001])
def test_limits_cannot_disable_safety(value):
    with pytest.raises(ValueError):
        ExpansionLimits(max_steps=value)


def test_include_cycle_and_no_output_are_errors():
    with pytest.raises(ExpansionError, match="cyclic"):
        expand_sdc({"a": "source b", "b": "source a"}, ["a"])
    with pytest.raises(ExpansionError, match="no SDC"):
        expand("if {0} {create_clock -period 10 [get_ports clk]}")
    with pytest.raises(ExpansionError):
        expand_sdc({}, [])


def test_procedure_scope_does_not_leak_between_calls():
    pack = expand("""
set p 10
proc clk {name {p 30}} {create_clock -name $name -period $p [get_ports clk]}
clk a 20
clk b
create_clock -name c -period $p [get_ports clk]
""")
    parsed = parse_sdc_text(pack["sdc"]).commands
    assert [c.option("-period") for c in parsed] == ["20", "30", "10"]
    assert expand(CLOCK) == expand(CLOCK)


def test_cli_compile_verify_and_failure_leave_inputs_intact(tmp_path: Path, capsys):
    source = tmp_path / "source.sdc"
    source.write_text(CLOCK)
    destination = tmp_path / "pack"
    args = ["--source", f"main={source}", "--entry", "main"]
    assert main(["compile", *args, "--output", str(destination)]) == 0
    assert main(["verify", *args, "--pack", str(destination)]) == 0
    assert main(["compile", *args, "--output", str(destination)]) == 2
    report = json.loads((destination / "provenance.json").read_text())
    assert report["sdc_sha256"] == sha256((destination / "normalized.sdc").read_bytes()).hexdigest()
    source.write_text(CLOCK.replace("10", "20"))
    assert main(["verify", *args, "--pack", str(destination)]) == 1
    source.write_text(CLOCK + "\nexec malicious")
    rejected = tmp_path / "rejected"
    assert main(["compile", *args, "--output", str(rejected)]) == 2
    assert not rejected.exists()
    assert "exec malicious" in source.read_text()
    assert main(["compile", *args, "--source", f"main={source}", "--output", str(rejected)]) == 2
    assert main(["compile", *args, "--define", "bad", "--output", str(rejected)]) == 2
    assert "openconstraint-expand:" in capsys.readouterr().err


@pytest.mark.parametrize(
    "text",
    [
        "08",
        "1/0",
        "2.5%2",
        "2**999",
        "1<<999",
        "[exec bad]",
        "foo",
        "$env(HOME)",
        "${::name}",
        '"$unknown"',
        "(1",
        "1 +",
        "1 2",
        "1 ? 2",
        "Inf",
        "NaN",
        "9" * 130,
    ],
)
def test_expression_rejections(text):
    with pytest.raises((ExpressionError, ExpansionError, ValueError)):
        Expression(text, lambda n: "").result()


def test_owned_multifile_example_both_modes_audit_at_full_coverage():
    import tempfile

    from openconstraint.engine import ModeInput, audit
    from openconstraint.parsers.liberty import parse_liberty
    from openconstraint.parsers.verilog import elaborate, parse_verilog

    root = Path(__file__).parents[1]
    sources = {
        "main": (root / "examples/expansion/main.sdc").read_text(),
        "clock_helpers.sdc": (root / "examples/expansion/clock_helpers.sdc").read_text(),
    }
    design = elaborate(
        parse_verilog([root / "examples/tiny/design.v"]), parse_liberty(root / "examples/tiny/cells.lib"), "tiny_top"
    )
    for mode, expected in (("functional", 10), ("slow", 20)):
        report = expand_sdc(sources, ["main"], {"MODE": mode})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "normalized.sdc"
            path.write_text(report["sdc"])
            result = audit(design, [ModeInput(mode, [str(path)])])
        assert result.modes[0].coverage.score == 100
        assert result.modes[0].clocks["core_clk"].period == expected
        assert not [d for d in result.diagnostics if d.severity == "error"]
    with pytest.raises(ExpansionError):
        expand_sdc(sources, ["main"], {"MODE": "typo"})


@pytest.mark.parametrize(
    "expression",
    [
        '"1e309" < "2e300"',
        '"nan" == "nan"',
        '"' + "9" * 130 + '" < "10"',
    ],
)
def test_nonfinite_and_bounded_numeric_operands_never_fall_back_to_string_comparison(expression):
    with pytest.raises(ExpressionError):
        Expression(expression, lambda n: "").result()


def test_source_return_is_local_to_source_and_inherits_current_local_frame():
    pack = expand_sdc(
        {
            "main": "proc p {n} {source helper; return $n}; create_clock -period [p 2] [get_ports clk]",
            "helper": "incr n; return; exec forbidden",
        },
        ["main"],
    )
    assert parse_sdc_text(pack["sdc"]).commands[0].option("-period") == "3"


def test_comments_braces_and_literal_injection_stay_data():
    script = """set n {unsafe\nexec not_executed; [open secret] $env(HOME)}
create_clock -name $n -period 10 [get_ports clk]
"""
    pack = expand(script)
    assert len(pack["commands"]) == 1
    assert "\nexec" not in pack["sdc"]
    parsed = parse_sdc_text(pack["sdc"]).commands[0]
    assert parsed.option("-name") == "unsafe\nexec not_executed; [open secret] $env(HOME)"


@pytest.mark.parametrize("text", ["\x00", "\ud800"])
def test_illegal_input_characters_rejected(text):
    with pytest.raises(ExpansionError):
        expand(CLOCK + "\n#" + text)


@pytest.mark.parametrize(
    "script",
    [
        "set x [list a b]; if {$x eq {a b}} {set p 10}",
        "create_clock -name [list a b] -period 10 [get_ports clk]",
        "create_clock -period [list 10] [get_ports clk]",
        "set x [list a b]; append x c",
        "set x [list [list a b]]",
        "set q [get_ports -filter [list name == clk]]",
        "proc p {{args 42}} {return $args}",
    ],
)
def test_ambiguous_generated_list_scalar_coercions_are_rejected(script):
    with pytest.raises(ExpansionError):
        expand(CLOCK + "\n" + script)


def test_generated_lists_can_supply_clock_waveforms_and_port_patterns():
    pack = expand("""
set wave [list 0 5]
set ports [list data spare]
create_clock -name core -period 10 -waveform $wave [get_ports clk]
set_input_delay 1 -clock core [get_ports $ports]
""")
    doc = parse_sdc_text(pack["sdc"])
    assert not doc.issues
    assert doc.commands[1].selectors[0].patterns == ("data", "spare")


def test_exported_schema_validates_provenance_and_rejects_extra_fields(tmp_path, capsys):
    from jsonschema import Draft202012Validator, ValidationError

    assert main(["schema"]) == 0
    schema = json.loads(capsys.readouterr().out)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    pack = expand(CLOCK)
    validator.validate(pack)
    bad = copy.deepcopy(pack)
    bad["commands"][0]["origin"][0]["fabricated"] = True
    with pytest.raises(ValidationError):
        validator.validate(bad)
    out = tmp_path / "schema.json"
    assert main(["schema", "--output", str(out)]) == 0
    assert main(["schema", "--output", str(out)]) == 2
