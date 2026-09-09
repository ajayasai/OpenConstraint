"""Differential tests execute only repository-owned fixtures in native Tcl."""

from __future__ import annotations

import random
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from openconstraint.expand import expand_sdc
from openconstraint.expand_expr import Expression
from openconstraint.parsers.sdc import MODELED_SDC_COMMANDS, QUERY_KINDS

TCLSH = shutil.which("tclsh")
pytestmark = pytest.mark.skipif(TCLSH is None, reason="separate native Tcl differential oracle not installed")


def native_tcl(harness: str) -> str:
    """Run only owned fixtures from a real script, not Tcl's interactive stdin.

    Some system Tcl launchers cannot consume a subprocess stdin pipe. A file
    also makes script errors non-interactive. Require a completion marker so
    a launcher that exits zero without evaluating the script cannot be an oracle.
    """
    assert TCLSH is not None
    completion = "__OPENCONSTRAINT_NATIVE_TCL_COMPLETED__\n"
    with tempfile.TemporaryDirectory(prefix="oc-tcl-oracle-") as directory:
        path = Path(directory) / "reference.tcl"
        path.write_text(harness + "\nputs {" + completion.rstrip("\n") + "}\n", encoding="utf-8")
        proc = subprocess.run(
            [TCLSH, str(path)],
            stdin=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            capture_output=True,
            timeout=5,
            check=True,
        )
    assert proc.stdout.endswith(completion), f"native Tcl did not complete: {proc.stderr}"
    return proc.stdout[: -len(completion)]


def native_capture(script: str) -> list[list[str]]:
    harness = """
set captured {}
proc emit {name args} {lappend ::captured [list $name {*}$args]; return {}}
proc query {name args} {return [list QUERY [list $name {*}$args]]}
"""
    for name in sorted(MODELED_SDC_COMMANDS):
        harness += f"interp alias {{}} {name} {{}} emit {name}\n"
    for name in sorted(set(QUERY_KINDS) | {"get_clock", "get_pin", "get_port", "get_cell", "get_net"}):
        harness += f"interp alias {{}} {name} {{}} query {name}\n"
    harness += f"""
set code [encoding convertfrom utf-8 [binary format H* {script.encode().hex()}]]
set status [catch {{eval $code}} message]
if {{$status != 0 && $status != 2}} {{puts stderr $message; exit 2}}
foreach row $captured {{
 set fields {{}}
 foreach word $row {{
  binary scan [encoding convertto utf-8 $word] H* encoded
  lappend fields $encoded
 }}
 puts [join $fields |]
}}
"""
    stdout = native_tcl(harness)
    return [[bytes.fromhex(w).decode() for w in row.split("|")] for row in stdout.splitlines()]


PROGRAMS = [
    "set p 10; create_clock -period $p [get_ports clk]",
    "set p 10; create_clock -period [expr {$p/2.0}] [get_ports clk]",
    "set names [list {clk A} {clk B}]; foreach n $names {create_clock -name $n -period 10 [get_ports clk]}",
    "set p 1; for {set i 0} {$i < 4} {incr i} {create_clock -name clk$i -period [expr {10+$i}] [get_ports clk]}",
    "set i 0; while {$i < 3} {incr i; create_clock -name clk$i -period 10 [get_ports clk]}",
    'foreach p {a b c d} {if {$p eq "b"} {continue}; if {$p eq "d"} {break}; create_clock -name $p -period 10 [get_ports clk]}',
    "proc p {n {v 10}} {create_clock -name $n -period $v [get_ports clk]}; p a; p b 20",
    "proc p {v} {return [expr {$v*2}]}; create_clock -period [p 10] [get_ports clk]",
    "proc p {args} {return [llength $args]}; create_clock -period [p a b c] [get_ports clk]",
    "set p [concat {a b} [list c]]; foreach n $p {create_clock -name $n -period 10 [get_ports clk]}",
    "set p [list a b c]; create_clock -name [lindex $p end-1] -period 10 [get_ports clk]",
    "lappend p a b; lappend p c; foreach n $p {create_clock -name $n -period 10 [get_ports clk]}",
    "set n core; append n {_clock}; create_clock -name $n -period 10 [get_ports clk]",
    "set p 10; unset p; incr p; create_clock -period $p [get_ports clk]",
    "foreach {n p} {a 10 b 20} other {x y z} {create_clock -name $other -period 10 [get_ports clk]}",
    "if {0} {set p 1} elseif {1} then {set p 2} else {set p 3}; create_clock -period $p [get_ports clk]",
    "if {0} {set p 1} {set p 2}; create_clock -period $p [get_ports clk]",
    "set p {literal$not_a_var}; create_clock -name $p -period 10 [get_ports clk]",
    r"set p literal\$name; create_clock -name $p -period 10 [get_ports clk]",
    r'set n core; create_clock -name "${n}\[0\]" -period 10 [get_ports clk]',
    "set q [get_ports {data spare}]; set_false_path -from $q -to [get_ports result]",
    "create_clock -name core -period 10 [get_ports clk]; set q [get_clocks core]; set_false_path -from $q -to [get_ports result]",
    "set q [get_pins -of_objects [get_cells foo] *]; set_false_path -through $q",
    "proc p {} {set n 4; return $n; exec never}; create_clock -period [p] [get_ports clk]",
    "set p 10; create_clock -period $p [get_ports clk]; return; exec never",
    "for {set i 0} {$i<5} {incr i} {if {$i==2} {continue}; if {$i==4} {break}; create_clock -name c$i -period 10 [get_ports clk]}",
]


@pytest.mark.parametrize("script", PROGRAMS)
def test_native_tcl_emits_identical_sdc_command_argument_vectors(script):
    result = expand_sdc({"main": script}, ["main"])
    assert native_capture(script) == native_capture(result["sdc"])


EXPRESSIONS = [
    "1+2*3",
    "(1+2)*3",
    "-3/2",
    "3/-2",
    "-3%2",
    "3%-2",
    "1.0/4",
    "010+1",
    "0x10+0b10",
    "01 eq 1",
    "0x10 eq 16",
    '"10" == 10',
    "true",
    "TRUE",
    "false",
    "true eq 1",
    "1 == true",
    "0 && $missing",
    "1 || $missing",
    "1 ? 2 : 1/0",
    "0 ? 1/0 : 3",
    "1<2 && 4>=4",
    "!(2==2)",
    "0 ? 1 : 1 ? 2 : 3",
    "1e-7",
    "1e20",
    "0.00001",
    "1e-5 + 1e-5",
    '"abc" < "abd"',
    '{001} eq "1"',
]


@pytest.mark.parametrize("expression", EXPRESSIONS)
def test_native_expression_results(expression):
    # Each expression is a static repository-owned test case; never run user input.
    harness = f"puts [expr {{{expression}}}]\n"
    stdout = native_tcl(harness)
    actual = Expression(expression, lambda name: (_ for _ in ()).throw(ValueError(name))).result()
    assert actual == stdout.rstrip("\n")


@pytest.mark.parametrize("seed", range(30))
def test_seeded_parameterized_programs_match_tcl(seed):
    rng = random.Random(seed)
    count, period, divisor = rng.randint(1, 12), rng.randint(2, 100), rng.randint(1, 5)
    script = f"""
set period {period}
proc delay {{n d}} {{return [expr {{$n / $d}}]}}
for {{set i 0}} {{$i < {count}}} {{incr i}} {{
 if {{($i % 2) == 0}} {{set suffix even}} else {{set suffix odd}}
 create_clock -name c${{i}}_$suffix -period [expr {{$period + $i}}] [get_ports clk]
 set_output_delay [delay $period {divisor}] -clock c${{i}}_$suffix [get_ports result]
}}
"""
    result = expand_sdc({"main": script}, ["main"])
    assert native_capture(script) == native_capture(result["sdc"])


@pytest.mark.parametrize(
    "script",
    [
        "set x {{a}  {b}}; lappend x; create_clock -name $x -period 10 [get_ports clk]",
        "set n {core\\\n  clock}; create_clock -name $n -period 10 [get_ports clk]",
        'set i 2; create_clock -name "clk[expr {$i+1}]" -period 10 [get_ports clk]',
        "set p 0x10; incr p -1; create_clock -period $p [get_ports clk]",
        "set n [lindex {a b} -1]; create_clock -name x$n -period 10 [get_ports clk]",
        "set n [lindex {a b} end-8]; create_clock -name x$n -period 10 [get_ports clk]",
    ],
)
def test_additional_native_word_and_list_edge_cases(script):
    result = expand_sdc({"main": script}, ["main"])
    assert native_capture(script) == native_capture(result["sdc"])
