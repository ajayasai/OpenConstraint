from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from openconstraint.parsers.liberty import parse_liberty_text
from openconstraint.parsers.sdc import parse_sdc_text
from openconstraint.parsers.tcl import parse_tcl, split_words
from openconstraint.parsers.verilog import parse_verilog_text

IDENTIFIER_START = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_"
IDENTIFIER_REST = IDENTIFIER_START + "0123456789$"


@st.composite
def identifiers(draw: st.DrawFn, *, max_size: int = 20) -> str:
    first = draw(st.sampled_from(IDENTIFIER_START))
    rest = draw(st.text(alphabet=IDENTIFIER_REST, max_size=max_size - 1))
    return first + rest


@settings(max_examples=150, deadline=None)
@given(text=st.text(max_size=4096))
def test_tcl_and_sdc_parsers_are_total_and_consistent_for_arbitrary_text(text: str) -> None:
    commands, issues = parse_tcl(text, "fuzz.sdc")
    document = parse_sdc_text(text, "fuzz.sdc")

    assert [command.tcl for command in document.commands] == commands
    assert document.issues == issues
    assert all(command.raw and command.words for command in commands)
    assert all(command.words == split_words(command.raw) for command in commands)
    final_line = text.count("\n") + 1
    assert all(1 <= command.location.line <= final_line for command in commands)
    assert all(1 <= issue.location.line <= final_line for issue in issues)


@settings(max_examples=100, deadline=None)
@given(patterns=st.lists(identifiers(), min_size=1, max_size=8, unique=True))
def test_sdc_selector_patterns_survive_braced_tcl_grouping(patterns: list[str]) -> None:
    grouped_patterns = " ".join(patterns)
    document = parse_sdc_text(
        "set_false_path "
        f"-from [get_clocks {{{grouped_patterns}}}] "
        f"-to [get_pins -hierarchical {{{grouped_patterns}}}]\n"
    )

    assert not document.issues
    assert len(document.commands) == 1
    selectors = document.commands[0].selectors
    assert [(selector.kind, selector.patterns, selector.hierarchical) for selector in selectors] == [
        ("clocks", tuple(patterns), False),
        ("pins", tuple(patterns), True),
    ]


@settings(max_examples=150, deadline=None)
@given(text=st.text(max_size=4096))
def test_verilog_parser_is_total_and_deterministic_for_arbitrary_text(text: str) -> None:
    first = parse_verilog_text(text)
    second = parse_verilog_text(text)

    assert first == second
    assert all(name == module.name for name, module in first.modules.items())


@settings(max_examples=100, deadline=None)
@given(
    module_name=identifiers(),
    ports=st.lists(
        st.tuples(st.sampled_from(("input", "output", "inout")), identifiers()),
        max_size=12,
        unique_by=lambda item: item[1],
    ),
)
def test_verilog_ansi_ports_preserve_generated_names_and_directions(
    module_name: str, ports: list[tuple[str, str]]
) -> None:
    declarations = ", ".join(f"{direction} {name}" for direction, name in ports)
    parsed = parse_verilog_text(f"module {module_name}({declarations}); endmodule\n")

    assert not parsed.warnings
    assert list(parsed.modules) == [module_name]
    assert [(port.name, port.direction) for port in parsed.modules[module_name].ports] == [
        (name, direction) for direction, name in ports
    ]


@settings(max_examples=150, deadline=None)
@given(text=st.text(max_size=4096))
def test_liberty_parser_is_total_and_deterministic_for_arbitrary_text(text: str) -> None:
    first = parse_liberty_text(text)
    second = parse_liberty_text(text)

    assert first == second
    assert all(name == cell.name for name, cell in first.cells.items())


@settings(max_examples=100, deadline=None)
@given(cell_name=identifiers(), pin_names=st.lists(identifiers(), min_size=3, max_size=3, unique=True))
def test_liberty_sequential_metadata_survives_generated_cell_syntax(cell_name: str, pin_names: list[str]) -> None:
    data_pin, clock_pin, output_pin = pin_names
    library = parse_liberty_text(
        f"""
library (generated) {{
  cell ({cell_name}) {{
    pin ({data_pin}) {{ direction : input; }}
    pin ({clock_pin}) {{ direction : input; clock : true; }}
    pin ({output_pin}) {{ direction : output; }}
    ff (IQ, IQN) {{ next_state : {data_pin}; clocked_on : {clock_pin}; }}
  }}
}}
"""
    )

    assert not library.warnings
    cell = library.cells[cell_name]
    assert cell.sequential
    assert cell.pin_directions == {data_pin: "input", clock_pin: "input", output_pin: "output"}
    assert cell.data_pins == {data_pin}
    assert cell.clock_pins == {clock_pin}
