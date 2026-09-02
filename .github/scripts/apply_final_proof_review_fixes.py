from __future__ import annotations

from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


proof_path = Path("src/openconstraint/proof.py")
proof = proof_path.read_text(encoding="utf-8")

proof = replace_once(
    proof,
    "from openconstraint.model import AuditResult, Design, Diagnostic, ExceptionPath, ModeResult\n",
    "from openconstraint.model import AuditResult, Design, Diagnostic, ExceptionPath, ModeResult\n"
    "from openconstraint.opensta import tcl_quote\n",
    "Tcl quoting import",
)
proof = replace_once(
    proof,
    "from openconstraint.parsers.sdc import ParsedCommand, parse_sdc_text\n",
    "from openconstraint.parsers.sdc import ParsedCommand, parse_sdc_text\n"
    "from openconstraint.parsers.tcl import TclSyntaxError, decode_tcl_word\n",
    "Tcl parser imports",
)
proof = replace_once(
    proof,
    '''_FATAL_MODEL_RULES = frozenset({"OC0001", "OC0002", "OC0003", "OC1003", "OC1004"})
''',
    '''_FATAL_MODEL_RULES = frozenset({"OC0001", "OC0002", "OC0003", "OC1003", "OC1004"})
_MULTICYCLE_VALUE_OPTIONS = (
    "-from",
    "-rise_from",
    "-fall_from",
    "-to",
    "-rise_to",
    "-fall_to",
    "-comment",
)
_MULTICYCLE_REPEATED_VALUE_OPTIONS = ("-through", "-rise_through", "-fall_through")
_MULTICYCLE_FLAG_OPTIONS = ("-setup", "-hold", "-rise", "-fall", "-start", "-end", "-reset_path")
_MULTICYCLE_PHASE_OPTIONS = frozenset({"-setup", "-hold"})
''',
    "multicycle grammar constants",
)
proof = replace_once(
    proof,
    '''    reached_nets = _target_nets(design, clock.targets)
    queue: deque[str] = deque(sorted(reached_nets))
    reached_pins: set[str] = set()
''',
    '''    reached_nets = _target_nets(design, clock.targets)
    queue: deque[str] = deque(sorted(reached_nets))
    reached_pins: set[str] = {target for target in clock.targets if target in design.pins}
''',
    "direct clock pin seeding",
)

old_collection = '''def _sdc_collection(design: Design, names: Sequence[str]) -> str:
    """Render an exact homogeneous SDC collection without changing intent."""

    if not names:
        return "<OBJECT_COLLECTION>"
    if all(name in design.ports for name in names):
        return f"[get_ports {{{' '.join(names)}}}]"
    if all(name in design.pins for name in names):
        return f"[get_pins {{{' '.join(names)}}}]"
    if all(name in design.nets for name in names):
        return f"[get_nets {{{' '.join(names)}}}]"
    if all(name in design.instances for name in names):
        return f"[get_cells {{{' '.join(names)}}}]"
    return "<OBJECT_COLLECTION>"


'''
new_collection = '''def _tcl_word_or_placeholder(value: object, placeholder: str) -> str:
    if not isinstance(value, str):
        return placeholder
    try:
        return tcl_quote(value)
    except ValueError:
        return placeholder


def _sdc_collection(design: Design, names: Sequence[str]) -> str:
    """Render an exact homogeneous SDC collection with substitution-safe Tcl words."""

    if not names:
        return "<OBJECT_COLLECTION>"
    command: str | None = None
    if all(name in design.ports for name in names):
        command = "get_ports"
    elif all(name in design.pins for name in names):
        command = "get_pins"
    elif all(name in design.nets for name in names):
        command = "get_nets"
    elif all(name in design.instances for name in names):
        command = "get_cells"
    if command is None:
        return "<OBJECT_COLLECTION>"
    words = [_tcl_word_or_placeholder(name, "") for name in names]
    if any(not word for word in words):
        return "<OBJECT_COLLECTION>"
    return f"[{command} {' '.join(words)}]"


def _canonical_multicycle_option(spelling: str) -> str | None:
    if spelling in _MULTICYCLE_REPEATED_VALUE_OPTIONS:
        return spelling
    for option in _MULTICYCLE_VALUE_OPTIONS:
        if option.startswith(spelling):
            return option
    for option in _MULTICYCLE_FLAG_OPTIONS:
        if option.startswith(spelling):
            return option
    return None


def _multicycle_pair_templates(exception: ExceptionPath, expected_hold: int) -> list[str]:
    document = parse_sdc_text(exception.raw, "<repair-multicycle>")
    if document.issues or len(document.commands) != 1:
        return []
    command = document.commands[0]
    if command.parse_errors or command.name != "set_multicycle_path" or len(command.positionals) != 1:
        return []
    try:
        setup_multiplier = int(command.positionals[0])
    except ValueError:
        return []

    words = list(command.tcl.words)
    positional_indices: list[int] = []
    phase_indices: set[int] = set()
    index = 1
    while index < len(words):
        try:
            decoded = decode_tcl_word(words[index])
        except TclSyntaxError:
            return []
        option = _canonical_multicycle_option(decoded) if decoded.startswith("-") else None
        if option is None:
            positional_indices.append(index)
            index += 1
            continue
        if option in _MULTICYCLE_PHASE_OPTIONS:
            phase_indices.add(index)
        if option in _MULTICYCLE_VALUE_OPTIONS or option in _MULTICYCLE_REPEATED_VALUE_OPTIONS:
            index += 2
        else:
            index += 1

    if len(positional_indices) != 1:
        return []
    multiplier_index = positional_indices[0]
    try:
        if decode_tcl_word(words[multiplier_index]) != command.positionals[0]:
            return []
    except TclSyntaxError:
        return []

    def render(multiplier: int, phase: str) -> str:
        rendered: list[str] = []
        for word_index, word in enumerate(words):
            if word_index in phase_indices:
                continue
            rendered.append(str(multiplier) if word_index == multiplier_index else word)
        rendered.insert(1, phase)
        return " ".join(rendered)

    return [render(setup_multiplier, "-setup"), render(expected_hold, "-hold")]


'''
proof = replace_once(proof, old_collection, new_collection, "safe collection and multicycle helpers")

proof = replace_once(
    proof,
    '''        clock_reference = "<CLOCK>"
        if mode is not None and len(mode.valid_clocks) == 1:
            clock_reference = next(iter(mode.valid_clocks))
        collection = " ".join(ports)
        templates = [
            f"set_{direction}_delay <MIN_RISE> -min -rise -clock {clock_reference} [get_ports {{{collection}}}]",
            f"set_{direction}_delay <MIN_FALL> -min -fall -clock {clock_reference} [get_ports {{{collection}}}]",
            f"set_{direction}_delay <MAX_RISE> -max -rise -clock {clock_reference} [get_ports {{{collection}}}]",
            f"set_{direction}_delay <MAX_FALL> -max -fall -clock {clock_reference} [get_ports {{{collection}}}]",
        ]
''',
    '''        clock_reference = "<CLOCK>"
        if mode is not None and len(mode.valid_clocks) == 1:
            clock_reference = _tcl_word_or_placeholder(next(iter(mode.valid_clocks)), "<CLOCK>")
        collection = _sdc_collection(design, ports).replace("<OBJECT_COLLECTION>", "<PORT_COLLECTION>")
        templates = [
            f"set_{direction}_delay <MIN_RISE> -min -rise -clock {clock_reference} {collection}",
            f"set_{direction}_delay <MIN_FALL> -min -fall -clock {clock_reference} {collection}",
            f"set_{direction}_delay <MAX_RISE> -max -rise -clock {clock_reference} {collection}",
            f"set_{direction}_delay <MAX_FALL> -max -fall -clock {clock_reference} {collection}",
        ]
''',
    "quoted I/O delay templates",
)
proof = replace_once(
    proof,
    '''        return _action(
            mode=diagnostic.mode,
            kind="repair_clock_period",
            confidence="medium",
            title=f"Provide a positive period for clock {clock_name!r}",
            rationale=diagnostic.rationale,
            source=source,
            review="Obtain the period and waveform from the architecture or interface specification; they cannot be inferred safely from connectivity.",
            sdc_template=[f"create_clock -name {clock_name} -period <PERIOD> {target}"],
        )
''',
    '''        clock_word = _tcl_word_or_placeholder(clock_name, "<CLOCK_NAME>")
        return _action(
            mode=diagnostic.mode,
            kind="repair_clock_period",
            confidence="medium",
            title=f"Provide a positive period for clock {clock_name!r}",
            rationale=diagnostic.rationale,
            source=source,
            review="Obtain the period and waveform from the architecture or interface specification; they cannot be inferred safely from connectivity.",
            sdc_template=[f"create_clock -name {clock_word} -period <PERIOD> {target}"],
        )
''',
    "quoted create_clock name",
)

old_multicycle = '''    if diagnostic.rule_id == "OC4011" and mode is not None:
        expected = diagnostic.evidence.get("expected_hold_multiplier")
        matching = next(
            (
                item
                for item in mode.exceptions
                if item.kind == "multicycle_path" and item.location == diagnostic.location
            ),
            None,
        )
        template: list[str] = []
        if matching is not None and isinstance(expected, int):
            raw = matching.raw.strip()
            candidate = re.sub(
                r"^(\s*set_multicycle_path\s+)\S+",
                rf"\g<1>{expected}",
                raw,
                count=1,
            )
            if "-setup" in candidate and "-hold" in candidate:
                candidate = candidate.replace("-setup", "", 1)
                candidate = re.sub(r"\s+", " ", candidate).strip()
            elif "-setup" in candidate:
                candidate = candidate.replace("-setup", "-hold", 1)
            elif "-hold" not in candidate:
                candidate += " -hold"
            template.append(candidate)
        return _action(
            mode=diagnostic.mode,
            kind="pair_multicycle_hold",
            confidence="medium",
            title="Review and add the usual N/N-1 hold counterpart",
            rationale=diagnostic.rationale,
            source=source,
            review="The N/N-1 pairing is common, not universal. Confirm launch/capture edge intent before adding the generated command.",
            sdc_template=template,
        )
'''
new_multicycle = '''    if diagnostic.rule_id == "OC4011" and mode is not None:
        expected = diagnostic.evidence.get("expected_hold_multiplier")
        matching = next(
            (
                item
                for item in mode.exceptions
                if item.kind == "multicycle_path" and item.location == diagnostic.location
            ),
            None,
        )
        templates = (
            _multicycle_pair_templates(matching, expected)
            if matching is not None and isinstance(expected, int)
            else []
        )
        return _action(
            mode=diagnostic.mode,
            kind="pair_multicycle_hold",
            confidence="medium",
            title="Replace the multicycle command with an explicit setup/hold pair",
            rationale=diagnostic.rationale,
            source=source,
            review="Replace the original command with the reviewed pair rather than appending it. The N/N-1 convention is common, not universal; confirm launch/capture edge intent first.",
            sdc_template=templates,
        )
'''
proof = replace_once(proof, old_multicycle, new_multicycle, "multicycle repair pair")
proof_path.write_text(proof, encoding="utf-8")


tests_path = Path("tests/test_proof.py")
tests = tests_path.read_text(encoding="utf-8")
tests = replace_once(
    tests,
    "from openconstraint.proof import (\n",
    "from openconstraint.engine import ModeInput, audit\n"
    "from openconstraint.model import Instance, Pin, Port\n"
    "from openconstraint.parsers.sdc import parse_sdc_text\n"
    "from openconstraint.proof import (\n",
    "test imports",
)
clock_marker = "def test_selector_kinds_disambiguate_clock_and_port_name_collision"
clock_test = '''def test_clock_scope_seeds_direct_unconnected_pin_targets(tmp_path: Path, design_factory) -> None:
    design = design_factory()
    direct_pins = {
        "CK": Pin("u_direct/CK", "u_direct", "CK", "input", None, is_clock=True),
        "D": Pin("u_direct/D", "u_direct", "D", "input", "data", is_data=True),
        "Q": Pin("u_direct/Q", "u_direct", "Q", "output", "direct_q"),
    }
    design.instances["u_direct"] = Instance("u_direct", "DFF", direct_pins, sequential=True)
    design.pins.update({pin.path: pin for pin in direct_pins.values()})
    design.ports["direct_q"] = Port("direct_q", "output", "direct_q")
    design.nets.add("direct_q")
    design.loads.setdefault("data", set()).add("u_direct/D")
    design.drivers.setdefault("direct_q", set()).add("u_direct/Q")

    sdc_path = tmp_path / "direct-pin.sdc"
    sdc_path.write_text(
        "create_clock -name core -period 10 [get_ports clk]\\n"
        "create_clock -name core -period 10 -add [get_pins u_direct/CK]\\n"
        "set_false_path -from [get_clocks core] -to [get_ports direct_q]\\n",
        encoding="utf-8",
    )
    result = audit(design, [ModeInput("default", [str(sdc_path)])])
    pack = analyze_proofs(design, result)
    proof = _proof(pack)
    assert proof["status"] == ProofStatus.WITNESSED.value
    assert proof["witness"][0]["name"] == "u_direct/Q"


'''
tests = replace_once(tests, clock_marker, clock_test + clock_marker, "direct pin clock test")

tests = replace_once(
    tests,
    '    assert "-clock core" in input_action["sdc_template"][0]\n',
    '    assert \'-clock "core"\' in input_action["sdc_template"][0]\n',
    "quoted simple clock expectation",
)

old_multicycle_test = '''def test_repair_plan_adds_multicycle_hold_template(audit_factory, design_factory) -> None:
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


'''
new_multicycle_test = '''@pytest.mark.parametrize(
    "multicycle_command",
    [
        "set_multicycle_path 3 -setup -from [get_ports data] -to [get_ports result]",
        "set_multicycle_path -setup -from [get_ports data] -to [get_ports result] 3",
        "set_multicycle_path 3 -from [get_ports data] -to [get_ports result]",
    ],
)
def test_repair_plan_replaces_multicycle_with_explicit_pair(
    audit_factory,
    design_factory,
    multicycle_command: str,
) -> None:
    sdc = "create_clock -name core -period 10 [get_ports clk]\\n" + multicycle_command
    design = design_factory()
    result = audit_factory(sdc)
    pack = analyze_proofs(design, result)
    plan = build_repair_plan(design, result, pack)
    actions = plan["actions"]
    assert isinstance(actions, list)
    action = next(item for item in actions if item["kind"] == "pair_multicycle_hold")
    templates = action["sdc_template"]
    assert isinstance(templates, list) and len(templates) == 2
    document = parse_sdc_text("\\n".join(templates), "<repair-test>")
    assert not document.issues
    assert len(document.commands) == 2
    setup, hold = document.commands
    assert not setup.parse_errors and not hold.parse_errors
    assert setup.positionals == ["3"]
    assert setup.has("-setup") and not setup.has("-hold")
    assert hold.positionals == ["2"]
    assert hold.has("-hold") and not hold.has("-setup")
    assert "Replace the original command" in action["review"]
    assert any(item["kind"] == "remove_or_narrow_vacuous_exception" for item in actions)


'''
tests = replace_once(tests, old_multicycle_test, new_multicycle_test, "multicycle repair tests")

clock_period_marker = "def test_clock_period_and_unconstrained_endpoint_repairs"
quoting_test = '''def test_repair_templates_quote_clock_names(audit_factory, design_factory) -> None:
    sdc = r"""
create_clock -name {core clock} -period 10 [get_ports clk]
create_clock -name {broken clock} [get_ports clk2]
"""
    design = design_factory()
    result = audit_factory(sdc)
    pack = analyze_proofs(design, result)
    plan = build_repair_plan(design, result, pack)
    actions = plan["actions"]
    assert isinstance(actions, list)
    input_action = next(item for item in actions if item["kind"] == "complete_input_delay_matrix")
    assert '-clock "core clock"' in input_action["sdc_template"][0]
    clock_action = next(
        item
        for item in actions
        if item["kind"] == "repair_clock_period" and item["source"]["message"].startswith("Clock 'broken clock'")
    )
    assert 'create_clock -name "broken clock" -period <PERIOD>' in clock_action["sdc_template"][0]


'''
tests = replace_once(tests, clock_period_marker, quoting_test + clock_period_marker, "clock quoting test")
tests_path.write_text(tests, encoding="utf-8")


docs_path = Path("docs/proof-carrying-analysis.md")
docs = docs_path.read_text(encoding="utf-8")
docs = replace_once(
    docs,
    '''A clock used in an exception endpoint is expanded to the sequential instances
whose clock pins it reaches. In a `-from` scope those instances contribute
output pins; in a `-to` scope they contribute modeled sequential data pins.
''',
    '''A clock used in an exception endpoint is expanded to the sequential instances
whose clock pins it reaches. Direct pin targets seed reachability even when the
pin is intentionally unconnected; connected targets also propagate through the
modeled clock network. In a `-from` scope those instances contribute output
pins; in a `-to` scope they contribute modeled sequential data pins.
''',
    "clock seed documentation",
)
marker = "The planner never rewrites the user's SDC. Every action has\n`automatic: false` and includes source evidence, a rationale, confidence, a\nreview instruction, and optional SDC templates."
replacement = (
    marker
    + " Generated selectors and concrete clock names are rendered as substitution-safe Tcl words. Multicycle pairing proposals are explicit replacement pairs—one setup command and one hold command—rather than an extra command to append beside an implicit setup-and-hold constraint."
)
docs = replace_once(docs, marker, replacement, "repair quoting documentation")
docs_path.write_text(docs, encoding="utf-8")
