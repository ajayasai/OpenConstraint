"""Static structural-Verilog reader and lightweight hierarchical elaborator."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from openconstraint.model import Design, Instance, Pin, Port
from openconstraint.parsers._text import strip_c_style_comments
from openconstraint.parsers.liberty import CellLibrary, CellSpec

IDENT = r"(?:\\\S+|[A-Za-z_$][A-Za-z0-9_$]*)"
MAX_EXPANDED_BUS_WIDTH = 1 << 16
MAX_BUS_INDEX_DIGITS = 64
MAX_EXPANDED_NAMES_PER_DECLARATION = 1 << 16
MAX_EXPANDED_NAMES_PER_PARSE = 1 << 17
MAX_INSTANCE_CONNECTIONS = 1 << 16
MAX_VERILOG_STATEMENTS_PER_PARSE = 200_000
MAX_VERILOG_MODULES = 10_000
MAX_VERILOG_WARNINGS = 1_000
MAX_HIERARCHY_DEPTH = 256
MAX_ELABORATION_OBJECTS = 1 << 18
VERILOG_TRUNCATION_WARNING = "Verilog retention limit reached; additional warnings were omitted"

_MODULE_RE = re.compile(r"\bmodule\b")
_ENDMODULE_RE = re.compile(r"\bendmodule\b")
_MODULE_NAME_RE = re.compile(rf"\s*({IDENT})")
_BUS_RANGE_RE = re.compile(r"\[\s*(-?\d+)\s*:\s*(-?\d+)\s*\]")
_EXPANDED_BUS_BIT_RE = re.compile(r"(.+)\[(-?\d+)\]")


@dataclass(slots=True)
class ModulePort:
    name: str
    direction: str = "unknown"


@dataclass(slots=True)
class ModuleInstance:
    cell_type: str
    name: str
    named_connections: dict[str, str] = field(default_factory=dict)
    positional_connections: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ModuleDef:
    name: str
    ports: list[ModulePort]
    nets: set[str]
    instances: list[ModuleInstance]
    aliases: list[tuple[str, str]] = field(default_factory=list)


@dataclass(slots=True)
class VerilogDesign:
    modules: dict[str, ModuleDef]
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class _ExpansionBudget:
    remaining: int
    exhausted: bool = False


class _WarningBuffer(list[str]):
    omitted = False

    def append(self, warning: str) -> None:
        if len(self) < MAX_VERILOG_WARNINGS:
            super().append(warning)
        else:
            self.omitted = True

    def finalized(self) -> list[str]:
        return [*self, VERILOG_TRUNCATION_WARNING] if self.omitted else list(self)


def _split_top_level(text: str, separator: str = ",", *, max_items: int | None = None) -> list[str]:
    items: list[str] = []
    buffer: list[str] = []
    depths = {"(": 0, "[": 0, "{": 0}
    pairs = {")": "(", "]": "[", "}": "{"}
    quote = False
    escaped = False
    for char in text:
        if escaped:
            buffer.append(char)
            escaped = False
            continue
        if char == "\\" and quote:
            buffer.append(char)
            escaped = True
            continue
        if char == '"':
            quote = not quote
        elif not quote:
            if char in depths:
                depths[char] += 1
            elif char in pairs:
                opener = pairs[char]
                depths[opener] = max(0, depths[opener] - 1)
            elif char == separator and not any(depths.values()):
                item = "".join(buffer).strip()
                if item:
                    items.append(item)
                    if max_items is not None and len(items) >= max_items:
                        return items
                buffer = []
                continue
        buffer.append(char)
    if buffer or text.strip():
        items.append("".join(buffer).strip())
    return [item for item in items if item]


def _split_statements(text: str, max_items: int) -> list[str]:
    return _split_top_level(text, ";", max_items=max_items)


def _expand_names(
    fragment: str,
    warnings: list[str] | None = None,
    budget: _ExpansionBudget | None = None,
) -> list[str]:
    fragment = re.sub(r"\b(?:wire|reg|logic|tri|signed|unsigned|supply0|supply1)\b", " ", fragment)
    range_match = _BUS_RANGE_RE.search(fragment)
    bit_range: range | None = None
    if range_match:
        raw_left, raw_right = range_match.group(1), range_match.group(2)
        if max(len(raw_left.lstrip("-")), len(raw_right.lstrip("-"))) > MAX_BUS_INDEX_DIGITS:
            if warnings is not None:
                warnings.append(
                    "ignored bus range with an index wider than "
                    f"{MAX_BUS_INDEX_DIGITS} decimal digits; the parser cannot expand it safely"
                )
            return []
        left, right = int(raw_left), int(raw_right)
        width = abs(left - right) + 1
        if width > MAX_EXPANDED_BUS_WIDTH:
            if warnings is not None:
                warnings.append(
                    f"ignored bus range [{left}:{right}] with {width} bits; "
                    f"the parser limit is {MAX_EXPANDED_BUS_WIDTH}"
                )
            return []
        step = 1 if right >= left else -1
        bit_range = range(left, right + step, step)
        fragment = fragment[: range_match.start()] + fragment[range_match.end() :]
    base_names: list[str] = []
    pieces = _split_top_level(fragment, max_items=MAX_EXPANDED_NAMES_PER_DECLARATION + 1)
    if len(pieces) > MAX_EXPANDED_NAMES_PER_DECLARATION:
        if warnings is not None:
            warnings.append(
                f"ignored declaration with more than {MAX_EXPANDED_NAMES_PER_DECLARATION} comma-separated names"
            )
        return []
    for piece in pieces:
        value = piece.split("=", 1)[0].strip()
        match = re.search(rf"({IDENT})\s*$", value)
        if not match:
            continue
        base = match.group(1).rstrip()
        if base.startswith("\\"):
            base = base[1:].rstrip()
        base_names.append(base)
    width = len(bit_range) if bit_range is not None else 1
    expanded_count = len(base_names) * width
    if expanded_count > MAX_EXPANDED_NAMES_PER_DECLARATION:
        if warnings is not None:
            warnings.append(
                f"ignored declaration that expands to {expanded_count} names; "
                f"the per-declaration limit is {MAX_EXPANDED_NAMES_PER_DECLARATION}"
            )
        return []
    if budget is not None:
        if budget.exhausted:
            return []
        if expanded_count > budget.remaining:
            budget.remaining = 0
            budget.exhausted = True
            if warnings is not None:
                warnings.append(
                    "ignored remaining declarations after reaching the parser-wide "
                    f"name expansion limit of {MAX_EXPANDED_NAMES_PER_PARSE}"
                )
            return []
        budget.remaining -= expanded_count
    if bit_range is None:
        return base_names
    return [f"{base}[{bit}]" for base in base_names for bit in bit_range]


def _declared_base_names(fragment: str) -> list[str]:
    """Return declaration identifiers without expanding a packed range.

    This intentionally has the same finite item bound as ``_expand_names``.  It
    is used only to retire non-ANSI scalar header placeholders when a bus could
    not be expanded because one of the parser's retention limits was reached.
    """

    fragment = re.sub(r"\b(?:wire|reg|logic|tri|signed|unsigned|supply0|supply1)\b", " ", fragment)
    fragment = _BUS_RANGE_RE.sub(" ", fragment, count=1)
    pieces = _split_top_level(fragment, max_items=MAX_EXPANDED_NAMES_PER_DECLARATION + 1)
    if len(pieces) > MAX_EXPANDED_NAMES_PER_DECLARATION:
        return []
    names: list[str] = []
    for piece in pieces:
        value = piece.split("=", 1)[0].strip()
        match = re.search(rf"({IDENT})\s*$", value)
        if not match:
            continue
        name = match.group(1).rstrip()
        names.append(name[1:].rstrip() if name.startswith("\\") else name)
    return names


def _expanded_bus_base(name: str) -> str | None:
    match = _EXPANDED_BUS_BIT_RE.fullmatch(name)
    return match.group(1) if match else None


def _ordered_port_groups(ports: list[ModulePort]) -> list[list[ModulePort]]:
    """Group expanded bus bits into their single positional interface slot."""

    groups: list[list[ModulePort]] = []
    previous_base: str | None = None
    for port in ports:
        base = _expanded_bus_base(port.name)
        if base is not None and base == previous_base:
            groups[-1].append(port)
        else:
            groups.append([port])
        previous_base = base
    return groups


def _merge_body_port_declaration(
    ports: list[ModulePort],
    port_map: dict[str, ModulePort],
    nets: set[str],
    kind: str,
    fragment: str,
    warnings: list[str],
    budget: _ExpansionBudget,
) -> None:
    """Merge a body declaration into ANSI or non-ANSI header ports.

    Non-ANSI headers name a packed port once (``module m(data);``), while the
    body supplies its range.  Replace that unknown-direction placeholder with
    the expanded bits in place instead of retaining a ghost scalar alongside
    the real bus.
    """

    expanded_names = _expand_names(fragment, warnings, budget)
    replacements: dict[str, list[str]] = {}
    for name in expanded_names:
        base = _expanded_bus_base(name)
        if base is not None:
            replacements.setdefault(base, []).append(name)

    replacement_bases = {
        base
        for base in replacements
        if (placeholder := port_map.get(base)) is not None and placeholder.direction == "unknown"
    }
    # If a valid packed declaration exceeded a retention limit, omit its
    # placeholder too.  Keeping a scalar with unknown direction would invent a
    # port that is not present in the source and produce misleading rule hits.
    if not expanded_names and _BUS_RANGE_RE.search(fragment):
        replacement_bases.update(
            base
            for base in _declared_base_names(fragment)
            if (placeholder := port_map.get(base)) is not None and placeholder.direction == "unknown"
        )

    if replacement_bases:
        merged_ports: list[ModulePort] = []
        for port in ports:
            if port.name not in replacement_bases or port.direction != "unknown":
                merged_ports.append(port)
                continue
            port_map.pop(port.name, None)
            nets.discard(port.name)
            for name in replacements.get(port.name, []):
                replacement = port_map.get(name)
                if replacement is None:
                    replacement = ModulePort(name, kind)
                    port_map[name] = replacement
                    merged_ports.append(replacement)
                else:
                    replacement.direction = kind
        ports[:] = merged_ports

    for net_name in expanded_names:
        nets.add(net_name)
        if net_name in port_map:
            port_map[net_name].direction = kind
        else:
            port = ModulePort(net_name, kind)
            ports.append(port)
            port_map[net_name] = port


def _parse_ports(header: str, warnings: list[str], budget: _ExpansionBudget) -> list[ModulePort]:
    ports: list[ModulePort] = []
    current_direction = "unknown"
    fragments: list[str] = []

    def flush() -> None:
        nonlocal fragments
        for name in _expand_names(", ".join(fragments), warnings, budget):
            ports.append(ModulePort(name, current_direction))
        fragments = []

    entries = _split_top_level(header, max_items=MAX_EXPANDED_NAMES_PER_DECLARATION + 1)
    if len(entries) > MAX_EXPANDED_NAMES_PER_DECLARATION:
        entries.pop()
        warnings.append(
            "ignored remaining port declarations after reaching the parser limit of "
            f"{MAX_EXPANDED_NAMES_PER_DECLARATION} comma-separated entries"
        )
    for entry in entries:
        match = re.match(r"\s*(input|output|inout)\b(.*)$", entry, re.DOTALL)
        if match:
            flush()
            current_direction = match.group(1)
            fragments.append(match.group(2))
        else:
            fragments.append(entry)
    flush()
    return ports


def _balanced_header(text: str, start: int) -> tuple[str, str, int] | None:
    name_match = _MODULE_NAME_RE.match(text, start)
    if not name_match:
        return None
    name = name_match.group(1).lstrip("\\").rstrip()
    index = name_match.end()
    while index < len(text) and text[index].isspace():
        index += 1
    if index < len(text) and text[index] == "#":
        index += 1
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text) or text[index] != "(":
            return None
        depth = 0
        while index < len(text):
            if text[index] == "(":
                depth += 1
            elif text[index] == ")":
                depth -= 1
                if depth == 0:
                    index += 1
                    break
            index += 1
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text) or text[index] != "(":
        return None
    open_index = index
    depth = 0
    while index < len(text):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                close_index = index
                index += 1
                break
        index += 1
    else:
        return None
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text) or text[index] != ";":
        return None
    return name, text[open_index + 1 : close_index], index + 1


def _parse_instance(statement: str, warnings: list[str] | None = None) -> ModuleInstance | None:
    match = re.match(
        rf"\s*(?P<type>{IDENT})\s*(?:#\s*\(.*\)\s*)?(?P<name>{IDENT})\s*\((?P<body>.*)\)\s*$",
        statement,
        re.DOTALL,
    )
    if not match:
        return None
    cell_type = match.group("type").lstrip("\\").rstrip()
    name = match.group("name").lstrip("\\").rstrip()
    body = match.group("body")
    named: dict[str, str] = {}
    positional: list[str] = []
    connections = _split_top_level(body, max_items=MAX_INSTANCE_CONNECTIONS + 1)
    if len(connections) > MAX_INSTANCE_CONNECTIONS:
        connections.pop()
        if warnings is not None:
            warnings.append(
                f"ignored remaining instance connections after reaching the parser limit of {MAX_INSTANCE_CONNECTIONS}"
            )
    for connection in connections:
        named_match = re.match(rf"\s*\.\s*({IDENT})\s*\((.*)\)\s*$", connection, re.DOTALL)
        if named_match:
            pin_name = named_match.group(1).lstrip("\\").rstrip()
            named[pin_name] = named_match.group(2).strip()
        else:
            positional.append(connection.strip())
    return ModuleInstance(cell_type, name, named, positional)


def parse_verilog_text(text: str) -> VerilogDesign:
    cleaned = strip_c_style_comments(text)
    modules: dict[str, ModuleDef] = {}
    warnings = _WarningBuffer()
    expansion_budget = _ExpansionBudget(MAX_EXPANDED_NAMES_PER_PARSE)
    statement_budget = MAX_VERILOG_STATEMENTS_PER_PARSE
    cursor = 0
    module_count = 0
    while True:
        module_match = _MODULE_RE.search(cleaned, cursor)
        if not module_match:
            break
        module_count += 1
        if module_count > MAX_VERILOG_MODULES:
            warnings.append(f"ignored remaining modules after reaching the parser limit of {MAX_VERILOG_MODULES}")
            break
        module_start = module_match.end()
        header = _balanced_header(cleaned, module_start)
        if header is None:
            warnings.append("could not parse a module header")
            cursor = module_start
            continue
        name, port_header, body_start = header
        end_match = _ENDMODULE_RE.search(cleaned, body_start)
        if not end_match:
            warnings.append(f"module {name!r} has no endmodule")
            break
        body_end = end_match.start()
        body = cleaned[body_start:body_end]
        ports = _parse_ports(port_header, warnings, expansion_budget)
        port_map = {port.name: port for port in ports}
        nets: set[str] = set(port_map)
        instances: list[ModuleInstance] = []
        aliases: list[tuple[str, str]] = []
        statements = _split_statements(body, statement_budget + 1)
        statements_truncated = len(statements) > statement_budget
        if statements_truncated:
            statements.pop()
            warnings.append(
                "ignored remaining statements after reaching the parser-wide limit of "
                f"{MAX_VERILOG_STATEMENTS_PER_PARSE}"
            )
        statement_budget -= len(statements)
        for statement in statements:
            declaration = re.match(r"\s*(input|output|inout|wire|tri|logic|reg)\b(.*)$", statement, re.DOTALL)
            if declaration:
                kind, fragment = declaration.group(1), declaration.group(2)
                if kind in {"input", "output", "inout"}:
                    _merge_body_port_declaration(
                        ports,
                        port_map,
                        nets,
                        kind,
                        fragment,
                        warnings,
                        expansion_budget,
                    )
                else:
                    nets.update(_expand_names(fragment, warnings, expansion_budget))
                continue
            assign = re.match(r"\s*assign\s+(.+?)\s*=\s*(.+)\s*$", statement, re.DOTALL)
            if assign:
                left = _simple_signal(assign.group(1))
                right = _simple_signal(assign.group(2))
                if left and right:
                    aliases.append((left, right))
                else:
                    warnings.append(f"ignored non-scalar assign in module {name}: {statement.strip()[:80]}")
                continue
            if re.match(r"\s*(?:always|initial|parameter|localparam|genvar)\b", statement):
                warnings.append(f"ignored unsupported statement in module {name}: {statement.strip()[:80]}")
                continue
            instance = _parse_instance(statement, warnings)
            if instance:
                instances.append(instance)
            elif statement.strip():
                warnings.append(f"ignored unsupported statement in module {name}: {statement.strip()[:80]}")
        modules[name] = ModuleDef(name, ports, nets, instances, aliases)
        cursor = end_match.end()
        if statements_truncated:
            break
    if not modules:
        warnings.append("no modules were found in the Verilog input")
    return VerilogDesign(modules, warnings.finalized())


def parse_verilog(paths: list[str | Path]) -> VerilogDesign:
    merged = VerilogDesign({})
    for path in paths:
        source = Path(path)
        parsed = parse_verilog_text(source.read_text(encoding="utf-8", errors="replace"))
        merged.modules.update(parsed.modules)
        merged.warnings.extend(f"{source}: {warning}" for warning in parsed.warnings)
    return merged


def _simple_signal(expression: str) -> str | None:
    value = expression.strip()
    while value.startswith(("~", "!")):
        value = value[1:].strip()
    if re.fullmatch(r"(?:\d+'[bBoOdDhH][0-9a-fA-FxXzZ_]+|[01])", value):
        return None
    if re.fullmatch(r"\\\S+|[A-Za-z_$][A-Za-z0-9_$/]*(?:\[-?\d+\])?", value):
        return value.lstrip("\\").rstrip()
    return None


def _inferred_spec(cell_type: str, pin_names: set[str]) -> CellSpec:
    sequential = bool(re.search(r"(?:^|_)(?:S?D?FF|FD|LATCH|DLAT)", cell_type, re.IGNORECASE))
    clock_candidates = {name for name in pin_names if name.upper() in {"CK", "CLK", "CP", "G", "GN"}}
    data_candidates = {name for name in pin_names if name.upper() in {"D", "DATA", "DI", "SI"}}
    directions: dict[str, str] = {}
    for name in pin_names:
        upper = name.upper()
        directions[name] = "output" if upper in {"Q", "QN", "QB", "Z", "ZN", "Y"} else "input"
    return CellSpec(cell_type, directions, sequential, data_candidates, clock_candidates)


def elaborate(verilog: VerilogDesign, library: CellLibrary, top: str | None = None) -> Design:
    if not verilog.modules:
        raise ValueError("Verilog input does not contain a module")
    instantiated_modules = {
        instance.cell_type
        for module in verilog.modules.values()
        for instance in module.instances
        if instance.cell_type in verilog.modules
    }
    candidates = [name for name in verilog.modules if name not in instantiated_modules]
    selected_top = top or (candidates[0] if len(candidates) == 1 else next(iter(verilog.modules)))
    if selected_top not in verilog.modules:
        raise ValueError(f"top module {selected_top!r} was not found")

    expanded_port_bits: dict[str, dict[str, list[tuple[str, str]]]] = {}
    ordered_port_groups: dict[str, list[list[ModulePort]]] = {}
    for module_name, module in verilog.modules.items():
        by_base: dict[str, list[tuple[str, str]]] = {}
        for module_port in module.ports:
            bit_match = _EXPANDED_BUS_BIT_RE.fullmatch(module_port.name)
            if bit_match:
                by_base.setdefault(bit_match.group(1), []).append((module_port.name, bit_match.group(2)))
        expanded_port_bits[module_name] = by_base
        ordered_port_groups[module_name] = _ordered_port_groups(module.ports)

    top_module = verilog.modules[selected_top]
    ports = {port.name: Port(port.name, port.direction, port.name) for port in top_module.ports}
    nets: set[str] = set(top_module.nets)
    instances: dict[str, Instance] = {}
    pins: dict[str, Pin] = {}
    warnings = list(verilog.warnings) + list(library.warnings)
    drivers: dict[str, set[str]] = {}
    loads: dict[str, set[str]] = {}
    combinational_arcs: dict[str, set[str]] = {}
    inferred_cell_types: set[str] = set()
    incomplete_arc_cell_types: set[str] = set()
    elaboration_remaining = MAX_ELABORATION_OBJECTS
    elaboration_limit_reported = False

    def reserve_elaboration(amount: int, location: str) -> bool:
        nonlocal elaboration_remaining, elaboration_limit_reported
        if amount <= elaboration_remaining:
            elaboration_remaining -= amount
            return True
        elaboration_remaining = 0
        if not elaboration_limit_reported:
            warnings.append(
                f"hierarchical elaboration stopped at {location}; "
                f"the parser-wide object limit is {MAX_ELABORATION_OBJECTS}"
            )
            elaboration_limit_reported = True
        return False

    def resolve(expression: str, mapping: dict[str, str], prefix: str) -> str | None:
        signal = _simple_signal(expression)
        if signal is None:
            return None
        if signal in mapping:
            return mapping[signal]
        return f"{prefix}/{signal}" if prefix else signal

    def visit(module: ModuleDef, prefix: str, bindings: dict[str, str], stack: tuple[str, ...]) -> None:
        if module.name in stack:
            warnings.append(f"recursive module instantiation stopped at {'/'.join(stack + (module.name,))}")
            return
        if len(stack) >= MAX_HIERARCHY_DEPTH:
            warnings.append(
                f"hierarchical elaboration stopped at {prefix or module.name}; "
                f"the parser limit is {MAX_HIERARCHY_DEPTH} module levels"
            )
            return
        if not reserve_elaboration(len(module.nets) + 1, prefix or module.name):
            return
        local_map: dict[str, str] = {}
        for local_net_name in module.nets:
            local_map[local_net_name] = bindings.get(
                local_net_name, f"{prefix}/{local_net_name}" if prefix else local_net_name
            )
            nets.add(local_map[local_net_name])
        # Scalar continuous assignments form equivalence classes.  Resolve them
        # with path-compressed union/find rather than repeatedly rewriting the
        # entire net map for every alias (quadratic for long assign chains).
        parents = {mapped: mapped for mapped in local_map.values()}

        def alias_root(mapped: str) -> str:
            parents.setdefault(mapped, mapped)
            root = mapped
            while parents[root] != root:
                root = parents[root]
            while parents[mapped] != mapped:
                following = parents[mapped]
                parents[mapped] = root
                mapped = following
            return root

        output_ports = {port.name for port in module.ports if port.direction in {"output", "inout"}}
        for left, right in module.aliases:
            if left not in local_map or right not in local_map:
                continue
            left_root = alias_root(local_map[left])
            right_root = alias_root(local_map[right])
            if left_root == right_root:
                continue
            if left in bindings or (right not in bindings and left in output_ports):
                parents[right_root] = left_root
            else:
                parents[left_root] = right_root
        for local_name, mapped in local_map.items():
            local_map[local_name] = alias_root(mapped)
        if not prefix:
            for port in module.ports:
                if port.name in ports and port.name in local_map:
                    ports[port.name].net = local_map[port.name]
        for child in module.instances:
            child_path = f"{prefix}/{child.name}" if prefix else child.name
            if child.cell_type in verilog.modules:
                child_module = verilog.modules[child.cell_type]
                child_bindings: dict[str, str] = {}
                if child.named_connections:
                    for port_name, expression in child.named_connections.items():
                        resolved_net = resolve(expression, local_map, prefix)
                        if resolved_net is not None:
                            child_bindings[port_name] = resolved_net
                        connection_signal = _simple_signal(expression)
                        if connection_signal is not None:
                            for child_port_name, bit_index in expanded_port_bits[child_module.name].get(port_name, ()):
                                bit_signal = f"{connection_signal}[{bit_index}]"
                                bit_net = resolve(bit_signal, local_map, prefix)
                                if bit_net is not None:
                                    child_bindings[child_port_name] = bit_net
                else:
                    for port_group, expression in zip(
                        ordered_port_groups[child_module.name], child.positional_connections, strict=False
                    ):
                        base = _expanded_bus_base(port_group[0].name)
                        signal = _simple_signal(expression)
                        if base is not None and signal is not None and _expanded_bus_base(signal) is None:
                            for port in port_group:
                                bit_match = _EXPANDED_BUS_BIT_RE.fullmatch(port.name)
                                assert bit_match is not None
                                bit_net = resolve(f"{signal}[{bit_match.group(2)}]", local_map, prefix)
                                if bit_net is not None:
                                    child_bindings[port.name] = bit_net
                            continue
                        resolved_net = resolve(expression, local_map, prefix)
                        if resolved_net is not None:
                            for port in port_group:
                                child_bindings[port.name] = resolved_net
                visit(child_module, child_path, child_bindings, stack + (module.name,))
                continue

            if child_path in instances:
                retained = instances[child_path]
                warnings.append(
                    f"flattened instance path collision at {child_path!r}; retained the first "
                    f"{retained.cell_type!r} instance and ignored {child.cell_type!r}. "
                    "Escaped identifiers containing '/' are ambiguous with hierarchy separators"
                )
                continue

            connection_names = set(child.named_connections)
            spec = library.cells.get(child.cell_type)
            if spec is None:
                inferred_cell_types.add(child.cell_type)
                spec = _inferred_spec(child.cell_type, connection_names)
            child_pins: dict[str, Pin] = {}
            if child.named_connections:
                connection_items = list(child.named_connections.items())
            else:
                connection_items = list(zip(spec.pin_directions, child.positional_connections, strict=False))
            if not reserve_elaboration(len(connection_items) + 1, child_path):
                return
            for pin_name, expression in connection_items:
                resolved_net = resolve(expression, local_map, prefix)
                pin_path = f"{child_path}/{pin_name}"
                direction = spec.pin_directions.get(pin_name, "unknown")
                pin = Pin(
                    path=pin_path,
                    instance=child_path,
                    name=pin_name,
                    direction=direction,
                    net=resolved_net,
                    is_clock=pin_name in spec.clock_pins,
                    is_data=pin_name in spec.data_pins,
                )
                child_pins[pin_name] = pin
                pins[pin_path] = pin
                if resolved_net is not None:
                    nets.add(resolved_net)
                    target = drivers if direction == "output" else loads
                    target.setdefault(resolved_net, set()).add(pin_path)
            instances[child_path] = Instance(child_path, child.cell_type, child_pins, spec.sequential)
            if not spec.sequential:
                connected_inputs = {
                    name
                    for name, pin in child_pins.items()
                    if pin.direction in {"input", "inout"} and pin.net is not None
                }
                connected_outputs = {
                    name
                    for name, pin in child_pins.items()
                    if pin.direction in {"output", "inout"} and pin.net is not None
                }
                for output_name in connected_outputs:
                    dependencies = spec.combinational_dependencies.get(output_name)
                    if dependencies is None:
                        if connected_inputs:
                            incomplete_arc_cell_types.add(child.cell_type)
                        continue
                    output_path = child_pins[output_name].path
                    for input_name in dependencies & connected_inputs:
                        input_path = child_pins[input_name].path
                        combinational_arcs.setdefault(input_path, set()).add(output_path)

    top_bindings = {port.name: port.name for port in top_module.ports}
    visit(top_module, "", top_bindings, ())
    if inferred_cell_types:
        sample = sorted(inferred_cell_types)[:20]
        warnings.append(
            f"Liberty metadata is missing for {len(inferred_cell_types)} instantiated cell type(s); "
            f"inferred sequential and pin roles from names (sample: {', '.join(sample)})"
        )
    if incomplete_arc_cell_types:
        sample = sorted(incomplete_arc_cell_types)[:20]
        warnings.append(
            f"Liberty function/timing dependencies are missing for {len(incomplete_arc_cell_types)} "
            f"instantiated combinational cell type(s); clock propagation stops at unknown arcs "
            f"(sample: {', '.join(sample)})"
        )
    for port in ports.values():
        target = drivers if port.direction in {"input", "inout"} else loads
        target.setdefault(port.net, set()).add(port.name)
    return Design(selected_top, ports, nets, instances, pins, drivers, loads, combinational_arcs, warnings)
