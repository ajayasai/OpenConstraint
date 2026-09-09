"""Deterministic, bounded elaboration of already techmapped Yosys JSON.

Module-local wire IDs are separate per instance. A disjoint-set structure joins
only explicitly connected port bits, including aliases and constant outputs.
This is connectivity elaboration, not RTL synthesis or a timing equivalence proof.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Any

ALGORITHM = "hierarchical-bit-connectivity-v1"
SCHEMA_VERSION = "1.0.0"
CONTRACT = {
    "input": "already-elaborated-techmapped-Yosys-JSON",
    "hierarchical_names": "slash-prefixed-JSON-pointer-components; top names unchanged",
    "constants": "two-state-only",
    "unresolved_parameters": "rejected",
    "unknown_cells": "rejected",
    "timing_signoff": False,
    "rtl_elaboration": False,
    "functional_property_proof": False,
    "clock_relationships_inferred": False,
}
Bit = int | str


class HierarchyInputError(ValueError):
    """The supplied hierarchy is malformed or outside the supported contract."""


class HierarchyLimitError(HierarchyInputError):
    """A deterministic expansion/resource ceiling was reached."""


@dataclass(frozen=True, slots=True)
class HierarchyLimits:
    max_source_bytes: int = 16 * 1024 * 1024
    max_instances: int = 20_000
    max_leaf_cells: int = 100_000
    max_wires: int = 400_000
    max_alias_bits: int = 2_000_000
    max_depth: int = 64
    max_name_chars: int = 4096
    max_output_bytes: int = 64 * 1024 * 1024

    def __post_init__(self) -> None:
        for name, field in self.__dataclass_fields__.items():
            value = getattr(self, name)
            assert isinstance(field.default, int)
            if type(value) is not int or not 1 <= value <= field.default:
                raise ValueError(f"{name} must be an integer in [1, {field.default}]")


def canonical(value: object) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise HierarchyInputError("input must be finite, bounded-depth JSON") from exc


def digest(value: object) -> str:
    return sha256(canonical(value).encode("utf-8")).hexdigest()


def _object(value: object, where: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise HierarchyInputError(f"{where} must be an object with string keys")
    return value


def _fields(value: Mapping[str, Any], allowed: set[str], where: str) -> None:
    if set(value) - allowed:
        raise HierarchyInputError(f"{where} has unsupported fields: {sorted(set(value) - allowed)}")


def _bit(value: object) -> Bit:
    if type(value) is int and 0 <= value <= 2**31 - 1:
        return value
    if isinstance(value, str) and value in {"0", "1"}:
        return value
    raise HierarchyInputError("wire IDs must be nonnegative 31-bit integers; X/Z constants are not modeled")


def _bits(value: object, where: str, limits: HierarchyLimits) -> tuple[Bit, ...]:
    if not isinstance(value, list) or not value:
        raise HierarchyInputError(f"{where} requires a nonempty bits array")
    if len(value) > limits.max_alias_bits:
        raise HierarchyLimitError("bits array exceeds max_alias_bits")
    return tuple(_bit(b) for b in value)


def _metadata_flags(info: Mapping[str, Any]) -> None:
    for key in ("hide_name", "upto", "signed", "offset"):
        if key not in info:
            continue
        value = info[key]
        if (
            type(value) is not int
            or (key == "offset" and abs(value) > 2**31 - 1)
            or (key != "offset" and value not in (0, 1))
        ):
            raise HierarchyInputError(f"{key} must be an integer metadata flag/index")


def _attributes(raw: object) -> dict[str, Any]:
    attributes = _object(raw, "attributes")
    for key in ("blackbox", "whitebox"):
        value = attributes.get(key, 0)
        disabled = value in (None, "", 0) or isinstance(value, str) and set(value) == {"0"}
        if not disabled:
            raise HierarchyInputError(f"{key} semantics are not modeled")
    return attributes


def _interface(kind: str) -> tuple[str, str]:
    gates = {
        "$_BUF_": "A",
        "$_NOT_": "A",
        "$_AND_": "AB",
        "$_NAND_": "AB",
        "$_OR_": "AB",
        "$_NOR_": "AB",
        "$_XOR_": "AB",
        "$_XNOR_": "AB",
        "$_ANDNOT_": "AB",
        "$_ORNOT_": "AB",
        "$_MUX_": "ABS",
        "$_NMUX_": "ABS",
    }
    if kind in gates:
        return gates[kind], "Y"
    if re.fullmatch(r"\$_DFF_[PN]_", kind):
        return "CD", "Q"
    if re.fullmatch(r"\$_DFFE_[PN][PN]_", kind):
        return "CDE", "Q"
    if re.fullmatch(r"\$_SDFF_[PN][PN][01]_", kind):
        return "CDR", "Q"
    if re.fullmatch(r"\$_(?:SDFFE|SDFFCE)_[PN][PN][01][PN]_", kind):
        return "CDRE", "Q"
    raise HierarchyInputError(f"unknown/unmapped primitive {kind!r}; resolve hierarchy and techmap first")


def hierarchical_name(path: tuple[str, ...], name: str) -> str:
    """Injective component encoding for children; no delimiter-name guessing."""
    if not path:
        return name
    return "/" + "/".join(part.replace("~", "~0").replace("/", "~1") for part in (*path, name))


@dataclass(slots=True)
class _Template:
    raw: dict[str, Any]
    ports: dict[str, tuple[str, tuple[Bit, ...]]]
    nets: dict[str, tuple[Bit, ...]]
    cells: dict[str, dict[str, Any]]
    connections: dict[str, dict[str, tuple[Bit, ...]]]
    local_bits: tuple[int, ...]
    byte_cost: int


class _Elaborator:
    def __init__(self, modules: dict[str, Any], top: str, limits: HierarchyLimits):
        self.modules, self.top, self.limits = modules, top, limits
        self.templates: dict[str, _Template] = {}
        self.parent = [0, 1]  # Global binary constant representatives.
        self.rank = [0, 0]
        self.top_ids: dict[int, int] = {}
        self.instance_records: list[dict[str, Any]] = []
        self.net_records: list[tuple[str, tuple[str, ...], str, dict[str, Any], tuple[int, ...]]] = []
        self.leaves: list[tuple[str, tuple[str, ...], str, dict[str, Any], dict[str, tuple[int, ...]]]] = []
        self.alias_bits = 0
        self.expanded_bytes = 0
        self.names: set[str] = set()
        self.cell_names: set[str] = set()
        self.input_ids: set[int] = set()
        self.input_bindings: list[int] = []

    def _charge(self, count: int) -> None:
        self.alias_bits += count
        if self.alias_bits > self.limits.max_alias_bits:
            raise HierarchyLimitError("expanded connectivity/aliases exceed max_alias_bits")

    def _name(self, path: tuple[str, ...], name: str, namespace: set[str]) -> str:
        value = hierarchical_name(path, name)
        if len(value) > self.limits.max_name_chars:
            raise HierarchyLimitError("expanded name exceeds max_name_chars")
        if value in namespace:
            raise HierarchyInputError(f"top/hierarchical name collision at {value!r}")
        namespace.add(value)
        return value

    def template(self, module_name: str) -> _Template:
        if module_name in self.templates:
            return self.templates[module_name]
        raw = _object(self.modules.get(module_name), f"module {module_name!r}")
        _fields(
            raw,
            {"attributes", "parameter_default_values", "ports", "cells", "netnames", "memories", "processes"},
            "module",
        )
        _attributes(raw.get("attributes", {}))
        if raw.get("memories") or raw.get("processes"):
            raise HierarchyInputError("unlowered processes or memories are not modeled")
        _object(raw.get("parameter_default_values", {}), "parameter defaults")
        ports: dict[str, tuple[str, tuple[Bit, ...]]] = {}
        nets: dict[str, tuple[Bit, ...]] = {}
        local: set[int] = set()
        for name, value in sorted(_object(raw.get("ports"), "ports").items()):
            info = _object(value, "port")
            _metadata_flags(info)
            _fields(info, {"direction", "bits", "offset", "upto", "signed"}, "port")
            direction = info.get("direction")
            if direction not in {"input", "output"}:
                raise HierarchyInputError("inout or unknown port direction is not modeled")
            bits = _bits(info.get("bits"), "port", self.limits)
            if direction == "input" and any(isinstance(b, str) for b in bits):
                raise HierarchyInputError("input port declarations cannot be constants")
            ports[name] = direction, bits
            local.update(b for b in bits if isinstance(b, int))
        for name, value in sorted(_object(raw.get("netnames", {}), "netnames").items()):
            info = _object(value, "netname")
            _metadata_flags(info)
            _fields(info, {"hide_name", "bits", "attributes", "offset", "upto", "signed"}, "netname")
            _attributes(info.get("attributes", {}))
            bits = _bits(info.get("bits"), "netname", self.limits)
            if name in ports and ports[name][1] != bits:
                raise HierarchyInputError(f"conflicting port/net alias {name!r}")
            nets[name] = bits
            local.update(b for b in bits if isinstance(b, int))
        cells: dict[str, dict[str, Any]] = {}
        connections: dict[str, dict[str, tuple[Bit, ...]]] = {}
        for name, value in sorted(_object(raw.get("cells"), "cells").items()):
            cell = _object(value, "cell")
            _metadata_flags(cell)
            _fields(cell, {"hide_name", "type", "parameters", "attributes", "port_directions", "connections"}, "cell")
            _attributes(cell.get("attributes", {}))
            kind = cell.get("type")
            if not isinstance(kind, str):
                raise HierarchyInputError("cell type must be a string")
            if _object(cell.get("parameters", {}), "parameters"):
                raise HierarchyInputError("unresolved instance parameters: run Yosys hierarchy before exporting")
            conns = {
                p: _bits(bits, "connection", self.limits)
                for p, bits in _object(cell.get("connections"), "connections").items()
            }
            directions = _object(cell.get("port_directions", {}), "port directions")
            if kind not in self.modules:
                inputs, output = _interface(kind)
                expected = {p: "input" for p in inputs} | {output: "output"}
                if set(conns) != set(expected) or any(len(b) != 1 for b in conns.values()):
                    raise HierarchyInputError(f"primitive {name!r} requires its exact single-bit interface")
                if directions and directions != expected:
                    raise HierarchyInputError(f"inconsistent primitive directions on {name!r}")
            elif kind.startswith("$_"):
                raise HierarchyInputError("module definitions may not shadow internal primitive semantics")
            cells[name], connections[name] = cell, conns
            local.update(b for bits in conns.values() for b in bits if isinstance(b, int))
        if len(local) > self.limits.max_wires:
            raise HierarchyLimitError("module-local wire count exceeds max_wires")
        result = _Template(
            raw, ports, nets, cells, connections, tuple(sorted(local)), len(canonical(raw).encode("utf-8"))
        )
        self.templates[module_name] = result
        return result

    def find(self, bit: int) -> int:
        while self.parent[bit] != bit:
            self.parent[bit] = self.parent[self.parent[bit]]
            bit = self.parent[bit]
        return bit

    def join(self, a: int, b: int) -> None:
        a, b = self.find(a), self.find(b)
        if a == b:
            return
        if a < 2 and b < 2:
            raise HierarchyInputError("port aliases connect contradictory binary constants")
        if b < 2 or a >= 2 and self.rank[a] < self.rank[b]:
            a, b = b, a
        self.parent[b] = a
        if self.rank[a] == self.rank[b]:
            self.rank[a] += 1

    def visit(
        self,
        name: str,
        path: tuple[str, ...],
        ancestors: tuple[str, ...],
        bindings: Mapping[str, tuple[int, ...]] | None = None,
        instance_attributes: Mapping[str, Any] | None = None,
    ) -> None:
        if name in ancestors:
            raise HierarchyInputError(f"recursive module hierarchy at {path!r}")
        if len(path) > self.limits.max_depth:
            raise HierarchyLimitError("instance hierarchy exceeds max_depth")
        if len(self.instance_records) >= self.limits.max_instances:
            raise HierarchyLimitError("expanded hierarchy exceeds max_instances")
        template = self.template(name)
        if len(hierarchical_name(path, "")) > self.limits.max_name_chars:
            raise HierarchyLimitError("instance name exceeds max_name_chars")
        # Charge repeated metadata before retaining expanded records or serializing
        # a report. The multiplier covers metadata in both output and provenance.
        self.expanded_bytes += 6 * (
            template.byte_cost
            + len(canonical(path).encode("utf-8"))
            * (len(template.cells) + len(template.nets) + len(template.ports) + 1)
        )
        if self.expanded_bytes > self.limits.max_output_bytes:
            raise HierarchyLimitError("expanded metadata exceeds max_output_bytes work budget")
        if len(self.parent) - 2 + len(template.local_bits) > self.limits.max_wires:
            raise HierarchyLimitError("instance-expanded wire count exceeds max_wires")
        start = len(self.parent)
        local = dict(zip(template.local_bits, range(start, start + len(template.local_bits)), strict=True))
        self.parent.extend(range(start, start + len(template.local_bits)))
        self.rank.extend([0] * len(template.local_bits))
        if not path:
            self.top_ids = local
            self.input_ids = {
                b
                for direction, bits in template.ports.values()
                if direction == "input"
                for b in bits
                if isinstance(b, int)
            }
        self.instance_records.append(
            {
                "path": list(path),
                "module": name,
                "attributes": template.raw.get("attributes", {}),
                "instance_attributes": dict(instance_attributes or {}),
            }
        )

        def translate(bits: tuple[Bit, ...]) -> tuple[int, ...]:
            self._charge(len(bits))
            return tuple(local[b] if isinstance(b, int) else int(b) for b in bits)

        for port, (direction, bits) in template.ports.items():
            nodes = translate(bits)
            if bindings is not None:
                if len(nodes) != len(bindings[port]):
                    raise HierarchyInputError(f"port width mismatch at {path!r}/{port}")
                for internal, external in zip(nodes, bindings[port], strict=True):
                    self.join(internal, external)
                if direction == "input":
                    self.input_bindings.extend(nodes)
        # Child ports are retained as signal aliases even when netnames omits them.
        for net_name in sorted(template.nets.keys() | template.ports.keys()):
            bits = template.nets[net_name] if net_name in template.nets else template.ports[net_name][1]
            raw = _object(template.raw.get("netnames", {}), "netnames").get(net_name, {})
            flat_name = self._name(path, net_name, self.names)
            self.net_records.append((flat_name, path, name, raw, translate(bits)))
        for cell_name, cell in template.cells.items():
            kind = cell["type"]
            conns = {p: translate(bits) for p, bits in sorted(template.connections[cell_name].items())}
            if kind in self.modules:
                child = self.template(kind)
                expected = {p: d for p, (d, _) in child.ports.items()}
                supplied_directions = cell.get("port_directions", {})
                if set(conns) != set(expected):
                    raise HierarchyInputError(f"missing/extra connected ports at {(*path, cell_name)!r}")
                if supplied_directions and supplied_directions != expected:
                    raise HierarchyInputError(f"instance directions disagree with module at {(*path, cell_name)!r}")
                self.visit(kind, (*path, cell_name), (*ancestors, name), conns, cell.get("attributes", {}))
            else:
                if len(self.leaves) >= self.limits.max_leaf_cells:
                    raise HierarchyLimitError("expanded primitive count exceeds max_leaf_cells")
                flat_name = self._name(path, cell_name, self.cell_names)
                self.leaves.append((flat_name, (*path, cell_name), name, cell, conns))

    def finish(self) -> tuple[dict[str, Any], dict[str, Any]]:
        labels: dict[int, Bit] = {0: "0", 1: "1"}
        for original, node in sorted(self.top_ids.items()):
            labels.setdefault(self.find(node), original)
        next_id = max(self.top_ids, default=1) + 1
        for node in range(2, len(self.parent)):
            root = self.find(node)
            if root not in labels:
                if next_id > 2**31 - 1:
                    raise HierarchyLimitError("flattened wire ID exceeds 31-bit namespace")
                labels[root] = next_id
                next_id += 1

        def translated(nodes: tuple[int, ...]) -> list[Bit]:
            return [labels[self.find(n)] for n in nodes]

        roots = [self.find(self.top_ids[b]) for b in sorted(self.input_ids)]
        if len(set(roots)) != len(roots) or any(r < 2 for r in roots):
            raise HierarchyInputError("hierarchy shorts distinct primary input bits or ties an input to a constant")
        driven = set(roots)
        used = set(self.find(n) for n in self.input_bindings)
        cells: dict[str, Any] = {}
        cell_origins = []
        for flat_name, path, module, cell, conns in self.leaves:
            inputs, output = _interface(cell["type"])
            root = self.find(conns[output][0])
            if root < 2 or root in driven:
                raise HierarchyInputError(f"constant or multiply driven primitive output {flat_name!r}")
            driven.add(root)
            used.update(self.find(conns[p][0]) for p in inputs)
            cells[flat_name] = dict(cell) | {"connections": {p: translated(b) for p, b in conns.items()}}
            cell_origins.append({"flat_name": flat_name, "path": list(path), "module": module, "type": cell["type"]})
        template = self.templates[self.top]
        ports = {}
        for name, (direction, bits) in template.ports.items():
            nodes = tuple(self.top_ids[b] if isinstance(b, int) else int(b) for b in bits)
            ports[name] = dict(template.raw["ports"][name]) | {"bits": translated(nodes)}
            if direction == "output":
                used.update(self.find(n) for n in nodes)
        if used - driven - {0, 1}:
            raise HierarchyInputError("undriven leaf input, module input, or top output after port binding")
        nets, net_origins = {}, []
        for flat_name, path, module, raw, nodes in self.net_records:
            nets[flat_name] = dict(raw) | {"bits": translated(nodes)}
            net_origins.append(
                {"flat_name": flat_name, "instance_path": list(path), "module": module, "bits": translated(nodes)}
            )
        flat = {
            "creator": "OpenConstraint hierarchical connectivity elaborator",
            "modules": {
                self.top: {
                    "attributes": template.raw.get("attributes", {}),
                    "ports": ports,
                    "netnames": nets,
                    "cells": cells,
                    "parameter_default_values": template.raw.get("parameter_default_values", {}),
                }
            },
        }
        provenance = {
            "instances": self.instance_records,
            "cells": cell_origins,
            "signals": net_origins,
            "top_bit_map": [{"original": b, "flat": labels[self.find(n)]} for b, n in sorted(self.top_ids.items())],
            "unused_modules": sorted(set(self.modules) - set(self.templates)),
            "counts": {
                "instances": len(self.instance_records),
                "leaf_cells": len(cells),
                "instance_wires": len(self.parent) - 2,
                "flat_wires": len(labels) - 2,
                "alias_bits": self.alias_bits,
                "charged_metadata_bytes": self.expanded_bytes,
                "signal_names": len(nets),
            },
            "primitive_counts": dict(sorted(Counter(c["type"] for c in cells.values()).items())),
        }
        return flat, provenance


def elaborate_hierarchy(
    netlist: Mapping[str, Any], top: str, *, limits: HierarchyLimits | None = None
) -> dict[str, Any]:
    """Return deterministic flattened connectivity and source-bound provenance.

    No input is mutated, no files are read, and no HDL or host command executes.
    Unused modules are recorded but not elaborated; their bytes remain digest-bound.
    """
    limits = limits or HierarchyLimits()
    if not isinstance(top, str) or not top:
        raise HierarchyInputError("top must be a nonempty module name")
    netlist = _object(netlist, "netlist")
    _fields(netlist, {"creator", "modules"}, "netlist")
    source = canonical(netlist).encode("utf-8")
    if len(source) > limits.max_source_bytes:
        raise HierarchyLimitError("canonical input exceeds max_source_bytes")
    # Isolate returned metadata from the caller's object graph as well.
    snapshot = json.loads(source)
    elaborator = _Elaborator(_object(snapshot.get("modules"), "modules"), top, limits)
    elaborator.visit(top, (), ())
    flat, provenance = elaborator.finish()
    if len(canonical(flat).encode("utf-8")) > 16 * 1024 * 1024:
        raise HierarchyLimitError("flattened netlist exceeds the proof CLI 16 MiB input ceiling")
    result = {
        "schema_version": SCHEMA_VERSION,
        "algorithm": ALGORITHM,
        "contract": dict(CONTRACT),
        "top": top,
        "source_digest": sha256(source).hexdigest(),
        "limits": asdict(limits),
        "netlist": flat,
        "netlist_digest": digest(flat),
        "provenance": provenance,
    }
    result["pack_digest"] = digest(result)
    if len(canonical(result).encode("utf-8")) > limits.max_output_bytes:
        raise HierarchyLimitError("elaboration evidence exceeds max_output_bytes")
    return result


def verify_hierarchy(
    pack: Mapping[str, Any], netlist: Mapping[str, Any], top: str, *, limits: HierarchyLimits | None = None
) -> bool:
    """Reconstruct all bindings and metadata, not just an integrity checksum."""
    return canonical(pack) == canonical(elaborate_hierarchy(netlist, top, limits=limits))


def flatten_if_needed(netlist: Mapping[str, Any], top: str, *, max_cells: int, max_bits: int) -> Mapping[str, Any]:
    """Preserve the existing flat-input contract; elaborate instantiated modules."""
    modules = _object(netlist.get("modules"), "modules")
    top_module = _object(modules.get(top), "selected top")
    cells = _object(top_module.get("cells"), "cells")
    if not any(isinstance(c, dict) and isinstance(c.get("type"), str) and c["type"] in modules for c in cells.values()):
        return netlist
    limits = HierarchyLimits(max_leaf_cells=min(max_cells, 100_000), max_wires=min(max_bits, 400_000))
    result = elaborate_hierarchy(netlist, top, limits=limits)
    return _object(result["netlist"], "flattened netlist")
