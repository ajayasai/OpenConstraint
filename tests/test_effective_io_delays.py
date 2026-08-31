from __future__ import annotations

from collections.abc import Callable
from typing import Any

from openconstraint.cli import _mode_semantics
from openconstraint.model import AuditResult, IODelay, SourceLocation, effective_io_delay_semantics


def _delay(
    value: float,
    *,
    kind: str = "input",
    port: str = "data",
    clock: str | None = "core",
    clock_edge: str = "rise",
    min_max: tuple[str, ...] = ("min", "max"),
    transitions: tuple[str, ...] = ("rise", "fall"),
    additive: bool = False,
    reference_pin: str | None = None,
    source_latency_included: bool = False,
    network_latency_included: bool = False,
    valid: bool = True,
) -> IODelay:
    return IODelay(
        kind=kind,
        ports=frozenset({port}),
        value=value,
        clocks=frozenset({clock}) if clock is not None else frozenset(),
        reference_pin=reference_pin,
        source_latency_included=source_latency_included,
        network_latency_included=network_latency_included,
        min_max=frozenset(min_max),
        transitions=frozenset(transitions),
        clock_edge=clock_edge,
        additive=additive,
        valid=valid,
        location=SourceLocation("constraints.sdc"),
        raw="set_input_delay ...",
    )


def _slot_values(records: list[dict[str, Any]]) -> dict[tuple[str, str, str, str], float]:
    return {
        (
            str(port),
            str(record["clocks"][0]) if record["clocks"] else "",
            str(transition),
            str(min_max),
        ): float(record["value"])
        for record in records
        for port in record["ports"]
        for transition in record["transitions"]
        for min_max in record["min_max"]
    }


def test_non_add_overwrites_selected_slots_and_removes_competing_relationships() -> None:
    initial = _delay(1.0)
    partial_overwrite = _delay(7.0, min_max=("max",), transitions=("rise",))

    retained = effective_io_delay_semantics([initial, partial_overwrite])

    assert _slot_values(retained) == {
        ("data", "core", "fall", "max"): 1.0,
        ("data", "core", "fall", "min"): 1.0,
        ("data", "core", "rise", "max"): 7.0,
        ("data", "core", "rise", "min"): 1.0,
    }

    replacement = _delay(
        3.0,
        clock="aux",
        clock_edge="fall",
        min_max=("min",),
        transitions=("fall",),
    )
    replaced = effective_io_delay_semantics([initial, partial_overwrite, replacement])

    assert _slot_values(replaced) == {("data", "aux", "fall", "min"): 3.0}


def test_add_delay_merges_by_analysis_sense_and_updates_relationship_properties() -> None:
    records = effective_io_delay_semantics(
        [
            _delay(2.0, transitions=("rise",)),
            _delay(
                1.0,
                min_max=("min",),
                transitions=("rise",),
                additive=True,
                reference_pin="u_ff/Q",
                source_latency_included=True,
            ),
            _delay(
                1.0,
                min_max=("max",),
                transitions=("rise",),
                additive=True,
                reference_pin="u_ff/Q",
                source_latency_included=True,
            ),
            _delay(
                5.0,
                clock="aux",
                clock_edge="fall",
                min_max=("min",),
                transitions=("fall",),
                additive=True,
            ),
        ]
    )

    assert _slot_values(records) == {
        ("data", "aux", "fall", "min"): 5.0,
        ("data", "core", "rise", "max"): 2.0,
        ("data", "core", "rise", "min"): 1.0,
    }
    core = [record for record in records if record["clocks"] == ["core"]]
    assert all(record["reference_pin"] == "u_ff/Q" for record in core)
    # OpenSTA ignores latency-inclusion flags when a reference pin is present.
    assert all(record["source_latency_included"] is False for record in core)
    assert all(record["additive"] is False and record["valid"] is True for record in records)


def test_canonical_order_is_stable_for_independent_commands_and_additive_extrema() -> None:
    independent = [
        _delay(4.0, port="spare", transitions=("fall",), min_max=("max",)),
        _delay(2.0, kind="output", port="result", transitions=("rise",), min_max=("min",)),
    ]
    assert effective_io_delay_semantics(independent) == effective_io_delay_semantics(reversed(independent))

    low = _delay(1.0, min_max=("min",), transitions=("rise",), additive=True)
    high = _delay(3.0, min_max=("min",), transitions=("rise",), additive=True)
    assert effective_io_delay_semantics([low, high]) == effective_io_delay_semantics([high, low])


def test_clockless_clock_fall_uses_the_single_null_clock_relationship() -> None:
    records = effective_io_delay_semantics(
        [
            _delay(1.0, clock=None, min_max=("min",), transitions=("rise",)),
            _delay(
                2.0,
                clock=None,
                clock_edge="fall",
                min_max=("max",),
                transitions=("fall",),
            ),
        ]
    )

    assert _slot_values(records) == {
        ("data", "", "fall", "max"): 2.0,
        ("data", "", "rise", "min"): 1.0,
    }
    assert all(record["clock_edge"] == "rise" for record in records)


def test_effective_state_preserves_meaningful_latency_inclusion_without_reference_pin() -> None:
    records = effective_io_delay_semantics(
        [
            _delay(
                1.0,
                source_latency_included=True,
                network_latency_included=True,
            )
        ]
    )

    assert records[0]["reference_pin"] is None
    assert records[0]["source_latency_included"] is True
    assert records[0]["network_latency_included"] is True


def test_reports_keep_history_while_opensta_digest_uses_active_state(
    audit_factory: Callable[..., AuditResult],
) -> None:
    result = audit_factory(
        """
create_clock -name core -period 10 [get_ports clk]
set_input_delay -max -rise 1 -clock core [get_ports data]
set_input_delay -max -rise 2 -clock core [get_ports data]
"""
    )
    mode = result.modes[0]

    assert len(mode.io_delays) == 2
    assert len(result.to_dict()["modes"][0]["io_delays"]) == 2
    assert _mode_semantics(mode)["io_delays"] == [
        {
            "kind": "input",
            "ports": ["data"],
            "value": 2.0,
            "clocks": ["core"],
            "reference_pin": None,
            "source_latency_included": False,
            "network_latency_included": False,
            "min_max": ["max"],
            "transitions": ["rise"],
            "clock_edge": "rise",
            "additive": False,
            "valid": True,
        }
    ]
