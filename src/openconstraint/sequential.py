"""Reset-aware synchronous safety proofs with concrete replay and k-induction.

An unbounded decision requires either an inductively closed reachable-state
set or a checked base case AND induction step. BMC exhaustion is never a pass.
The evidence describes the declared transition system, not physical timing.
"""

from __future__ import annotations

import importlib
from collections import Counter, deque
from collections.abc import Iterator, Mapping
from dataclasses import asdict, dataclass
from hashlib import sha256
from itertools import product
from typing import Any

from openconstraint.functional import (
    FunctionalInputError,
    FunctionalLimitError,
    _digest,
    _keys,
    _object,
    _z3_expression,
)
from openconstraint.parsers.sdc import MODELED_SDC_COMMANDS, parse_sdc_text
from openconstraint.sequential_model import (
    MODEL,
    Budget,
    InconsistentContract,
    Machine,
    SequentialLimitError,
    SequentialLimits,
    SynchronousModel,
    assignments,
    build_machine,
    load_synchronous_model,
)
from openconstraint.version import __version__

ALGORITHM = "synchronous-safety-v1"
EXCEPTION_COMMANDS = frozenset(
    {"set_false_path", "set_multicycle_path", "set_max_delay", "set_min_delay", "set_clock_groups"}
)
STATUSES = frozenset({"proven", "counterexample", "bounded", "unsupported", "inconsistent_assumptions"})


@dataclass(frozen=True)
class Contract:
    initial: Mapping[int, bool]
    assumptions: Mapping[int, bool]
    prefix: tuple[Mapping[int, bool], ...]


@dataclass(frozen=True)
class Trail:
    frame: dict[str, Any]
    previous: Trail | None
    length: int


def _checks(spec: Mapping[str, Any], limits: SequentialLimits) -> list[dict[str, Any]]:
    fields = {"schema_version", "model", "top", "clock", "edge", "initial", "assumptions", "prefix", "checks"}
    _keys(spec, fields, {"schema_version", "model", "top", "clock", "edge", "checks"}, "sequential specification")
    if spec["schema_version"] != "1.0.0" or spec["model"] != MODEL:
        raise FunctionalInputError("explicit schema 1.0.0 and single_clock_synchronous_v1 model required")
    if not isinstance(spec["top"], str) or not spec["top"]:
        raise FunctionalInputError("top must be a nonempty string")
    for key in ("initial", "assumptions", "prefix"):
        value = spec.get(key, [])
        if not isinstance(value, list):
            raise FunctionalInputError(f"{key} must be an array")
        if len(value) > (limits.max_prefix if key == "prefix" else limits.max_bits):
            raise SequentialLimitError(f"{key} exceeds the configured bound")
    for frame in spec.get("prefix", []):
        if not isinstance(frame, list) or len(frame) > limits.max_bits:
            raise FunctionalInputError("prefix entries must be bounded assignment arrays")
    raw_checks = spec["checks"]
    if not isinstance(raw_checks, list) or not raw_checks:
        raise FunctionalInputError("checks must be nonempty")
    if len(raw_checks) > limits.max_checks:
        raise SequentialLimitError("check count exceeds max_checks")
    result = []
    seen: set[str] = set()
    for raw in raw_checks:
        check = _object(raw, "check")
        kind = check.get("kind")
        required = {"id", "kind", "forbid"} if kind == "forbid" else {"id", "kind", "event", "cycles"}
        if kind not in {"forbid", "min_spacing"}:
            raise FunctionalInputError("check kind must be forbid or min_spacing")
        _keys(check, required | {"binding"}, required, "check")
        ident = check["id"]
        if not isinstance(ident, str) or not 1 <= len(ident) <= 200 or ident in seen:
            raise FunctionalInputError("check IDs must be unique nonempty strings up to 200 characters")
        seen.add(ident)
        if "binding" in check:
            binding = _object(check["binding"], "SDC binding")
            keys = {"source", "sha256", "command_index"}
            _keys(binding, keys, keys, "SDC binding")
            if not isinstance(binding["source"], str) or not 1 <= len(binding["source"]) <= 200:
                raise FunctionalInputError("binding source must be a nonempty logical input ID")
            digest = binding["sha256"]
            if not isinstance(digest, str) or len(digest) != 64 or set(digest) - set("0123456789abcdef"):
                raise FunctionalInputError("binding sha256 must be 64 lowercase hexadecimal characters")
            if type(binding["command_index"]) is not int or binding["command_index"] < 0:
                raise FunctionalInputError("binding command_index must be a nonnegative integer")
        result.append(check)
    return result


def _contract(model: SynchronousModel, spec: Mapping[str, Any]) -> Contract:
    initial = assignments(model, spec.get("initial", []), model.logic.state_outputs, "initial state")
    fixed = assignments(model, spec.get("assumptions", []), model.inputs, "assumptions")
    prefix = []
    for raw in spec.get("prefix", []):
        item = assignments(model, raw, model.inputs, "prefix")
        if any(k in fixed and fixed[k] != v for k, v in item.items()):
            raise InconsistentContract("prefix contradicts an all-cycle assumption")
        prefix.append(fixed | item)
    return Contract(initial, fixed, tuple(prefix))


def _source_manifest(sources: Mapping[str, bytes]) -> list[dict[str, Any]]:
    if not isinstance(sources, Mapping):
        raise FunctionalInputError("SDC sources must be a mapping of explicit inputs")
    if len(sources) > 64:
        raise SequentialLimitError("at most 64 explicitly supplied SDC sources are supported")
    for name, raw in sources.items():
        if not isinstance(name, str) or not 1 <= len(name) <= 200 or not isinstance(raw, bytes):
            raise FunctionalInputError("SDC sources require logical IDs and byte contents")
        if len(raw) > 16 * 1024 * 1024:
            raise SequentialLimitError("SDC input exceeds 16 MiB")
    if sum(len(value) for value in sources.values()) > 16 * 1024 * 1024:
        raise SequentialLimitError("aggregate SDC input exceeds 16 MiB")
    return [{"id": key, "sha256": sha256(value).hexdigest()} for key, value in sorted(sources.items())]


def _binding(check: Mapping[str, Any], sources: Mapping[str, bytes], cache: dict[str, Any]) -> dict[str, Any] | None:
    if "binding" not in check:
        return None
    binding = check["binding"]
    source = binding["source"]
    if source not in sources:
        raise FunctionalInputError(f"SDC binding source {source!r} was not explicitly supplied")
    raw = sources[source]
    if sha256(raw).hexdigest() != binding["sha256"]:
        raise FunctionalInputError(f"stale SDC binding for {source!r}: source SHA256 changed")
    if source not in cache:
        cache[source] = parse_sdc_text(raw.decode("utf-8"), f"<bound:{source}>")
    doc = cache[source]
    if doc.issues or any(
        c.name not in MODELED_SDC_COMMANDS
        or c.parse_errors
        or c.opaque_substitutions
        or c.dynamic_name
        or any(selector.dynamic or selector.parse_error for selector in c.selectors)
        for c in doc.commands
    ):
        raise FunctionalInputError("bound SDC must be static and parse without unsupported semantics")
    index = binding["command_index"]
    if index >= len(doc.commands) or doc.commands[index].name not in EXCEPTION_COMMANDS:
        raise FunctionalInputError("binding command_index does not identify a timing exception")
    command = doc.commands[index]
    return dict(binding) | {
        "command": command.name,
        "command_sha256": sha256(command.raw.encode("utf-8")).hexdigest(),
        "line": command.location.line,
        "role": "review_property_link",
        "exception_validated": False,
    }


def _worlds(bits: tuple[int, ...], fixed: Mapping[int, bool], limits: SequentialLimits) -> Iterator[dict[int, bool]]:
    free = tuple(b for b in bits if b not in fixed)
    if len(free) > limits.max_enum_free_bits:
        raise SequentialLimitError("enumeration free-variable limit")
    base = {b: fixed[b] for b in bits if b in fixed}
    for values in product((False, True), repeat=len(free)):
        yield base | dict(zip(free, values, strict=True))


def _frame(
    machine: Machine, state: tuple[bool, ...], inputs: Mapping[int, bool], observed: tuple[bool, ...]
) -> dict[str, Any]:
    return {
        "state": [int(v) for v in state],
        "inputs": [int(inputs[b]) for b in machine.inputs],
        "observed": [int(v) for v in observed],
    }


def _trace(trail: Trail | None, last: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    frames = [] if last is None else [last]
    while trail is not None:
        frames.append(trail.frame)
        trail = trail.previous
    return list(reversed(frames))


def _initial_states(machine: Machine, contract: Contract, budget: Budget) -> dict[tuple[bool, ...], Trail | None]:
    states: dict[tuple[bool, ...], Trail | None] = {}
    for values in _worlds(machine.states, contract.initial, budget.limits):
        budget.charge(machine.cost)
        state = tuple(values[b] for b in machine.states) + (False,) * machine.history
        states[state] = None
        if len(states) > budget.limits.max_states:
            raise SequentialLimitError("initial state count exceeds max_states")
    for prefix_index, fixed in enumerate(contract.prefix):
        following: dict[tuple[bool, ...], Trail | None] = {}
        for state, trail in sorted(states.items()):
            for inputs in _worlds(machine.inputs, fixed, budget.limits):
                budget.charge(machine.cost)
                next_state, observed, _ = machine.step(state, inputs, prefix=True)
                if next_state not in following:
                    following[next_state] = Trail(_frame(machine, state, inputs, observed), trail, prefix_index + 1)
                    if len(following) > budget.limits.max_states:
                        raise SequentialLimitError("prefix reachable states exceed max_states")
        states = following
    return states


def _binary(state: tuple[bool, ...]) -> str:
    return "".join("1" if v else "0" for v in state)


def _answer(
    status: str,
    reason: str,
    *,
    depth: int = -1,
    proof: object = None,
    witness: object = None,
    activation: object = None,
    unreachable: bool = False,
    spacing: bool = False,
) -> dict[str, Any]:
    return {
        "status": status,
        "reason": reason,
        "checked_depth": depth,
        "proof": proof,
        "counterexample": witness,
        "activation": "not_applicable"
        if not spacing
        else ("witnessed" if activation is not None else "unreachable" if unreachable else "not_witnessed"),
        "activation_witness": activation,
    }


def _enumerate(machine: Machine, contract: Contract, budget: Budget) -> dict[str, Any]:
    reached = _initial_states(machine, contract, budget)
    queue = deque(sorted(reached))
    activation = None
    depth = 0
    while queue:
        state = queue.popleft()
        trail = reached[state]
        depth = max(depth, (trail.length if trail else 0) - len(contract.prefix))
        for inputs in _worlds(machine.inputs, contract.assumptions, budget.limits):
            budget.charge(machine.cost)
            next_state, observed, bad = machine.step(state, inputs)
            frame = _frame(machine, state, inputs, observed)
            if machine.history and observed[0] and activation is None:
                activation = _trace(trail, frame)
            if bad:
                witness = _trace(trail, frame)
                return _answer(
                    "counterexample",
                    "reachable synchronous property violation",
                    depth=len(witness) - len(contract.prefix) - 1,
                    witness=witness,
                    activation=activation,
                    spacing=bool(machine.history),
                )
            if next_state not in reached:
                if len(reached) >= budget.limits.max_states:
                    raise SequentialLimitError("reachable-state limit; closure is not established")
                reached[next_state] = Trail(frame, trail, (trail.length if trail else 0) + 1)
                queue.append(next_state)
    return _answer(
        "proven",
        "complete inductively closed reachable-state set",
        depth=depth,
        proof={"kind": "reachable_invariant", "states": sorted(_binary(s) for s in reached)},
        activation=activation,
        unreachable=bool(machine.history and activation is None),
        spacing=bool(machine.history),
    )


def _symbolic_frame(
    z3: Any, machine: Machine, solver: Any, label: str, time: int, fixed: Mapping[int, bool], budget: Budget
) -> dict[str, Any]:
    budget.charge(machine.cost)
    values: dict[Any, Any] = {"0": z3.BoolVal(False), "1": z3.BoolVal(True)}
    state = [z3.Bool(f"{label}_state_{time}_{i}") for i in range(machine.width)]
    values.update(zip(machine.states, state[: len(machine.states)], strict=True))
    inputs = {b: z3.Bool(f"{label}_input_{time}_{b}") for b in machine.inputs}
    values.update(inputs)
    for bit in machine.inputs:
        if bit in fixed:
            solver.add(inputs[bit] == fixed[bit])
    for gate in machine.gates:
        output = z3.Bool(f"{label}_gate_{time}_{gate.output}")
        solver.add(output == _z3_expression(z3, gate.kind, [values[b] for b in gate.inputs]))
        values[gate.output] = output
    observed = [values[b] for b in machine.observed]
    bad = (
        z3.And(observed[0], z3.Or(*state[len(machine.states) :]))
        if machine.history
        else z3.And(*[value == expected for value, expected in zip(observed, machine.forbidden, strict=True)])
    )
    next_state = [values[b] for b in machine.next_bits]
    if machine.history:
        next_state += [observed[0]] + state[len(machine.states) : -1]
    return {"state": state, "inputs": inputs, "observed": observed, "bad": bad, "next": next_state}


def _transition(
    z3: Any,
    machine: Machine,
    solver: Any,
    previous: Mapping[str, Any],
    current: Mapping[str, Any],
    *,
    prefix: bool = False,
) -> None:
    expected = list(previous["next"])
    if prefix and machine.history:
        expected[len(machine.states) :] = [z3.BoolVal(False)] * machine.history
    solver.add(*[a == b for a, b in zip(expected, current["state"], strict=True)])


def _sat(solver: Any, z3: Any, budget: Budget) -> Any:
    budget.solver_call()
    answer = solver.check()
    if answer not in (z3.sat, z3.unsat):
        raise SequentialLimitError("solver returned unknown: " + str(solver.reason_unknown()))
    return answer


def _solver(z3: Any, limits: SequentialLimits) -> Any:
    solver = z3.Solver()
    solver.set(timeout=limits.solver_timeout_ms, rlimit=limits.solver_rlimit, random_seed=0)
    return solver


def _symbolic_trace(z3: Any, frames: list[dict[str, Any]], model: Any, machine: Machine) -> list[dict[str, Any]]:
    def concrete(value: Any) -> int:
        return int(z3.is_true(model.eval(value, model_completion=True)))

    return [
        {
            "state": [concrete(v) for v in f["state"]],
            "inputs": [concrete(f["inputs"][b]) for b in machine.inputs],
            "observed": [concrete(v) for v in f["observed"]],
        }
        for f in frames
    ]


def _induct(z3: Any, machine: Machine, contract: Contract, budget: Budget) -> dict[str, Any]:
    base, step = _solver(z3, budget.limits), _solver(z3, budget.limits)
    frames: list[dict[str, Any]] = []
    inductive: list[dict[str, Any]] = []
    activation = None
    proven_k = None
    prefix = len(contract.prefix)
    for time in range(prefix + budget.limits.max_depth + 1):
        fixed = contract.prefix[time] if time < prefix else contract.assumptions
        frame = _symbolic_frame(z3, machine, base, "base", time, fixed, budget)
        if frames:
            _transition(z3, machine, base, frames[-1], frame, prefix=time <= prefix)
        else:
            for index, bit in enumerate(machine.states):
                if bit in contract.initial:
                    base.add(frame["state"][index] == contract.initial[bit])
            base.add(*[z3.Not(v) for v in frame["state"][len(machine.states) :]])
        frames.append(frame)
        if time < prefix:
            continue
        depth = time - prefix
        if depth == 0 and _sat(base, z3, budget) != z3.sat:
            raise InconsistentContract("initial/prefix transition system is infeasible")
        base.push()
        base.add(frame["bad"])
        answer = _sat(base, z3, budget)
        if answer == z3.sat:
            witness = _symbolic_trace(z3, frames, base.model(), machine)
            base.pop()
            return _answer(
                "counterexample",
                "SAT bounded trace, independently concretely replayed",
                depth=depth,
                witness=witness,
                activation=witness if machine.history else None,
                spacing=bool(machine.history),
            )
        base.pop()
        if machine.history and activation is None:
            base.push()
            base.add(frame["observed"][0])
            if _sat(base, z3, budget) == z3.sat:
                activation = _symbolic_trace(z3, frames, base.model(), machine)
            base.pop()
        if depth >= 1 and proven_k is None:
            while len(inductive) <= depth:
                fresh = _symbolic_frame(z3, machine, step, "step", len(inductive), contract.assumptions, budget)
                if inductive:
                    step.add(z3.Not(inductive[-1]["bad"]))
                    _transition(z3, machine, step, inductive[-1], fresh)
                inductive.append(fresh)
            step.push()
            step.add(inductive[-1]["bad"])
            if _sat(step, z3, budget) == z3.unsat:
                proven_k = depth
            step.pop()
        if proven_k is not None and (not machine.history or activation is not None):
            break
    if proven_k is not None:
        return _answer(
            "proven",
            "base case and k-induction step are UNSAT",
            depth=depth,
            proof={"kind": "k_induction", "k": proven_k},
            activation=activation,
            spacing=bool(machine.history),
        )
    return _answer(
        "bounded",
        "no counterexample within the search depth, but no unbounded proof",
        depth=depth,
        activation=activation,
        spacing=bool(machine.history),
    )


def _cone(machine: Machine) -> dict[str, Any]:
    return {
        "state_bits": list(machine.states),
        "input_bits": list(machine.inputs),
        "history_bits": machine.history,
        "gate_count": len(machine.gates),
    }


def validate_trace(machine: Machine, contract: Contract, trace: object, budget: Budget, *, cover: bool = False) -> bool:
    """Concrete replay, independent of both the BFS and SMT search algorithms."""
    if (
        not isinstance(trace, list)
        or not len(contract.prefix)
        < len(trace)
        <= budget.limits.max_states + budget.limits.max_prefix + budget.limits.max_depth + 1
    ):
        return False
    previous: tuple[bool, ...] | None = None
    for index, raw in enumerate(trace):
        budget.charge(machine.cost)
        if not isinstance(raw, dict) or set(raw) != {"state", "inputs", "observed"}:
            return False
        sizes = {"state": machine.width, "inputs": len(machine.inputs), "observed": len(machine.observed)}
        if any(
            not isinstance(raw[k], list)
            or len(raw[k]) != size
            or any(type(v) is not int or v not in {0, 1} for v in raw[k])
            for k, size in sizes.items()
        ):
            return False
        state = tuple(bool(v) for v in raw["state"])
        inputs = dict(zip(machine.inputs, (bool(v) for v in raw["inputs"]), strict=True))
        if previous is not None and state != previous:
            return False
        if index == 0 and (
            any(bit in contract.initial and state[i] != contract.initial[bit] for i, bit in enumerate(machine.states))
            or any(state[len(machine.states) :])
        ):
            return False
        prefix = index < len(contract.prefix)
        fixed = contract.prefix[index] if prefix else contract.assumptions
        if any(bit in inputs and inputs[bit] != value for bit, value in fixed.items()):
            return False
        previous, observed, bad = machine.step(state, inputs, prefix=prefix)
        if raw["observed"] != [int(v) for v in observed]:
            return False
        if not prefix:
            if index == len(trace) - 1:
                return bool(observed[0]) if cover and machine.history else bad if not cover else False
            if bad:
                return False
    return False


def validate_invariant(
    machine: Machine, contract: Contract, proof: object, budget: Budget, *, require_unreachable: bool = False
) -> bool:
    """Check initiation, closure and safety of a supplied finite invariant.

    This is not a comparison of hashes and does not trust a BFS completion flag.
    Supersets of the reachable set are allowed only when all proof obligations
    hold. Event reachability must be established with a separate concrete trace.
    """
    if not isinstance(proof, dict) or set(proof) != {"kind", "states"} or proof["kind"] != "reachable_invariant":
        return False
    items = proof["states"]
    if not isinstance(items, list) or not 1 <= len(items) <= budget.limits.max_states:
        return False
    if any(not isinstance(s, str) or len(s) != machine.width or set(s) - {"0", "1"} for s in items) or items != sorted(
        set(items)
    ):
        return False
    invariant = {tuple(c == "1" for c in s) for s in items}
    initial = _initial_states(machine, contract, budget)
    if not initial or not set(initial) <= invariant:
        return False
    for state in sorted(invariant):
        for inputs in _worlds(machine.inputs, contract.assumptions, budget.limits):
            budget.charge(machine.cost)
            following, observed, bad = machine.step(state, inputs)
            if bad or following not in invariant or (require_unreachable and machine.history and observed[0]):
                return False
    return True


def analyze_sequential(
    netlist: Mapping[str, Any],
    specification: Mapping[str, Any],
    *,
    backend: str = "z3",
    limits: SequentialLimits | None = None,
    sdc_sources: Mapping[str, bytes] | None = None,
) -> dict[str, Any]:
    limits = limits or SequentialLimits()
    checks = _checks(specification, limits)
    if backend not in {"z3", "enumerate"}:
        raise FunctionalInputError("backend must be z3 or enumerate")
    sources = sdc_sources or {}
    manifest = _source_manifest(sources)
    budget = Budget(limits)
    z3 = None
    version = "builtin-v1" if backend == "enumerate" else "unavailable"
    model = None
    contract = None
    failure = None
    failure_status = "unsupported"
    try:
        model = load_synchronous_model(
            netlist, specification["top"], specification["clock"], specification["edge"], limits
        )
        contract = _contract(model, specification)
        if backend == "z3":
            z3 = importlib.import_module("z3")
            version = str(z3.get_version_string())
    except (SequentialLimitError, FunctionalLimitError) as error:
        failure, failure_status = str(error), "bounded"
    except InconsistentContract as error:
        failure, failure_status = str(error), "inconsistent_assumptions"
    except (FunctionalInputError, ImportError) as error:
        failure = str(error)
    results = []
    binding_cache: dict[str, Any] = {}
    for check in checks:
        entry: dict[str, Any] = {"id": check["id"], "query_digest": _digest(check), "cone": None, "binding": None}
        try:
            if failure:
                answer = _answer(failure_status, failure)
            else:
                assert model is not None and contract is not None
                entry["binding"] = _binding(check, sources, binding_cache)
                machine = build_machine(model, check, limits)
                entry["cone"] = _cone(machine)
                answer = (
                    _enumerate(machine, contract, budget)
                    if backend == "enumerate"
                    else _induct(z3, machine, contract, budget)
                )
                # Checking witnesses uses a separate finite budget: a search
                # exhausting its own budget may not suppress witness validation.
                replay_budget = Budget(limits)
                if answer["counterexample"] is not None and not validate_trace(
                    machine, contract, answer["counterexample"], replay_budget
                ):
                    raise RuntimeError("sequential solver returned an invalid counterexample")
                if answer["activation_witness"] is not None and not validate_trace(
                    machine, contract, answer["activation_witness"], replay_budget, cover=True
                ):
                    raise RuntimeError("sequential solver returned an invalid activation witness")
        except (SequentialLimitError, FunctionalLimitError) as error:
            answer = _answer("bounded", str(error))
        except InconsistentContract as error:
            answer = _answer("inconsistent_assumptions", str(error))
        except (FunctionalInputError, UnicodeError) as error:
            answer = _answer("unsupported", str(error))
        entry.update(answer)
        results.append(entry)
    report = {
        "schema_version": "1.0.0",
        "algorithm": ALGORITHM,
        "model": MODEL,
        "timing_signoff": False,
        "tool": {"name": "OpenConstraint", "version": __version__},
        "backend": {"name": backend, "version": version},
        "limits": asdict(limits),
        "netlist_digest": _digest(netlist),
        "specification_digest": _digest(specification),
        "sdc_sources": manifest,
        "summary": dict(sorted(Counter(c["status"] for c in results).items())),
        "checks": results,
        "passed": all(c["status"] == "proven" and c["activation"] in {"witnessed", "not_applicable"} for c in results),
    }
    report["report_digest"] = _digest(report)
    return report


def verify_sequential(
    expected: Mapping[str, Any],
    netlist: Mapping[str, Any],
    specification: Mapping[str, Any],
    *,
    backend: str = "enumerate",
    limits: SequentialLimits | None = None,
    sdc_sources: Mapping[str, bytes] | None = None,
) -> dict[str, Any]:
    """Replay counterexamples and prove saved safety conclusions afresh.

    The default verifier needs no SMT solver for finite-invariant certificates
    or counterexamples. An SMT proof can be cross-checked by complete search.
    Resource-limited or unsupported outcomes never count as verified proofs.
    """
    limits = limits or SequentialLimits()
    sources = sdc_sources or {}
    errors: list[str] = []
    passed = True
    try:
        if backend not in {"enumerate", "z3"}:
            raise FunctionalInputError("invalid replay backend")
        checks = _checks(specification, limits)
        model = load_synchronous_model(
            netlist, specification["top"], specification["clock"], specification["edge"], limits
        )
        contract = _contract(model, specification)
        fields = {
            "schema_version",
            "algorithm",
            "model",
            "timing_signoff",
            "tool",
            "backend",
            "limits",
            "netlist_digest",
            "specification_digest",
            "sdc_sources",
            "summary",
            "checks",
            "passed",
            "report_digest",
        }
        _keys(expected, fields, fields, "saved sequential report")
        if expected["report_digest"] != _digest({k: v for k, v in expected.items() if k != "report_digest"}):
            raise FunctionalInputError("report integrity mismatch")
        required = {
            "schema_version": "1.0.0",
            "algorithm": ALGORITHM,
            "model": MODEL,
            "timing_signoff": False,
            "netlist_digest": _digest(netlist),
            "specification_digest": _digest(specification),
            "sdc_sources": _source_manifest(sources),
        }
        for key, value in required.items():
            if type(expected[key]) is not type(value) or expected[key] != value:
                raise FunctionalInputError(f"{key} mismatch")
        for key in ("tool", "backend"):
            meta = _object(expected[key], key)
            _keys(meta, {"name", "version"}, {"name", "version"}, key)
            if (
                not isinstance(meta["version"], str)
                or not meta["version"]
                or meta["name"] not in ({"OpenConstraint"} if key == "tool" else {"z3", "enumerate"})
            ):
                raise FunctionalInputError(f"invalid {key}")
        saved_limits = _object(expected["limits"], "saved limits")
        _keys(saved_limits, set(asdict(limits)), set(asdict(limits)), "saved limits")
        SequentialLimits(**saved_limits)
        entries = expected["checks"]
        if not isinstance(entries, list) or len(entries) != len(checks):
            raise FunctionalInputError("check inventory mismatch")
        summary = _object(expected["summary"], "summary")
        if any(type(v) is not int or v < 1 for v in summary.values()):
            raise FunctionalInputError("invalid summary counts")
        cache: dict[str, Any] = {}
        budget = Budget(limits)
        statuses = []
        for raw, check in zip(entries, checks, strict=True):
            entry = _object(raw, "saved check")
            entry_fields = {
                "id",
                "query_digest",
                "cone",
                "binding",
                "status",
                "reason",
                "checked_depth",
                "proof",
                "counterexample",
                "activation",
                "activation_witness",
            }
            _keys(entry, entry_fields, entry_fields, "saved check")
            machine = build_machine(model, check, limits)
            if (
                entry["id"] != check["id"]
                or entry["query_digest"] != _digest(check)
                or entry["cone"] != _cone(machine)
                or entry["binding"] != _binding(check, sources, cache)
            ):
                raise FunctionalInputError("query, cone or SDC binding mismatch")
            status = entry["status"]
            statuses.append(status)
            if status not in {"proven", "counterexample"}:
                raise FunctionalInputError("nondecision cannot be verified as a proof")
            if (
                not isinstance(entry["reason"], str)
                or type(entry["checked_depth"]) is not int
                or entry["checked_depth"] < 0
            ):
                raise FunctionalInputError("invalid decision metadata")
            activation = entry["activation"]
            if (machine.history and activation not in {"witnessed", "unreachable", "not_witnessed"}) or (
                not machine.history and activation != "not_applicable"
            ):
                raise FunctionalInputError("invalid activation state")
            if activation == "witnessed":
                if not validate_trace(machine, contract, entry["activation_witness"], budget, cover=True):
                    raise FunctionalInputError("invalid activation trace")
            elif entry["activation_witness"] is not None:
                raise FunctionalInputError("unexpected activation trace")
            if status == "counterexample":
                if entry["proof"] is not None or not validate_trace(machine, contract, entry["counterexample"], budget):
                    raise FunctionalInputError("invalid stored counterexample")
                if machine.history and activation != "witnessed":
                    raise FunctionalInputError("spacing violation must witness activation")
                passed = False
            else:
                if entry["counterexample"] is not None:
                    raise FunctionalInputError("unexpected violation trace on proof")
                proof = _object(entry["proof"], "proof certificate")
                if proof.get("kind") == "reachable_invariant":
                    if not validate_invariant(
                        machine, contract, proof, budget, require_unreachable=activation == "unreachable"
                    ):
                        raise FunctionalInputError("invariant initiation, safety, or closure failed")
                elif proof.get("kind") == "k_induction":
                    _keys(proof, {"kind", "k"}, {"kind", "k"}, "induction proof")
                    if (
                        type(proof["k"]) is not int
                        or not 1 <= proof["k"] <= entry["checked_depth"] <= saved_limits["max_depth"]
                        or activation == "unreachable"
                    ):
                        raise FunctionalInputError("invalid induction metadata")
                    fresh = (
                        _enumerate(machine, contract, budget)
                        if backend == "enumerate"
                        else _induct(importlib.import_module("z3"), machine, contract, budget)
                    )
                    if fresh["status"] != "proven":
                        raise FunctionalInputError("unbounded proof could not be independently reproduced")
                else:
                    raise FunctionalInputError("unknown proof certificate kind")
                passed = passed and activation in {"witnessed", "not_applicable"}
        if summary != dict(Counter(statuses)) or type(expected["passed"]) is not bool or expected["passed"] != passed:
            raise FunctionalInputError("summary or pass-state mismatch")
    except (ValueError, TypeError, KeyError, ImportError, UnicodeError, RecursionError) as error:
        errors.append(str(error))
    return {
        "verified": not errors,
        "passed": not errors and passed,
        "timing_signoff": False,
        "replay_backend": backend,
        "errors": errors,
    }
