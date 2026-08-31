"""Opt-in validation with an installed OpenSTA executable.

This module deliberately does not run OpenSTA at import time.  SDC is Tcl, so the
adapter is only suitable for netlists, libraries, and constraints that the caller
trusts to execute with the caller's permissions.
"""

from __future__ import annotations

import math
import os
import shutil
import subprocess
import tempfile
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

DEFAULT_TIMEOUT = 120.0
_BINARY_NAMES = ("sta", "opensta")
_CHECK_SETUP_FAILURE = "OpenConstraint: check_setup reported one or more issues."

PathValue = str | os.PathLike[str]


class OpenSTAError(RuntimeError):
    """Base error raised when OpenSTA cannot be started reliably."""


class OpenSTANotFoundError(OpenSTAError, FileNotFoundError):
    """Raised when neither ``sta`` nor ``opensta`` can be found."""


@dataclass(frozen=True, slots=True)
class OpenSTAModeConfig:
    """The SDC files that form one independently evaluated mode."""

    name: str
    sdc_paths: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "sdc_paths": list(self.sdc_paths)}


@dataclass(frozen=True, slots=True)
class OpenSTAConfig:
    """Resolved configuration used for an OpenSTA validation run."""

    binary: str
    timeout: float
    verilog_paths: tuple[str, ...]
    liberty_paths: tuple[str, ...]
    top: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "binary": self.binary,
            "timeout": self.timeout,
            "verilog_paths": list(self.verilog_paths),
            "liberty_paths": list(self.liberty_paths),
            "top": self.top,
        }


@dataclass(frozen=True, slots=True)
class OpenSTAModeResult:
    """Captured result of one isolated OpenSTA process."""

    mode: str
    sdc_paths: tuple[str, ...]
    version: str
    command: tuple[str, ...]
    stdout: str
    stderr: str
    returncode: int | None
    timed_out: bool
    duration_seconds: float
    effective_sdc: str | None
    effective_sdc_sha256: str | None

    @property
    def return_code(self) -> int | None:
        """Alias using the spelling commonly used in machine-readable reports."""

        return self.returncode

    @property
    def effective_sdc_hash(self) -> str | None:
        """SHA-256 alias for callers that do not need to name the algorithm."""

        return self.effective_sdc_sha256

    @property
    def succeeded(self) -> bool:
        """Whether OpenSTA completed cleanly and emitted effective constraints."""

        return not self.timed_out and self.returncode == 0 and self.effective_sdc is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "sdc_paths": list(self.sdc_paths),
            "version": self.version,
            "command": list(self.command),
            "stdout": self.stdout,
            "stderr": self.stderr,
            "return_code": self.returncode,
            "timed_out": self.timed_out,
            "duration_seconds": self.duration_seconds,
            "effective_sdc": self.effective_sdc,
            "effective_sdc_sha256": self.effective_sdc_sha256,
            "succeeded": self.succeeded,
        }


@dataclass(frozen=True, slots=True)
class OpenSTAValidationResult:
    """All mode results from one explicit validation request."""

    config: OpenSTAConfig
    version: str
    modes: tuple[OpenSTAModeResult, ...]

    @property
    def succeeded(self) -> bool:
        return bool(self.modes) and all(mode.succeeded for mode in self.modes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "config": self.config.to_dict(),
            "version": self.version,
            "succeeded": self.succeeded,
            "modes": [mode.to_dict() for mode in self.modes],
        }


def _text(value: object, label: str) -> str:
    if isinstance(value, str):
        result = value
    elif isinstance(value, os.PathLike):
        path_value = os.fspath(value)
        if not isinstance(path_value, str):
            raise TypeError(f"{label} must resolve to text, not bytes")
        result = path_value
    else:
        raise TypeError(f"{label} must be a string or path-like object")
    if "\n" in result or "\r" in result:
        raise ValueError(f"{label} must not contain newlines")
    if "\x00" in result:
        raise ValueError(f"{label} must not contain NUL characters")
    return result


def tcl_quote(value: PathValue) -> str:
    """Return one substitution-safe Tcl word, rejecting line-based injection."""

    raw = _text(value, "Tcl value")
    escaped = raw.replace("\\", "\\\\")
    escaped = escaped.replace('"', '\\"')
    escaped = escaped.replace("$", "\\$")
    escaped = escaped.replace("[", "\\[").replace("]", "\\]")
    return f'"{escaped}"'


def discover_opensta(binary: PathValue | None = None) -> str:
    """Resolve an explicit OpenSTA executable or discover ``sta``/``opensta``."""

    candidates: tuple[str, ...]
    if binary is not None:
        requested = _text(binary, "OpenSTA binary")
        candidates = (requested,)
    else:
        candidates = _BINARY_NAMES

    for candidate in candidates:
        located = shutil.which(candidate)
        if located is None and binary is not None:
            candidate_path = Path(candidate).expanduser()
            if candidate_path.is_file():
                located = str(candidate_path.resolve())
        if located is not None:
            return str(Path(located).resolve())

    if binary is None:
        detail = " or ".join(repr(name) for name in _BINARY_NAMES)
        raise OpenSTANotFoundError(f"OpenSTA was not found on PATH (looked for {detail})")
    raise OpenSTANotFoundError(f"OpenSTA executable was not found: {candidates[0]!r}")


def _input_file(value: object, label: str) -> str:
    raw = _text(value, label)
    path = Path(raw).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"{label} is not a file: {path}")
    return str(path)


def _input_paths(values: Iterable[PathValue], label: str) -> tuple[str, ...]:
    paths = tuple(_input_file(value, label) for value in values)
    if not paths:
        raise ValueError(f"at least one {label} is required")
    return paths


def _path_items(value: object, label: str) -> tuple[object, ...]:
    if isinstance(value, (str, os.PathLike)):
        return (value,)
    if not isinstance(value, Iterable):
        raise TypeError(f"{label} must be a path or an iterable of paths")
    return tuple(value)


def _mode_parts(value: object) -> tuple[object, object]:
    if isinstance(value, OpenSTAModeConfig):
        return value.name, value.sdc_paths
    if isinstance(value, tuple) and len(value) == 2:
        return value[0], value[1]
    name = getattr(value, "name", None)
    paths = getattr(value, "sdc_paths", None)
    if name is None or paths is None:
        raise TypeError("each mode must provide 'name' and 'sdc_paths'")
    return name, paths


def _normalize_modes(modes: Mapping[str, object] | Iterable[object]) -> tuple[OpenSTAModeConfig, ...]:
    if isinstance(modes, Mapping):
        raw_modes: Iterable[tuple[object, object]] = modes.items()
    else:
        raw_modes = (_mode_parts(value) for value in modes)

    normalized: list[OpenSTAModeConfig] = []
    names: set[str] = set()
    for raw_name, raw_paths in raw_modes:
        if not isinstance(raw_name, str):
            raise TypeError("mode names must be strings")
        name = _text(raw_name, "mode name").strip()
        if not name:
            raise ValueError("mode names must not be empty")
        if name in names:
            raise ValueError(f"duplicate mode name: {name!r}")
        paths = tuple(_input_file(path, f"SDC file for mode {name!r}") for path in _path_items(raw_paths, "SDC paths"))
        if not paths:
            raise ValueError(f"mode {name!r} must contain at least one SDC file")
        names.add(name)
        normalized.append(OpenSTAModeConfig(name, paths))
    if not normalized:
        raise ValueError("at least one mode is required")
    return tuple(normalized)


def render_opensta_tcl(
    config: OpenSTAConfig,
    mode: OpenSTAModeConfig,
    effective_sdc_path: PathValue,
) -> str:
    """Build the fixed Tcl driver used for one mode.

    Dynamic data is always passed as a quoted Tcl word.  The SDC files themselves
    remain executable Tcl and must therefore be trusted by the caller.
    """

    effective_path = str(Path(_text(effective_sdc_path, "effective SDC path")).resolve())
    commands = ["# Generated by OpenConstraint; do not edit.", "set ::sta_continue_on_error 0"]
    commands.extend(f"read_liberty {tcl_quote(path)}" for path in config.liberty_paths)
    commands.extend(f"read_verilog {tcl_quote(path)}" for path in config.verilog_paths)
    commands.append(f"link_design {tcl_quote(config.top)}")
    commands.extend(f"read_sdc {tcl_quote(path)}" for path in mode.sdc_paths)
    commands.extend(
        (
            "set ::openconstraint_check_ok [check_setup -verbose]",
            f"write_sdc -no_timestamp {tcl_quote(effective_path)}",
            "if {!$::openconstraint_check_ok} {",
            f"    puts stderr {tcl_quote(_CHECK_SETUP_FAILURE)}",
            "    exit 2",
            "}",
        )
    )
    return "\n".join(commands) + "\n"


def _timeout_value(timeout: float) -> float:
    if isinstance(timeout, bool):
        raise TypeError("timeout must be a positive number of seconds")
    try:
        result = float(timeout)
    except (TypeError, ValueError) as error:
        raise TypeError("timeout must be a positive number of seconds") from error
    if not math.isfinite(result) or result <= 0:
        raise ValueError("timeout must be a positive, finite number of seconds")
    return result


def _captured_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _opensta_version(binary: str, timeout: float) -> str:
    command = (binary, "-version")
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as error:
        raise OpenSTAError(f"OpenSTA version query timed out after {timeout:g} seconds") from error
    except OSError as error:
        raise OpenSTAError(f"could not execute OpenSTA at {binary!r}: {error}") from error
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        suffix = f": {detail}" if detail else ""
        raise OpenSTAError(f"OpenSTA version query exited with {completed.returncode}{suffix}")
    output = completed.stdout.strip() or completed.stderr.strip()
    return output.splitlines()[0].strip() if output else "unknown"


def _effective_sdc(path: Path) -> tuple[str | None, str | None]:
    try:
        payload = path.read_bytes()
    except FileNotFoundError:
        return None, None
    return payload.decode("utf-8", errors="replace"), sha256(payload).hexdigest()


def _validate_mode(config: OpenSTAConfig, mode: OpenSTAModeConfig, version: str) -> OpenSTAModeResult:
    with tempfile.TemporaryDirectory(prefix="openconstraint-opensta-") as temporary_directory:
        directory = Path(temporary_directory)
        script_path = directory / "validate.tcl"
        effective_path = directory / "effective.sdc"
        script_path.write_text(
            render_opensta_tcl(config, mode, effective_path),
            encoding="utf-8",
            newline="\n",
        )
        command = (config.binary, "-no_init", "-no_splash", "-exit", str(script_path))
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=config.timeout,
                check=False,
                shell=False,
            )
            stdout = completed.stdout
            stderr = completed.stderr
            returncode: int | None = completed.returncode
            timed_out = False
        except subprocess.TimeoutExpired as error:
            stdout = _captured_text(error.stdout)
            stderr = _captured_text(error.stderr)
            returncode = None
            timed_out = True
        except OSError as error:
            raise OpenSTAError(f"could not execute OpenSTA for mode {mode.name!r}: {error}") from error
        duration = time.monotonic() - started
        effective_sdc, effective_hash = _effective_sdc(effective_path)
        return OpenSTAModeResult(
            mode=mode.name,
            sdc_paths=mode.sdc_paths,
            version=version,
            command=command,
            stdout=stdout,
            stderr=stderr,
            returncode=returncode,
            timed_out=timed_out,
            duration_seconds=duration,
            effective_sdc=effective_sdc,
            effective_sdc_sha256=effective_hash,
        )


def validate_with_opensta(
    verilog_paths: Iterable[PathValue],
    liberty_paths: Iterable[PathValue],
    top: str,
    modes: Mapping[str, object] | Iterable[object],
    binary: PathValue | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> OpenSTAValidationResult:
    """Validate trusted SDC modes with independent OpenSTA subprocesses.

    ``modes`` may be a mapping from mode names to SDC paths, an iterable of
    :class:`OpenSTAModeConfig`, or existing mode-like objects with ``name`` and
    ``sdc_paths`` attributes.  Calling this function is the only action in this
    module that executes OpenSTA.
    """

    timeout_seconds = _timeout_value(timeout)
    top_name = _text(top, "top module").strip()
    if not top_name:
        raise ValueError("top module must not be empty")
    config = OpenSTAConfig(
        binary=discover_opensta(binary),
        timeout=timeout_seconds,
        verilog_paths=_input_paths(verilog_paths, "Verilog file"),
        liberty_paths=_input_paths(liberty_paths, "Liberty file"),
        top=top_name,
    )
    mode_configs = _normalize_modes(modes)
    version = _opensta_version(config.binary, config.timeout)
    results = tuple(_validate_mode(config, mode, version) for mode in mode_configs)
    return OpenSTAValidationResult(config=config, version=version, modes=results)


__all__ = [
    "DEFAULT_TIMEOUT",
    "OpenSTAConfig",
    "OpenSTAError",
    "OpenSTAModeConfig",
    "OpenSTAModeResult",
    "OpenSTANotFoundError",
    "OpenSTAValidationResult",
    "discover_opensta",
    "render_opensta_tcl",
    "tcl_quote",
    "validate_with_opensta",
]
