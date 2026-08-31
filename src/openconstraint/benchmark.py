"""Reproducible, offline-capable benchmark acquisition and execution.

The benchmark layer intentionally uses only the Python standard library.  It
does not vendor third-party designs: manifests record upstream provenance and
the cache stores content-addressed archives outside the source tree.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import stat
import tarfile
import tempfile
import time
import tracemalloc
import unicodedata
import urllib.error
import urllib.request
import zipfile
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Literal
from urllib.parse import urlparse

from openconstraint.engine import AuditOptions, ModeInput, audit
from openconstraint.model import AuditResult, Design, Diagnostic, effective_io_delay_semantics
from openconstraint.parsers.liberty import CellLibrary, parse_liberty
from openconstraint.parsers.verilog import elaborate, parse_verilog
from openconstraint.version import __version__

MANIFEST_SCHEMA_VERSION = "1.0.0"
RESULT_SCHEMA_VERSION = "1.0.0"
BASELINE_SCHEMA_VERSION = "1.0.0"
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_ARCHIVE_ENTRIES = 100_000
_MAX_JSON_BYTES = 64 * 1024 * 1024
_MAX_JSON_DEPTH = 256
_MAX_JSON_NODES = 1_000_000
_WINDOWS_RESERVED_NAMES = {
    "aux",
    "con",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}

JsonObject = dict[str, Any]
Downloader = Callable[["Artifact", Path], None]
_GITHUB_TOKEN_ENV = "OPENCONSTRAINT_GITHUB_TOKEN"


class BenchmarkError(ValueError):
    """A manifest, acquisition, cache, or baseline error."""


@dataclass(frozen=True, slots=True)
class LicenseMetadata:
    spdx: str
    url: str
    notice: str
    repository_license_url: str | None = None


@dataclass(frozen=True, slots=True)
class SuiteFile:
    path: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class Artifact:
    artifact_id: str
    url: str
    sha256: str
    size_bytes: int
    archive: str
    unpacked_size_limit_bytes: int
    license: LicenseMetadata
    strip_prefix: str = ""
    filename: str | None = None


@dataclass(frozen=True, slots=True)
class ArtifactCachePaths:
    """Content-addressed cache locations derived from one artifact record."""

    blob: Path
    digest_root: Path
    materialization_root: Path
    logical_root: Path


@dataclass(frozen=True, slots=True)
class InputReference:
    origin: str
    path: str


@dataclass(frozen=True, slots=True)
class BenchmarkCase:
    case_id: str
    description: str
    top: str
    verilog: tuple[InputReference, ...]
    liberty: tuple[InputReference, ...]
    modes: Mapping[str, tuple[InputReference, ...]]
    tags: tuple[str, ...] = ()
    options: AuditOptions = field(default_factory=AuditOptions)


@dataclass(frozen=True, slots=True)
class Dataset:
    dataset_id: str
    description: str
    artifacts: tuple[Artifact, ...]
    cases: tuple[BenchmarkCase, ...]


@dataclass(frozen=True, slots=True)
class BenchmarkManifest:
    path: Path
    suite_id: str
    name: str
    description: str
    datasets: tuple[Dataset, ...]
    suite_files: Mapping[str, SuiteFile]
    digest: str


def _reject_constant(value: str) -> None:
    raise BenchmarkError(f"non-finite JSON number {value!r} is not allowed")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            raise BenchmarkError(f"duplicate JSON key {key!r} is not allowed")
        result[key] = value
    return result


def _validate_json_shape(value: object, label: str) -> None:
    """Bound nested/container work before schema-specific traversal."""

    stack: list[tuple[object, int]] = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES:
            raise BenchmarkError(f"{label} exceeds the JSON node limit of {_MAX_JSON_NODES}")
        if depth > _MAX_JSON_DEPTH:
            raise BenchmarkError(f"{label} exceeds the JSON nesting limit of {_MAX_JSON_DEPTH}")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)


def _load_json(path: Path, label: str) -> object:
    try:
        size = path.stat().st_size
        if size > _MAX_JSON_BYTES:
            raise BenchmarkError(f"{label} exceeds the JSON size limit of {_MAX_JSON_BYTES} bytes")
        text = path.read_text(encoding="utf-8")
        value = json.loads(
            text,
            parse_constant=_reject_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except json.JSONDecodeError as error:
        raise BenchmarkError(f"invalid {label} JSON: {error}") from error
    except RecursionError as error:
        raise BenchmarkError(f"{label} exceeds the JSON nesting limit of {_MAX_JSON_DEPTH}") from error
    _validate_json_shape(value, label)
    return value


def _object(value: object, where: str) -> JsonObject:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise BenchmarkError(f"{where} must be a JSON object")
    return value


def _array(value: object, where: str) -> list[object]:
    if not isinstance(value, list):
        raise BenchmarkError(f"{where} must be a JSON array")
    return value


def _string(value: object, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BenchmarkError(f"{where} must be a non-empty string")
    return value


def _identifier(value: object, where: str) -> str:
    result = _string(value, where)
    if not _IDENTIFIER.fullmatch(result):
        raise BenchmarkError(f"{where} must match {_IDENTIFIER.pattern}")
    return result


def _positive_integer(value: object, where: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise BenchmarkError(f"{where} must be a positive integer")
    return value


def _known_keys(value: Mapping[str, object], allowed: set[str], where: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise BenchmarkError(f"{where} contains unknown key(s): {', '.join(unknown)}")


def _relative_path(value: object, where: str, *, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    result = _string(value, where).replace("\\", "/")
    path = PurePosixPath(result)
    windows_path = PureWindowsPath(result)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise BenchmarkError(f"{where} must be a normalized relative path")
    if windows_path.drive or windows_path.root or ":" in result:
        raise BenchmarkError(f"{where} must not use a Windows drive, root, or alternate data stream")
    normalized = path.as_posix()
    if normalized != result or normalized in {".", ""}:
        raise BenchmarkError(f"{where} must be a normalized relative path")
    return normalized


def _parse_license(raw: object, where: str) -> LicenseMetadata:
    value = _object(raw, where)
    _known_keys(value, {"spdx", "url", "notice", "repository_license_url"}, where)
    spdx = _string(value.get("spdx"), f"{where}.spdx")
    url = _string(value.get("url"), f"{where}.url")
    if urlparse(url).scheme != "https":
        raise BenchmarkError(f"{where}.url must use HTTPS")
    repository_value = value.get("repository_license_url")
    repository_url = None if repository_value is None else _string(repository_value, f"{where}.repository_license_url")
    if repository_url is not None and urlparse(repository_url).scheme != "https":
        raise BenchmarkError(f"{where}.repository_license_url must use HTTPS")
    return LicenseMetadata(spdx, url, _string(value.get("notice"), f"{where}.notice"), repository_url)


def _parse_suite_file(raw: object, where: str) -> SuiteFile:
    value = _object(raw, where)
    _known_keys(value, {"path", "sha256", "size_bytes"}, where)
    digest = _string(value.get("sha256"), f"{where}.sha256")
    if not _SHA256.fullmatch(digest):
        raise BenchmarkError(f"{where}.sha256 must be 64 lowercase hexadecimal characters")
    return SuiteFile(
        _relative_path(value.get("path"), f"{where}.path"),
        digest,
        _positive_integer(value.get("size_bytes"), f"{where}.size_bytes"),
    )


def _parse_artifact(raw: object, where: str) -> Artifact:
    value = _object(raw, where)
    _known_keys(
        value,
        {
            "id",
            "url",
            "sha256",
            "size_bytes",
            "archive",
            "unpacked_size_limit_bytes",
            "strip_prefix",
            "filename",
            "license",
        },
        where,
    )
    url = _string(value.get("url"), f"{where}.url")
    if urlparse(url).scheme != "https":
        raise BenchmarkError(f"{where}.url must use HTTPS")
    digest = _string(value.get("sha256"), f"{where}.sha256")
    if not _SHA256.fullmatch(digest):
        raise BenchmarkError(f"{where}.sha256 must be 64 lowercase hexadecimal characters")
    archive = _string(value.get("archive"), f"{where}.archive")
    if archive not in {"none", "tar.gz", "tar.xz", "zip"}:
        raise BenchmarkError(f"{where}.archive must be one of none, tar.gz, tar.xz, or zip")
    filename_value = value.get("filename")
    if archive == "none":
        filename = _relative_path(filename_value, f"{where}.filename")
    elif filename_value is not None:
        raise BenchmarkError(f"{where}.filename is only valid when archive is none")
    else:
        filename = None
    return Artifact(
        artifact_id=_identifier(value.get("id"), f"{where}.id"),
        url=url,
        sha256=digest,
        size_bytes=_positive_integer(value.get("size_bytes"), f"{where}.size_bytes"),
        archive=archive,
        unpacked_size_limit_bytes=_positive_integer(
            value.get("unpacked_size_limit_bytes"), f"{where}.unpacked_size_limit_bytes"
        ),
        strip_prefix=_relative_path(value.get("strip_prefix", ""), f"{where}.strip_prefix", allow_empty=True),
        license=_parse_license(value.get("license"), f"{where}.license"),
        filename=filename,
    )


def _parse_reference(raw: object, where: str, artifact_ids: set[str]) -> InputReference:
    value = _string(raw, where)
    if ":" not in value:
        raise BenchmarkError(f"{where} must use ORIGIN:PATH syntax")
    origin, path = value.split(":", 1)
    if origin != "suite" and origin not in artifact_ids:
        raise BenchmarkError(f"{where} refers to unknown artifact {origin!r}")
    return InputReference(origin, _relative_path(path, where))


def _parse_references(raw: object, where: str, artifact_ids: set[str]) -> tuple[InputReference, ...]:
    values = _array(raw, where)
    if not values:
        raise BenchmarkError(f"{where} must not be empty")
    return tuple(_parse_reference(item, f"{where}[{index}]", artifact_ids) for index, item in enumerate(values))


def _parse_options(raw: object, where: str) -> AuditOptions:
    value = _object(raw, where)
    _known_keys(
        value,
        {"broad_match_count", "broad_match_ratio", "broad_match_min_universe", "report_implicit_waveform"},
        where,
    )
    count = value.get("broad_match_count", 50)
    minimum = value.get("broad_match_min_universe", 5)
    ratio = value.get("broad_match_ratio", 0.8)
    waveform = value.get("report_implicit_waveform", True)
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise BenchmarkError(f"{where}.broad_match_count must be a nonnegative integer")
    if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 0:
        raise BenchmarkError(f"{where}.broad_match_min_universe must be a nonnegative integer")
    if not isinstance(ratio, (int, float)) or isinstance(ratio, bool) or not 0 <= ratio <= 1:
        raise BenchmarkError(f"{where}.broad_match_ratio must be from 0 through 1")
    if not isinstance(waveform, bool):
        raise BenchmarkError(f"{where}.report_implicit_waveform must be a boolean")
    return AuditOptions(count, float(ratio), minimum, waveform)


def _parse_case(raw: object, where: str, artifact_ids: set[str]) -> BenchmarkCase:
    value = _object(raw, where)
    _known_keys(value, {"id", "description", "top", "verilog", "liberty", "modes", "tags", "options"}, where)
    raw_modes = _object(value.get("modes"), f"{where}.modes")
    if not raw_modes:
        raise BenchmarkError(f"{where}.modes must not be empty")
    modes: dict[str, tuple[InputReference, ...]] = {}
    for mode_name, references in raw_modes.items():
        name = _identifier(mode_name, f"{where}.modes key")
        modes[name] = _parse_references(references, f"{where}.modes.{name}", artifact_ids)
    tags_raw = _array(value.get("tags", []), f"{where}.tags")
    tags = tuple(_identifier(item, f"{where}.tags[{index}]") for index, item in enumerate(tags_raw))
    if len(tags) != len(set(tags)):
        raise BenchmarkError(f"{where}.tags contains duplicates")
    return BenchmarkCase(
        case_id=_identifier(value.get("id"), f"{where}.id"),
        description=_string(value.get("description"), f"{where}.description"),
        top=_string(value.get("top"), f"{where}.top"),
        verilog=_parse_references(value.get("verilog"), f"{where}.verilog", artifact_ids),
        liberty=_parse_references(value.get("liberty"), f"{where}.liberty", artifact_ids),
        modes=modes,
        tags=tags,
        options=_parse_options(value.get("options", {}), f"{where}.options"),
    )


def _parse_dataset(raw: object, where: str) -> Dataset:
    value = _object(raw, where)
    _known_keys(value, {"id", "description", "artifacts", "cases"}, where)
    raw_artifacts = _array(value.get("artifacts"), f"{where}.artifacts")
    artifacts = tuple(_parse_artifact(item, f"{where}.artifacts[{index}]") for index, item in enumerate(raw_artifacts))
    artifact_ids = [artifact.artifact_id for artifact in artifacts]
    if len(artifact_ids) != len(set(artifact_ids)):
        raise BenchmarkError(f"{where}.artifacts contains duplicate IDs")
    raw_cases = _array(value.get("cases"), f"{where}.cases")
    if not raw_cases:
        raise BenchmarkError(f"{where}.cases must not be empty")
    cases = tuple(
        _parse_case(item, f"{where}.cases[{index}]", set(artifact_ids)) for index, item in enumerate(raw_cases)
    )
    case_ids = [case.case_id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise BenchmarkError(f"{where}.cases contains duplicate IDs")
    return Dataset(
        dataset_id=_identifier(value.get("id"), f"{where}.id"),
        description=_string(value.get("description"), f"{where}.description"),
        artifacts=artifacts,
        cases=cases,
    )


def load_manifest(path: str | Path) -> BenchmarkManifest:
    """Load and strictly validate one benchmark manifest."""

    manifest_path = Path(path).resolve()
    raw = _load_json(manifest_path, "benchmark manifest")
    root = _object(raw, "manifest")
    _known_keys(root, {"schema_version", "suite", "suite_files", "datasets"}, "manifest")
    version = _string(root.get("schema_version"), "manifest.schema_version")
    if version != MANIFEST_SCHEMA_VERSION:
        raise BenchmarkError(f"unsupported benchmark manifest schema {version!r}")
    suite = _object(root.get("suite"), "manifest.suite")
    _known_keys(suite, {"id", "name", "description"}, "manifest.suite")
    raw_datasets = _array(root.get("datasets"), "manifest.datasets")
    if not raw_datasets:
        raise BenchmarkError("manifest.datasets must not be empty")
    datasets = tuple(_parse_dataset(item, f"manifest.datasets[{index}]") for index, item in enumerate(raw_datasets))
    dataset_ids = [dataset.dataset_id for dataset in datasets]
    if len(dataset_ids) != len(set(dataset_ids)):
        raise BenchmarkError("manifest.datasets contains duplicate IDs")
    raw_suite_files = _array(root.get("suite_files"), "manifest.suite_files")
    suite_file_values = tuple(
        _parse_suite_file(item, f"manifest.suite_files[{index}]") for index, item in enumerate(raw_suite_files)
    )
    suite_file_paths = [item.path for item in suite_file_values]
    if len(suite_file_paths) != len(set(suite_file_paths)):
        raise BenchmarkError("manifest.suite_files contains duplicate paths")
    suite_files = {item.path: item for item in suite_file_values}
    referenced_suite_files = {
        reference.path
        for dataset in datasets
        for case in dataset.cases
        for reference in [*case.verilog, *case.liberty, *(item for values in case.modes.values() for item in values)]
        if reference.origin == "suite"
    }
    missing_suite_files = referenced_suite_files - set(suite_files)
    if missing_suite_files:
        raise BenchmarkError(
            "manifest.suite_files has no integrity metadata for: " + ", ".join(sorted(missing_suite_files))
        )
    unused_suite_files = set(suite_files) - referenced_suite_files
    if unused_suite_files:
        raise BenchmarkError("manifest.suite_files contains unused path(s): " + ", ".join(sorted(unused_suite_files)))
    canonical = json.dumps(root, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return BenchmarkManifest(
        manifest_path,
        _identifier(suite.get("id"), "manifest.suite.id"),
        _string(suite.get("name"), "manifest.suite.name"),
        _string(suite.get("description"), "manifest.suite.description"),
        datasets,
        suite_files,
        hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    )


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_junction(path: Path) -> bool:
    checker = getattr(os.path, "isjunction", None)
    return bool(checker and checker(path))


def _materialization_sha256(root: Path) -> str:
    """Fingerprint every materialized directory and regular file.

    The root marker is intentionally excluded because it stores this digest.
    Symlinks, junctions, and special files are invalid even if introduced only
    after safe extraction.
    """

    digest = hashlib.sha256()

    def add(record: object) -> None:
        digest.update(_canonical_json(record).encode("utf-8"))
        digest.update(b"\n")

    def visit(directory: Path, prefix: PurePosixPath) -> None:
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda item: item.name)
        for entry in entries:
            relative = prefix / entry.name
            normalized = relative.as_posix()
            if not prefix.parts and entry.name == ".openconstraint-artifact.json":
                continue
            path = Path(entry.path)
            if entry.is_symlink() or _is_junction(path):
                raise BenchmarkError(f"cached materialization contains a link at {normalized!r}")
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                add(["directory", normalized])
                visit(path, relative)
            elif stat.S_ISREG(metadata.st_mode):
                add(["file", normalized, metadata.st_size, _hash_file(path)])
            else:
                raise BenchmarkError(f"cached materialization contains a special file at {normalized!r}")

    visit(root, PurePosixPath())
    return digest.hexdigest()


def _remove_materialization(path: Path) -> None:
    """Remove one exact cache materialization without following links."""

    if path.is_symlink():
        path.unlink()
    elif _is_junction(path):
        path.rmdir()
    elif path.is_dir():
        shutil.rmtree(path)
    elif os.path.lexists(path):
        path.unlink()


class _RejectAuthenticatedRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward a GitHub API bearer token through an HTTP redirect."""

    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        del request, file_pointer, code, message, headers, new_url
        raise BenchmarkError("authenticated GitHub API download redirected unexpectedly")


def _download_request(artifact: Artifact) -> tuple[urllib.request.Request, bool]:
    headers = {"User-Agent": f"OpenConstraint/{__version__}"}
    github_api = urlparse(artifact.url).hostname == "api.github.com"
    authenticated = False
    if github_api:
        # GitHub's raw host rejects repository blobs above its direct-download
        # limit. The Contents API serves those same commit-pinned bytes when
        # its documented raw media type is requested.
        headers.update(
            {
                "Accept": "application/vnd.github.raw+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        )
        token = os.environ.get(_GITHUB_TOKEN_ENV, "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
            authenticated = True
    return urllib.request.Request(artifact.url, headers=headers), authenticated


def _download_https(artifact: Artifact, destination: Path) -> None:
    request, authenticated = _download_request(artifact)
    try:
        if authenticated:
            response_context = urllib.request.build_opener(_RejectAuthenticatedRedirect()).open(request, timeout=60)
        else:
            response_context = urllib.request.urlopen(request, timeout=60)  # noqa: S310
        with response_context as response, destination.open("wb") as output:
            if urlparse(response.geturl()).scheme != "https":
                raise BenchmarkError(f"artifact {artifact.artifact_id!r} redirected away from HTTPS")
            remaining = artifact.size_bytes
            while chunk := response.read(min(1024 * 1024, remaining + 1)):
                output.write(chunk)
                remaining -= len(chunk)
                if remaining < 0:
                    raise BenchmarkError(f"artifact {artifact.artifact_id!r} exceeds its pinned size")
    except urllib.error.HTTPError as error:
        token_hint = (
            f"; set {_GITHUB_TOKEN_ENV} to a least-privilege token if this is a shared-runner rate limit"
            if urlparse(artifact.url).hostname == "api.github.com" and not authenticated
            else ""
        )
        raise BenchmarkError(
            f"download failed for artifact {artifact.artifact_id!r} with HTTP {error.code}{token_hint}"
        ) from error


def _validate_blob(path: Path, artifact: Artifact) -> str | None:
    if path.stat().st_size != artifact.size_bytes:
        return f"size is {path.stat().st_size}, expected {artifact.size_bytes}"
    actual = _hash_file(path)
    if actual != artifact.sha256:
        return f"SHA-256 is {actual}, expected {artifact.sha256}"
    return None


def _member_path(root: Path, name: str) -> tuple[Path, str]:
    normalized = name.replace("\\", "/")
    portable_name = normalized[:-1] if normalized.endswith("/") else normalized
    raw_parts = portable_name.split("/")
    relative = PurePosixPath(portable_name)
    windows_path = PureWindowsPath(portable_name)
    if (
        relative.is_absolute()
        or windows_path.drive
        or windows_path.root
        or ":" in portable_name
        or not portable_name
        or any(part in {"", ".", ".."} for part in raw_parts)
        or any(part.endswith((".", " ")) for part in raw_parts)
        or any(any(ord(character) < 32 or character in '<>"|?*' for character in part) for part in raw_parts)
        or any(part.split(".", 1)[0].casefold() in _WINDOWS_RESERVED_NAMES for part in raw_parts)
        or not relative.parts
        or relative.as_posix() in {"", "."}
    ):
        raise BenchmarkError(f"unsafe archive member path {name!r}")
    canonical = relative.as_posix()
    if canonical.casefold() == ".openconstraint-artifact.json":
        raise BenchmarkError(f"archive member uses reserved cache path {name!r}")
    target = root.joinpath(*relative.parts)
    if not target.resolve().is_relative_to(root.resolve()):
        raise BenchmarkError(f"archive member escapes extraction root: {name!r}")
    return target, canonical


def _record_archive_member(
    canonical: str,
    *,
    is_directory: bool,
    entries: dict[str, bool],
    spellings: dict[str, str],
    artifact: Artifact,
) -> None:
    parts = canonical.split("/")
    keys: list[str] = []
    for index, part in enumerate(parts):
        normalized_part = unicodedata.normalize("NFC", part).casefold()
        keys.append(normalized_part)
        key = "/".join(keys)
        spelling = "/".join(parts[: index + 1])
        previous_spelling = spellings.get(key)
        if previous_spelling is not None and previous_spelling != spelling:
            raise BenchmarkError(
                f"artifact {artifact.artifact_id!r} has portable path aliases {previous_spelling!r} and {spelling!r}"
            )
        spellings[key] = spelling
    full_key = "/".join(keys)
    if full_key in entries:
        raise BenchmarkError(f"artifact {artifact.artifact_id!r} has duplicate member {canonical!r}")
    for index in range(1, len(keys)):
        ancestor = "/".join(keys[:index])
        if entries.get(ancestor) is False:
            raise BenchmarkError(f"artifact {artifact.artifact_id!r} has file/directory path conflict at {canonical!r}")
    if not is_directory and any(key.startswith(f"{full_key}/") for key in entries):
        raise BenchmarkError(f"artifact {artifact.artifact_id!r} has file/directory path conflict at {canonical!r}")
    entries[full_key] = is_directory


def _extract_zip(blob: Path, destination: Path, artifact: Artifact) -> None:
    with zipfile.ZipFile(blob) as archive:
        members = archive.infolist()
        if len(members) > _MAX_ARCHIVE_ENTRIES:
            raise BenchmarkError(f"artifact {artifact.artifact_id!r} has too many archive entries")
        total = 0
        entries: dict[str, bool] = {}
        spellings: dict[str, str] = {}
        for member in members:
            target, canonical = _member_path(destination, member.filename)
            _record_archive_member(
                canonical,
                is_directory=member.is_dir(),
                entries=entries,
                spellings=spellings,
                artifact=artifact,
            )
            if member.flag_bits & 0x1:
                raise BenchmarkError(f"artifact {artifact.artifact_id!r} contains an encrypted member")
            mode = member.external_attr >> 16
            file_type = stat.S_IFMT(mode)
            if file_type == stat.S_IFLNK:
                raise BenchmarkError(f"artifact {artifact.artifact_id!r} contains a symbolic link")
            if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                raise BenchmarkError(f"artifact {artifact.artifact_id!r} contains a special file")
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            total += member.file_size
            if total > artifact.unpacked_size_limit_bytes:
                raise BenchmarkError(f"artifact {artifact.artifact_id!r} exceeds its unpacked size limit")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)


def _extract_tar(blob: Path, destination: Path, artifact: Artifact) -> None:
    mode: Literal["r|gz", "r|xz"] = "r|gz" if artifact.archive == "tar.gz" else "r|xz"
    with tarfile.open(blob, mode) as archive:
        total = 0
        entry_count = 0
        entries: dict[str, bool] = {}
        spellings: dict[str, str] = {}
        for member in archive:
            entry_count += 1
            if entry_count > _MAX_ARCHIVE_ENTRIES:
                raise BenchmarkError(f"artifact {artifact.artifact_id!r} has too many archive entries")
            target, canonical = _member_path(destination, member.name)
            _record_archive_member(
                canonical,
                is_directory=member.isdir(),
                entries=entries,
                spellings=spellings,
                artifact=artifact,
            )
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise BenchmarkError(f"artifact {artifact.artifact_id!r} contains a link or special file")
            total += member.size
            if total > artifact.unpacked_size_limit_bytes:
                raise BenchmarkError(f"artifact {artifact.artifact_id!r} exceeds its unpacked size limit")
            source = archive.extractfile(member)
            if source is None:
                raise BenchmarkError(f"could not read archive member {canonical!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with source, target.open("wb") as output:
                shutil.copyfileobj(source, output)


def _extract_raw(blob: Path, destination: Path, artifact: Artifact) -> None:
    if artifact.size_bytes > artifact.unpacked_size_limit_bytes:
        raise BenchmarkError(f"artifact {artifact.artifact_id!r} exceeds its unpacked size limit")
    if artifact.filename is None:  # Defensive: strict manifest parsing requires this for raw files.
        raise BenchmarkError(f"artifact {artifact.artifact_id!r} has no logical filename")
    target, _ = _member_path(destination, artifact.filename)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(blob, target)


def _artifact_cache_marker(artifact: Artifact) -> JsonObject:
    """Return the extraction settings bound into a materialization key."""

    return {
        "archive": artifact.archive,
        "filename": artifact.filename,
        "sha256": artifact.sha256,
        "size_bytes": artifact.size_bytes,
        "strip_prefix": artifact.strip_prefix,
        "unpacked_size_limit_bytes": artifact.unpacked_size_limit_bytes,
    }


def artifact_cache_paths(artifact: Artifact, cache_dir: str | Path) -> ArtifactCachePaths:
    """Derive the exact cache paths used to acquire and materialize an artifact."""

    cache = Path(cache_dir).resolve()
    marker = _artifact_cache_marker(artifact)
    materialization = hashlib.sha256(
        json.dumps(marker, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:16]
    digest_root = cache / "sources" / artifact.sha256
    materialization_root = digest_root / materialization
    logical_root = materialization_root / artifact.strip_prefix if artifact.strip_prefix else materialization_root
    return ArtifactCachePaths(
        blob=cache / "artifacts" / f"{artifact.sha256}.blob",
        digest_root=digest_root,
        materialization_root=materialization_root,
        logical_root=logical_root,
    )


def acquire_artifact(
    artifact: Artifact,
    cache_dir: str | Path,
    *,
    offline: bool = False,
    downloader: Downloader | None = None,
) -> Path:
    """Verify/download and safely extract an artifact, returning its logical root."""

    paths = artifact_cache_paths(artifact, cache_dir)
    artifact_dir = paths.blob.parent
    source_parent = paths.digest_root.parent
    artifact_dir.mkdir(parents=True, exist_ok=True)
    source_parent.mkdir(parents=True, exist_ok=True)
    blob = paths.blob
    if blob.exists():
        problem = _validate_blob(blob, artifact)
        if problem:
            if offline:
                raise BenchmarkError(f"cached artifact {artifact.artifact_id!r} is invalid: {problem}")
            blob.unlink()
    if not blob.exists():
        if offline:
            raise BenchmarkError(
                f"artifact {artifact.artifact_id!r} is not cached; run benchmark fetch without --offline first"
            )
        descriptor, temporary_name = tempfile.mkstemp(prefix=".download-", dir=artifact_dir)
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            (downloader or _download_https)(artifact, temporary)
            problem = _validate_blob(temporary, artifact)
            if problem:
                raise BenchmarkError(f"downloaded artifact {artifact.artifact_id!r} is invalid: {problem}")
            os.replace(temporary, blob)
        finally:
            temporary.unlink(missing_ok=True)

    expected_marker = _artifact_cache_marker(artifact)
    extracted = paths.materialization_root
    extracted.parent.mkdir(parents=True, exist_ok=True)
    marker = extracted / ".openconstraint-artifact.json"
    if marker.is_file() and not marker.is_symlink() and not _is_junction(marker):
        marker_value: JsonObject | None
        try:
            loaded_marker = _load_json(marker, "benchmark cache marker")
            marker_value = loaded_marker if isinstance(loaded_marker, dict) else None
        except (OSError, UnicodeError, BenchmarkError):
            marker_value = None
        logical_root = extracted / artifact.strip_prefix if artifact.strip_prefix else extracted
        expected_marker_keys = {*expected_marker, "materialized_sha256"}
        materialization_valid = (
            isinstance(marker_value, dict)
            and set(marker_value) == expected_marker_keys
            and all(marker_value.get(key) == value for key, value in expected_marker.items())
            and logical_root.is_dir()
        )
        if materialization_valid and marker_value is not None:
            try:
                materialization_valid = marker_value["materialized_sha256"] == _materialization_sha256(extracted)
            except (OSError, BenchmarkError):
                materialization_valid = False
        if materialization_valid:
            return logical_root
    if os.path.lexists(extracted):
        _remove_materialization(extracted)

    temporary_root = Path(tempfile.mkdtemp(prefix=".extract-", dir=source_parent))
    try:
        if artifact.archive == "none":
            _extract_raw(blob, temporary_root, artifact)
        elif artifact.archive == "zip":
            _extract_zip(blob, temporary_root, artifact)
        else:
            _extract_tar(blob, temporary_root, artifact)
        logical_root = temporary_root / artifact.strip_prefix if artifact.strip_prefix else temporary_root
        if not logical_root.is_dir():
            raise BenchmarkError(
                f"artifact {artifact.artifact_id!r} does not contain strip_prefix {artifact.strip_prefix!r}"
            )
        marker_value = {**expected_marker, "materialized_sha256": _materialization_sha256(temporary_root)}
        (temporary_root / ".openconstraint-artifact.json").write_text(
            json.dumps(marker_value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
        )
        os.replace(temporary_root, extracted)
    finally:
        if temporary_root.exists():
            shutil.rmtree(temporary_root)
    return extracted / artifact.strip_prefix if artifact.strip_prefix else extracted


def _select(
    manifest: BenchmarkManifest,
    dataset_ids: Iterable[str] | None,
    case_ids: Iterable[str] | None,
) -> list[tuple[Dataset, BenchmarkCase]]:
    selected_datasets = set(dataset_ids or ())
    known_datasets = {dataset.dataset_id for dataset in manifest.datasets}
    unknown_datasets = selected_datasets - known_datasets
    if unknown_datasets:
        raise BenchmarkError(f"unknown dataset(s): {', '.join(sorted(unknown_datasets))}")
    requested_cases = set(case_ids or ())
    known_cases = {f"{dataset.dataset_id}/{case.case_id}" for dataset in manifest.datasets for case in dataset.cases}
    unknown_cases = requested_cases - known_cases
    if unknown_cases:
        raise BenchmarkError(f"unknown case(s): {', '.join(sorted(unknown_cases))}")
    selected: list[tuple[Dataset, BenchmarkCase]] = []
    for dataset in manifest.datasets:
        if selected_datasets and dataset.dataset_id not in selected_datasets:
            continue
        for case in dataset.cases:
            qualified = f"{dataset.dataset_id}/{case.case_id}"
            if requested_cases and qualified not in requested_cases:
                continue
            selected.append((dataset, case))
    if not selected:
        raise BenchmarkError("benchmark selection is empty")
    return selected


def _required_artifact_ids(case: BenchmarkCase) -> set[str]:
    references = [*case.verilog, *case.liberty]
    for mode_references in case.modes.values():
        references.extend(mode_references)
    return {reference.origin for reference in references if reference.origin != "suite"}


def selected_required_artifacts(
    manifest: BenchmarkManifest,
    dataset_ids: Iterable[str] | None = None,
    case_ids: Iterable[str] | None = None,
) -> tuple[tuple[Dataset, Artifact], ...]:
    """Return selected artifacts once, in deterministic manifest order."""

    required_by_dataset: dict[str, set[str]] = {}
    for dataset, case in _select(manifest, dataset_ids, case_ids):
        required_by_dataset.setdefault(dataset.dataset_id, set()).update(_required_artifact_ids(case))
    return tuple(
        (dataset, artifact)
        for dataset in manifest.datasets
        for artifact in dataset.artifacts
        if artifact.artifact_id in required_by_dataset.get(dataset.dataset_id, set())
    )


def fetch_suite(
    manifest: BenchmarkManifest,
    cache_dir: str | Path,
    *,
    dataset_ids: Iterable[str] | None = None,
    case_ids: Iterable[str] | None = None,
    offline: bool = False,
    downloader: Downloader | None = None,
) -> JsonObject:
    """Acquire all unique artifacts required by the selected cases."""

    records: list[JsonObject] = []
    for dataset, artifact in selected_required_artifacts(manifest, dataset_ids, case_ids):
        acquire_artifact(artifact, cache_dir, offline=offline, downloader=downloader)
        records.append(
            {
                "dataset": dataset.dataset_id,
                "artifact": artifact.artifact_id,
                "sha256": artifact.sha256,
                "size_bytes": artifact.size_bytes,
                "license": {
                    "spdx": artifact.license.spdx,
                    "url": artifact.license.url,
                    "notice": artifact.license.notice,
                    "repository_license_url": artifact.license.repository_license_url,
                },
            }
        )
    return {
        "kind": "benchmark-fetch",
        "schema_version": RESULT_SCHEMA_VERSION,
        "suite_id": manifest.suite_id,
        "manifest_sha256": manifest.digest,
        "offline": offline,
        "artifacts": records,
    }


def _resolve_reference(
    reference: InputReference,
    roots: Mapping[str, Path],
    suite_root: Path,
    suite_files: Mapping[str, SuiteFile],
) -> Path:
    root = suite_root if reference.origin == "suite" else roots[reference.origin]
    candidate = root.joinpath(*PurePosixPath(reference.path).parts).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise BenchmarkError(f"input reference escapes {reference.origin!r}: {reference.path!r}")
    if not candidate.is_file():
        raise BenchmarkError(f"input reference does not exist: {reference.origin}:{reference.path}")
    if reference.origin == "suite":
        metadata = suite_files.get(reference.path)
        if metadata is None:
            raise BenchmarkError(f"suite input has no integrity metadata: {reference.path}")
        if candidate.stat().st_size != metadata.size_bytes:
            raise BenchmarkError(f"suite input size mismatch: {reference.path}")
        if _hash_file(candidate) != metadata.sha256:
            raise BenchmarkError(f"suite input SHA-256 mismatch: {reference.path}")
    return candidate


def _canonical_json(value: object) -> str:
    """Return the canonical JSON representation used by semantic fingerprints."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _design_inventory_sha256(design: Design) -> str:
    """Fingerprint every elaborated structural object and its connectivity.

    Aggregate design counts are useful for review, but they cannot distinguish
    two elaborations that contain the same number of incorrectly connected
    objects. This compact digest binds a baseline to the complete normalized
    structural inventory without making large public-design baselines
    unwieldy. Records are fed incrementally so computing the fingerprint does
    not duplicate the whole elaborated design in memory.
    """

    digest = hashlib.sha256()

    def add(section: str, value: object) -> None:
        digest.update(section.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(_canonical_json(value).encode("utf-8"))
        digest.update(b"\n")

    add("top", design.top)
    for name, port in sorted(design.ports.items()):
        add("port", [name, port.direction, port.net])
    for net in sorted(design.nets):
        add("net", net)
    for path, instance in sorted(design.instances.items()):
        add("instance", [path, instance.cell_type, instance.sequential])
        for pin_name, pin in sorted(instance.pins.items()):
            add("instance-pin", [path, pin_name, pin.path, pin.direction, pin.net, pin.is_clock, pin.is_data])
    for path, pin in sorted(design.pins.items()):
        add("pin-index", [path, pin.instance, pin.name])
    for net, objects in sorted(design.drivers.items()):
        add("drivers", [net, sorted(objects)])
    for net, objects in sorted(design.loads.items()):
        add("loads", [net, sorted(objects)])
    for input_pin, output_pins in sorted(design.combinational_arcs.items()):
        add("combinational_arcs", [input_pin, sorted(output_pins)])
    return digest.hexdigest()


def _normalized_source_path(path: str, aliases: Mapping[str, str]) -> str:
    normalized = path.replace("\\", "/")
    if normalized.startswith("<"):
        return normalized
    if normalized in aliases:
        return aliases[normalized]
    # A source outside the declared benchmark inputs must never disclose the
    # runner's checkout or cache path. Preserve the basename for review while
    # making the fallback deliberately location-independent.
    return f"<external>/{PurePosixPath(normalized).name}"


def _normalize_semantic_string(value: str, aliases: Mapping[str, str]) -> str:
    result = value
    for source, alias in sorted(aliases.items(), key=lambda item: len(item[0]), reverse=True):
        result = result.replace(source, alias).replace(source.replace("/", "\\"), alias)
    return result


def _normalize_semantic_value(value: object, aliases: Mapping[str, str]) -> object:
    """Normalize nested evidence into deterministic, JSON-native values."""

    if isinstance(value, Mapping):
        return {
            str(key): (
                _normalized_source_path(item, aliases)
                if str(key) == "path" and isinstance(item, str)
                else _normalize_semantic_value(item, aliases)
            )
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_normalize_semantic_value(item, aliases) for item in value]
    if isinstance(value, (set, frozenset)):
        normalized = [_normalize_semantic_value(item, aliases) for item in value]
        return sorted(normalized, key=_canonical_json)
    if isinstance(value, str):
        return _normalize_semantic_string(value, aliases)
    return value


def _diagnostic_snapshot(finding: Diagnostic, aliases: Mapping[str, str]) -> JsonObject:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "mode": finding.mode,
        "message": _normalize_semantic_string(finding.message, aliases),
        "location": {
            "path": _normalized_source_path(finding.location.path, aliases),
            "line": finding.location.line,
            "column": finding.location.column,
        },
        "evidence": _normalize_semantic_value(finding.evidence, aliases),
    }


def _semantic_snapshot(result: AuditResult, design: Design, path_aliases: Mapping[str, str]) -> JsonObject:
    diagnostics = result.diagnostics
    counts = Counter(item.severity.value for item in diagnostics)
    by_rule = Counter(item.rule_id for item in diagnostics)
    design_summary = result.design
    findings = [_diagnostic_snapshot(item, path_aliases) for item in diagnostics]
    findings.sort(key=_canonical_json)
    modes: dict[str, JsonObject] = {}
    for mode in sorted(result.modes, key=lambda item: item.name):
        clocks = [
            {
                "name": clock.name,
                "targets": sorted(clock.targets),
                "period": clock.period,
                "waveform": list(clock.waveform) if clock.waveform is not None else None,
                "waveform_explicit": clock.waveform_explicit,
                "valid": clock.name in mode.valid_clocks,
                "generated": clock.generated,
                "source_targets": sorted(clock.source_targets),
                "master_clock": clock.master_clock,
                "divide_by": clock.divide_by,
                "multiply_by": clock.multiply_by,
                "duty_cycle": clock.duty_cycle,
                "invert": clock.invert,
                "combinational": clock.combinational,
                "edges": list(clock.edges) if clock.edges is not None else None,
                "edge_shift": list(clock.edge_shift) if clock.edge_shift is not None else None,
            }
            for clock in sorted(mode.clocks.values(), key=lambda item: item.name)
        ]
        exceptions = [
            {
                "kind": item.kind,
                "from": sorted(item.from_objects),
                "to": sorted(item.to_objects),
                "through": [sorted(group) for group in item.through_objects],
                "qualifiers": item.qualifiers,
            }
            for item in mode.exceptions
        ]
        exceptions.sort(key=_canonical_json)
        io_delays = effective_io_delay_semantics(mode.io_delays)
        components = {
            component.key: {
                "covered": component.covered,
                "total": component.total,
                "percentage": component.percentage,
                "weight": component.weight,
            }
            for component in sorted(mode.coverage.components, key=lambda item: item.key)
        }
        modes[mode.name] = {
            "clocks": clocks,
            "exceptions": exceptions,
            "io_delays": io_delays,
            "coverage": {
                "score": mode.coverage.score,
                "grade": mode.coverage.grade,
                "components": components,
            },
        }
    return {
        "design": {
            "top": design_summary["top"],
            "ports": design_summary["ports"],
            "nets": design_summary["nets"],
            "instances": design_summary["instances"],
            "sequential_instances": design_summary["sequential_instances"],
            "sequential_endpoints": design_summary["sequential_endpoints"],
            "parser_warning_count": len(design_summary["parser_warnings"]),
            "parser_warnings": [
                _normalize_semantic_string(item, path_aliases) for item in design_summary["parser_warnings"]
            ],
            "inventory_sha256": _design_inventory_sha256(design),
        },
        "modes": modes,
        "diagnostics": {
            "total": len(diagnostics),
            "errors": counts["error"],
            "warnings": counts["warning"],
            "notes": counts["note"],
            "by_rule": dict(sorted(by_rule.items())),
            "findings": findings,
        },
    }


def _differences(expected: object, actual: object, path: str = "$") -> list[str]:
    if isinstance(expected, dict) and isinstance(actual, dict):
        differences: list[str] = []
        for key in sorted(set(expected) | set(actual)):
            child = f"{path}.{key}"
            if key not in expected:
                differences.append(f"{child}: unexpected value {actual[key]!r}")
            elif key not in actual:
                differences.append(f"{child}: expected {expected[key]!r}, value is missing")
            else:
                differences.extend(_differences(expected[key], actual[key], child))
        return differences
    if expected != actual:
        return [f"{path}: expected {expected!r}, got {actual!r}"]
    return []


def load_baseline(path: str | Path, manifest: BenchmarkManifest) -> Mapping[str, JsonObject]:
    """Load a deterministic semantic baseline and bind it to the manifest."""

    baseline_path = Path(path)
    raw = _load_json(baseline_path, "benchmark baseline")
    value = _object(raw, "baseline")
    _known_keys(value, {"schema_version", "suite_id", "manifest_sha256", "cases"}, "baseline")
    if value.get("schema_version") != BASELINE_SCHEMA_VERSION:
        raise BenchmarkError("unsupported benchmark baseline schema")
    if value.get("suite_id") != manifest.suite_id:
        raise BenchmarkError("benchmark baseline suite_id does not match the manifest")
    if value.get("manifest_sha256") != manifest.digest:
        raise BenchmarkError("benchmark baseline manifest_sha256 does not match the manifest")
    cases = _object(value.get("cases"), "baseline.cases")
    return {key: _object(item, f"baseline.cases.{key}") for key, item in cases.items()}


def run_suite(
    manifest: BenchmarkManifest,
    cache_dir: str | Path,
    *,
    dataset_ids: Iterable[str] | None = None,
    case_ids: Iterable[str] | None = None,
    offline: bool = False,
    baseline: Mapping[str, JsonObject] | None = None,
    downloader: Downloader | None = None,
) -> JsonObject:
    """Run selected cases and return semantic plus observational metrics."""

    selected = _select(manifest, dataset_ids, case_ids)
    suite_root = manifest.path.parent
    roots_by_dataset: dict[str, dict[str, Path]] = {}
    case_results: list[JsonObject] = []
    for dataset, case in selected:
        roots = roots_by_dataset.setdefault(dataset.dataset_id, {})
        required_ids = _required_artifact_ids(case)
        for artifact in dataset.artifacts:
            if artifact.artifact_id in required_ids and artifact.artifact_id not in roots:
                roots[artifact.artifact_id] = acquire_artifact(
                    artifact, cache_dir, offline=offline, downloader=downloader
                )
        qualified = f"{dataset.dataset_id}/{case.case_id}"
        try:
            verilog = [_resolve_reference(item, roots, suite_root, manifest.suite_files) for item in case.verilog]
            liberty = [_resolve_reference(item, roots, suite_root, manifest.suite_files) for item in case.liberty]
            modes = {
                name: [_resolve_reference(item, roots, suite_root, manifest.suite_files) for item in references]
                for name, references in case.modes.items()
            }
            path_aliases = {
                str(path.resolve()).replace("\\", "/"): f"{reference.origin}:{reference.path}"
                for references, paths in [
                    (case.verilog, verilog),
                    (case.liberty, liberty),
                    *[(case.modes[name], paths) for name, paths in modes.items()],
                ]
                for reference, path in zip(references, paths, strict=True)
            }
            tracemalloc.start()
            started = time.perf_counter()
            try:
                library = CellLibrary()
                for path in liberty:
                    library.merge(parse_liberty(path))
                design = elaborate(parse_verilog(list[str | Path](verilog)), library, case.top)
                result = audit(
                    design,
                    [ModeInput(name, [str(path) for path in paths]) for name, paths in modes.items()],
                    case.options,
                )
                elapsed = time.perf_counter() - started
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            semantic = _semantic_snapshot(result, design, path_aliases)
            expected = baseline.get(qualified) if baseline is not None else None
            differences = (
                [f"$.cases.{qualified}: baseline entry is missing"]
                if baseline is not None and expected is None
                else _differences(expected, semantic)
                if expected is not None
                else []
            )
            baseline_status = "not_checked" if baseline is None else "match" if not differences else "mismatch"
            case_results.append(
                {
                    "id": qualified,
                    "dataset": dataset.dataset_id,
                    "case": case.case_id,
                    "description": case.description,
                    "tags": list(case.tags),
                    "status": "regression" if differences else "passed",
                    "baseline_status": baseline_status,
                    "differences": differences,
                    "source_sha256": {
                        artifact.artifact_id: artifact.sha256
                        for artifact in dataset.artifacts
                        if artifact.artifact_id in required_ids
                    },
                    "input_bytes": sum(path.stat().st_size for path in [*verilog, *liberty, *sum(modes.values(), [])]),
                    "analysis_duration_seconds": round(elapsed, 6),
                    "peak_python_bytes": peak,
                    "semantic": semantic,
                }
            )
        except (OSError, UnicodeError, ValueError) as error:
            case_results.append(
                {
                    "id": qualified,
                    "dataset": dataset.dataset_id,
                    "case": case.case_id,
                    "description": case.description,
                    "tags": list(case.tags),
                    "status": "error",
                    "baseline_status": "not_checked" if baseline is None else "mismatch",
                    "differences": [],
                    "source_sha256": {
                        artifact.artifact_id: artifact.sha256
                        for artifact in dataset.artifacts
                        if artifact.artifact_id in required_ids
                    },
                    "error": str(error),
                }
            )
    counts = Counter(item["status"] for item in case_results)
    return {
        "kind": "benchmark-result",
        "schema_version": RESULT_SCHEMA_VERSION,
        "tool": {"name": "OpenConstraint", "version": __version__},
        "environment": {
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "processor": platform.processor() or None,
            "cpu_count": os.cpu_count(),
        },
        "suite": {"id": manifest.suite_id, "name": manifest.name},
        "manifest_sha256": manifest.digest,
        "offline": offline,
        "summary": {
            "case_count": len(case_results),
            "passed": counts["passed"],
            "regressions": counts["regression"],
            "errors": counts["error"],
        },
        "cases": case_results,
    }


def baseline_from_result(result: Mapping[str, object]) -> JsonObject:
    """Strip observational metrics from a successful run to form a baseline."""

    cases_raw = result.get("cases")
    if not isinstance(cases_raw, list):
        raise BenchmarkError("benchmark result has no cases array")
    cases: dict[str, object] = {}
    for index, raw_case in enumerate(cases_raw):
        case = _object(raw_case, f"result.cases[{index}]")
        case_id = _string(case.get("id"), f"result.cases[{index}].id")
        if case.get("status") == "error" or "semantic" not in case:
            raise BenchmarkError(f"cannot baseline failed case {case_id!r}")
        cases[case_id] = case["semantic"]
    suite = _object(result.get("suite"), "result.suite")
    return {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "suite_id": _string(suite.get("id"), "result.suite.id"),
        "manifest_sha256": _string(result.get("manifest_sha256"), "result.manifest_sha256"),
        "cases": dict(sorted(cases.items())),
    }


def render_benchmark_json(value: Mapping[str, object]) -> str:
    """Render benchmark metadata without non-finite values."""

    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
