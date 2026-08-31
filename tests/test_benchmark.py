from __future__ import annotations

import copy
import hashlib
import io
import json
import tarfile
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import openconstraint.benchmark as benchmark_module
from openconstraint.benchmark import (
    BASELINE_SCHEMA_VERSION,
    BenchmarkError,
    _differences,
    _download_https,
    _download_request,
    acquire_artifact,
    baseline_from_result,
    fetch_suite,
    load_baseline,
    load_manifest,
    render_benchmark_json,
    run_suite,
)
from openconstraint.cli import main

from .conftest import COMPLETE_SDC, SYNTHETIC_LIBERTY, SYNTHETIC_VERILOG


def _zip_bytes(entries: dict[str, str]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in entries.items():
            archive.writestr(name, value)
    return output.getvalue()


def _tar_bytes(entries: dict[str, str]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, value in entries.items():
            payload = value.encode()
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    return output.getvalue()


def _manifest_payload(blob: bytes, *, archive: str = "zip") -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "suite": {
            "id": "public-designs",
            "name": "Public designs",
            "description": "A pinned public-design compatibility suite.",
        },
        "suite_files": [],
        "datasets": [
            {
                "id": "sample",
                "description": "Small stand-in for an upstream design.",
                "artifacts": [
                    {
                        "id": "design",
                        "url": "https://example.invalid/design.zip",
                        "sha256": hashlib.sha256(blob).hexdigest(),
                        "size_bytes": len(blob),
                        "archive": archive,
                        "unpacked_size_limit_bytes": 1_000_000,
                        "strip_prefix": "bundle",
                        "license": {
                            "spdx": "Apache-2.0",
                            "url": "https://example.invalid/license",
                            "notice": "Upstream test artifact; not redistributed by OpenConstraint.",
                        },
                    }
                ],
                "cases": [
                    {
                        "id": "functional",
                        "description": "Complete single-mode constraints.",
                        "top": "top",
                        "verilog": ["design:design.v"],
                        "liberty": ["design:cells.lib"],
                        "modes": {"functional": ["design:constraints.sdc"]},
                        "tags": ["public", "smoke"],
                        "options": {"report_implicit_waveform": False},
                    }
                ],
            }
        ],
    }


def _fixture(
    tmp_path: Path,
    *,
    archive: str = "zip",
    verilog: str = SYNTHETIC_VERILOG,
    sdc: str = COMPLETE_SDC,
) -> tuple[Path, Path, bytes]:
    entries = {
        "bundle/design.v": verilog,
        "bundle/cells.lib": SYNTHETIC_LIBERTY,
        "bundle/constraints.sdc": sdc,
    }
    blob = _zip_bytes(entries) if archive == "zip" else _tar_bytes(entries)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(_manifest_payload(blob, archive=archive)), encoding="utf-8")
    cache = tmp_path / "cache"
    artifact_path = cache / "artifacts" / f"{hashlib.sha256(blob).hexdigest()}.blob"
    artifact_path.parent.mkdir(parents=True)
    artifact_path.write_bytes(blob)
    return manifest_path, cache, blob


def test_manifest_digest_is_canonical_and_records_provenance(tmp_path: Path) -> None:
    manifest_path, _, blob = _fixture(tmp_path)
    manifest = load_manifest(manifest_path)
    reformatted = tmp_path / "reformatted.json"
    reformatted.write_text(json.dumps(json.loads(manifest_path.read_text()), indent=4), encoding="utf-8")

    assert load_manifest(reformatted).digest == manifest.digest
    assert manifest.suite_id == "public-designs"
    artifact = manifest.datasets[0].artifacts[0]
    assert artifact.sha256 == hashlib.sha256(blob).hexdigest()
    assert artifact.license.spdx == "Apache-2.0"


def test_json_loaders_reject_duplicate_keys(tmp_path: Path) -> None:
    manifest_path = tmp_path / "duplicate-manifest.json"
    manifest_path.write_text(
        '{"schema_version":"1.0.0","schema_version":"1.0.0"}',
        encoding="utf-8",
    )

    with pytest.raises(BenchmarkError, match="duplicate JSON key 'schema_version'"):
        load_manifest(manifest_path)

    valid_manifest_path, cache, _ = _fixture(tmp_path)
    manifest = load_manifest(valid_manifest_path)
    baseline = baseline_from_result(run_suite(manifest, cache, offline=True))
    rendered = render_benchmark_json(baseline)
    duplicate_baseline = tmp_path / "duplicate-baseline.json"
    duplicate_baseline.write_text(
        rendered.replace('"schema_version": "1.0.0"', '"schema_version": "1.0.0",\n  "schema_version": "1.0.0"', 1),
        encoding="utf-8",
    )

    with pytest.raises(BenchmarkError, match="duplicate JSON key 'schema_version'"):
        load_baseline(duplicate_baseline, manifest)


def test_json_loader_bounds_size_and_nesting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    oversized = tmp_path / "oversized.json"
    oversized.write_text('{"padding":"0123456789"}', encoding="utf-8")
    monkeypatch.setattr(benchmark_module, "_MAX_JSON_BYTES", 8)
    with pytest.raises(BenchmarkError, match="JSON size limit"):
        load_manifest(oversized)

    monkeypatch.setattr(benchmark_module, "_MAX_JSON_BYTES", 64 * 1024 * 1024)
    nested = tmp_path / "nested.json"
    nested.write_text("[" * 300 + "0" + "]" * 300, encoding="utf-8")
    with pytest.raises(BenchmarkError, match="JSON nesting limit"):
        load_manifest(nested)


def test_cli_reports_deep_benchmark_json_as_input_error(tmp_path: Path, capsys) -> None:
    nested = tmp_path / "nested.json"
    nested.write_text("[" * 300 + "0" + "]" * 300, encoding="utf-8")

    with pytest.raises(SystemExit) as exit_info:
        main(
            [
                "benchmark",
                "fetch",
                "--manifest",
                str(nested),
                "--cache-dir",
                str(tmp_path / "cache"),
            ]
        )

    assert exit_info.value.code == 2
    stderr = capsys.readouterr().err
    assert "input error" in stderr
    assert "JSON nesting limit" in stderr


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda data: data.update(extra=True), "unknown key"),
        (lambda data: data.update(schema_version="2"), "unsupported"),
        (lambda data: data["suite"].update(id="Bad ID"), "must match"),
        (lambda data: data["datasets"][0]["artifacts"][0].update(url="http://example.test/a"), "HTTPS"),
        (lambda data: data["datasets"][0]["artifacts"][0].update(sha256="A" * 64), "lowercase"),
        (lambda data: data["datasets"][0]["artifacts"][0].update(archive="rar"), "must be one of"),
        (lambda data: data["datasets"][0]["cases"][0].update(verilog=["missing:a.v"]), "unknown artifact"),
        (lambda data: data["datasets"][0]["cases"][0].update(verilog=["design:../a.v"]), "relative path"),
        (
            lambda data: data["datasets"][0]["artifacts"][0].update(strip_prefix="C:/Windows"),
            "Windows drive",
        ),
        (
            lambda data: data["datasets"][0]["artifacts"][0].update(
                archive="none", filename="C:relative.v", strip_prefix=""
            ),
            "Windows drive",
        ),
        (
            lambda data: data["datasets"][0]["cases"][0].update(verilog=["design:C:/Windows/system.ini"]),
            "Windows drive",
        ),
        (
            lambda data: data.update(suite_files=[{"path": "file.txt:stream", "sha256": "0" * 64, "size_bytes": 1}]),
            "alternate data stream",
        ),
        (
            lambda data: data["datasets"][0]["cases"][0].update(options={"broad_match_ratio": 2}),
            "from 0 through 1",
        ),
    ],
)
def test_manifest_rejects_unsafe_or_ambiguous_metadata(tmp_path: Path, mutation, message: str) -> None:
    _, _, blob = _fixture(tmp_path)
    payload = _manifest_payload(blob)
    mutation(payload)
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(BenchmarkError, match=message):
        load_manifest(path)


@pytest.mark.parametrize(
    "path",
    [".", "./file.v", "rtl/./file.v", "rtl//file.v", "rtl/file.v/", "C:relative.v", "file:stream"],
)
def test_manifest_schema_rejects_non_normalized_paths(path: str) -> None:
    payload = _manifest_payload(b"payload")
    payload["datasets"][0]["artifacts"][0]["strip_prefix"] = path
    schema_path = Path(__file__).parents[1] / "benchmarks" / "schemas" / "manifest.schema.json"
    validator = Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8")))

    assert list(validator.iter_errors(payload))


def test_offline_acquisition_verifies_extracts_and_reuses_cache(tmp_path: Path) -> None:
    manifest_path, cache, _ = _fixture(tmp_path)
    artifact = load_manifest(manifest_path).datasets[0].artifacts[0]

    root = acquire_artifact(artifact, cache, offline=True)
    assert (root / "design.v").is_file()
    assert acquire_artifact(artifact, cache, offline=True) == root

    marker = root.parent / ".openconstraint-artifact.json"
    marker.write_text("{}", encoding="utf-8")
    repaired = acquire_artifact(artifact, cache, offline=True)
    assert (repaired / "design.v").is_file()

    marker = repaired.parent / ".openconstraint-artifact.json"
    marker.write_text("[" * 300 + "0" + "]" * 300, encoding="utf-8")
    repaired = acquire_artifact(artifact, cache, offline=True)
    assert (repaired / "design.v").is_file()

    (repaired / "design.v").write_text("TAMPERED", encoding="utf-8")
    (repaired / "unexpected.txt").write_text("untracked", encoding="utf-8")
    reverified = acquire_artifact(artifact, cache, offline=True)
    assert reverified == root
    assert reverified.joinpath("design.v").read_text(encoding="utf-8").strip().startswith("module top")
    assert not (reverified / "unexpected.txt").exists()


def test_online_acquisition_uses_injected_downloader_and_repairs_bad_blob(tmp_path: Path) -> None:
    manifest_path, cache, blob = _fixture(tmp_path)
    artifact = load_manifest(manifest_path).datasets[0].artifacts[0]
    cached_blob = next((cache / "artifacts").iterdir())
    cached_blob.write_bytes(b"bad")
    calls: list[str] = []

    def download(selected, destination: Path) -> None:
        calls.append(selected.artifact_id)
        destination.write_bytes(blob)

    root = acquire_artifact(artifact, cache, downloader=download)

    assert calls == ["design"]
    assert (root / "constraints.sdc").is_file()
    assert hashlib.sha256(cached_blob.read_bytes()).hexdigest() == artifact.sha256


def test_github_api_download_requests_the_raw_media_type(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = b"pinned bytes"
    manifest_value = _manifest_payload(payload, archive="none")
    artifact_value = manifest_value["datasets"][0]["artifacts"][0]
    artifact_value.update(
        url="https://api.github.com/repos/example/project/contents/design.v?ref=" + "a" * 40,
        filename="design.v",
        strip_prefix="",
        unpacked_size_limit_bytes=len(payload),
    )
    manifest_path = tmp_path / "github-api-manifest.json"
    manifest_path.write_text(json.dumps(manifest_value), encoding="utf-8")
    artifact = load_manifest(manifest_path).datasets[0].artifacts[0]
    requests = []

    class Response:
        def __init__(self) -> None:
            self.remaining = payload

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

        def geturl(self) -> str:
            return artifact.url

        def read(self, _size: int) -> bytes:
            result, self.remaining = self.remaining, b""
            return result

    def open_request(request, timeout: int):
        requests.append((request, timeout))
        return Response()

    monkeypatch.delenv("OPENCONSTRAINT_GITHUB_TOKEN", raising=False)
    monkeypatch.setattr("urllib.request.urlopen", open_request)
    destination = tmp_path / "downloaded.v"

    _download_https(artifact, destination)

    request, timeout = requests[0]
    assert timeout == 60
    assert request.get_header("Accept") == "application/vnd.github.raw+json"
    assert request.get_header("X-github-api-version") == "2022-11-28"
    assert destination.read_bytes() == payload

    monkeypatch.setenv("OPENCONSTRAINT_GITHUB_TOKEN", "test-token")
    authenticated_request, authenticated = _download_request(artifact)
    public_request, public_authenticated = _download_request(replace(artifact, url="https://example.invalid/design.v"))
    assert authenticated
    assert authenticated_request.get_header("Authorization") == "Bearer test-token"
    assert not public_authenticated
    assert public_request.get_header("Authorization") is None


def test_offline_acquisition_rejects_missing_or_corrupt_blob(tmp_path: Path) -> None:
    manifest_path, cache, _ = _fixture(tmp_path)
    artifact = load_manifest(manifest_path).datasets[0].artifacts[0]
    blob = next((cache / "artifacts").iterdir())
    blob.unlink()
    with pytest.raises(BenchmarkError, match="not cached"):
        acquire_artifact(artifact, cache, offline=True)

    blob.write_bytes(b"x" * artifact.size_bytes)
    with pytest.raises(BenchmarkError, match="cached artifact.*invalid"):
        acquire_artifact(artifact, cache, offline=True)


def test_archive_traversal_and_unpacked_limits_are_rejected(tmp_path: Path) -> None:
    cases = [
        ({"../escape": "bad"}, "unsafe archive member", 100),
        ({"bundle/input.v": "first", "bundle/INPUT.v": "second"}, "portable path aliases", 100),
        ({"victim": "first", "victim.": "second"}, "unsafe archive member", 100),
        ({"A/x": "first", "a/y": "second"}, "portable path aliases", 100),
        ({"CON.txt": "device"}, "unsafe archive member", 100),
        ({"bundle/large": "too large"}, "unpacked size limit", 2),
    ]
    for index, (entries, message, limit) in enumerate(cases):
        blob = _zip_bytes(entries)
        payload = _manifest_payload(blob)
        artifact = payload["datasets"][0]["artifacts"][0]
        artifact["strip_prefix"] = ""
        artifact["unpacked_size_limit_bytes"] = limit
        manifest_path = tmp_path / f"manifest-{index}.json"
        manifest_path.write_text(json.dumps(payload), encoding="utf-8")
        manifest = load_manifest(manifest_path)
        cache = tmp_path / f"cache-{index}"
        cached = cache / "artifacts" / f"{hashlib.sha256(blob).hexdigest()}.blob"
        cached.parent.mkdir(parents=True)
        cached.write_bytes(blob)
        with pytest.raises(BenchmarkError, match=message):
            acquire_artifact(manifest.datasets[0].artifacts[0], cache, offline=True)
    assert not (tmp_path / "escape").exists()


def test_tar_gzip_acquisition_uses_same_safe_cache_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest_path, cache, _ = _fixture(tmp_path, archive="tar.gz")
    artifact = load_manifest(manifest_path).datasets[0].artifacts[0]

    def reject_eager_member_loading(_archive) -> None:
        raise AssertionError("tar acquisition must stream rather than call getmembers()")

    monkeypatch.setattr(tarfile.TarFile, "getmembers", reject_eager_member_loading)

    root = acquire_artifact(artifact, cache, offline=True)

    assert (root / "design.v").read_text(encoding="utf-8").strip().startswith("module top")


def test_tar_stream_enforces_entry_limit_before_retaining_all_headers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    blob = _tar_bytes({"one": "1", "two": "2", "three": "3"})
    payload = _manifest_payload(blob, archive="tar.gz")
    artifact_value = payload["datasets"][0]["artifacts"][0]
    artifact_value["strip_prefix"] = ""
    manifest_path = tmp_path / "tar-entry-limit.json"
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    artifact = load_manifest(manifest_path).datasets[0].artifacts[0]
    cache = tmp_path / "tar-entry-cache"
    cached = cache / "artifacts" / f"{artifact.sha256}.blob"
    cached.parent.mkdir(parents=True)
    cached.write_bytes(blob)
    monkeypatch.setattr("openconstraint.benchmark._MAX_ARCHIVE_ENTRIES", 2)

    with pytest.raises(BenchmarkError, match="too many archive entries"):
        acquire_artifact(artifact, cache, offline=True)


@pytest.mark.parametrize(
    ("entries", "message"),
    [
        ({"victim": "first", "victim ": "second"}, "unsafe archive member"),
        ({"A/x": "first", "a/y": "second"}, "portable path aliases"),
    ],
)
def test_tar_rejects_windows_portable_path_aliases(tmp_path: Path, entries: dict[str, str], message: str) -> None:
    blob = _tar_bytes(entries)
    payload = _manifest_payload(blob, archive="tar.gz")
    artifact_value = payload["datasets"][0]["artifacts"][0]
    artifact_value["strip_prefix"] = ""
    manifest_path = tmp_path / "tar-alias-manifest.json"
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    artifact = load_manifest(manifest_path).datasets[0].artifacts[0]
    cache = tmp_path / "tar-alias-cache"
    cached = cache / "artifacts" / f"{artifact.sha256}.blob"
    cached.parent.mkdir(parents=True)
    cached.write_bytes(blob)

    with pytest.raises(BenchmarkError, match=message):
        acquire_artifact(artifact, cache, offline=True)


def test_raw_file_artifact_is_pinned_and_given_a_logical_filename(tmp_path: Path) -> None:
    blob = SYNTHETIC_VERILOG.encode()
    payload = _manifest_payload(blob)
    artifact_value = payload["datasets"][0]["artifacts"][0]
    artifact_value.update(archive="none", filename="rtl/design.v", strip_prefix="")
    path = tmp_path / "raw-manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    manifest = load_manifest(path)
    artifact = manifest.datasets[0].artifacts[0]
    cache = tmp_path / "raw-cache"
    cached = cache / "artifacts" / f"{artifact.sha256}.blob"
    cached.parent.mkdir(parents=True)
    cached.write_bytes(blob)

    root = acquire_artifact(artifact, cache, offline=True)

    assert (root / "rtl" / "design.v").read_bytes() == blob
    assert artifact.filename == "rtl/design.v"


def test_fetch_and_run_emit_machine_readable_metrics(tmp_path: Path) -> None:
    manifest_path, cache, _ = _fixture(tmp_path)
    manifest = load_manifest(manifest_path)

    fetched = fetch_suite(manifest, cache, offline=True)
    result = run_suite(manifest, cache, offline=True)

    assert fetched["artifacts"][0]["license"]["spdx"] == "Apache-2.0"
    assert result["summary"] == {"case_count": 1, "passed": 1, "regressions": 0, "errors": 0}
    assert result["environment"]["python_implementation"]
    assert result["environment"]["system"]
    case = result["cases"][0]
    assert case["status"] == "passed"
    assert case["baseline_status"] == "not_checked"
    semantic = case["semantic"]
    assert semantic["design"]["inventory_sha256"] == "16f544bfc2dad2d22947a992fcd9d9dd094487ee9b74f35ca1314b746ce24b4e"
    assert semantic["modes"]["functional"]["clocks"] == [
        {
            "name": "core",
            "targets": ["clk"],
            "period": 10.0,
            "waveform": [0.0, 5.0],
            "waveform_explicit": True,
            "generated": False,
            "source_targets": [],
            "master_clock": None,
            "divide_by": None,
            "multiply_by": None,
            "duty_cycle": None,
            "invert": False,
            "combinational": False,
            "edges": None,
            "edge_shift": None,
        }
    ]
    assert semantic["modes"]["functional"]["io_delays"] == [
        {
            "kind": "input",
            "ports": ["clk2", "data", "spare"],
            "value": 1.0,
            "clocks": ["core"],
            "reference_pin": None,
            "source_latency_included": False,
            "network_latency_included": False,
            "min_max": ["max", "min"],
            "transitions": ["fall", "rise"],
            "clock_edge": "rise",
            "additive": False,
            "valid": True,
        },
        {
            "kind": "output",
            "ports": ["result"],
            "value": 2.0,
            "clocks": ["core"],
            "reference_pin": None,
            "source_latency_included": False,
            "network_latency_included": False,
            "min_max": ["max", "min"],
            "transitions": ["fall", "rise"],
            "clock_edge": "rise",
            "additive": False,
            "valid": True,
        },
    ]
    assert semantic["modes"]["functional"]["coverage"] == {
        "score": 100.0,
        "grade": "A",
        "components": {
            "input_delays": {"covered": 12, "total": 12, "percentage": 100.0, "weight": 0.2},
            "output_delays": {"covered": 4, "total": 4, "percentage": 100.0, "weight": 0.2},
            "query_health": {"covered": 3, "total": 3, "percentage": 100.0, "weight": 0.1},
            "sequential_endpoints": {"covered": 1, "total": 1, "percentage": 100.0, "weight": 0.5},
        },
    }
    assert case["analysis_duration_seconds"] >= 0
    assert case["peak_python_bytes"] > 0
    assert json.loads(render_benchmark_json(result))["manifest_sha256"] == manifest.digest


def test_semantic_snapshot_normalizes_latency_flags_ignored_with_reference_pin(tmp_path: Path) -> None:
    manifest_path, cache, _ = _fixture(
        tmp_path,
        sdc="""
create_clock -name core -period 10 [get_ports clk]
set_input_delay 1 -clock core -reference_pin [get_pins u_ff/Q] \
  -source_latency_included -network_latency_included [get_ports data]
""",
    )

    result = run_suite(load_manifest(manifest_path), cache, offline=True)
    io_delay = result["cases"][0]["semantic"]["modes"]["functional"]["io_delays"][0]

    assert io_delay["reference_pin"] == "u_ff/Q"
    assert io_delay["source_latency_included"] is False
    assert io_delay["network_latency_included"] is False


def test_semantic_snapshot_projects_active_io_delay_state(tmp_path: Path) -> None:
    manifest_path, cache, _ = _fixture(
        tmp_path,
        sdc="""
create_clock -name core -period 10 [get_ports clk]
set_input_delay -max -rise 1 -clock core [get_ports data]
set_input_delay -max -rise 2 -clock core [get_ports data]
""",
    )

    result = run_suite(load_manifest(manifest_path), cache, offline=True)

    assert result["cases"][0]["semantic"]["modes"]["functional"]["io_delays"] == [
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


def test_semantic_baseline_matches_and_detects_regression(tmp_path: Path) -> None:
    manifest_path, cache, _ = _fixture(tmp_path)
    manifest = load_manifest(manifest_path)
    first = run_suite(manifest, cache, offline=True)
    baseline_payload = baseline_from_result(first)
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(render_benchmark_json(baseline_payload), encoding="utf-8")
    baseline = load_baseline(baseline_path, manifest)

    matching = run_suite(manifest, cache, offline=True, baseline=baseline)
    assert matching["cases"][0]["baseline_status"] == "match"

    changed = copy.deepcopy(baseline)
    changed["sample/functional"]["modes"]["functional"]["coverage"]["score"] = 99.0
    regression = run_suite(manifest, cache, offline=True, baseline=changed)
    assert regression["summary"]["regressions"] == 1
    assert regression["cases"][0]["differences"] == ["$.modes.functional.coverage.score: expected 99.0, got 100.0"]


def test_inventory_fingerprint_detects_same_count_connectivity_regression(tmp_path: Path) -> None:
    original_root = tmp_path / "original"
    changed_root = tmp_path / "changed"
    original_root.mkdir()
    changed_root.mkdir()
    original_manifest_path, original_cache, _ = _fixture(original_root)
    changed_manifest_path, changed_cache, _ = _fixture(
        changed_root,
        verilog=SYNTHETIC_VERILOG.replace(".D(data)", ".D(spare)"),
    )
    original_manifest = load_manifest(original_manifest_path)
    changed_manifest = load_manifest(changed_manifest_path)
    original_result = run_suite(original_manifest, original_cache, offline=True)
    original_baseline = baseline_from_result(original_result)
    changed_result = run_suite(
        changed_manifest,
        changed_cache,
        offline=True,
        baseline=original_baseline["cases"],
    )

    original_design = copy.deepcopy(original_result["cases"][0]["semantic"]["design"])
    changed_design = copy.deepcopy(changed_result["cases"][0]["semantic"]["design"])
    original_fingerprint = original_design.pop("inventory_sha256")
    changed_fingerprint = changed_design.pop("inventory_sha256")

    assert original_design == changed_design
    assert original_fingerprint != changed_fingerprint
    assert changed_result["summary"]["regressions"] == 1
    assert changed_result["cases"][0]["differences"] == [
        f"$.design.inventory_sha256: expected {original_fingerprint!r}, got {changed_fingerprint!r}"
    ]


def test_semantic_snapshot_normalizes_exception_and_diagnostic_evidence(tmp_path: Path) -> None:
    sdc = (
        COMPLETE_SDC
        + r"""
set_false_path -from [get_cells u_ff] -to [get_ports result]
set_multicycle_path 2 -from [get_cells u_ff] -to [get_ports result]
"""
    )
    manifest_path, cache, _ = _fixture(tmp_path, sdc=sdc)

    semantic = run_suite(load_manifest(manifest_path), cache, offline=True)["cases"][0]["semantic"]
    functional = semantic["modes"]["functional"]

    assert functional["exceptions"] == [
        {
            "kind": "false_path",
            "from": ["u_ff"],
            "to": ["result"],
            "through": [],
            "qualifiers": {
                "from_transition": "rise_fall",
                "to_transition": "rise_fall",
                "end_transition": "rise_fall",
                "through_transitions": [],
                "from_specified": True,
                "to_specified": True,
                "scope_resolvable": True,
                "definition_valid": True,
                "definition_problems": [],
                "reset_path": False,
                "applies_to": ["hold", "setup"],
            },
        },
        {
            "kind": "multicycle_path",
            "from": ["u_ff"],
            "to": ["result"],
            "through": [],
            "qualifiers": {
                "from_transition": "rise_fall",
                "to_transition": "rise_fall",
                "end_transition": "rise_fall",
                "through_transitions": [],
                "from_specified": True,
                "to_specified": True,
                "scope_resolvable": True,
                "definition_valid": True,
                "definition_problems": [],
                "multiplier": 2,
                "applies_to": ["hold", "setup"],
                "start_end": "default",
                "reset_path": False,
            },
        },
    ]
    overlap = next(item for item in semantic["diagnostics"]["findings"] if item["rule_id"] == "OC4001")
    assert overlap == {
        "rule_id": "OC4001",
        "severity": "error",
        "mode": "functional",
        "message": "False-path and multicycle exceptions overlap",
        "location": {"path": "design:constraints.sdc", "line": 7, "column": 1},
        "evidence": {
            "first": {"path": "design:constraints.sdc", "line": 6, "column": 1},
            "second": {"path": "design:constraints.sdc", "line": 7, "column": 1},
            "from_intersection": ["u_ff"],
            "to_intersection": ["result"],
        },
    }
    assert str(tmp_path).replace("\\", "/") not in render_benchmark_json(semantic)


def test_baseline_rejects_wrong_binding_and_failed_results(tmp_path: Path) -> None:
    manifest_path, cache, _ = _fixture(tmp_path)
    manifest = load_manifest(manifest_path)
    baseline = baseline_from_result(run_suite(manifest, cache, offline=True))
    baseline["manifest_sha256"] = "0" * 64
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(baseline), encoding="utf-8")
    with pytest.raises(BenchmarkError, match="manifest_sha256"):
        load_baseline(path, manifest)

    with pytest.raises(BenchmarkError, match="failed case"):
        baseline_from_result(
            {
                "suite": {"id": "public-designs"},
                "manifest_sha256": manifest.digest,
                "cases": [{"id": "sample/bad", "status": "error"}],
            }
        )


def test_run_records_input_error_without_aborting_other_cases(tmp_path: Path) -> None:
    manifest_path, cache, blob = _fixture(tmp_path)
    payload = _manifest_payload(blob)
    payload["datasets"][0]["cases"][0]["verilog"] = ["design:missing.v"]
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    result = run_suite(load_manifest(manifest_path), cache, offline=True)

    assert result["summary"]["errors"] == 1
    assert result["cases"][0]["status"] == "error"
    assert "does not exist" in result["cases"][0]["error"]


def test_selection_errors_are_explicit(tmp_path: Path) -> None:
    manifest_path, cache, _ = _fixture(tmp_path)
    manifest = load_manifest(manifest_path)

    with pytest.raises(BenchmarkError, match="unknown dataset"):
        run_suite(manifest, cache, dataset_ids=["nope"], offline=True)
    with pytest.raises(BenchmarkError, match="unknown case"):
        run_suite(manifest, cache, case_ids=["sample/nope"], offline=True)


def test_case_selection_does_not_acquire_unreferenced_artifacts(tmp_path: Path) -> None:
    _, _, blob = _fixture(tmp_path)
    payload = _manifest_payload(blob)
    unused = b"not used by the selected case"
    payload["datasets"][0]["artifacts"].append(
        {
            "id": "unrelated",
            "url": "https://example.invalid/unrelated.v",
            "sha256": hashlib.sha256(unused).hexdigest(),
            "size_bytes": len(unused),
            "archive": "none",
            "filename": "unrelated.v",
            "unpacked_size_limit_bytes": len(unused),
            "license": {
                "spdx": "Apache-2.0",
                "url": "https://example.invalid/license",
                "notice": "Unrelated test artifact.",
            },
        }
    )
    manifest_path = tmp_path / "selection-manifest.json"
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    calls: list[str] = []

    def download(artifact, destination: Path) -> None:
        calls.append(artifact.artifact_id)
        destination.write_bytes(blob if artifact.artifact_id == "design" else unused)

    manifest = load_manifest(manifest_path)
    fetch_suite(manifest, tmp_path / "fetch-cache", case_ids=["sample/functional"], downloader=download)
    assert calls == ["design"]

    calls.clear()
    run_suite(manifest, tmp_path / "run-cache", case_ids=["sample/functional"], downloader=download)
    assert calls == ["design"]


def test_suite_input_hash_is_verified_before_analysis(tmp_path: Path) -> None:
    manifest_path, cache, blob = _fixture(tmp_path)
    overlay = tmp_path / "overlay.sdc"
    overlay.write_text("set_input_delay 1 -clock core [all_inputs]\n", encoding="utf-8", newline="\n")
    payload = _manifest_payload(blob)
    payload["suite_files"] = [
        {
            "path": "overlay.sdc",
            "sha256": hashlib.sha256(overlay.read_bytes()).hexdigest(),
            "size_bytes": overlay.stat().st_size,
        }
    ]
    payload["datasets"][0]["cases"][0]["modes"]["functional"].append("suite:overlay.sdc")
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    manifest = load_manifest(manifest_path)
    assert run_suite(manifest, cache, offline=True)["summary"]["errors"] == 0

    overlay.write_text("set_input_delay 2 -clock core [all_inputs]\n", encoding="utf-8", newline="\n")
    result = run_suite(manifest, cache, offline=True)

    assert result["summary"]["errors"] == 1
    assert "SHA-256 mismatch" in result["cases"][0]["error"]


def test_cli_fetch_baseline_and_regression_gate_are_offline_reproducible(tmp_path: Path, capsys) -> None:
    manifest_path, cache, _ = _fixture(tmp_path)
    common = ["--manifest", str(manifest_path), "--cache-dir", str(cache), "--offline"]

    assert main(["benchmark", "fetch", *common]) == 0
    assert json.loads(capsys.readouterr().out)["artifacts"][0]["artifact"] == "design"

    baseline = tmp_path / "baseline.json"
    assert main(["benchmark", "baseline", *common, "--output", str(baseline)]) == 0
    assert json.loads(baseline.read_text())["schema_version"] == BASELINE_SCHEMA_VERSION

    output = tmp_path / "result.json"
    assert main(["benchmark", "run", *common, "--baseline", str(baseline), "--output", str(output)]) == 0
    assert json.loads(output.read_text())["summary"]["passed"] == 1

    payload = json.loads(baseline.read_text())
    payload["cases"]["sample/functional"]["diagnostics"]["total"] = 99
    baseline.write_text(json.dumps(payload), encoding="utf-8")
    assert main(["benchmark", "run", *common, "--baseline", str(baseline)]) == 1
    assert json.loads(capsys.readouterr().out)["summary"]["regressions"] == 1


def test_cli_rejects_benchmark_output_that_overlaps_manifest_or_baseline(tmp_path: Path, capsys) -> None:
    manifest_path, cache, _ = _fixture(tmp_path)
    common = ["--manifest", str(manifest_path), "--cache-dir", str(cache), "--offline"]
    original_manifest = manifest_path.read_bytes()

    with pytest.raises(SystemExit) as caught:
        main(["benchmark", "fetch", *common, "--output", str(manifest_path)])
    assert caught.value.code == 2
    assert "must not overlap --manifest input path" in capsys.readouterr().err
    assert manifest_path.read_bytes() == original_manifest

    baseline = tmp_path / "baseline.json"
    assert main(["benchmark", "baseline", *common, "--output", str(baseline)]) == 0
    original_baseline = baseline.read_bytes()
    with pytest.raises(SystemExit) as caught:
        main(["benchmark", "run", *common, "--baseline", str(baseline), "--output", str(baseline)])
    assert caught.value.code == 2
    assert "must not overlap --baseline input path" in capsys.readouterr().err
    assert baseline.read_bytes() == original_baseline


def test_difference_messages_cover_missing_and_unexpected_values() -> None:
    assert _differences({"a": 1}, {"b": 2}) == [
        "$.a: expected 1, value is missing",
        "$.b: unexpected value 2",
    ]


def test_benchmark_schemas_validate_manifest_fetch_baseline_and_result(tmp_path: Path) -> None:
    manifest_path, cache, _ = _fixture(tmp_path)
    manifest = load_manifest(manifest_path)
    fetched = fetch_suite(manifest, cache, offline=True)
    result = run_suite(manifest, cache, offline=True)
    baseline = baseline_from_result(result)
    root = Path(__file__).parents[1] / "benchmarks" / "schemas"
    values = {
        "manifest.schema.json": json.loads(manifest_path.read_text()),
        "fetch.schema.json": fetched,
        "result.schema.json": result,
        "baseline.schema.json": baseline,
    }

    for schema_name, value in values.items():
        schema = json.loads((root / schema_name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value)


def test_committed_public_baseline_is_schema_valid_digest_bound_and_suite_files_match() -> None:
    root = Path(__file__).parents[1]
    benchmark_root = root / "benchmarks"
    manifest_path = benchmark_root / "manifest.json"
    baseline_path = benchmark_root / "baseline.json"
    manifest = load_manifest(manifest_path)
    loaded_baseline = load_baseline(baseline_path, manifest)

    for instance_path, schema_path in (
        (manifest_path, benchmark_root / "schemas" / "manifest.schema.json"),
        (baseline_path, benchmark_root / "schemas" / "baseline.schema.json"),
    ):
        instance = json.loads(instance_path.read_text(encoding="utf-8"))
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(instance)

    assert set(loaded_baseline) == {
        f"{dataset.dataset_id}/{case.case_id}" for dataset in manifest.datasets for case in dataset.cases
    }
    for metadata in manifest.suite_files.values():
        source = manifest.path.parent / metadata.path
        assert source.stat().st_size == metadata.size_bytes
        assert hashlib.sha256(source.read_bytes()).hexdigest() == metadata.sha256
