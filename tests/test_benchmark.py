"""Benchmark results are observations only after the workload is checked."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from rbinforensics import __version__
from rbinforensics.scanner import ScanOptions, scan
from tools import benchmark


def test_generator_produces_repeatable_mixed_layouts_and_known_hashes(tmp_path: Path) -> None:
    first, second = tmp_path / "first", tmp_path / "second"
    info = benchmark.generate_workload(first, 3, 64)
    assert info["versions"] == {"1": 2, "2": 1}
    benchmark.generate_workload(second, 3, 64)
    assert {item.name: item.read_bytes() for item in first.iterdir()} == {
        item.name: item.read_bytes() for item in second.iterdir()
    }
    result = scan(first, ScanOptions(hash_payload=True))
    assert [record["metadata"]["format_version"] for record in result["records"]] == [1, 2, 1]
    assert [record["metadata"]["deletion_filetime"] for record in result["records"]] == [
        benchmark.BASE_FILETIME + index for index in range(3)
    ]
    expected = b"SYNTHETIC BENCHMARK ONLY\n" + b"\0" * 8 + b"." * 31
    assert len(expected) == 64
    assert result["records"][0]["payload"]["sha256"] == hashlib.sha256(expected).hexdigest()
    benchmark.verify_report(result, 3, 64, True)


def test_generator_refuses_existing_destination_without_touching_contents(tmp_path: Path) -> None:
    existing = tmp_path / "existing"
    existing.mkdir()
    sentinel = existing / "sentinel"
    sentinel.write_text("keep")
    with pytest.raises(FileExistsError):
        benchmark.generate_workload(existing, 2, 64)
    assert sentinel.read_text() == "keep"
    assert list(existing.iterdir()) == [sentinel]


@pytest.mark.parametrize("count,size", [(0, 1), (-1, 1), (1, 0), (1, -1)])
def test_bad_workload_dimensions_create_nothing(tmp_path: Path, count: int, size: int) -> None:
    target = tmp_path / "no-output"
    with pytest.raises(ValueError):
        benchmark.generate_workload(target, count, size)
    assert not target.exists()


def test_incomplete_or_corrupted_workload_cannot_be_reported_as_success(tmp_path: Path) -> None:
    target = tmp_path / "evidence"
    benchmark.generate_workload(target, 2, 64)
    (target / "$RBENCH000000000.txt").write_bytes(b"x" * 64)
    with pytest.raises(RuntimeError, match="digest mismatch"):
        benchmark.scan_measurement(target, 2, 64, True)
    (target / "$RBENCH000000000.txt").unlink()
    with pytest.raises(RuntimeError, match="payload size mismatch"):
        benchmark.scan_measurement(target, 2, 64, False)


def test_scan_measurement_counts_only_parsed_items_and_labels_memory(tmp_path: Path) -> None:
    target = tmp_path / "evidence"
    benchmark.generate_workload(target, 4, 64)
    result = benchmark.scan_measurement(target, 4, 64, False)
    assert result["elapsed_seconds"] > 0
    assert result["process_cpu_seconds"] >= 0
    assert result["metadata_per_second"] > 0
    assert result["end_to_end_payload_bytes_per_second"] is None
    assert result["memory_method"]
    assert result["peak_resident_bytes"] is None or result["peak_resident_bytes"] > 0
    assert result["validated"] is True


def test_fresh_process_end_to_end_report_has_both_modes_and_reproducibility_context(
    tmp_path: Path,
) -> None:
    output = tmp_path / "benchmark.json"
    assert (
        benchmark.main(
            [
                "--counts",
                "3",
                "5",
                "--repeats",
                "2",
                "--output",
                str(output),
                "--work-dir",
                str(tmp_path),
            ]
        )
        == 0
    )
    report = json.loads(output.read_text())
    assert report["schema_version"] == "1.0"
    assert report["report_kind"] == "benchmark"
    assert report["status"] == "completed"
    assert report["application_version"] == __version__
    assert report["environment"]["python"]
    assert report["environment"]["cpu"]
    assert len(report["measurements"]) == 8
    assert len(report["summary"]) == 4
    assert all(result["validated"] for result in report["measurements"])
    assert {result["hash_payload"] for result in report["measurements"]} == {False, True}
    assert not list(tmp_path.glob("rbf-benchmark-*")), "Temporary workload must be cleaned up"


def test_summary_median_is_per_workload_and_mode() -> None:
    samples = [
        {
            "kind": "scan",
            "count": 9,
            "hash_payload": False,
            "elapsed_seconds": elapsed,
            "metadata_per_second": 9 / elapsed,
            "peak_resident_bytes": memory,
        }
        for elapsed, memory in [(1, 10), (3, 30), (8, None)]
    ]
    samples.append({"kind": "gui", "count": 9})
    summary = benchmark.summarize(samples)
    assert len(summary) == 1
    assert summary[0]["median_elapsed_seconds"] == 3
    assert summary[0]["min_elapsed_seconds"] == 1
    assert summary[0]["max_elapsed_seconds"] == 8
    assert summary[0]["median_metadata_per_second"] == 3
    assert summary[0]["max_peak_resident_bytes"] == 30


def test_heartbeat_reports_observed_stall_without_converting_it_to_a_pass_grade() -> None:
    stats = benchmark.heartbeat_summary([0.01, 0.01, 0.25])
    assert stats["samples"] == 3
    assert stats["median_gap_ms"] == 10
    assert stats["p95_gap_ms"] == 250
    assert stats["max_lateness_ms"] == 240
    assert benchmark.heartbeat_summary([])["max_gap_ms"] is None


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "-inf"])
def test_nonpositive_or_unbounded_timeout_is_rejected(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        benchmark.positive_seconds(value)


@pytest.mark.parametrize(
    "arguments",
    [
        ["--counts", "0"],
        ["--repeats", "0"],
        ["--payload-bytes", "0"],
        ["--counts", "1", "1"],
        ["--timeout", "nan"],
    ],
)
def test_invalid_cli_options_fail_before_generating_files(
    tmp_path: Path, arguments: list[str]
) -> None:
    output = tmp_path / "report.json"
    with pytest.raises(SystemExit) as error:
        benchmark.main([*arguments, "--output", str(output), "--work-dir", str(tmp_path)])
    assert error.value.code != 0
    assert list(tmp_path.iterdir()) == []


def test_existing_output_is_preserved_and_prevents_measurement(tmp_path: Path, monkeypatch) -> None:
    output = tmp_path / "report.json"
    output.write_text("previous report")
    monkeypatch.setattr(benchmark, "generate_workload", lambda *_: pytest.fail("must not generate"))
    with pytest.raises(SystemExit) as error:
        benchmark.main(["--counts", "1", "--output", str(output)])
    assert error.value.code == 1
    assert output.read_text() == "previous report"


def test_worker_failure_does_not_leave_success_report(tmp_path: Path, monkeypatch) -> None:
    output = tmp_path / "report.json"

    def fail(*_):
        raise RuntimeError("child failed")

    monkeypatch.setattr(benchmark, "run_worker", fail)
    with pytest.raises(SystemExit) as error:
        benchmark.main(["--counts", "1", "--output", str(output), "--work-dir", str(tmp_path)])
    assert error.value.code == 1
    assert not output.exists()
    assert not list(tmp_path.glob("rbf-benchmark-*"))


def test_timed_out_worker_is_not_treated_as_a_result(tmp_path: Path, monkeypatch) -> None:
    def timeout(*_, **__):
        raise subprocess.TimeoutExpired("test-child", 0.01)

    monkeypatch.setattr(benchmark.subprocess, "run", timeout)
    with pytest.raises(RuntimeError, match="exceeded"):
        benchmark.run_worker("scan", tmp_path, 1, 64, False, 0.01)


def test_worker_must_validate_its_requested_workload(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        benchmark.subprocess,
        "run",
        lambda *_, **__: subprocess.CompletedProcess(
            [], 0, stdout='{"kind":"scan","count":2,"validated":true}', stderr=""
        ),
    )
    with pytest.raises(RuntimeError, match="mismatched"):
        benchmark.run_worker("scan", tmp_path, 1, 64, False, 1)


def test_failed_json_write_cleans_only_its_own_partial_file(tmp_path: Path, monkeypatch) -> None:
    output = tmp_path / "report.json"

    def fail(*_, **__):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(benchmark.json, "dump", fail)
    with pytest.raises(OSError, match="disk failure"):
        benchmark.write_document(output, {})
    assert not output.exists()


def test_output_and_workload_redirects_are_rejected(tmp_path: Path) -> None:
    original = tmp_path / "original"
    original.mkdir()
    redirect = tmp_path / "redirect"
    try:
        redirect.symlink_to(original, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation unavailable")
    with pytest.raises(ValueError, match="Symlink/reparse"):
        benchmark.generate_workload(redirect / "evidence", 1, 64)
    with pytest.raises(ValueError, match="Symlink/reparse"):
        benchmark.validate_destination(redirect / "report.json")
    assert list(original.iterdir()) == []
