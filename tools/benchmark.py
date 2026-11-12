"""Measure synthetic Recycle Bin workloads in isolated application processes.

Run from an installed checkout, for example:
    python tools/benchmark.py --counts 1000 10000 --repeats 3 --output work/bench.json

Generation is excluded from measured scan time. Filesystem caches are not
flushed. This is an end-to-end small-file workload, not a disk bandwidth test.
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import math
import os
import platform
import re
import statistics
import struct
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from pathlib import Path

from rbinforensics import __version__
from rbinforensics.output import validate_output
from rbinforensics.scanner import ScanOptions, ensure_no_symlinks, scan

BASE_FILETIME = 134_129_198_451_234_567
HEARTBEAT_MS = 10
ROOT = Path(__file__).resolve().parents[1]


def positive_integer(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def positive_seconds(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be finite and greater than zero")
    return number


def payload_bytes(index: int, length: int) -> bytes:
    """Deterministic, fictitious bytes; no external evidence is read."""
    prefix = b"SYNTHETIC BENCHMARK ONLY\n" + struct.pack("<Q", index)
    return (prefix + b"." * length)[:length]


def generate_workload(destination: Path, count: int, payload_size: int) -> dict:
    """Create a new paired-file dataset with mixed v1/v2 metadata layouts."""
    if count < 1 or payload_size < 1:
        raise ValueError("count and payload size must be positive")
    ensure_no_symlinks(destination)
    destination.mkdir(parents=False, exist_ok=False)
    metadata_bytes = 0
    for index in range(count):
        # A deterministic permutation avoids benchmarking only sorted paths.
        number = (index * 2_654_435_761) & 0xFFFFFFFF
        original = rf"C:\SYNTHETIC_BENCH\record-{number:010d}.txt"
        encoded = (original + "\0").encode("utf-16-le")
        version = 1 if index % 2 == 0 else 2
        header = struct.pack("<QQQ", version, payload_size, BASE_FILETIME + index)
        data = (
            header + encoded.ljust(520, b"\0")
            if version == 1
            else header + struct.pack("<I", len(encoded) // 2) + encoded
        )
        suffix = f"BENCH{index:09d}.txt"
        with (destination / ("$I" + suffix)).open("xb") as stream:
            stream.write(data)
        with (destination / ("$R" + suffix)).open("xb") as stream:
            stream.write(payload_bytes(index, payload_size))
        metadata_bytes += len(data)
    return {
        "metadata_count": count,
        "payload_count": count,
        "payload_size_bytes": payload_size,
        "logical_metadata_bytes": metadata_bytes,
        "logical_payload_bytes": count * payload_size,
        "versions": {"1": (count + 1) // 2, "2": count // 2},
    }


def peak_rss() -> tuple[int | None, str]:
    """Return process high-water resident bytes, not Python allocation size."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        function = psapi.GetProcessMemoryInfo
        function.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
        function.restype = wintypes.BOOL
        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        if function(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
            return int(counters.PeakWorkingSetSize), "Windows PeakWorkingSetSize (bytes)"
        return None, "Windows process memory query failed"
    try:
        import resource

        high_water = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if sys.platform == "darwin":
            return int(high_water), "getrusage ru_maxrss (macOS bytes)"
        if sys.platform.startswith("linux"):
            return int(high_water * 1024), "getrusage ru_maxrss (Linux KiB converted to bytes)"
        return None, "ru_maxrss units unspecified on this platform"
    except (ImportError, OSError, ValueError):
        return None, "process resident high-water mark unavailable"


def verify_report(report: dict, count: int, payload_size: int, hashed: bool) -> None:
    expected = {
        "candidates": count,
        "parsed": count,
        "errors": 0,
        "warnings": 0,
        "skipped": 0,
        "payloads_hashed": count if hashed else 0,
        "orphan_payloads": 0,
    }
    if report["summary"] != expected or len(report["records"]) != count:
        raise RuntimeError(f"Benchmark workload failed its result check: {report['summary']!r}")
    if report["selection"]["matched"] != count or len(report["timeline"]["events"]) != count:
        raise RuntimeError("Benchmark selection/timeline is incomplete")
    for index, record in enumerate(report["records"]):
        payload = record["payload"]
        if payload["size"] != payload_size or payload["size_matches_metadata"] is not True:
            raise RuntimeError("Benchmark payload size mismatch")
        if (
            hashed
            and payload["sha256"] != hashlib.sha256(payload_bytes(index, payload_size)).hexdigest()
        ):
            raise RuntimeError("Benchmark payload digest mismatch")


def scan_measurement(evidence: Path, count: int, payload_size: int, hashed: bool) -> dict:
    gc.collect()
    cpu_started = time.process_time()
    started = time.perf_counter()
    report = scan(evidence, ScanOptions(hash_payload=hashed))
    elapsed = time.perf_counter() - started
    cpu = time.process_time() - cpu_started
    verify_report(report, count, payload_size, hashed)
    memory, method = peak_rss()
    return {
        "kind": "scan",
        "count": count,
        "hash_payload": hashed,
        "elapsed_seconds": elapsed,
        "process_cpu_seconds": cpu,
        "metadata_per_second": count / elapsed,
        "end_to_end_payload_bytes_per_second": count * payload_size / elapsed if hashed else None,
        "peak_resident_bytes": memory,
        "memory_method": method,
        "validated": True,
    }


def heartbeat_summary(gaps: list[float]) -> dict:
    ordered = sorted(gaps)
    return {
        "samples": len(gaps),
        "requested_interval_ms": HEARTBEAT_MS,
        "median_gap_ms": statistics.median(ordered) * 1000 if ordered else None,
        "p95_gap_ms": ordered[max(0, math.ceil(len(ordered) * 0.95) - 1)] * 1000
        if ordered
        else None,
        "max_gap_ms": max(ordered) * 1000 if ordered else None,
        "max_lateness_ms": max(0, max(ordered) * 1000 - HEARTBEAT_MS) if ordered else None,
    }


def gui_measurement(evidence: Path, count: int, payload_size: int, timeout: float) -> dict:
    """Observe actual Tk widgets and timer gaps; no responsiveness pass grade."""
    from rbinforensics.gui import PAGE_SIZE, ForensicsApp

    started = time.perf_counter()
    app = ForensicsApp()
    app.geometry("1000x700")
    errors = []
    app._dialog_error = lambda title, error: errors.append(f"{title}: {error}")
    app.report_callback_exception = lambda kind, error, _tb: errors.append(f"{kind}: {error}")
    app.update()
    startup = time.perf_counter() - started
    gaps: list[float] = []
    last_beat = time.perf_counter()
    heartbeat_id = None

    def heartbeat() -> None:
        nonlocal last_beat, heartbeat_id
        now = time.perf_counter()
        gaps.append(now - last_beat)
        last_beat = now
        heartbeat_id = app.after(HEARTBEAT_MS, heartbeat)

    def pump_until(predicate: Callable[[], bool], deadline: float) -> None:
        while not predicate():
            if time.perf_counter() >= deadline:
                raise TimeoutError("GUI benchmark exceeded its measurement timeout")
            app.update()
            if errors:
                raise RuntimeError("GUI benchmark failed: " + "; ".join(errors))
            time.sleep(0.001)

    def measure(action: Callable[[], None], predicate: Callable[[], bool]) -> dict:
        nonlocal last_beat
        gaps.clear()
        last_beat = time.perf_counter()
        begin = time.perf_counter()
        action()
        pump_until(predicate, begin + timeout)
        elapsed = time.perf_counter() - begin
        # Capture the heartbeat delayed by the last synchronous callback too.
        settle = time.perf_counter() + 0.03
        pump_until(lambda: time.perf_counter() >= settle, begin + timeout)
        return {"elapsed_seconds": elapsed, "heartbeat": heartbeat_summary(gaps)}

    try:
        heartbeat_id = app.after(HEARTBEAT_MS, heartbeat)
        app.source_var.set(str(evidence))
        app.hash_var.set(False)
        scan_result = measure(app.start_scan, lambda: not app._awaiting_terminal)
        if app.session.state != "complete" or app.session.report is None:
            raise RuntimeError("GUI benchmark did not publish a complete report")
        verify_report(app.session.report, count, payload_size, False)
        visible = len(app.inventory.get_children())
        if visible != min(PAGE_SIZE, count):
            raise RuntimeError("GUI benchmark pagination produced an unexpected row count")
        sort_result = measure(lambda: app.sort_table(app.inventory, "path"), lambda: True)
        page_result = (
            measure(lambda: app._change_page(app.inventory, 1), lambda: True)
            if count > PAGE_SIZE
            else None
        )
        memory, method = peak_rss()
        return {
            "kind": "gui",
            "count": count,
            "geometry": "1000x700",
            "tk_patchlevel": app.tk.call("info", "patchlevel"),
            "startup_seconds": startup,
            "scan_and_first_page": scan_result,
            "sort_path_ascending": sort_result,
            "next_page": page_result,
            "visible_rows_first_page": visible,
            "peak_resident_bytes": memory,
            "memory_method": method,
            "validated": True,
        }
    finally:
        if heartbeat_id is not None:
            app.after_cancel(heartbeat_id)
        app.destroy()


def environment_info(workspace: Path) -> dict:
    cpu_name = platform.processor() or platform.machine()
    if sys.platform.startswith("linux"):
        try:
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.startswith("model name"):
                    cpu_name = line.split(":", 1)[1].strip()
                    break
        except OSError:
            pass
    return {
        "application_version": __version__,
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu": cpu_name,
        "logical_cpu_count": os.cpu_count(),
        "filesystem_block_size": os.statvfs(workspace).f_frsize if hasattr(os, "statvfs") else None,
        "storage_scope": "Generated local small files; backing media and filesystem caches uncontrolled",
    }


def run_worker(
    kind: str, evidence: Path, count: int, size: int, hashed: bool, timeout: float
) -> dict:
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--worker",
        kind,
        "--evidence",
        str(evidence),
        "--count",
        str(count),
        "--payload-bytes",
        str(size),
        "--timeout",
        str(timeout),
    ]
    if hashed:
        command.append("--hash-payload")
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=True
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{kind} measurement for {count} records exceeded {timeout}s") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"{kind} measurement failed: {exc.stderr.strip()}") from exc
    try:
        result = json.loads(completed.stdout)
    except ValueError as exc:
        raise RuntimeError("Benchmark worker did not return valid JSON") from exc
    if (
        result.get("kind") != kind
        or result.get("count") != count
        or result.get("validated") is not True
    ):
        raise RuntimeError("Benchmark worker returned an unvalidated or mismatched result")
    return result


def summarize(measurements: list[dict]) -> list[dict]:
    groups: dict[tuple[int, bool], list[dict]] = {}
    for item in measurements:
        if item["kind"] == "scan":
            groups.setdefault((item["count"], item["hash_payload"]), []).append(item)
    output = []
    for (count, hashed), items in sorted(groups.items()):
        elapsed = [item["elapsed_seconds"] for item in items]
        resident = [
            item["peak_resident_bytes"] for item in items if item["peak_resident_bytes"] is not None
        ]
        output.append(
            {
                "count": count,
                "hash_payload": hashed,
                "repeats": len(items),
                "min_elapsed_seconds": min(elapsed),
                "median_elapsed_seconds": statistics.median(elapsed),
                "max_elapsed_seconds": max(elapsed),
                "median_metadata_per_second": statistics.median(
                    item["metadata_per_second"] for item in items
                ),
                "max_peak_resident_bytes": max(resident) if resident else None,
            }
        )
    return output


def validate_destination(destination: Path) -> None:
    ensure_no_symlinks(destination)
    if destination.exists():
        raise ValueError("Output already exists; choose a new filename")
    if not destination.parent.is_dir():
        raise ValueError("Output parent must already exist")


def source_commit() -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        value = result.stdout.strip()
        return value if re.fullmatch(r"[0-9a-f]{40,64}", value) else None
    except (OSError, subprocess.SubprocessError):
        return None


def source_tree_dirty() -> bool | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=normal"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        return bool(result.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        return None


def write_document(output: Path, document: dict) -> None:
    identity = None
    try:
        with output.open("x", encoding="utf-8", newline="\n") as stream:
            info = os.fstat(stream.fileno())
            identity = info.st_dev, info.st_ino
            json.dump(document, stream, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        if identity is not None:
            try:
                current = output.lstat()
                if identity == (current.st_dev, current.st_ino):
                    output.unlink()
            except OSError:
                pass
        raise


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--counts", type=positive_integer, nargs="+", default=[1000, 10000])
    parser.add_argument("--repeats", type=positive_integer, default=3)
    parser.add_argument("--payload-bytes", type=positive_integer, default=64)
    parser.add_argument("--timeout", type=positive_seconds, default=300)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--work-dir", type=Path, help="Existing directory for temporary synthetic files"
    )
    parser.add_argument(
        "--gui", action="store_true", help="Also measure actual Tk widgets; requires a display"
    )
    parser.add_argument("--worker", choices=("scan", "gui"), help=argparse.SUPPRESS)
    parser.add_argument("--evidence", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--count", type=positive_integer, help=argparse.SUPPRESS)
    parser.add_argument("--hash-payload", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        if args.worker:
            if args.evidence is None or args.count is None:
                parser.error("Internal worker requires evidence and count")
            result = (
                scan_measurement(args.evidence, args.count, args.payload_bytes, args.hash_payload)
                if args.worker == "scan"
                else gui_measurement(args.evidence, args.count, args.payload_bytes, args.timeout)
            )
            print(json.dumps(result, allow_nan=False))
            return 0
        if args.output is None:
            parser.error("--output is required")
        output = args.output.absolute()
        validate_destination(output)
        if len(set(args.counts)) != len(args.counts):
            parser.error("--counts must not contain duplicates")
        if args.work_dir is not None:
            ensure_no_symlinks(args.work_dir)
            if not args.work_dir.is_dir():
                parser.error("--work-dir must be an existing directory")
        measurements = []
        workloads = []
        commit, dirty = source_commit(), source_tree_dirty()
        with tempfile.TemporaryDirectory(prefix="rbf-benchmark-", dir=args.work_dir) as temporary:
            workspace = Path(temporary)
            validate_output(workspace, output)
            environment = environment_info(workspace)
            for count in args.counts:
                evidence = workspace / f"evidence-{count}"
                started = time.perf_counter()
                workload = generate_workload(evidence, count, args.payload_bytes)
                workload["generation_seconds"] = time.perf_counter() - started
                workloads.append(workload)
                for repeat in range(args.repeats):
                    for hashed in (False, True):
                        result = run_worker(
                            "scan", evidence, count, args.payload_bytes, hashed, args.timeout
                        )
                        result["repeat"] = repeat + 1
                        measurements.append(result)
                    if args.gui:
                        result = run_worker(
                            "gui", evidence, count, args.payload_bytes, False, args.timeout
                        )
                        result["repeat"] = repeat + 1
                        measurements.append(result)
            document = {
                "schema_version": "1.0",
                "report_kind": "benchmark",
                "status": "completed",
                "application_version": __version__,
                "source_commit": commit,
                "source_tree_dirty": dirty,
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
                "environment": environment,
                "method": {
                    "timing": "perf_counter; scan only; generation/import/startup/validation excluded",
                    "gui_timing": "start_scan through completed first-page load; synchronous sort/page separately",
                    "memory": "Fresh child process resident high-water includes imports/report validation; not a scan-only delta",
                    "cache": "No OS cache flush; generated files and repeated scans generally warm caches",
                    "throughput": "End-to-end logical bytes/time, including metadata/discovery work; not disk bandwidth",
                    "gui_heartbeat": "10ms Tk timer; gaps include scheduling/painting/worker contention; 30ms settling captured outside elapsed timing",
                    "repeats": args.repeats,
                    "worker_timeout_seconds": args.timeout,
                },
                "workloads": workloads,
                "measurements": measurements,
                "summary": summarize(measurements),
            }
            validate_output(workspace, output)
            # Exclusive creation, with no report emitted for a failed workload.
            write_document(output, document)
        print(f"Wrote validated benchmark results to {output}")
        return 0
    except (OSError, ValueError, RuntimeError, TimeoutError) as exc:
        parser.exit(1, f"Benchmark failed: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
