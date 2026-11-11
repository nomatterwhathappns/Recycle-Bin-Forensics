"""Exercise every GUI scenario in a fresh Windows application process.

Repeated destruction/recreation of Tcl interpreters in one Windows process can
fail inside Tk script loading. The shipped application uses one interpreter per
process. Isolating scenarios preserves that lifecycle without retries or skips;
coverage is appended across all scenarios and checked once at the end.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "tools" / "gui.coveragerc"


def main() -> int:
    environment = os.environ.copy()
    environment["RBF_RUN_GUI"] = "1"
    collected = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "--color=no",
            "tests/test_gui.py",
            "tests/test_gui_entry.py",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    nodes = [
        line.strip()
        for line in collected.stdout.splitlines()
        if line.startswith(("tests/", "tests\\")) and "::" in line
    ]
    if not nodes:
        raise RuntimeError("No GUI tests were collected; refusing an empty validation run.")
    with tempfile.TemporaryDirectory(prefix="rbf-gui-coverage-") as temporary:
        environment["COVERAGE_FILE"] = str(Path(temporary) / ".coverage")
        failures = []
        for node in nodes:
            print(f"\nNative GUI scenario: {node}", flush=True)
            try:
                subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "pytest",
                        node,
                        "--cov=rbinforensics.gui",
                        f"--cov-config={CONFIG}",
                        "--cov-append",
                        "--cov-report=",
                        "--cov-fail-under=0",
                        "-v",
                    ],
                    cwd=ROOT,
                    env=environment,
                    timeout=90,
                    check=True,
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                failures.append(node)
        measured = subprocess.run(
            [sys.executable, "-m", "coverage", "report", f"--rcfile={CONFIG}", "--fail-under=85"],
            cwd=ROOT,
            env=environment,
            check=False,
        )
        if failures:
            print("Failed native GUI scenarios:\n" + "\n".join(failures), file=sys.stderr)
        print(f"Native GUI scenarios: {len(nodes) - len(failures)}/{len(nodes)} passed.")
        return 1 if failures or measured.returncode else 0


if __name__ == "__main__":
    raise SystemExit(main())
