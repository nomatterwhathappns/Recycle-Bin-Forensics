"""Build and exercise a portable native Windows desktop distribution.

Run on 64-bit Windows with ``python -m pip install '.[freeze]'`` first. Build
intermediates stay in a temporary directory and completed archives are created
exclusively, so an earlier tested build is never silently overwritten.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from rbinforensics import __version__

ROOT = Path(__file__).resolve().parents[1]
APP_NAME = "RecycleBinForensics"


class BuildError(RuntimeError):
    """The build or its packaged-application validation did not complete."""


def version_tuple(version: str) -> tuple[int, int, int, int]:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise BuildError("Windows builds require a three-part numeric release version.")
    numbers = tuple(int(part) for part in version.split("."))
    if any(number > 65535 for number in numbers):
        raise BuildError("Windows version fields must be between 0 and 65535.")
    return (*numbers, 0)


def version_resource(version: str) -> str:
    """Create trusted numeric product metadata for Explorer's EXE properties."""
    numbers = version_tuple(version)
    return f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={numbers!r}, prodvers={numbers!r}, mask=0x3f,
                   flags=0, OS=0x40004, fileType=1, subtype=0, date=(0, 0)),
  kids=[StringFileInfo([StringTable('040904B0', [
    StringStruct('CompanyName', 'nomatterwhathappns'),
    StringStruct('FileDescription', 'Recycle Bin Forensics desktop application'),
    StringStruct('FileVersion', '{version}'),
    StringStruct('ProductName', 'Recycle Bin Forensics'),
    StringStruct('ProductVersion', '{version}'),
    StringStruct('OriginalFilename', '{APP_NAME}.exe')
  ])]), VarFileInfo([VarStruct('Translation', [1033, 1200])])]
)
"""


def verify_smoke(executable: Path, destination: Path, version: str) -> dict:
    """Require the bundled application to prove successful Tk/parser startup."""
    environment = os.environ.copy()
    for name in ("PYTHONHOME", "PYTHONPATH", "TCL_LIBRARY", "TK_LIBRARY"):
        environment.pop(name, None)
    subprocess.run(
        [str(executable), "--smoke-test", "--smoke-output", str(destination)],
        check=True,
        timeout=90,
        cwd=destination.parent,
        env=environment,
    )
    try:
        result = json.loads(destination.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BuildError("Packaged GUI did not write a valid smoke-test result.") from exc
    if not isinstance(result, dict) or result.get("status") != "ok":
        raise BuildError(f"Packaged GUI smoke test did not succeed: {result!r}")
    if result.get("version") != version:
        raise BuildError("Packaged GUI version differs from the distribution version.")
    checks = result.get("checks")
    if not isinstance(checks, dict) or not all(
        checks.get(name) is True for name in ("tk", "parser", "widgets")
    ):
        raise BuildError("Packaged GUI did not verify Tk, parser, and application widgets.")
    if not isinstance(result.get("tk_version"), str) or not result["tk_version"]:
        raise BuildError("Packaged GUI did not identify its bundled Tk runtime.")
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build(output: Path) -> tuple[Path, Path]:
    if platform.system() != "Windows" or struct.calcsize("P") != 8:
        raise BuildError("Build on native 64-bit Windows; PyInstaller does not cross-compile.")
    if platform.machine().lower() not in ("amd64", "x86_64"):
        raise BuildError("This distribution targets Windows x64.")
    version_tuple(__version__)
    output = output.resolve()
    archive = output / f"{APP_NAME}-{__version__}-windows-x64.zip"
    checksum = output / "SHA256SUMS.txt"
    if archive.exists() or checksum.exists():
        raise BuildError("Build output already exists; choose a new output directory.")
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rbf-windows-build-", dir=output) as temporary:
        staging = Path(temporary)
        resource = staging / "version.txt"
        resource.write_text(version_resource(__version__), encoding="utf-8")
        command = [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--onedir",
            "--windowed",
            "--name",
            APP_NAME,
            "--distpath",
            str(staging / "dist"),
            "--workpath",
            str(staging / "work"),
            "--specpath",
            str(staging),
            "--paths",
            str(ROOT / "src"),
            "--collect-data",
            "tzdata",
            "--collect-submodules",
            "tzdata",
            "--hidden-import",
            "tkinter",
            "--version-file",
            str(resource),
            str(ROOT / "tools" / "gui_entry.py"),
        ]
        subprocess.run(command, cwd=ROOT, check=True)
        application = staging / "dist" / APP_NAME
        executable = application / f"{APP_NAME}.exe"
        if not executable.is_file():
            raise BuildError("PyInstaller did not produce the expected desktop executable.")
        smoke = verify_smoke(executable, staging / "smoke-result.json", __version__)
        information = {
            "version": __version__,
            "platform": "windows-x64",
            "windows_build": platform.version(),
            "python": platform.python_version(),
            "pyinstaller": importlib.metadata.version("pyinstaller"),
            "commit": os.environ.get("GITHUB_SHA"),
            "smoke_test": smoke,
        }
        (application / "BUILD-INFO.json").write_text(
            json.dumps(information, indent=2) + "\n", encoding="utf-8"
        )
        shutil.copyfile(ROOT / "LICENSE", application / "LICENSE")
        (application / "START_HERE.txt").write_text(
            f"Recycle Bin Forensics {__version__}\n\n"
            "Extract the entire ZIP to a separate application folder.\n"
            f"Double-click {APP_NAME}.exe to open the desktop application.\n"
            "Keep the _internal directory beside the EXE; it contains the bundled runtime.\n"
            "Python, a server, and an account are not required to run this application.\n\n"
            "Analyze a verified working copy or read-only evidence. Save reports outside it.\n"
            "This tool does not acquire evidence or recover permanently deleted data.\n"
            "No source evidence is uploaded. Reports may contain sensitive paths and labels.\n\n"
            "Source, instructions, and limitations:\n"
            "https://github.com/nomatterwhathappns/Recycle-Bin-Forensics\n",
            encoding="utf-8",
        )
        archive_created = False
        checksum_created = False
        try:
            with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as bundle:
                archive_created = True
                for path in sorted(application.rglob("*")):
                    if path.is_file():
                        bundle.write(path, str(Path(APP_NAME) / path.relative_to(application)))
            # Test exactly the archive users will extract, independently of the
            # source checkout, build staging, and developer Python/Tcl settings.
            with tempfile.TemporaryDirectory(prefix="rbf-portable-check-") as relocated:
                extracted = Path(relocated)
                with zipfile.ZipFile(archive) as bundle:
                    bundle.extractall(extracted)
                verify_smoke(
                    extracted / APP_NAME / f"{APP_NAME}.exe",
                    extracted / "portable-smoke.json",
                    __version__,
                )
            print("Relocated portable GUI smoke test passed.")
            digest = sha256_file(archive)
            with checksum.open("x", encoding="utf-8", newline="\n") as stream:
                checksum_created = True
                stream.write(f"{digest}  {archive.name}\n")
        except BaseException:
            if archive_created:
                archive.unlink(missing_ok=True)
            if checksum_created:
                checksum.unlink(missing_ok=True)
            raise
    return archive, checksum


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "windows")
    args = parser.parse_args(argv)
    try:
        archive, checksum = build(args.output)
    except (BuildError, OSError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"Windows package build failed: {exc}\n")
    print(f"Created {archive}")
    print(f"Created {checksum}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
