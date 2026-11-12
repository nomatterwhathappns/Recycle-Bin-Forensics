"""Publication gates over package identity, integrity, and synthetic assets."""

from __future__ import annotations

import io
import json
import stat
import tarfile
import zipfile

import pytest

from examples.corpus import verify_corpus
from rbinforensics import __version__
from tools import prepare_release as release

COMMIT = "1234567890abcdef1234567890abcdef12345678"


@pytest.fixture
def assets(tmp_path):
    windows = tmp_path / f"RecycleBinForensics-{__version__}-windows-x64.zip"
    info = {
        "version": __version__,
        "commit": COMMIT,
        "platform": "windows-x64",
        "smoke_test": {
            "version": __version__,
            "status": "ok",
            "tk_version": "8.6.15",
            "checks": dict.fromkeys(("tk", "parser", "widgets", "timezone", "export"), True),
        },
    }
    members = {
        "RecycleBinForensics/BUILD-INFO.json": json.dumps(info).encode(),
        "RecycleBinForensics/RecycleBinForensics.exe": b"MZsynthetic test executable header",
        "RecycleBinForensics/_internal/python.dll": b"synthetic runtime fixture",
        "RecycleBinForensics/LICENSE": b"MIT fixture",
        "RecycleBinForensics/THIRD_PARTY_LICENSES.txt": b"Runtime license fixture",
        "RecycleBinForensics/START_HERE.txt": b"Startup instructions fixture",
    }
    checksum = tmp_path / "SHA256SUMS.txt"

    def write_windows():
        with zipfile.ZipFile(windows, "w") as bundle:
            for name, contents in members.items():
                bundle.writestr(name, contents)
        checksum.write_text(f"{release.digest(windows)}  {windows.name}\n", encoding="utf-8")

    write_windows()
    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = dist / f"rbinforensics-{__version__}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as bundle:
        bundle.writestr(
            f"rbinforensics-{__version__}.dist-info/METADATA", f"Version: {__version__}\n"
        )
    source = dist / f"rbinforensics-{__version__}.tar.gz"
    with tarfile.open(source, "w:gz") as bundle:
        contents = f"Version: {__version__}\n".encode()
        metadata = tarfile.TarInfo(f"rbinforensics-{__version__}/PKG-INFO")
        metadata.size = len(contents)
        bundle.addfile(metadata, io.BytesIO(contents))
    return windows, checksum, dist, members, info, write_windows


def test_stage_complete_assets_with_verifiable_deterministic_demo(assets, tmp_path):
    windows, checksum, dist, *_ = assets
    first, second = tmp_path / "first", tmp_path / "second"
    names = release.prepare_release(windows, checksum, dist, first, COMMIT, tag="v" + __version__)
    release.prepare_release(windows, checksum, dist, second, COMMIT)
    assert len(names) == 6
    release.verify_checksums(first)
    demo = f"RecycleBinForensics-{__version__}-demo.zip"
    assert (first / demo).read_bytes() == (second / demo).read_bytes()
    extracted = tmp_path / "demo-extracted"
    with zipfile.ZipFile(first / demo) as bundle:
        bundle.extractall(extracted)
    assert verify_corpus(extracted / "synthetic-corpus")["status"] == "passed"
    assert f"`{COMMIT}`" in (first / "RELEASE-NOTES.md").read_text()


def test_release_never_replaces_existing_destination(assets, tmp_path):
    windows, checksum, dist, *_ = assets
    output = tmp_path / "existing"
    output.mkdir()
    original = output / "original.txt"
    original.write_text("keep this")
    with pytest.raises(release.ReleaseError, match="already exists"):
        release.prepare_release(windows, checksum, dist, output, COMMIT)
    assert original.read_text() == "keep this"
    assert list(output.iterdir()) == [original]


@pytest.mark.parametrize("commit,tag", [("short", None), (COMMIT, "v0.0.1")])
def test_reject_unmatched_tag_or_nonfull_commit(assets, tmp_path, commit, tag):
    windows, checksum, dist, *_ = assets
    output = tmp_path / "rejected"
    with pytest.raises(release.ReleaseError):
        release.prepare_release(windows, checksum, dist, output, commit, tag=tag)
    assert not output.exists()


@pytest.mark.parametrize(
    "field,value", [("version", "0.0.0"), ("commit", "0" * 40), ("platform", "linux")]
)
def test_reject_windows_build_identity_mismatch(assets, field, value):
    windows, checksum, _, members, info, write = assets
    info[field] = value
    members["RecycleBinForensics/BUILD-INFO.json"] = json.dumps(info).encode()
    write()
    with pytest.raises(release.ReleaseError, match="source commit differs"):
        release.verify_windows(windows, checksum, COMMIT)


def test_windows_integrity_and_smoke_are_independent_gates(assets):
    windows, checksum, _, members, info, write = assets
    checksum.write_text("0" * 64 + "  " + windows.name + "\n")
    with pytest.raises(release.ReleaseError, match="checksum"):
        release.verify_windows(windows, checksum, COMMIT)
    info["smoke_test"]["checks"]["export"] = False
    members["RecycleBinForensics/BUILD-INFO.json"] = json.dumps(info).encode()
    write()
    with pytest.raises(release.ReleaseError, match="complete successful smoke"):
        release.verify_windows(windows, checksum, COMMIT)


@pytest.mark.parametrize(
    "name", ["../outside", "/absolute", "C:/drive", "a\\windows-path", "bad\nname"]
)
def test_reject_unsafe_archive_paths_before_staging(assets, tmp_path, name):
    windows, checksum, dist, members, _, write = assets
    members[name] = b"untrusted member"
    write()
    output = tmp_path / "rejected"
    # Windows ZipInfo normalizes backslashes to forward slashes. Either the
    # unsafe-member gate or the application-root gate must refuse that input.
    with pytest.raises(release.ReleaseError):
        release.prepare_release(windows, checksum, dist, output, COMMIT)
    assert not output.exists()


def test_literal_archive_member_guard_rejects_windows_redirect_syntax():
    assert not release.safe_member("a\\windows-path")
    assert not release.safe_member("../outside")
    assert not release.safe_member("C:/outside")


def test_owned_temp_alias_is_canonicalized_without_accepting_user_redirects(
    assets, tmp_path, monkeypatch
):
    canonical = tmp_path.resolve()
    backing = canonical / "system-temp"
    backing.mkdir()
    alias = canonical / "temp-alias"
    try:
        alias.symlink_to(backing, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Directory symlinks are unavailable on this test host.")
    allocate = release.tempfile.TemporaryDirectory

    def temporary_directory(*args, **kwargs):
        if kwargs.get("dir") is None:
            kwargs["dir"] = alias
        return allocate(*args, **kwargs)

    monkeypatch.setattr(release.tempfile, "TemporaryDirectory", temporary_directory)
    windows, checksum, dist, *_ = assets
    output = canonical / "release-assets"
    release.prepare_release(windows, checksum, dist, output, COMMIT)
    release.verify_checksums(output)
    assert list(backing.iterdir()) == []
    redirected_output = alias / "user-selected-output"
    with pytest.raises(ValueError, match="Symlink/reparse-point"):
        release.prepare_release(windows, checksum, dist, redirected_output, COMMIT)
    assert not (backing / "user-selected-output").exists()


def test_reject_case_colliding_and_redirect_archive_entries(assets):
    windows, checksum, _, _, _, _ = assets
    with zipfile.ZipFile(windows, "a") as bundle:
        bundle.writestr("recyclebinforensics/license", b"case collision")
    checksum.write_text(f"{release.digest(windows)}  {windows.name}\n")
    with pytest.raises(release.ReleaseError, match="unsafe or duplicate"):
        release.verify_windows(windows, checksum, COMMIT)
    with zipfile.ZipFile(windows, "w") as bundle:
        link = zipfile.ZipInfo("RecycleBinForensics/link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        bundle.writestr(link, "../outside")
    checksum.write_text(f"{release.digest(windows)}  {windows.name}\n")
    with pytest.raises(release.ReleaseError, match="unsafe or duplicate"):
        release.verify_windows(windows, checksum, COMMIT)


def test_release_assets_refuse_unlisted_or_changed_downloads(assets, tmp_path):
    windows, checksum, dist, *_ = assets
    output = tmp_path / "staged"
    release.prepare_release(windows, checksum, dist, output, COMMIT)
    extra = output / "unlisted.txt"
    extra.write_text("unlisted")
    with pytest.raises(release.ReleaseError, match="unlisted"):
        release.verify_checksums(output)
    extra.unlink()
    (output / "RELEASE-NOTES.md").write_text("changed")
    with pytest.raises(release.ReleaseError, match="Checksum mismatch"):
        release.verify_checksums(output)


def report_value(kind="reference_validation"):
    return {
        "schema_version": "1.0",
        "application_version": __version__,
        "report_kind": kind,
        "status": "passed" if kind == "reference_validation" else "completed",
        "summary": {
            "compared_records": 12,
            "unexplained_differences": 0,
            "ground_truth_differences": 0,
            "documented_reference_differences": 2,
        },
    }


def test_reports_are_included_without_concealing_known_reference_differences(assets, tmp_path):
    windows, checksum, dist, *_ = assets
    report = tmp_path / "synthetic-reference.json"
    report.write_text(json.dumps(report_value()))
    output = tmp_path / "published-assets"
    release.prepare_release(windows, checksum, dist, output, COMMIT, reports=[report])
    release.verify_checksums(output)
    notes = (output / "RELEASE-NOTES.md").read_text()
    assert "2 documented reference differences" in notes
    assert "whole UTC seconds" in notes
    assert "not counted as exact matches" in notes


@pytest.mark.parametrize(
    "changes",
    [
        {"application_version": "0.0.0"},
        {"schema_version": "future"},
        {"report_kind": "unknown"},
        {"status": "different"},
        {"summary": {"compared_records": 0}},
        {
            "summary": {
                "compared_records": 1,
                "unexplained_differences": 1,
                "ground_truth_differences": 0,
            }
        },
        {
            "summary": {
                "compared_records": 1,
                "unexplained_differences": 0,
                "ground_truth_differences": 1,
            }
        },
    ],
)
def test_release_rejects_wrong_or_failed_reports(assets, tmp_path, changes):
    windows, checksum, dist, *_ = assets
    report = tmp_path / "reference.json"
    report.write_text(json.dumps({**report_value(), **changes}))
    output = tmp_path / "rejected"
    with pytest.raises(release.ReleaseError):
        release.prepare_release(windows, checksum, dist, output, COMMIT, reports=[report])
    assert not output.exists()


def test_reject_duplicate_report_names_and_incomplete_benchmarks(assets, tmp_path):
    windows, checksum, dist, *_ = assets
    report = tmp_path / "benchmark.json"
    value = report_value("benchmark")
    value["status"] = "started"
    report.write_text(json.dumps(value))
    with pytest.raises(release.ReleaseError, match="completed"):
        release.prepare_release(windows, checksum, dist, tmp_path / "bad", COMMIT, reports=[report])
    value["status"] = "completed"
    report.write_text(json.dumps(value))
    with pytest.raises(release.ReleaseError, match="duplicate"):
        release.prepare_release(
            windows, checksum, dist, tmp_path / "bad", COMMIT, reports=[report, report]
        )


def test_source_distribution_version_must_match_release(assets):
    _, _, dist, *_ = assets
    wheel = dist / f"rbinforensics-{__version__}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as bundle:
        bundle.writestr(f"rbinforensics-{__version__}.dist-info/METADATA", "Version: 0.0.0\n")
    with pytest.raises(release.ReleaseError, match="Wheel metadata"):
        release.source_assets(dist)
