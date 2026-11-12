"""Ground-truth corpus validation detects data, oracle, and engine changes."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from examples.corpus import (
    PREFIX,
    TICKS,
    encode_metadata,
    expected_manifest,
    generate_corpus,
    verify_corpus,
)
from rbinforensics import scanner

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "synthetic-v1"


@pytest.fixture
def corpus(tmp_path):
    root = tmp_path.resolve() / "corpus"
    generate_corpus(root)
    return root


def test_published_fixture_and_regenerated_bytes_match_fixed_specification(corpus):
    assert verify_corpus(FIXTURE)["status"] == "passed"
    expected = {
        path.relative_to(FIXTURE).as_posix(): path.read_bytes()
        for path in FIXTURE.rglob("*")
        if path.is_file()
    }
    actual = {
        path.relative_to(corpus).as_posix(): path.read_bytes()
        for path in corpus.rglob("*")
        if path.is_file()
    }
    assert actual == expected
    manifest = expected_manifest()
    assert len(manifest["cases"]) == 20
    assert len(manifest["files"]) == 33
    assert manifest["expected_summary"]["errors"] == 6


def test_verification_checks_every_case_and_every_published_file(corpus):
    result = verify_corpus(corpus)
    assert result == {
        "corpus_id": "rbf-synthetic-v1",
        "status": "passed",
        "cases_checked": 20,
        "files_verified": 33,
        "failures": [],
    }


def test_ground_truth_preserves_uint64_and_adjacent_tick_expectations():
    cases = {case["id"]: case for case in expected_manifest()["cases"]}
    assert cases["large-uint64"]["expected"]["metadata"]["original_size"] == 9_007_199_254_740_995
    assert (
        cases["max-uint64"]["expected"]["metadata"]["original_size"] == 18_446_744_073_709_551_615
    )
    assert cases["v1-ascii"]["expected"]["metadata"]["deletion_filetime"] == TICKS
    assert cases["adjacent-tick"]["expected"]["metadata"]["deletion_filetime"] == TICKS + 1
    assert cases["adjacent-tick"]["expected"]["metadata"]["deleted_at_utc"].endswith("1234568Z")


@pytest.mark.parametrize("mutation", ["changed", "missing", "extra", "directory", "nested-payload"])
def test_integrity_mismatches_fail_before_engine_reads(corpus, monkeypatch, mutation):
    target = corpus / PREFIX / "$RV10001.txt"
    if mutation == "changed":
        target.write_bytes(b"tampered")
    elif mutation == "missing":
        target.unlink()
    elif mutation == "extra":
        (corpus / "extra.txt").write_bytes(b"extra")
    elif mutation == "directory":
        (corpus / "unexpected-directory").mkdir()
    else:
        (corpus / PREFIX / "$RDIR009" / "readme.txt").write_bytes(b"changed nested content")
    monkeypatch.setattr(
        scanner, "scan", lambda *_args, **_kwargs: pytest.fail("scan ran on modified corpus")
    )
    result = verify_corpus(corpus)
    assert result["status"] == "failed"
    assert result["cases_checked"] == 0


def test_rewriting_manifest_to_match_tampering_cannot_replace_the_oracle(corpus):
    changed = corpus / PREFIX / "$RV10001.txt"
    changed.write_bytes(b"EVIL!!")
    manifest_path = corpus / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = next(entry for entry in manifest["files"] if entry["path"] == f"{PREFIX}/$RV10001.txt")
    entry["sha256"] = hashlib.sha256(changed.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = verify_corpus(corpus)
    assert result["status"] == "failed"
    assert any("manifest.json" in issue for issue in result["failures"])


@pytest.mark.parametrize("data", [b"{malformed", b"[]", b"\xff"])
def test_invalid_manifest_is_a_failed_validation(corpus, data):
    (corpus / "manifest.json").write_bytes(data)
    assert verify_corpus(corpus)["status"] == "failed"


def test_changed_engine_field_is_not_self_validated(corpus, monkeypatch):
    original = scanner.scan

    def altered(*args, **kwargs):
        report = original(*args, **kwargs)
        record = next(record for record in report["records"] if record["metadata"] is not None)
        record["metadata"]["original_path"] = r"C:\Wrong\value.txt"
        return report

    monkeypatch.setattr(scanner, "scan", altered)
    result = verify_corpus(corpus)
    assert result["status"] == "failed"
    assert any("metadata differs" in issue for issue in result["failures"])


def test_changed_engine_inventory_and_summary_are_detected(corpus, monkeypatch):
    original = scanner.scan

    def altered(*args, **kwargs):
        report = original(*args, **kwargs)
        report["records"].pop()
        report["summary"]["errors"] = 0
        return report

    monkeypatch.setattr(scanner, "scan", altered)
    result = verify_corpus(corpus)
    assert result["status"] == "failed"
    assert any("record inventory" in issue for issue in result["failures"])
    assert any("summary" in issue for issue in result["failures"])


def test_generation_refuses_existing_destination_without_modifying_it(corpus):
    before = (corpus / "manifest.json").read_bytes()
    with pytest.raises(FileExistsError):
        generate_corpus(corpus)
    assert (corpus / "manifest.json").read_bytes() == before


def test_generator_and_verifier_refuse_symlink_components(corpus, tmp_path):
    link = tmp_path.resolve() / "redirect"
    try:
        link.symlink_to(corpus, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Creating symlinks requires platform/user support")
    with pytest.raises(ValueError, match="symlink/reparse"):
        generate_corpus(link / "new")
    result = verify_corpus(link)
    assert result["status"] == "failed"
    assert not (corpus / "new").exists()


def test_verifier_rejects_oversized_unexpected_file(corpus):
    (corpus / "large.bin").write_bytes(b"x" * (1024 * 1024 + 1))
    result = verify_corpus(corpus)
    assert result["status"] == "failed"
    assert any("oversized" in issue for issue in result["failures"])


def test_invalid_encoder_input_is_rejected():
    with pytest.raises(ValueError, match="Version 1 path"):
        encode_metadata(1, "C:\\" + "a" * 260, 0)
    with pytest.raises(ValueError, match="versions 1 and 2"):
        encode_metadata(3, r"C:\Demo\x", 0)


def test_cli_returns_zero_for_expected_errors_and_nonzero_for_corruption(tmp_path):
    destination = tmp_path.resolve() / "cli-corpus"
    generated = subprocess.run(
        [sys.executable, str(ROOT / "examples/generate_corpus.py"), str(destination)],
        capture_output=True,
        text=True,
    )
    assert generated.returncode == 0, generated.stderr
    verified = subprocess.run(
        [sys.executable, str(ROOT / "examples/verify_corpus.py"), str(destination)],
        capture_output=True,
        text=True,
    )
    assert verified.returncode == 0, verified.stderr
    assert json.loads(verified.stdout)["cases_checked"] == 20
    (destination / "manifest.json").unlink()
    failed = subprocess.run(
        [sys.executable, str(ROOT / "examples/verify_corpus.py"), str(destination)],
        capture_output=True,
        text=True,
    )
    assert failed.returncode == 1
    assert json.loads(failed.stdout)["status"] == "failed"
