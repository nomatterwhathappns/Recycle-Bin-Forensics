"""Reference comparisons preserve disagreements and reject false validation."""

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
from pathlib import Path

import pytest

from examples.corpus import generate_corpus
from tools import compare_reference as reference

TICKS = 133_485_408_001_234_567
SOURCE_NAME = "$ISAMPLE.txt"
ORIGINAL = r"C:\Demo\report.txt"


def xml(*, size=7, path=ORIGINAL, time="2024-01-01T00:00:00Z", index=SOURCE_NAME):
    return (
        '<recyclebin format="dir" version="2">'
        f'<record index="{index}" size="{size}" time="{time}">'
        f"<path><![CDATA[{path}]]></path></record></recyclebin>"
    )


@pytest.fixture
def sample(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    source = evidence / SOURCE_NAME
    field = (ORIGINAL + "\0").encode("utf-16-le")
    source.write_bytes(struct.pack("<QQQI", 2, 7, TICKS, len(field) // 2) + field)
    executable = tmp_path / "rifiuti-vista"
    executable.write_bytes(b"independent executable identity")
    return source, executable


def fake_reference(monkeypatch, *, output=None, code=0, version="0.8.2", diagnostics=b""):
    original_run = reference.subprocess.run

    def run(command, **kwargs):
        if Path(command[0]).name != "rifiuti-vista":
            return original_run(command, **kwargs)
        assert kwargs["timeout"] in (15, 30)
        if command[1] == "--version":
            return subprocess.CompletedProcess(command, 0, f"rifiuti2 {version}\n".encode(), b"")
        return subprocess.CompletedProcess(
            command, code, (output if output is not None else xml()).encode(), diagnostics
        )

    monkeypatch.setattr(reference.subprocess, "run", run)


def test_xml_adapter_preserves_large_integer_and_unicode():
    values = reference.parse_rifiuti_xml(
        xml(size=9_007_199_254_740_995, path="C:\\Demo\\資料-📄.txt"), SOURCE_NAME
    )
    assert values["original_size"] == 9_007_199_254_740_995
    assert values["original_path"] == "C:\\Demo\\資料-📄.txt"


@pytest.mark.parametrize(
    "output",
    [
        "not XML",
        '<recyclebin format="dir" version="2"/>',
        xml().replace("</recyclebin>", xml()[xml().index("<record") :]),
        xml(index="$IOTHER.txt"),
        xml().replace("<path>", "<other>"),
        xml(time="2024-01-01T00:00:00.123Z"),
        xml().replace('size="7"', 'size="NaN"'),
        xml().replace('version="2"', 'version="bad"'),
    ],
)
def test_invalid_or_wrong_reference_record_is_not_a_match(output):
    with pytest.raises(reference.ReferenceError):
        reference.parse_rifiuti_xml(output, SOURCE_NAME)


def test_comparison_restricts_time_agreement_to_whole_seconds():
    rbf = {
        "format_version": 2,
        "original_size": 7,
        "original_path": ORIGINAL,
        "deletion_filetime": TICKS,
        "deleted_at_utc": "2024-01-01T00:00:00.1234567Z",
    }
    values = reference.parse_rifiuti_xml(xml(), SOURCE_NAME)
    assert reference.compare_values(rbf, values, "0.8.2") == []
    values["deleted_at_utc"] = "2024-01-01T00:00:01Z"
    assert reference.compare_values(rbf, values, "0.8.2")[0]["classification"] == "unexplained"


def test_size_difference_exception_requires_exact_maximum_and_pinned_version():
    rbf = {"original_size": (1 << 64) - 1}
    values = {"original_size": -1}
    assert reference.compare_values(rbf, values, "0.8.2")[0]["classification"] == (
        "documented_reference_difference"
    )
    assert reference.compare_values(rbf, values, "0.8.3")[0]["classification"] == "unexplained"
    rbf["original_size"] = 1 << 63
    values["original_size"] = -(1 << 63)
    assert reference.compare_values(rbf, values, "0.8.2")[0]["classification"] == "unexplained"


def test_zero_time_exception_cannot_accept_arbitrary_unknown_timestamps():
    rbf = {"deletion_filetime": 0, "deleted_at_utc": None}
    values = {"deleted_at_utc": "1601-01-01T00:00:00Z"}
    assert reference.compare_values(rbf, values, "0.8.2")[0]["classification"] == (
        "documented_reference_difference"
    )
    rbf["deletion_filetime"] = (1 << 64) - 1
    assert reference.compare_values(rbf, values, "0.8.2")[0]["classification"] == "unexplained"


def test_real_input_agreement_keeps_raw_ticks_and_source_hash(sample, monkeypatch):
    source, executable = sample
    fake_reference(monkeypatch)
    report = reference.run_comparison(executable, [{"id": "sample", "source": source}])
    assert report["status"] == "passed"
    assert report["report_kind"] == "reference_validation"
    assert report["summary"]["compared_records"] == 1
    assert report["results"][0]["rbf"]["deletion_filetime"] == TICKS
    assert len(report["results"][0]["source_sha256"]) == 64
    assert "whole UTC seconds" in report["scope"]["time_comparison"]
    assert report["summary"]["ground_truth_checked_records"] == 0
    assert "not checked" in report["scope"]["ground_truth"]


def test_unexplained_difference_never_passes_allow_known_flag(sample, monkeypatch):
    source, executable = sample
    fake_reference(monkeypatch, output=xml(path=r"C:\different.txt"))
    report = reference.run_comparison(
        executable, [{"id": "sample", "source": source}], allow_known_differences=True
    )
    assert report["status"] == "different"
    assert report["summary"]["unexplained_differences"] == 1


def test_ground_truth_mismatch_cannot_pass_when_two_parsers_agree(sample, monkeypatch):
    source, executable = sample
    fake_reference(monkeypatch)
    report = reference.run_comparison(
        executable,
        [{"id": "sample", "source": source, "expected": {"original_size": 99}}],
    )
    assert report["status"] == "different"
    assert report["summary"]["ground_truth_differences"] == 1
    assert report["summary"]["matching_records"] == 0


def test_documented_difference_requires_explicit_acceptance(sample, monkeypatch):
    source, executable = sample
    data = bytearray(source.read_bytes())
    data[8:16] = ((1 << 64) - 1).to_bytes(8, "little")
    source.write_bytes(data)
    fake_reference(monkeypatch, output=xml(size=-1))
    inputs = [{"id": "maximum", "source": source}]
    assert reference.run_comparison(executable, inputs)["status"] == "different"
    report = reference.run_comparison(executable, inputs, allow_known_differences=True)
    assert report["status"] == "passed"
    assert report["summary"]["documented_reference_differences"] == 1
    assert report["summary"]["matching_records"] == 0


def test_reference_warnings_remain_visible_when_decoded_fields_agree(sample, monkeypatch):
    source, executable = sample
    fake_reference(monkeypatch, code=5, diagnostics=b"Ignored dangling extraneous data")
    report = reference.run_comparison(executable, [{"id": "sample", "source": source}])
    result = report["results"][0]
    assert result["status"] == "match_with_reference_warning"
    assert "extraneous" in result["reference_diagnostics"]
    assert report["summary"]["reference_warning_records"] == 1


def test_empty_validation_is_an_error(sample, monkeypatch):
    _, executable = sample
    fake_reference(monkeypatch)
    with pytest.raises(reference.ReferenceError, match="No decoded metadata"):
        reference.run_comparison(executable, [{"id": "orphan", "skip": "no metadata"}])


def test_known_valid_input_rejection_cannot_silently_reduce_validation(sample, monkeypatch):
    source, executable = sample
    source.write_bytes(b"broken")
    fake_reference(monkeypatch, code=2, output="")
    with pytest.raises(reference.ReferenceError, match="Known-valid"):
        reference.run_comparison(
            executable, [{"id": "sample", "source": source, "expected": {"original_size": 7}}]
        )


def test_malformed_input_retains_reference_diagnostic_without_claiming_field_agreement(
    sample, monkeypatch
):
    source, executable = sample
    source.write_bytes(b"broken")
    fake_reference(monkeypatch, code=2, output="", diagnostics=b"Not a valid index")
    result = reference.compare_file(source, executable, "0.8.2")
    assert result["status"] == "not_comparable"
    assert result["compared_fields"] == []
    assert result["rbf_error_code"] == "truncated_header"
    assert result["reference_exit_code"] == 2
    assert result["reference_diagnostics"] == "Not a valid index"


def test_failed_reference_execution_is_never_a_match(sample, monkeypatch):
    source, executable = sample
    fake_reference(monkeypatch, code=2, diagnostics=b"error")
    with pytest.raises(reference.ReferenceError, match="exit 2"):
        reference.compare_file(source, executable, "0.8.2")


def test_changed_source_between_parsers_invalidates_comparison(sample, monkeypatch):
    source, executable = sample

    def run(command, **_kwargs):
        source.write_bytes(source.read_bytes() + b"changed")
        return subprocess.CompletedProcess(command, 0, xml().encode(), b"")

    monkeypatch.setattr(reference.subprocess, "run", run)
    with pytest.raises(reference.ReferenceError, match="Input changed"):
        reference.compare_file(source, executable, "0.8.2")


def test_corpus_digest_and_unsafe_relative_paths_are_rejected(tmp_path):
    corpus = tmp_path / "corpus"
    generate_corpus(corpus)
    inputs, provenance = reference.corpus_inputs(corpus)
    assert len([item for item in inputs if "expected" in item]) == 12
    assert provenance["corpus_id"] == "rbf-synthetic-v1"
    manifest_path = corpus / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    source = corpus / manifest["cases"][0]["source"]
    source.write_bytes(source.read_bytes() + b"changed")
    with pytest.raises(reference.ReferenceError, match="digest/size"):
        reference.corpus_inputs(corpus)
    manifest["cases"][0]["source"] = "../outside"
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(reference.ReferenceError, match="safe relative"):
        reference.corpus_inputs(corpus)


def test_cli_writes_new_output_and_does_not_overwrite_or_write_into_evidence(sample, monkeypatch):
    source, executable = sample
    fake_reference(monkeypatch)
    output = source.parent.parent / "comparison.json"
    args = ["--input", str(source), "--reference", str(executable), "--output", str(output)]
    assert reference.main(args) == 0
    saved = output.read_bytes()
    assert reference.main(args) == 2
    assert output.read_bytes() == saved
    args[-1] = str(source.parent / "comparison.json")
    assert reference.main(args) == 2
    assert not (source.parent / "comparison.json").exists()


def test_cli_difference_status_is_nonzero(sample, monkeypatch):
    source, executable = sample
    fake_reference(monkeypatch, output=xml(size=8))
    assert reference.main(["--input", str(source), "--reference", str(executable)]) == 1


def test_cli_missing_reference_and_unknown_executable_are_errors(sample, monkeypatch):
    source, executable = sample
    monkeypatch.setattr(reference.shutil, "which", lambda _: None)
    assert reference.main(["--input", str(source)]) == 2

    def wrong_program(command, **_kwargs):
        return subprocess.CompletedProcess(command, 0, b"another tool 0.8.2", b"")

    monkeypatch.setattr(reference.subprocess, "run", wrong_program)
    assert reference.main(["--input", str(source), "--reference", str(executable)]) == 2


def test_symlink_input_is_rejected_without_reference_execution(sample, tmp_path):
    source, executable = sample
    alias = tmp_path / "$IALIAS.txt"
    try:
        alias.symlink_to(source)
    except OSError:
        pytest.skip("Host does not grant symlink creation")
    with pytest.raises(ValueError, match="Symlink/reparse"):
        reference.compare_file(alias, executable, "0.8.2")


def test_nonregular_and_oversized_inputs_are_rejected(sample, tmp_path):
    _, executable = sample
    with pytest.raises(reference.ReferenceError, match="regular file"):
        reference.compare_file(tmp_path, executable, "0.8.2")
    huge = tmp_path / "$IHUGE.bin"
    with huge.open("wb") as stream:
        stream.truncate(reference.MAX_METADATA_BYTES + 1)
    with pytest.raises(reference.ReferenceError, match="exceeds"):
        reference.compare_file(huge, executable, "0.8.2")


@pytest.fixture
def windows_samples(tmp_path):
    root = tmp_path / "windows-samples"
    root.mkdir()
    for name in ("ascii-sample", "unicode-資料-📄"):
        case = root / name
        case.mkdir()
        field = (ORIGINAL + "\0").encode("utf-16-le")
        data = struct.pack("<QQQI", 2, 7, TICKS, len(field) // 2) + field
        (case / SOURCE_NAME).write_bytes(data)
        facts = {
            "sample_kind": "controlled_windows_shell",
            "windows_build": "10.0.26100",
            "original_path": ORIGINAL,
            "original_size": 7,
            "payload_sha256": hashlib.sha256(b"payload").hexdigest(),
            "metadata_name": SOURCE_NAME,
            "metadata_sha256": hashlib.sha256(data).hexdigest(),
            "deletion_lower_bound_filetime": TICKS - 20_000_000,
            "deletion_upper_bound_filetime": TICKS + 20_000_000,
        }
        (case / "provenance.json").write_text(json.dumps(facts), encoding="utf-8")
    return root


def test_windows_sample_comparison_binds_independent_facts_and_provenance(
    sample, windows_samples, monkeypatch
):
    _, executable = sample
    fake_reference(monkeypatch)
    inputs, scope = reference.windows_samples_inputs(windows_samples)
    report = reference.run_comparison(executable, inputs, windows_samples=scope)
    assert report["status"] == "passed"
    assert report["summary"]["ground_truth_checked_records"] == 2
    assert report["windows_samples"]["expected_sample_count"] == 2
    for result in report["results"]:
        assert result["provenance"]["windows_build"] == "10.0.26100"
        assert result["source_sha256"] == result["provenance"]["metadata_sha256"]
        expected_bytes = (windows_samples / result["id"] / "provenance.json").read_bytes()
        assert result["provenance_sha256"] == hashlib.sha256(expected_bytes).hexdigest()
        assert result["ground_truth"]["expected_fields"] == {
            "original_path": ORIGINAL,
            "original_size": 7,
        }
        assert "deleted_at_utc" not in result["ground_truth"]["expected_fields"]
        assert result["ground_truth"]["deletion_filetime_interval"]["lower"] < TICKS


@pytest.mark.parametrize("field,value", [("original_size", 8), ("original_path", r"C:\other.txt")])
def test_agreeing_parsers_cannot_pass_wrong_known_windows_facts(
    field, value, sample, windows_samples, monkeypatch
):
    _, executable = sample
    fake_reference(monkeypatch)
    provenance = windows_samples / "ascii-sample" / "provenance.json"
    facts = json.loads(provenance.read_text())
    facts[field] = value
    provenance.write_text(json.dumps(facts))
    inputs, scope = reference.windows_samples_inputs(windows_samples)
    report = reference.run_comparison(executable, inputs, windows_samples=scope)
    assert report["status"] == "different"
    assert report["summary"]["ground_truth_differences"] == 1


def test_windows_independent_time_interval_is_enforced(sample, windows_samples, monkeypatch):
    _, executable = sample
    fake_reference(monkeypatch)
    provenance = windows_samples / "ascii-sample" / "provenance.json"
    facts = json.loads(provenance.read_text())
    facts["deletion_lower_bound_filetime"] = TICKS + 1
    facts["deletion_upper_bound_filetime"] = TICKS + 2
    provenance.write_text(json.dumps(facts))
    inputs, scope = reference.windows_samples_inputs(windows_samples)
    report = reference.run_comparison(executable, inputs, windows_samples=scope)
    assert report["status"] == "different"
    mismatch = report["results"][0]["ground_truth_differences"][0]
    assert mismatch["field"] == "deletion_filetime"
    assert mismatch["expected_interval"] == {"lower": TICKS + 1, "upper": TICKS + 2}


@pytest.mark.parametrize(
    "field,value",
    [
        ("sample_kind", "arbitrary_input"),
        ("metadata_name", "../$IESCAPE"),
        ("metadata_name", "$I\\escape"),
        ("metadata_name", "ordinary.txt"),
        ("metadata_sha256", "invalid"),
        ("original_path", "relative.txt"),
        ("original_size", True),
        ("deletion_lower_bound_filetime", False),
        ("deletion_upper_bound_filetime", str(TICKS)),
        ("windows_build", None),
    ],
)
def test_windows_provenance_invalid_types_and_paths_fail(windows_samples, field, value):
    provenance = windows_samples / "ascii-sample" / "provenance.json"
    facts = json.loads(provenance.read_text())
    facts[field] = value
    provenance.write_text(json.dumps(facts))
    with pytest.raises(reference.ReferenceError, match="Invalid controlled"):
        reference.windows_samples_inputs(windows_samples)


def test_windows_provenance_hash_tampering_and_unbound_files_fail(windows_samples):
    source = windows_samples / "ascii-sample" / SOURCE_NAME
    original = source.read_bytes()
    source.write_bytes(original + b"changed")
    with pytest.raises(reference.ReferenceError, match="digest differs"):
        reference.windows_samples_inputs(windows_samples)
    source.write_bytes(original)
    extra = source.with_name("$IUNBOUND.txt")
    extra.write_bytes(original)
    with pytest.raises(reference.ReferenceError, match="unbound"):
        reference.windows_samples_inputs(windows_samples)


@pytest.mark.parametrize("expected_count", [0, -1, True, 3])
def test_windows_sample_count_is_positive_and_exact(windows_samples, expected_count):
    with pytest.raises(reference.ReferenceError):
        reference.windows_samples_inputs(windows_samples, expected_count=expected_count)


def test_windows_source_cannot_change_after_binding(sample, windows_samples, monkeypatch):
    _, executable = sample
    fake_reference(monkeypatch)
    inputs, scope = reference.windows_samples_inputs(windows_samples)
    # Both parsers permit trailing bytes with warnings, and still agree on all
    # original fields. The hash binding must independently reject these bytes.
    source = inputs[0]["source"]
    source.write_bytes(source.read_bytes() + b"changed")
    with pytest.raises(reference.ReferenceError, match="bound manifest/provenance"):
        reference.run_comparison(executable, inputs, windows_samples=scope)


@pytest.mark.parametrize(
    "manifest",
    [
        [],
        None,
        "wrong",
        {"schema_version": "1.0", "corpus_id": "rbf-synthetic-v1", "files": [None], "cases": []},
    ],
)
def test_malformed_manifest_returns_cli_error_without_traceback(tmp_path, sample, manifest, capsys):
    _, executable = sample
    corpus = tmp_path / "corpus-malformed"
    corpus.mkdir()
    (corpus / "manifest.json").write_text(json.dumps(manifest))
    assert reference.main(["--corpus", str(corpus), "--reference", str(executable)]) == 2
    assert "could not complete" in capsys.readouterr().err


@pytest.mark.parametrize(
    "container,entry",
    [
        ("files", []),
        ("cases", []),
        ("cases", None),
        ("cases", {"id": "bad", "record_type": "metadata", "source": "file", "expected": []}),
    ],
)
def test_corpus_entry_container_types_are_validated(tmp_path, container, entry):
    corpus = tmp_path / "corpus-invalid-entry"
    generate_corpus(corpus)
    path = corpus / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest[container][0] = entry
    path.write_text(json.dumps(manifest))
    with pytest.raises(reference.ReferenceError):
        reference.corpus_inputs(corpus)


def test_windows_cli_uses_bound_mode_and_records_ground_truth_count(
    sample, windows_samples, monkeypatch
):
    _, executable = sample
    fake_reference(monkeypatch)
    output = windows_samples.parent / "windows-bound-result.json"
    assert (
        reference.main(
            [
                "--windows-samples",
                str(windows_samples),
                "--expected-samples",
                "2",
                "--reference",
                str(executable),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    report = json.loads(output.read_text())
    assert report["summary"]["ground_truth_checked_records"] == 2
