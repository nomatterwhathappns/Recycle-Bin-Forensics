"""Whole-dataset ordering retains exact evidence values and clear statuses."""

from __future__ import annotations

import copy

import pytest

from rbinforensics.presentation import display_statuses, record_label, sort_records


def record(
    name: str,
    *,
    path: str | None = r"C:\Users\Demo\report.txt",
    size: int | None = 7,
    ticks: int | None = 133_485_408_001_234_567,
    utc: str | None = "2024-01-01T00:00:00.1234567Z",
    status: str = "ok",
    kind: str = "metadata",
    payload_status: str | None = "available_file",
    payload_size: int | None = 7,
) -> dict:
    return {
        "source_name": name,
        "source_path": "/case/" + name,
        "record_type": kind,
        "status": status,
        "metadata": {
            "original_path": path,
            "original_size": size,
            "deletion_filetime": ticks,
            "deleted_at_utc": utc,
        }
        if kind == "metadata"
        else None,
        "payload": {"status": payload_status, "size": payload_size} if payload_status else None,
        "issues": [],
    }


def names(records: list[dict]) -> list[str]:
    return [item["source_name"] for item in records]


@pytest.mark.parametrize("column", ["path", "time", "size", "status"])
@pytest.mark.parametrize("descending", [False, True])
def test_sort_returns_new_list_without_changing_records_or_audit_order(column, descending):
    observations = [record("B", size=9), record("A", size=3, status="warning")]
    original = copy.deepcopy(observations)
    ordered = sort_records(observations, column, descending)
    assert ordered is not observations
    assert observations == original
    assert {id(item) for item in ordered} == {id(item) for item in observations}


def test_size_sort_uses_exact_uint64_and_not_display_text_or_float():
    observations = [
        record("max", size=2**64 - 1),
        record("large-next", size=2**53 + 1),
        record("ten", size=10),
        record("large", size=2**53),
        record("two", size=2),
        record("zero", size=0),
    ]
    assert names(sort_records(observations, "size")) == [
        "zero",
        "two",
        "ten",
        "large",
        "large-next",
        "max",
    ]
    assert names(sort_records(observations, "size", True)) == [
        "max",
        "large-next",
        "large",
        "ten",
        "two",
        "zero",
    ]


def test_time_sort_preserves_the_last_100ns_tick_even_inside_one_microsecond():
    ticks = 133_485_408_001_234_560
    observations = [
        record("later", ticks=ticks + 2, utc="2024-01-01T00:00:00.1234562Z"),
        record("first", ticks=ticks + 1, utc="2024-01-01T00:00:00.1234561Z"),
    ]
    assert names(sort_records(observations, "time")) == ["first", "later"]
    assert names(sort_records(observations, "time", True)) == ["later", "first"]


@pytest.mark.parametrize("descending", [False, True])
def test_undated_and_orphan_records_always_stay_last_without_fabricated_time(descending):
    observations = [
        record("unset", ticks=0, utc=None),
        record("orphan", kind="orphan_payload", payload_size=3),
        record("later", ticks=20),
        record("first", ticks=10),
        record("invalid", ticks=None),
    ]
    ordered = names(sort_records(observations, "time", descending))
    assert ordered[:2] == (["later", "first"] if descending else ["first", "later"])
    assert ordered[2:] == ["unset", "orphan", "invalid"]


@pytest.mark.parametrize("descending", [False, True])
def test_unknown_sizes_stay_last_and_orphan_size_is_an_observation(descending):
    observations = [
        record("unknown", size=None, payload_size=999),
        record("orphan", kind="orphan_payload", payload_size=3),
        record("regular", size=2),
        record(
            "directory",
            kind="orphan_payload",
            payload_status="available_directory",
            payload_size=None,
        ),
    ]
    ordered = names(sort_records(observations, "size", descending))
    assert ordered[:2] == (["orphan", "regular"] if descending else ["regular", "orphan"])
    assert ordered[2:] == ["unknown", "directory"]


@pytest.mark.parametrize("bad", [True, False, 2.5, "7", -1])
def test_invalid_numeric_values_are_unknown_instead_of_coerced(bad):
    item = record("invalid", size=bad, ticks=bad)
    regular = record("known", size=0, ticks=0)
    assert names(sort_records([item, regular], "size", True)) == ["known", "invalid"]
    assert names(sort_records([item, regular], "time", True)) == ["known", "invalid"]


def test_path_sort_is_case_insensitive_and_supports_unicode_and_orphan_names():
    observations = [
        record("unicode", path=r"C:\資料\報告.txt"),
        record("lower", path=r"c:\alpha.txt"),
        record("upper", path=r"C:\Alpha.txt"),
        record("$Rorphan.txt", kind="orphan_payload"),
    ]
    assert names(sort_records(observations, "path")) == [
        "$Rorphan.txt",
        "lower",
        "upper",
        "unicode",
    ]
    assert names(sort_records(observations, "path", True)) == [
        "unicode",
        "lower",
        "upper",
        "$Rorphan.txt",
    ]


def test_empty_original_path_uses_the_acquired_name_shown_in_the_table():
    observations = [record("Z", path=""), record("A", path=None)]
    assert names(sort_records(observations, "path")) == ["A", "Z"]


def test_missing_path_values_are_last_in_both_directions():
    unknown = {"metadata": None, "source_name": None}
    known = record("known", path="A")
    assert sort_records([unknown, known], "path") == [known, unknown]
    assert sort_records([unknown, known], "path", True) == [known, unknown]


@pytest.mark.parametrize("column", ["path", "time", "size", "status"])
@pytest.mark.parametrize("descending", [False, True])
def test_equal_sort_keys_keep_baseline_order_across_direction_changes(column, descending):
    observations = [record("C"), record("A"), record("B")]
    assert sort_records(observations, column, descending) == observations


def test_sorting_applies_to_the_entire_dataset_before_pagination():
    observations = [record(f"item-{index}", size=1000 - index) for index in range(450)]
    ordered = sort_records(observations, "size")
    assert names(ordered[:200]) == [f"item-{index}" for index in range(449, 249, -1)]
    assert names(observations[:2]) == ["item-0", "item-1"]


def test_parsed_metadata_remains_sortable_when_payload_hashing_has_failed():
    parsed_error = record("error", ticks=4, size=4, status="error", payload_status="unreadable")
    regular = record("regular", ticks=5, size=5)
    assert sort_records([regular, parsed_error], "time") == [parsed_error, regular]
    assert sort_records([regular, parsed_error], "size") == [parsed_error, regular]


@pytest.mark.parametrize("column", ["", "original_size", "mtime", "__class__"])
def test_invalid_sort_columns_fail_explicitly(column):
    with pytest.raises(ValueError, match="Unsupported sort column"):
        sort_records([], column)


@pytest.mark.parametrize(
    "status,kind,payload,expected",
    [
        ("error", "orphan_payload", "missing", "Error"),
        ("skipped", "orphan_payload", "missing", "Dilewati"),
        ("warning", "orphan_payload", "available_file", "Orphan"),
        ("ok", "metadata", "missing", "Payload hilang"),
        ("warning", "metadata", "available_file", "Perlu ditinjau"),
        ("ok", "metadata", "available_file", "OK"),
        ("unknown", "metadata", None, "Tidak diketahui"),
    ],
)
def test_record_labels_keep_failures_and_payload_absence_explicit(status, kind, payload, expected):
    assert (
        record_label(record("sample", status=status, kind=kind, payload_status=payload)) == expected
    )


def test_status_sort_uses_visible_labels_without_modifying_raw_status_codes():
    observations = [
        record("ok"),
        record("error", status="error"),
        record("warning", status="warning"),
    ]
    assert names(sort_records(observations, "status")) == ["error", "ok", "warning"]
    assert observations[0]["status"] == "ok"


def test_status_pair_separates_successful_metadata_from_a_missing_payload():
    assert display_statuses(record("missing", payload_status="missing")) == (
        "Berhasil dibaca",
        "Tidak ditemukan",
    )


def test_payload_failure_does_not_relabel_decoded_metadata_as_a_parse_failure():
    assert display_statuses(record("bad-payload", status="error", payload_status="unreadable")) == (
        "Berhasil dibaca",
        "Gagal diperiksa",
    )


@pytest.mark.parametrize(
    "item,metadata_label,payload_label",
    [
        (
            record("orphan", kind="orphan_payload", status="warning"),
            "Tidak ditemukan",
            "File tersedia",
        ),
        (
            {"record_type": "metadata", "status": "error", "metadata": None, "payload": None},
            "Gagal dibaca",
            "Belum diperiksa",
        ),
        (
            {
                "record_type": "discovery",
                "status": "skipped",
                "metadata": None,
                "payload": {"status": "available_file"},
            },
            "Dilewati",
            "File tersedia",
        ),
        (
            {"record_type": "discovery", "status": "error", "metadata": None, "payload": None},
            "Tidak tersedia",
            "Belum diperiksa",
        ),
    ],
)
def test_status_pair_never_invents_metadata_for_orphan_or_discovery(
    item, metadata_label, payload_label
):
    assert display_statuses(item) == (metadata_label, payload_label)


@pytest.mark.parametrize(
    "payload,label",
    [
        ("available_directory", "Folder tersedia"),
        ("not_checked", "Belum diperiksa"),
        ("ambiguous", "Pasangan ambigu"),
        ("symlink_skipped", "Dilewati: symlink/junction"),
        ("special_file_skipped", "Dilewati: file khusus"),
        ("future-status", "Tidak diketahui"),
    ],
)
def test_payload_status_labels_are_explicit(payload, label):
    assert display_statuses(record("sample", payload_status=payload))[1] == label
