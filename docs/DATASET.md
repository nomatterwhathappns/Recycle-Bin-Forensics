# Synthetic known-answer dataset

`rbf-synthetic-v1` is a small, deterministic dataset for learning, regression
testing, and comparing parsers. Every Windows path, SID, and payload is fictitious.
It contains **20 expected records: 18 metadata candidates and two orphan payloads**.
The dataset includes deliberate failures so a user can learn to distinguish an
unreadable record from an empty result or an unavailable payload.

The [checked-in fixture](../tests/fixtures/synthetic-v1) can be used directly after
cloning the repository. A release's synthetic demo ZIP contains the same generated
content. The original [five-record introductory demo](../examples/generate_demo.py)
remains available for a simpler first scan.

## Create and verify a working copy

Run these commands from the repository with its Python environment activated:

```sh
python examples/generate_corpus.py work/corpus
python examples/verify_corpus.py work/corpus
```

Generation refuses an existing destination and symlink/reparse-point components.
Choose another new directory when repeating the exercise. The verifier checks
the manifest, the complete file and directory inventory, file sizes and SHA-256
digests, then the scanner's observed fields against the canonical expected facts.
It does not modify the corpus or produce a report inside it.

A successful validation returns exit code `0` and:

```json
{
  "corpus_id": "rbf-synthetic-v1",
  "status": "passed",
  "cases_checked": 20,
  "files_verified": 33,
  "failures": []
}
```

A changed, missing, additional, or redirected item is a validation failure. Even
rewriting `manifest.json` to match altered evidence cannot replace the oracle:
the verifier compares that manifest with the fixed specification in
[`examples/corpus.py`](../examples/corpus.py). This detects unintended edits; it
does not authenticate a maliciously replaced verifier or source checkout.

## Scan it through the CLI or desktop

```sh
rbf scan work/corpus/evidence --recursive --hash-payload
rbf scan work/corpus/evidence --recursive --hash-payload --format json --output work/corpus-report.json
rbf scan work/corpus/evidence --recursive --hash-payload --format html --output work/corpus-report.html
```

Report destinations must be new files outside the input evidence directory.
For the desktop, select `work/corpus/evidence`, enable subfolders and payload
hashing, and select UTC. The same selection can be made with the fixture's
`tests/fixtures/synthetic-v1/evidence` directory. Linux and Windows both analyse
these acquired byte sequences; the encoded `C:\Demo\...` paths are never opened
on the examiner's computer.

**A normal scan of this corpus returns exit code `1`.** That is the expected
scan result because six intentionally malformed metadata files produce errors.
By contrast, the corpus verifier returns `0` when those errors and all the other
findings match their specified results. These exit codes answer different
questions: scan success versus correctness of a validation exercise.

Expected full-scan summary with recursive scanning, payload hashing, and UTC:

| Field | Expected |
| --- | ---: |
| Metadata candidates | 18 |
| Parsed metadata | 12 |
| Records with errors | 6 |
| Records with warnings | 5 |
| Skipped records | 0 |
| Payloads hashed | 10 |
| Orphan payloads | 2 |

Warnings include size mismatch, unknown deletion time, trailing metadata bytes,
and both orphan records. A missing payload is presented separately from a
successful metadata decode; it is not a parse error.

## Cases and known answers

Each case in `manifest.json` identifies its acquired source path and expected
record type, status, issue codes, parsed metadata, source hash, and payload
observation. Paths in the manifest use `/` and are relative to the corpus root,
so expected results are independent of the examiner's checkout location or OS.

| Case ID | What it exercises |
| --- | --- |
| `v1-ascii` | Version 1's fixed 260 UTF-16-code-unit path field and a matching file |
| `v2-unicode` | Version 2's code-unit length with CJK and a non-BMP emoji |
| `zero-size` | A known zero-byte original and an empty regular payload |
| `large-uint64` | Original size `9007199254740995`, above JavaScript's safe integer range |
| `max-uint64` | Maximum unsigned 64-bit original size `18446744073709551615` |
| `adjacent-tick` | A deletion exactly 100 ns after the base instant |
| `missing-payload` | Decoded metadata without an observed sibling `$R` |
| `size-mismatch` | A payload smaller than the original size encoded in `$I` |
| `paired-folder` | A sibling `$R` directory; its contents are not scanned as another inventory |
| `unknown-time` | Zero FILETIME, with an explicit unknown timestamp |
| `trailing-bytes` | Parseable metadata followed by extra bytes, retained as a warning |
| `long-path` | A version 2 original path longer than the version 1 fixed field |
| `truncated-header` | Three header bytes; safe failure despite a matching readable payload |
| `truncated-v1-path` | A complete common header without the version 1 path field |
| `truncated-v2-path` | Declared path length greater than the available bytes |
| `unsupported-version` | An unsupported format version, with no invented original metadata |
| `invalid-utf16` | An unpaired high surrogate in the path field |
| `invalid-path-length` | A version 2 path-length DWORD of zero |
| `orphan-file` | A regular `$R` without a sibling `$I`, with a content hash |
| `orphan-folder` | A `$R` directory without a sibling `$I`, with no fabricated deletion time |

The base raw FILETIME is `133485408001234567`, corresponding to
`2024-01-01T00:00:00.1234567Z`. `adjacent-tick` is
`133485408001234568`, or `2024-01-01T00:00:00.1234568Z`. Compare the raw integers
and seven-digit timestamps rather than converting them to floating point.
The large original-size fields do not allocate or create giant payload files.

## How the oracle stays independent of the engine

`encode_metadata()` writes the documented structures using `struct.pack` with
explicit little-endian widths. The cases declare their original paths, sizes,
raw FILETIME values, UTC strings, errors, and payload expectations directly.
Generation never calls `parse_metadata()` or `scan()` to obtain expected values.
The verifier imports the scanner only after checking corpus integrity.

The `files` list hashes every generated content file, including the notice and
files inside payload directories. `manifest.json` excludes its own hash to avoid
a circular definition; its entire logical content is checked against the fixed
specification. The checked-in fixture is also tested against newly generated
bytes. The dataset identifier is stable independently of application versions;
changes to these bytes or known answers require a new corpus identifier.

## What this establishes

Passing the verifier establishes agreement with these 20 hand-specified cases.
The fixture was authored with the project, so it is **not an independently
maintained compatibility corpus or a Windows acquisition**. It cannot establish
that all Windows versions, filesystem states, acquisition methods, or damaged
artefacts are supported.

Use it alongside the [real Windows Shell validation](VALIDATION_WINDOWS.md) and
the project's comparison-tool validation. Shell-generated examples test native
interoperability on a recorded Windows build; a reference parser checks another
implementation's interpretation; the synthetic oracle provides reproducible
edge cases and exact known answers. Record the provenance and limitations of
each result when presenting this project or using it in an investigation.
