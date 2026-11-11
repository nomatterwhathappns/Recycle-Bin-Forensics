# Recycle Bin Forensics

A Python command-line tool for examining modern Windows Recycle Bin `$I` metadata from an acquired file or directory. It decodes original paths, original sizes, and deletion timestamps, correlates sibling `$R` items, and produces reviewable JSON, CSV, or terminal reports.

**Designed for offline artefact triage, incident-response support, and learning binary forensics.** It reads evidence and does not restore deleted files or acquire a disk image. Validate it against known-good Windows samples before depending on its output in an investigation.

## What it does

- Parses the version 1 and version 2 `$I` layouts, including UTF-16LE paths.
- Retains the original 64-bit FILETIME value and seven-digit UTC fractional seconds.
- Reports malformed, unsupported, inaccessible, or truncated records individually.
- Computes SHA-256 for metadata bytes and optionally for regular sibling `$R` files.
- Distinguishes available file payloads, directory payloads, missing payloads, and unsafe links.
- Scans one file, a directory, or a recursive evidence tree in deterministic order.
- Exports structured JSON or spreadsheet-friendly CSV, with a readable table for triage.
- Supports optional local-time display, case identifiers, and examiner labels.
- Avoids following evidence symlinks and refuses to overwrite existing report files.

The parser never treats a decoded original Windows path as a local file to open. `$R` correlation uses the metadata filename in its acquired directory.

## Install

Requires **Python 3.10 or newer**. There are no runtime dependencies for UTC operation.

```sh
git clone https://github.com/nomatterwhathappns/Recycle-Bin-Forensics.git
cd Recycle-Bin-Forensics
python -m venv .venv
```

Activate the environment:

```sh
# Linux/macOS
source .venv/bin/activate
```

```powershell
# Windows PowerShell
.venv\Scripts\Activate.ps1
```

```sh
python -m pip install .
rbf --help
rbf --version
```

On Windows or a host without an IANA timezone database, install `tzdata` if you need a named timezone such as `Asia/Jakarta`:

```sh
python -m pip install '.[timezone]'
```

This optional extra installs the timezone database; `python -m pip install tzdata` also works for an existing installation.

`python -m rbinforensics` is available as an alternative to the `rbf` command.

## Try it without real evidence

The generator requires a new destination and writes fictitious metadata and harmless text payloads. It includes both metadata versions, a Unicode path, and a record whose payload is absent.

```sh
python examples/generate_demo.py work/demo
rbf scan work/demo --recursive
rbf scan work/demo --recursive --format json --output work/demo-report.json
rbf scan work/demo --recursive --format csv --output work/demo-report.csv
```

Add `--include-broken` with a different destination to see a deliberately damaged record and partial-failure reporting. Generated samples demonstrate behavior; they are not evidence of interoperability with every Windows release.

## Examine acquired evidence

Use a forensic acquisition or verified working copy, ideally on a read-only mount. Place reports outside the evidence input tree.

Prefer `--output` for saved reports so destination checks and exclusive creation apply. Shell redirection such as `>` happens before this program runs and can overwrite files without those checks.

```sh
# A single acquired metadata file; single quotes keep the dollar sign literal.
rbf scan '/cases/working/$IABC123.docx'

# All users and nested directories in an acquired Recycle Bin tree.
rbf scan /cases/working/recycle-bin --recursive --format json \
  --output /cases/reports/recycle-bin.json --case-id IR-2026-001 --examiner analyst

# Display a second timestamp in a chosen zone and hash regular $R payloads.
rbf scan /cases/working/recycle-bin --recursive --timezone Asia/Jakarta \
  --hash-payload --format csv --output /cases/reports/recycle-bin.csv
```

PowerShell also expands `$` inside double quotes. Use single quotes:

```powershell
rbf scan 'D:\Case\Working\$Recycle.Bin' --recursive --format json --output 'D:\Case\Reports\recycle-bin.json'
```

For `cmd.exe`, use ordinary double-quoted paths:

```bat
rbf scan "D:\Case\Working\$Recycle.Bin" --recursive
```

Do not interpret an empty scan as proof that nothing was deleted. The data may be outside the supplied scope or no longer exist.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed without record or scan errors. Warnings may still need review. |
| `1` | One or more record/discovery errors or skipped evidence items; review the report. |
| `2` | Invalid usage/configuration, a top-level input/output failure, or no metadata candidates found. |
| `130` | Interrupted by the operator; the scan is incomplete. |

Use JSON for automated processing; table formatting is intended for people. JSON includes a schema version, tool/run context, input/options, summary, and per-file results. Numeric sizes are bytes. Raw FILETIME remains available alongside converted timestamps. CSV escapes control characters and formula-leading text for safer spreadsheet viewing; use JSON when exact text preservation matters. See the [report schema](docs/REPORT_SCHEMA.md) for field meanings and integer-precision considerations.

## Understanding the findings

| Finding | What it supports | What it does not establish |
| --- | --- | --- |
| Original path | The path recorded in this `$I` file | The present existence of that path or verified file content |
| Deletion FILETIME | The timestamp encoded in the artefact | A verified clock, a user identity, or intent |
| Original size | The original size recorded in metadata | Integrity of a remaining `$R` item |
| Sibling `$R` file | A matching item exists by acquired filename | Authenticity or a complete recovery |
| SHA-256 | A fingerprint of the bytes the tool read | Acquisition quality, provenance, or chain of custody |

Reading a writable filesystem can update access timestamps even when a program never opens evidence for writing. Hashes and case labels support documentation but do not replace acquisition procedures or independent corroboration.

This release does not parse legacy `INFO2`, carve unallocated disk space, recover permanently deleted files, parse filesystem journals, or identify who performed a deletion. It does not recursively hash directory payloads or inventory `$R` items without a metadata counterpart. A copied Recycle Bin can lose permissions, original filesystem metadata, or context.

Metadata reads are limited to 128 KiB per candidate. Payload hashing streams regular files in chunks, but the full report is assembled in memory. Partition very large cases into documented input scopes. Paths containing symlink/reparse-point components are rejected; use a direct path to the working copy.

## Documentation

- [Indonesian learning guide: architecture, critical code, and real cases](docs/LEARNING_ID.md)
- [Binary layouts, parsing decisions, and references](docs/FORMAT.md)
- [JSON/CSV schema and result interpretation](docs/REPORT_SCHEMA.md), with a [machine-readable JSON Schema](schemas/report-v1.schema.json)
- [Evidence workflow and interpretation](docs/EVIDENCE_WORKFLOW.md)
- [Contributing](CONTRIBUTING.md) and [security reporting](SECURITY.md)

## Development

```sh
python -m pip install -e '.[dev]'
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m build
```

Tests use independently constructed synthetic bytes and temporary directories, including malformed metadata and CLI/report behavior. They do not constitute a known-good corpus acquired on real Windows systems. CI exercises supported platforms; see the workflow for the exact Python and OS matrix.

Licensed under the [MIT License](LICENSE).
