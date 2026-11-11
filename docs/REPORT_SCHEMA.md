# Report schema, version 1.0

JSON is the structured report format. Table output is a human-readable view. CSV is a flattened, spreadsheet-oriented view with text protections and less context than JSON.

The [machine-readable JSON Schema](../schemas/report-v1.schema.json) describes the report shape for validation. Schema validation checks structure, types, and supported field values; it does not authenticate evidence or prove the interpretation is correct.

## Top-level JSON fields

| Field | Meaning |
| --- | --- |
| `schema_version` | Report contract version, currently `"1.0"` |
| `tool` | Tool name and version |
| `started_at_utc`, `completed_at_utc` | Examiner-system run times; not evidence deletion times |
| `input` | Absolute acquired input path used for this run |
| `options` | Recursive/hash/timezone settings and operator-supplied case/examiner labels |
| `summary` | Counts described below |
| `records` | Metadata candidates and discovery issues, sorted by acquired source path |

Run timestamps come from the system running the tool. They neither authenticate the source device's clock nor replace an externally managed acquisition log.

## Summary counts

| Field | Definition |
| --- | --- |
| `candidates` | Number of metadata candidate records, including candidates that fail parsing |
| `parsed` | Number of records containing decoded metadata |
| `errors` | Number of records whose status is `error`, including discovery problems |
| `warnings` | Number of records containing at least one warning issue; not the number of individual warning messages |
| `skipped` | Number of records with `skipped` status |
| `payloads_hashed` | Number of records containing a computed payload SHA-256 |

These counts are not mutually exclusive partitions. A parsed record can later acquire an error during requested payload hashing. An error record can also have warnings. Discovery issues can increase `errors` or `skipped` without increasing `candidates`.

For the unmodified synthetic demo, a recursive run with `--hash-payload` reports `candidates=3`, `parsed=3`, `errors=0`, `warnings=0`, `skipped=0`, and `payloads_hashed=2`. The third metadata record has no payload; that state is not itself a parse error.

### Example values

Below are selected fields from a single-file scan of the first generated demo with `--hash-payload`. Source paths are shortened to `/demo/...`; metadata bytes and hashes are the generator's actual deterministic values. A full report also contains tool/run/input/options context.

```json
{
  "summary": {
    "candidates": 1,
    "parsed": 1,
    "errors": 0,
    "warnings": 0,
    "skipped": 0,
    "payloads_hashed": 1
  },
  "records": [
    {
      "record_type": "metadata",
      "source_path": "/demo/$Recycle.Bin/S-1-5-21-111111111-222222222-333333333-1001/$IDEMO01.txt",
      "source_name": "$IDEMO01.txt",
      "source_size": 544,
      "source_sha256": "75278dd8b0dac2c4d19f6b063280786951f30bdcffb35b64548a60c5b05c64b9",
      "sid": "S-1-5-21-111111111-222222222-333333333-1001",
      "status": "ok",
      "metadata": {
        "format_version": 1,
        "original_size": 35,
        "deletion_filetime": 134129198451234567,
        "deleted_at_utc": "2026-01-15T03:04:05.1234567Z",
        "original_path": "C:\\Users\\Demo\\Documents\\notes.txt",
        "deleted_at_display": "2026-01-15T03:04:05.1234567+00:00"
      },
      "payload": {
        "path": "/demo/$Recycle.Bin/S-1-5-21-111111111-222222222-333333333-1001/$RDEMO01.txt",
        "status": "available_file",
        "size": 35,
        "sha256": "24611b81fbb7ced5b39e84abf35390540e2216eef8b20e4efa4bcb26b06f8ae0",
        "hash_status": "computed",
        "size_matches_metadata": true
      },
      "issues": []
    }
  ]
}
```

## Per-record fields

| Field | Meaning |
| --- | --- |
| `record_type` | `metadata` for a candidate or `discovery` for a scan-scope issue |
| `source_path`, `source_name` | Acquired path and basename, not the decoded original Windows path |
| `source_size` | Number of metadata bytes read, or `null` when a complete bounded read did not succeed |
| `source_sha256` | SHA-256 of all metadata bytes read, or `null` when unavailable |
| `sid` | Nearest SID-like ancestor name inferred lexically, or `null`; no identity verification |
| `status` | `ok`, `warning`, `error`, or `skipped` |
| `metadata` | Decoded metadata object, or `null` when parsing failed/was not applicable |
| `payload` | Correlation result, or `null` when not reached |
| `issues` | Array of `code`, `severity`, and human-readable `message` objects |

Issue codes are useful for classification. Messages can contain OS-specific details and should not be treated as a stable parsing API. Warnings and errors can both occur on the same record.

A malformed file can still have a `source_sha256`: hashing the source bytes does not require successful decoding. An oversized candidate is rejected without hashing the full object. A skipped link is not hashed by following its target.

## Metadata object

| Field | Meaning |
| --- | --- |
| `format_version` | Encoded `$I` format, `1` or `2` |
| `original_size` | Unsigned original size recorded in metadata, in bytes |
| `deletion_filetime` | Original unsigned FILETIME integer, in 100 ns ticks since 1601-01-01 UTC |
| `deleted_at_utc` | UTC ISO timestamp with seven fractional digits and `Z`, or `null` |
| `deleted_at_display` | Same instant in requested display zone with seven fractional digits and UTC offset, or `null` |
| `original_path` | Strictly decoded UTF-16LE path text |

**Large-integer handling:** JSON contains exact decimal integer literals emitted by Python. FILETIME commonly exceeds JavaScript's safe integer range (`2^53 - 1`), and recorded sizes may also exceed it. A standard JavaScript `JSON.parse` into `Number` can silently round those fields. Use an arbitrary-precision/lossless JSON parser, or retain the original JSON text and process with Python or another exact-integer consumer. Converting an already rounded `Number` to `BigInt` does not recover the original value. CSV writes those integers as decimal text, but spreadsheet software may also round them when auto-importing; import large-integer columns as text.

The seven-digit timestamp fraction preserves the encoded granularity; it is not a claim that the source clock was accurate to 100 ns.

## Payload object

| Field | Meaning |
| --- | --- |
| `path` | Matching sibling `$R` path when uniquely identified, otherwise `null` |
| `status` | Availability/classification listed below |
| `size` | Observed regular-file size, or `null` |
| `sha256` | Computed regular-file payload hash, or `null` |
| `hash_status` | `not_requested`, `unavailable`, `not_applicable`, or `computed` |
| `size_matches_metadata` | Observed regular-file size comparison, or `null` when not available/applicable |

Payload status values:

- `not_checked`: a matching name could not be inferred, for example for an explicitly supplied metadata file with a nonstandard basename.
- `missing`: no matching sibling `$R` entry was found.
- `ambiguous`: more than one ASCII-case-insensitive candidate matched; no candidate was chosen.
- `available_file`: a matching regular file was observed.
- `available_directory`: a matching directory was observed; its contents are not recursively hashed.
- `symlink_skipped`: a matching symlink/reparse point was not opened.
- `special_file_skipped`: the match was a nonregular, nondirectory item.
- `unreadable`: lookup or requested hashing encountered an error/unsafe change.

`missing` is an observed availability state and does not itself make a successfully decoded metadata record erroneous. A size match is a useful consistency check, not proof of authenticity. Correlation is based on acquired sibling names, not on a signed relationship in the metadata.

An ASCII-case-insensitive match whose spelling differs from the expected `$R` name adds `payload_case_insensitive_match`. Unicode casefold substitutions are not used. This is a conservative correlation rule for copied artefacts, not an emulation of every filesystem's name comparison rules.

## CSV differences

CSV contains one row per record. It flattens selected source, metadata, and payload fields and joins issue codes with semicolons. It does not include the complete JSON run context or issue messages.

Control characters are rendered as visible escapes. Formula-leading text receives a leading apostrophe for safer spreadsheet use. These protections can change the displayed text from the original decoded string. Use JSON and preserved source bytes when exact text is required. CSV quoting alone does not prevent spreadsheet formula interpretation.

## Comparing two runs

Record ordering is deterministic for a fixed acquired tree, but run timestamps and absolute input paths can differ. Compare content fields and hashes deliberately instead of expecting byte-identical JSON from separate runs. Changes in `source_sha256`, parsing status, payload classification, or options warrant review. Keep both original reports and the version of the tool that generated each.
