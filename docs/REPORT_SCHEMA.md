# Report schema, version 2.0

Application releases **1.0.0**, **1.1.0**, **1.2.0**, **1.3.0**, and **1.4.0** emit completed-report schema **2.0**. Desktop progress, cancellation, layout, text size, and column sorting are run/presentation controls, not new evidence fields. A cancelled scan does not emit a completed report. Desktop column sorting does not reorder report records or change the selection's deletion timeline. These version numbers describe different contracts. The [current JSON Schema](../schemas/report-v2.schema.json) describes the expanded report; the [historical schema 1.0](../schemas/report-v1.schema.json) remains available for earlier development reports.

JSON is the complete structured audit report. Terminal, CSV, and HTML are views of the selected records. Schema validation checks structure, types, and supported values; it does not authenticate evidence or certify an interpretation.

## Top-level fields

| Field | Meaning |
| --- | --- |
| `schema_version` | Report contract version, currently `"2.0"` |
| `tool` | Application name and version |
| `started_at_utc`, `completed_at_utc` | Examiner-system run times, separate from evidence deletion times |
| `input` | Absolute acquired input path |
| `options` | Scan settings and operator-supplied case/examiner labels |
| `summary` | Counts for the complete scan, before selection |
| `records` | Complete inventory, including failed candidates and discovery issues |
| `selection` | Filter criteria and indexes identifying the requested view |
| `timeline` | Ordered events and aggregate counts from selected dated metadata |

A JSON filter never deletes excluded records from `records`. This makes the report's discovery/processing scope inspectable. A viewer or downstream consumer can use `selection.record_indexes` to reproduce the intended view.

Run timestamps are taken from the examining system. They neither verify the source clock nor replace external acquisition logs. Case/examiner labels are unverified operator input.

## Record types and provenance

| Field | Meaning |
| --- | --- |
| `record_type` | `metadata`, `orphan_payload`, or `discovery` |
| `source_path`, `source_name` | Acquired source path/basename; original Windows path is stored separately |
| `source_size` | Metadata bytes read, or observed regular orphan-payload size; `null` when unavailable/not applicable |
| `source_sha256` | Metadata SHA-256, or the computed source/payload SHA-256 for an orphan; `null` when not computed |
| `sid` | Nearest SID-like ancestor inferred lexically; no identity authentication |
| `status` | `ok`, `warning`, `error`, or `skipped` |
| `metadata` | Decoded `$I` fields, or `null` |
| `payload` | Payload availability/hash object when applicable, otherwise `null` |
| `issues` | Objects with machine-readable `code`, `severity`, and human-readable `message` |

`metadata` records are `$I` candidates, including candidates whose decoding fails. `orphan_payload` records represent `$R` entries without a matching metadata filename in the acquired directory. They do not gain an invented original path, original size, or deletion timestamp. Their acquired path identifies a payload, not a metadata file; their source size/hash fields refer to that same observed payload. Inspect `record_type` before interpreting source hashes. `discovery` records describe scan-scope issues such as inaccessible directories or skipped redirects.

A matching malformed `$I` still prevents orphan classification: inability to decode a counterpart is different from absence of its name. Payload name comparisons use conservative ASCII case normalization; Unicode casefold substitutions are not used. Ambiguities are reported rather than resolved by guessing. The literal `$Recycle.Bin` container is not a payload candidate.

An `orphan_payload` warning records the absence of matching metadata in scope. It does not establish whether metadata was lost, omitted during acquisition, deleted, or manipulated. Directory payloads are inventoried as objects; scanning does not descend into them to reinterpret their contents as Recycle Bin artefacts.

Issue codes support automation. OS-specific messages should not be treated as a stable parsing API. A record may contain warnings and errors together. A malformed metadata file can still have a SHA-256 if its complete bounded read succeeded. Oversized/unreadable metadata is not falsely reported as fully hashed.

## Metadata object

| Field | Meaning |
| --- | --- |
| `format_version` | Encoded `$I` layout, `1` or `2` |
| `original_size` | Unsigned size recorded in metadata, in bytes |
| `deletion_filetime` | Raw unsigned count of 100 ns ticks since 1601-01-01 UTC |
| `deleted_at_utc` | UTC ISO timestamp with seven fractional digits and `Z`, or `null` |
| `deleted_at_display` | Same instant in requested display zone with seven digits and offset, or `null` |
| `original_path` | Strictly decoded UTF-16LE path text |

Zero or unrepresentable deletion timestamps remain raw values with a warning and unavailable converted time. A filesystem modification time or current time is never substituted.

**Large integer precision:** Python emits exact decimal uint64 literals. FILETIME commonly exceeds JavaScript's safe integer range (`2^53 - 1`); sizes may exceed it too. Ordinary `JSON.parse` into `Number` can round these values. Use an exact-integer/lossless parser, retain original JSON, or process with Python. Converting an already rounded number to `BigInt` does not restore the original. Spreadsheet imports should treat large integer columns as text.

Seven fractional digits preserve encoded granularity. They do not establish a clock accuracy of 100 ns.

## Payload object

| Field | Meaning |
| --- | --- |
| `path` | Acquired `$R` path when uniquely identified, otherwise `null` |
| `status` | Availability/type classification |
| `size` | Observed regular-file size where available |
| `sha256` | Computed regular-file SHA-256, or `null` |
| `hash_status` | `not_requested`, `unavailable`, `not_applicable`, or `computed` |
| `size_matches_metadata` | Metadata comparison where applicable; `null` for orphan payloads |

Payload statuses include `not_checked`, `missing`, `ambiguous`, `available_file`, `available_directory`, `symlink_skipped`, `special_file_skipped`, and `unreadable`.

Missing payload content does not invalidate decoded metadata. A matching size does not prove authenticity. Hashing regular payloads requires `--hash-payload`; directory payload contents are not recursively hashed. Orphan payload hashes, if computed, remain payload hashes and must not be mistaken for metadata hashes.

A nonexact ASCII-case-insensitive pairing emits `payload_case_insensitive_match`. Correlation identifies an acquired name relationship, not a cryptographically signed association or a simulation of every Windows filesystem naming rule.

## Full scan summary

Summary counts refer to the entire scanned inventory. They are not recomputed after filters.

| Counter | Meaning |
| --- | --- |
| `candidates` | Metadata candidate records, including failed `$I` candidates |
| `parsed` | Records containing decoded metadata |
| `errors` | Records whose status is `error` |
| `warnings` | Records containing at least one warning issue, not individual warning-message count |
| `skipped` | Records whose status is `skipped` |
| `payloads_hashed` | Records with computed payload hashes, including applicable orphans |
| `orphan_payloads` | Records typed `orphan_payload` |

These counts are not mutually exclusive. Metadata can parse successfully and later encounter a payload hashing error. Discovery failures can increase errors without increasing metadata candidates.

## Selection object

| Field | Meaning |
| --- | --- |
| `filters` | Recorded filter values |
| `active` | Whether an effective filter was supplied |
| `matched` | Number of records shown, including mandatory diagnostics |
| `excluded` | Number of records outside the selected view |
| `record_indexes` | Zero-based indexes into the complete `records` array |

Filter categories combine with **AND**. Repeated extension values are alternatives within that category. Query matching is a case-insensitive literal substring search, not a regular expression. It checks decoded/acquired paths and source names. SID matching is exact, ignoring case. Extension matching uses the recorded original Windows path for metadata and the acquired name for orphan payloads.

Size criteria use the recorded original size and require decoded metadata. Time criteria use deletion FILETIME and require a valid decoded deletion timestamp. Orphans and undated records cannot satisfy time bounds through guessed values. Records typed `discovery` or with status `error`/`skipped` are always retained for review, even when they cannot satisfy a normal finding filter. Thus `matched` is a shown-record count, not a count of only successfully matched findings. Filter selection does not suppress scan failure exit codes.

Date-only bounds mean UTC midnight. Aware ISO datetimes must specify `Z` or an explicit offset; comparisons are inclusive and retain all seven fractional digits. `--timezone` affects display, not date-bound interpretation. For a complete UTC day, an upper bound such as `2026-01-31T23:59:59.9999999Z` is explicit.

## Timeline object

| Field | Meaning |
| --- | --- |
| `order` | `deletion_time_ascending` |
| `events` | Selected dated metadata ordered by raw deletion tick, then source path |
| `undated_records` | Selected records without a usable deletion timestamp |
| `daily_counts` | Event counts per UTC date |
| `by_sid` | Event counts per recorded SID context |
| `by_extension` | Event counts per original-path extension |

Each event records source path, SID context, original path/size, raw FILETIME, UTC/display deletion time, and payload status. No deletion event is inferred from payload filesystem timestamps. A mandatory diagnostic record with valid parsed metadata, for example a payload-hash error, can still supply a timeline event even if its other fields do not match the requested filter. The counts describe the shown selection, including such diagnostics; a burst or gap does not independently identify intent, activity volume outside the acquisition scope, or an actor.

## Output differences

- **JSON:** full inventory, scan summary, explicit selection, timeline, and context.
- **CSV:** selected records flattened to columns; issue codes are joined, and full run context/messages are not retained.
- **Terminal:** selected findings and readable issues with full-scan/selection context.
- **HTML:** a standalone selected-view report, timeline, review controls, and provenance details. Browser search further narrows the rendered view and does not rerun acquisition or analysis.

Control characters become visible escapes in terminal/CSV. Formula-leading CSV text receives a protective apostrophe. HTML escapes evidence text and does not turn acquired/original paths into executable links. Use JSON and preserved source bytes for exact text examination.

## Migration and comparison

Consumers of development schema `1.0` must explicitly support schema `2.0`; record types and top-level objects have expanded. Preserve historical reports with the software/schema that produced them.

Deterministic ordering aids comparisons, but run times and absolute paths can differ. Compare evidence values, hashes, errors, and options deliberately rather than expecting byte-identical JSON between runs. This release does not automatically reconcile or diff two separate case reports.
