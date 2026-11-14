# Resource limits and incomplete operations

Every scan, filter, sort, and report export has workload limits. These bound defined work rather than asserting a universal RAM ceiling. Metadata still has its separate 128 KiB per-file safety cap.

| CLI option | Default | Meaning |
| --- | ---: | --- |
| `--max-records` | 100000 | Complete inventory records, including metadata, orphans, and discovery diagnostics |
| `--max-payload-hash-bytes` | 10737418240 | Aggregate regular payload bytes hashed (10 GiB) |
| `--max-metadata-bytes` | 268435456 | Aggregate metadata bytes read (256 MiB) |
| `--max-depth` | 64 | Directory traversal depth; the selected input directory has depth zero |
| `--max-operation-seconds` | 600 | Cooperative monotonic-clock deadline per operation |
| `--max-export-bytes` | 134217728 | Actual UTF-8 report bytes (128 MiB) |
| `--max-visited-entries` | 1000000 | Inspected directory entries, including unrelated filenames |

Counts and byte limits must be positive integers. Depth also permits zero. Duration must be finite and positive. A matching `$I`/`$R` pair counts as one metadata record, and payload folders remain opaque rather than contributing recursively inspected contents. Single-file scans still inspect sibling names when looking for acquired payloads, so their sibling enumeration is budgeted too.

For example, choose a new output outside the evidence directory and an existing reports directory:

```sh
rbf scan work/evidence --recursive --hash-payload \
  --max-records 25000 --max-payload-hash-bytes 2147483648 \
  --max-operation-seconds 300 --format json --output reports/case-001.json
```

## What happens at a limit

The CLI returns **3** and explains that the operation is incomplete. It does not print a half-rendered stdout report or return a completed partial scan. A failed file export removes only the partial file it created; an existing or concurrently replaced file is preserved.

The desktop marks a limited scan **Analisis belum lengkap** and disables export of that incomplete scan. A limited filter, sort, or export preserves the previous complete baseline and view. The unsaved-result guard stays active until a complete ordinary JSON save succeeds. Open **Atur batas beban** to revise bounds before the next operation; raising an export limit does not require rescanning existing results.

Filtering retains the complete inventory in an isolated view, so its record cap applies to the entire baseline, including records outside the requested selection. All report formats likewise enforce the inventory record cap, while their report-byte limit measures the actual serialized output.

## Timing and memory interpretation

Each independent operation starts a fresh clock and counters. Idle time spent reviewing an analysis is not export/filter time. Nested helpers share the parent operation's consumption and deadline; explicit nested limits can tighten that parent but cannot enlarge it. Cancellation remains separate from a limit violation.

Checks occur around reads, loops, sorting, writes, flush, and finalization. An operating-system read or other blocking call cannot be forcibly interrupted by the cooperative deadline. Checkpoints observe it once control returns.

JSON, CSV, HTML, and text file exports stream checked chunks. Stdout uses a bounded complete rendering before emitting text. Filtering still preserves deep isolation of the inventory, which can require another substantial allocation; metadata/record bounds are not a promise that every case will fit a given machine's memory. Choose smaller scopes/budgets for constrained hosts. The historical [1.3 benchmarks](BENCHMARKS.md) describe their measured workload and do not establish worst-case RAM or timings for this version.

## Report contract

Successful forensic reports retain schema **2.0** and its original five scan-option fields. Workload controls are runtime safeguards rather than new evidence fields. A limit violation cannot masquerade as schema-2 completed evidence. Preserve the command/configuration and the operation's diagnostic when documenting an incomplete run.
