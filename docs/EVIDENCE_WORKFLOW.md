# Evidence workflow

This tool examines artefacts supplied by an operator. It does not acquire evidence, mount images, establish chain of custody, or certify findings.

## Before a scan

1. Confirm the scope and authority for the examination.
2. Acquire or preserve the source using the procedures required by your organisation and case.
3. Record acquisition details, host/device identifiers, tool versions, relevant clock information, and custody transfers separately.
4. Verify acquisition hashes where available. Keep a protected original and use a verified working copy or read-only mount.
5. Preserve the directory structure, including volume and user-SID context. If artifacts from different volumes are combined, keep them in distinct directories.
6. Choose a report destination outside the evidence input tree. Give every run a new filename.

For most modern installations, the artefacts are found in a volume's `$Recycle.Bin` directory under SID-named subdirectories. SID context can assist an investigation but should not be treated as conclusive proof of who clicked Delete. This tool does not resolve or authenticate SIDs.

## Perform the scan

```sh
rbf scan /cases/working/recycle-bin --recursive --format json \
  --output /cases/reports/run-001.json --case-id IR-2026-001 --examiner analyst
```

Keep the command, application version, output, exit status, and external acquisition notes. JSON is the preferred report for downstream processing because it preserves structured context and exact field text.

Use `--output` instead of shell redirection when saving a report. The program validates its `--output` path and refuses an existing file. A shell can truncate a target through `>` before the tool gets control, so the tool cannot protect a redirection destination. The report directory must already exist. For a single-file scan, place the report outside that file's parent evidence directory as well.

If content comparison is necessary, add `--hash-payload`. This increases I/O and can take significant time for large files. Directory payloads are identified but are not recursively hashed. Missing metadata, missing content, and unreadable content are distinct findings.

## Inventory, selection, and review reports

Directory scans include orphan `$R` entries without a matching `$I` name. Keep them in the inventory even though original path and deletion time are unknown. A malformed matching `$I` is a different condition; review its error and the separately observed payload. Do not infer cause or actor from an orphan classification.

Recursive scans treat `$R` directories as payload objects and do not reinterpret their contents as Recycle Bin artefacts. Preserve volume/SID collection boundaries so sibling relationships remain meaningful. A single metadata-file input analyses that item and its sibling correlation; it does not inventory unrelated siblings as orphans.

Use filters to produce a view relevant to a question, and retain the complete JSON inventory:

```sh
rbf scan /cases/working/recycle-bin --recursive --query archive --extension .zip \
  --deleted-after 2026-01-01T00:00:00Z --deleted-before 2026-01-31T23:59:59.9999999Z \
  --format json --output /cases/reports/archive-scope.json
```

`summary` remains the full scan scope. `selection.record_indexes` identifies shown records, including mandatory error/skipped/discovery diagnostics. CSV, terminal, and HTML use that selected view. A diagnostic with decoded metadata may still appear in the timeline despite not matching other filters. Read status and issues when interpreting counts.

The deletion timeline uses raw FILETIME ordering and UTC calendar-day grouping. Payload filesystem timestamps do not replace missing deletion timestamps. Time filters are inclusive; date-only values mean UTC midnight. The display timezone does not silently reinterpret a date-only filter as local time.

For a local review copy, request `--format html` with a fresh `--output` filename. The result is standalone and works offline. It can contain sensitive paths, hashes, labels, and findings; handle it under the same access rules as other case reports. Browser controls narrow/sort the already generated view and do not perform another source scan.

## Review every run

Check all of the following before relying on results:

- Was the intended input selected, and did the scan include nested SID directories?
- Does the number of discovered candidates make sense for the supplied evidence?
- Were any directories inaccessible, records malformed, or files skipped for safety?
- Are raw timestamp values plausible and their UTC/local interpretations understood?
- Do any metadata/payload size differences or missing payloads need investigation?
- Has the original byte evidence been retained for independent examination?

A nonzero exit code does not mean the entire report is worthless. It can mean a mixture of successfully parsed and failed candidates. Review the report summary, record errors, and scan issues together. A zero exit code does not mean the evidence is complete or genuine.

## Corroborate the interpretation

A recorded original path and deletion timestamp can help build a hypothesis. Compare them with independent artefacts such as filesystem metadata, `$MFT` and `$UsnJrnl` records, application history, logs, backups, or other acquired evidence using tools appropriate to those sources. This application does not parse those sources itself.

Examples:

| Situation | Useful question | Required caution |
| --- | --- | --- |
| Incident response | Were suspicious tools or archives recorded in Recycle Bin around an incident? | An absent record does not rule out deletion; malware may bypass or empty Recycle Bin. |
| Insider investigation | Is a named document path present with a relevant timestamp? | A path alone does not verify document contents, the actor, or intent. |
| Help-desk recovery triage | Is matching `$R` content still present in an acquired copy? | Availability is not a restored/verified file; directory handling and recovery require separate steps. |
| Training and forensic validation | Does a controlled Windows deletion produce the expected values? | Keep an independent ground truth and document operating system/build and test steps. |

## Operational limitations

Read-only file opens can still update filesystem access times on writable mounts. Some operating systems, permission models, reparse points, concurrent writers, or copying tools can affect what is visible. A working copy that is changing during analysis is unsuitable for dependable comparison. Prefer immutable snapshots or read-only evidence.

SHA-256 tells you which bytes were read. It does not certify where they originated, whether collection was complete, or whether they were altered before hashing. Case and examiner labels are operator-supplied annotations, not authenticated identities.

Windows does not route every deletion through Recycle Bin. Permanent deletion, some network/removable-volume operations, emptying the bin, cleanup tools, and missing acquisitions can leave no parseable `$I` files. The tool does not recover overwritten/unallocated data or prove that a missing item never existed.

## Validation before operational adoption

The repository's synthetic tests establish behavior for known byte sequences and error cases. Its opt-in native Windows Shell validation checks controlled files against independently recorded facts on a disposable host; see [VALIDATION_WINDOWS.md](VALIDATION_WINDOWS.md) for the command and scope. Neither layer constitutes a corpus spanning every Windows build or acquisition method.

Before adoption, add a separately maintained known-good corpus acquired from the Windows versions and configurations relevant to your organisation. Record the actual source path, file size, controlled deletion time, metadata bytes, `$R` state, expected timezone interpretation, and independent comparison results. Test malformed and partial acquisitions as well as ordinary samples.

Keep sensitive case data outside the repository. Do not commit real user paths, confidential files, custody records, or access tokens when reporting a bug. Prefer a minimal synthetic reproduction or follow private reporting guidance in `SECURITY.md`.
