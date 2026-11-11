# Controlled Windows validation

Synthetic fixtures are useful for exact byte boundaries and corruption tests. Controlled deletion on a real Windows filesystem provides a different check: whether the tool's interpretation agrees with independently recorded facts about files actually sent to Recycle Bin.

Perform this work on a disposable test machine or runner, never on a case source. The procedure deliberately creates and recycles test-owned files. Do not empty a user's Recycle Bin or alter unrelated artefacts to prepare the test.

## Record the environment and ground truth

Before deletion, record:

- Windows edition, build, patch level, Python version, and tool commit/version.
- Volume/filesystem type and relevant Recycle Bin settings.
- Test user's SID context without treating it as authenticated evidence of an actor.
- Full source path, exact file size, SHA-256, and creation procedure for each test item.
- A UTC time immediately before and after the recycle operation.
- Relevant clock synchronisation information and timezone configuration.

Use only disposable files created for the test, with a unique random marker in their names. Include ordinary ASCII, non-BMP Unicode, long paths supported by the test environment, empty/nonempty files, and directory payloads as separate documented cases. Different Windows configurations may produce different coverage; do not silently extrapolate from one build.

## Collect and compare

1. Send only the test-owned files through the Windows recycle operation.
2. Find the resulting `$I`/`$R` objects using the unique source-path marker and preserve their directory structure.
3. Acquire a verified working copy outside the active Recycle Bin, recording collection hashes and steps.
4. Scan that working copy and save JSON outside its evidence directory.
5. Compare decoded path and original size with the pre-recorded facts.
6. Compare deletion time with the independently measured UTC operation window, documenting clock/tolerance assumptions.
7. Compare regular payload SHA-256 with the pre-deletion file hash.
8. Check format version, warnings, SID context, pairing, and report selection/timeline.
9. Retain the original metadata bytes and the validation report privately for reproducibility.

Example analysis command after collection:

```powershell
rbf scan 'D:\Validation\Working' --recursive --hash-payload --format json --output 'D:\Validation\Reports\run-001.json'
```

Do not build expected values by running this parser and copying its output into the test. Original path, size, content hash, and time window should be recorded independently before deletion.

## Optional automated live test

The repository's [Windows live-validation test](../tests/test_windows_live.py) is separate from ordinary cross-platform unit tests. It is environment-gated so routine local test runs do not unexpectedly recycle files. On a disposable Windows validation host, install development dependencies and opt in explicitly:

```powershell
python -m pip install -e '.[dev]'
$env:RBF_RUN_WINDOWS_LIVE = '1'
python -m pytest tests/test_windows_live.py -v --junitxml=windows-live.xml
Remove-Item Env:RBF_RUN_WINDOWS_LIVE
```

The CI workflow includes a dedicated Windows Shell validation job that enables this flag on its disposable Windows runner. Ordinary unit-test matrix jobs leave it disabled.

The live test recycles two freshly created files: one ASCII filename and one containing non-BMP Unicode. It invokes the native Shell operation, locates only this run's UUID-extension metadata in the current-user bin, and checks independently known path, size, content hash, and a measured UTC time window with a documented two-second tolerance. It records the runner Windows build and the layout version actually emitted. It does not force Windows to emit format version 1 or claim that both layouts were natively acquired.

Cleanup is limited to the positively verified pair whose original path and payload digest still match the test's known values. There is no whole-bin cleanup. A path or digest mismatch leaves the item intact for diagnosis. The automated scenario uses paths below the native operation's MAX_PATH limit; longer-path and directory cases belong in the separately documented broader corpus.

A successful automated live test demonstrates the checked scenario on that runner's Windows build and volume. It is not an independent corpus spanning Windows versions, all deletion routes, Recycle Bin policies, removable/network filesystems, or third-party acquisition methods. A live test can also expose a runner configuration that does not support recycling; preserve that failure as an environment limitation rather than silently treating permanent deletion as success.

## Broader operational corpus

Maintain a private known-good corpus for the environments your organisation actually examines. Include:

- `$I` versions 1 and 2 obtained from identified Windows builds.
- Both matching and absent payloads, collected without losing original context.
- File and directory payloads, Unicode, boundary path lengths, and different volumes/SIDs.
- Partial acquisitions, truncated metadata, duplicate/case-variant names on copied filesystems, and unsupported layouts.
- Independently checked expected values and comparison results from an established second tool where appropriate.

Record exactly which configurations passed and which remain untested. The release number `1.0.0`, passing unit tests, and a single CI live test do not replace this adoption-specific validation.

## Cleanup and privacy

Remove only artefacts positively identified as belonging to the disposable validation run. Do not use whole-bin cleanup as part of automated validation. Keep real user paths, content, custody records, and confidential acquisition samples outside this repository. Report bugs with minimal synthetic reproductions or use the private reporting guidance in [SECURITY.md](../SECURITY.md).
