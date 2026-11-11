# Contributing

Contributions that improve decoding accuracy, evidence handling, diagnostics,
and reproducible validation are welcome. Keep changes focused and explain the
observable behavior before and after your change.

## Development setup

Use Python 3.10 or newer and a virtual environment:

```console
python -m venv .venv
```

Activate it with `source .venv/bin/activate` on Linux/macOS or
`.venv\Scripts\Activate.ps1` in Windows PowerShell. Then run:

```console
python -m pip install -e ".[dev]"
python -m pytest --cov=rbinforensics --cov-report=term-missing --cov-fail-under=85
python -m ruff check .
python -m ruff format --check .
python -m build
```

Use `python -m ruff format .` to apply the formatter. Runtime code must use
the Python standard library unless a new dependency has a documented need.

## Desktop and Windows packaging

The desktop uses Tk from the selected Python installation. Check it with `python -m tkinter`. On a graphical development machine, enable native widget tests with:

```sh
RBF_RUN_GUI=1 python -m pytest tests/test_gui.py -v
```

In PowerShell, set `$env:RBF_RUN_GUI = '1'` before running pytest. The Linux GUI CI job uses a virtual display; ordinary test collection does not require one. Keep worker code independent from Tk widgets: send progress/results through the session queue and update widgets on the GUI thread. Cover cancellation and state transitions, including rejection of export after a cancelled or failed scan.

Coverage has separate gates for the headless engine/controller and the native desktop. Default coverage omits only `gui.py`, because CLI-only hosts need no display. The desktop CI job measures that module independently with a real Tk display:

```sh
RBF_RUN_GUI=1 python -m pytest tests/test_gui.py tests/test_gui_entry.py --cov=rbinforensics.gui --cov-config=tools/gui.coveragerc --cov-fail-under=85
```

Build portable distributions on native Windows x64; PyInstaller does not cross-compile a Windows executable from Linux:

```sh
python -m pip install -e '.[dev,freeze]'
python tools/build_windows.py
```

The builder creates new files under `dist/windows` by default and refuses to overwrite an earlier archive/checksum. Use a fresh `--output` directory for another build. It must run the packaged executable's smoke test before a ZIP is considered complete. This test is separate from the controlled Windows artefact validation described in [docs/VALIDATION_WINDOWS.md](docs/VALIDATION_WINDOWS.md).

## Tests and forensic claims

- Cover changed behavior with a regression test. Include negative cases such
  as truncated input, invalid lengths, and encoding errors for parser changes.
- Construct synthetic samples in tests where practical. Keep the expected
  values independent of the production decoding logic.
- State whether a finding comes from synthetic fixtures, independently acquired
  Windows artefacts, comparison with another parser, or a published reference.
  Passing generated tests alone does not establish real-world compatibility.
- Document supported structures and uncertain behavior. Do not silently repair
  evidence, fabricate missing values, or claim that a timestamp proves who
  performed an action.
- Preserve raw values needed to reproduce interpretation, stable error codes,
  and the documented JSON schema. Explain compatibility changes in your PR.

## Protect case data

Never commit or attach real case evidence, personal paths, credentials, customer
documents, or unredacted reports to issues and pull requests. Recycle Bin file
names can contain sensitive information even when their contents are absent.

The ignore rules help keep common evidence locations out of Git, but are not a
privacy boundary. Review `git status` and your staged diff before each commit.
Use a minimal synthetic reproduction for bug reports. Synthetic fixtures under
`tests/fixtures/` may be committed when they contain no personal data.

Use only evidence you are authorized to handle. Acquisition, write blocking,
chain of custody, retention, and legal conclusions remain the responsibility
of the analyst and their organization.

## Pull requests

Describe the problem, resulting behavior, relevant references, and checks run.
If a platform-specific check was not run, say so. CI tests Linux, Windows, and
macOS; a configured CI job is not a claim that a particular run has passed.
For security-sensitive bugs, follow [SECURITY.md](SECURITY.md).
