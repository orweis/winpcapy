# Contributing

Thanks for helping improve winpcapy!

## Development setup

```bash
python -m venv .venv
. .venv/bin/activate          # .venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

## Checks

```bash
ruff check .            # lint
ruff format .           # format
pytest --cov            # tests with coverage
python -m build && twine check dist/*   # packaging
```

CI runs the same checks on Linux and Windows for every supported Python
version.

## Tests

- `tests/conftest.py` loads the real pcap library when one is installed and
  falls back to a fake library otherwise. The autouse `pcap` fixture replaces
  every `pcap_*` binding with a `MagicMock`, so unit tests never call native
  code. Configure return values and side effects on it, e.g.
  `pcap.pcap_compile.return_value = -1`.
- Tests marked `integration` (see `tests/test_integration.py`) use the real
  library. They are skipped when it is not installed, and tests that open a
  live device are skipped without capture privileges. On Linux:
  `sudo apt install libpcap-dev`.
- Set `WINPCAPY_TEST_FAKE_LIBRARY=1` to force the fake library.

## Guidelines

- Keep the public API backwards compatible: `WinPcap`, `WinPcapDevices`,
  `WinPcapUtils` and every name in `winpcapy.winpcapy_types`. A test checks
  the legacy names.
- Add a test for every bug fix and feature, and an entry to `CHANGELOG.md`.
- Behavior changes that can break users need a major version bump and a note
  in the README "Upgrading" section.
- Report security issues privately, see [SECURITY.md](SECURITY.md).
