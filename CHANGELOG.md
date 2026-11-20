# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project follows [Semantic Versioning](https://semver.org/).

## [2.0.0] - Unreleased

The public API (`WinPcap`, `WinPcapDevices`, `WinPcapUtils` and every name in
`winpcapy.winpcapy_types`) is unchanged. The major version bump is for the
dropped Python versions and the changed error behavior listed below; see
"Upgrading from 1.x" in the README.

### Security
- **Out-of-bounds read in the packet callback.** `WinPcap.packet_handler`
  read `header.len` (the original wire length) bytes from the packet buffer
  instead of `header.caplen` (the captured length). When packets were
  truncated by `snap_length`, this read past the end of the buffer: process
  memory was handed to the callback, or the process crashed. Callbacks now
  receive exactly `caplen` bytes.
- **Use after free / NULL handle.** A failed `pcap_open_live` (NULL handle) was
  not detected, and the handle was not reset after `pcap_close`, so methods
  called after a failed open or after the `with` block passed an invalid
  pointer to the native library. `WinPcapDevices` could likewise iterate a
  freed device list after its `with` block.
- **DLL search-order hijacking.** `wpcap.dll` was loaded by bare name. It is
  now loaded by absolute path from the Windows system directory (Npcap first),
  with the safe default search order only as a last resort.
- `assert` statements used as state guards (removed under `python -O`) are now
  real checks.

### Changed (breaking)
- Require Python 3.9 or newer; Python 2.7 and 3.4-3.8 are no longer supported.
- `WinPcap.__enter__` raises the new `WinPcap.DeviceOpenError` (a
  `WinPcapException`) with pcap's error text when the device cannot be opened.
- Exceptions raised inside capture callbacks (including `KeyboardInterrupt`)
  stop the capture loop and are re-raised by `WinPcap.run()`. Before, ctypes
  printed and ignored them and the capture went on (Ctrl+C could not stop a
  capture).
- `WinPcap.run()` raises `CallbackIsNotCallable` before starting the capture
  (it used to loop forever printing errors), returns the `pcap_loop` return
  code (was `None`) and raises `WinPcapException` when `pcap_loop` fails.
- `WinPcapUtils.compile_and_capture_on_device_name()` returns `True` after a
  capture (it always returned a falsy value before) and `False` when the
  filter cannot be compiled or applied.
- `WinPcapUtils.packet_printer_callback` no longer calls `sys.exit()`.
- On Windows, Npcap's `System32\Npcap\wpcap.dll` is preferred over a
  `System32\wpcap.dll` (WinPcap or Npcap in WinPcap-compatible mode).
- When no pcap library is found, import raises `PcapLibraryNotFoundError`
  (an `OSError`) with installation instructions. On Linux it used to raise
  an unrelated `AttributeError`.

### Added
- `WinPcap.last_error` with the pcap error text of the last failed operation.
- `WinPcap.send()` returns `True`/`False` (was `None`, errors were ignored)
  and accepts any bytes-like object.
- `WinPcap(...)` accepts `bytes` device names (as yielded by `WinPcapDevices`).
- `WinPcapUtils.compile_on_device_name()`; `test_compile_on_device_name` is
  kept as an alias.
- `winpcapy.WinPcapException` and `winpcapy.PcapLibraryNotFoundError` exports,
  `__all__`, `WinPcap.DeviceAlreadyOpen` and
  `WinPcapDevices.DevicesAlreadyOpen` (both also `AssertionError`s for
  compatibility).
- A test suite (unit tests with a mocked library and
  integration tests against libpcap), GitHub Actions CI on Linux and Windows,
  Dependabot, `CONTRIBUTING.md` and `SECURITY.md`.
- pcap functions missing from the installed library no longer break the
  import. They are replaced by a falsy placeholder that raises
  `NotImplementedError` when called.

### Fixed
- `WinPcap.compile()` accepts `str` filters on Python 3 (raised `TypeError`).
- Compiled filter programs are freed (`pcap_freecode`) on recompile and close.
- `WinPcapDevices.list_devices()` no longer crashes on devices without a
  description or with non-UTF-8 names.
- `WinPcapDevices.get_matching_device(None)` matches any device instead of
  raising `TypeError`.
- `WinPcapUtils.capture_on()`/`send_packet()` log a warning when no device
  matches (they silently did nothing).
- Typos in ctypes prototypes (`argtype`, `retype`, `restypes`) that left
  `pcap_setmintocopy`, `pcap_sendqueue_transmit`, `pcap_findalldevs_ex`,
  `pcap_parsesrcstr`, `pcap_remoteact_close` and `pcap_remoteact_cleanup`
  without the declared signature.
- `timeval` layout on macOS.
- `WinPcapUtils.send_packet` first argument renamed from `self` to `cls`.

### Packaging
- Migrated from `setup.py`/`setup.cfg` to `pyproject.toml` (PEP 621). No more
  universal (Python 2) wheels.
- README rewritten for Python 3 and Npcap.

## [1.0.3] - 2024-04-18
- Fix for Python 3.10.

## Earlier releases
- Added `compile`/`setfilter`, packet sending and Cygwin support.
