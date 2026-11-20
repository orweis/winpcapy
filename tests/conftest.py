"""Test configuration.

The package loads the native pcap library at import time. When no library is
available (CI runners, Windows without Npcap...) a fake library is injected so
that the pure-Python logic can still be tested. Unit tests never call into the
real library: the ``pcap`` fixture (autouse) replaces every ``pcap_*`` binding
with a :class:`unittest.mock.MagicMock`. Tests marked ``integration`` use the
real library and are skipped when it is not installed (or when the
``WINPCAPY_TEST_FAKE_LIBRARY`` environment variable is set).
"""

import ctypes
import ctypes.util
import os
from unittest import mock

import pytest


class FakeLibrary:
    """Stand-in for a ``ctypes.CDLL``: every attribute is a MagicMock function."""

    def __init__(self, name="fake-pcap", missing=()):
        self._name = name
        self._missing = set(missing)
        self._functions = {}

    def __getattr__(self, name):
        if name.startswith("__") or name in self._missing:
            raise AttributeError(name)
        return self._functions.setdefault(name, mock.MagicMock(name=name))


def _import_package():
    """Import winpcapy; return True if the real native library was loaded."""
    if not os.environ.get("WINPCAPY_TEST_FAKE_LIBRARY"):
        try:
            return True
        except OSError:
            pass
    fake_cdll = mock.patch.object(ctypes, "CDLL", side_effect=lambda *a, **kw: FakeLibrary())
    fake_find = mock.patch.object(ctypes.util, "find_library", return_value="libpcap-fake")
    with fake_cdll, fake_find:
        pass
    return False


REAL_LIBRARY = _import_package()

from winpcapy import winpcapy_types as wtypes  # noqa: E402


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "integration: needs a real Npcap/WinPcap/libpcap library installed"
    )


def pytest_collection_modifyitems(config, items):
    if REAL_LIBRARY:
        return
    skip = pytest.mark.skip(reason="no pcap library installed (Npcap/libpcap)")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip)


def _pcap_function_names():
    return sorted(
        name
        for name, value in vars(wtypes).items()
        if name.startswith("pcap_") and callable(value) and not isinstance(value, type)
    )


@pytest.fixture(autouse=True)
def pcap(request, monkeypatch):
    """Replace every pcap_* binding with a MagicMock (except for integration tests).

    Returns the patched ``winpcapy_types`` module. Defaults model a healthy
    library: calls succeed and return 0, ``pcap_open_live`` returns a non-NULL
    handle.
    """
    if "integration" in request.keywords:
        yield wtypes
        return
    for name in _pcap_function_names():
        monkeypatch.setattr(wtypes, name, mock.MagicMock(name=name, return_value=0))
    wtypes.pcap_open_live.return_value = mock.MagicMock(name="pcap_t*")
    wtypes.pcap_geterr.return_value = b"mock pcap error"
    yield wtypes
