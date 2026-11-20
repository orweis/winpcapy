"""Integration tests against the real pcap library.

Skipped automatically when Npcap/WinPcap/libpcap is not installed. Tests that
need to open a live device are skipped when the process lacks the privileges.
"""

import socket
import sys
import threading

import pytest

from winpcapy import WinPcap, WinPcapDevices
from winpcapy import winpcapy_types as wtypes

pytestmark = pytest.mark.integration


def test_library_version_is_reported():
    version = wtypes.pcap_lib_version()
    assert isinstance(version, bytes)
    assert b"pcap" in version.lower()


def test_list_devices_returns_text():
    try:
        devices = WinPcapDevices.list_devices()
    except WinPcapDevices.PcapFindDevicesException as exc:
        pytest.skip("cannot enumerate devices: %s" % exc)
    assert all(isinstance(k, str) and isinstance(v, str) for k, v in devices.items())


def test_opening_unknown_device_raises():
    with pytest.raises(WinPcap.DeviceOpenError):
        with WinPcap("winpcapy-no-such-device-0"):
            pass


@pytest.fixture
def loopback():
    if not sys.platform.startswith("linux"):
        pytest.skip("loopback capture test is Linux-only")
    capture = WinPcap("lo", snap_length=64, timeout=100)
    try:
        capture.__enter__()
    except WinPcap.DeviceOpenError as exc:
        pytest.skip("cannot open loopback (needs CAP_NET_RAW): %s" % exc)
    yield capture
    capture.__exit__(None, None, None)


def test_filter_compile_errors_are_reported(loopback):
    assert loopback.compile("this is (not a filter") is False
    assert loopback.last_error


def test_live_capture_truncates_to_snap_length(loopback):
    port = 50999
    assert loopback.compile("udp and dst port %d" % port)
    assert loopback.setfilter()
    received = []
    watchdog = threading.Timer(10, loopback.stop)

    def send():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for _ in range(20):
                sock.sendto(b"x" * 500, ("127.0.0.1", port))

    def callback(win_pcap, param, header, data):
        received.append((len(data), header.contents.caplen, header.contents.len))

    sender = threading.Timer(0.3, send)
    watchdog.start()
    sender.start()
    try:
        loopback.run(callback, limit=1)
    finally:
        watchdog.cancel()
        sender.join()
    assert received, "no packet captured"
    data_len, caplen, wire_len = received[0]
    assert data_len == caplen == 64
    assert wire_len > caplen
