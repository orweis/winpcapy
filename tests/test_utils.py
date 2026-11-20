"""Tests for the WinPcapUtils helpers."""

import ctypes
import logging
import time
from typing import ClassVar

import pytest

from winpcapy import WinPcapDevices, WinPcapUtils
from winpcapy import winpcapy as core
from winpcapy import winpcapy_types as wtypes


class FakeCapture:
    """Records how WinPcapUtils drives a WinPcap instance."""

    instances: ClassVar[list] = []

    def __init__(self, device_name, **kwargs):
        self.device_name = device_name
        self.calls = []
        self.compile_result = True
        self.setfilter_result = True
        self.send_result = True
        self.last_error = "fake error"
        FakeCapture.instances.append(self)

    def __enter__(self):
        self.calls.append("enter")
        return self

    def __exit__(self, *exc):
        self.calls.append("exit")

    def compile(self, packet_filter, netmask=core.DEFAULT_NETMASK):
        self.calls.append(("compile", packet_filter, netmask))
        return self.compile_result

    def setfilter(self):
        self.calls.append("setfilter")
        return self.setfilter_result

    def run(self, callback=None, limit=0):
        self.calls.append(("run", callback, limit))
        return 0

    def send(self, packet_buffer):
        self.calls.append(("send", packet_buffer))
        return self.send_result


@pytest.fixture
def fake_capture(monkeypatch):
    FakeCapture.instances = []
    monkeypatch.setattr(core, "WinPcap", FakeCapture)
    return FakeCapture


@pytest.fixture
def one_device(monkeypatch):
    monkeypatch.setattr(
        WinPcapDevices,
        "list_devices",
        classmethod(lambda cls: {"dev0": "Loopback", "dev1": "Intel(R) Ethernet"}),
    )


def callback(*args):
    return None


def test_capture_on_uses_matching_device(fake_capture, one_device):
    WinPcapUtils.capture_on("*Ethernet*", callback)
    (capture,) = fake_capture.instances
    assert capture.device_name == "dev1"
    assert capture.calls == ["enter", ("run", callback, 0), "exit"]


def test_capture_on_without_match_warns(fake_capture, one_device, caplog):
    with caplog.at_level(logging.WARNING, logger="winpcapy"):
        WinPcapUtils.capture_on("*Wireless*", callback)
    assert fake_capture.instances == []
    assert "Wireless" in caplog.text


def test_capture_on_device_name(fake_capture):
    WinPcapUtils.capture_on_device_name("dev7", callback)
    assert fake_capture.instances[0].device_name == "dev7"


def test_capture_on_and_print_uses_printer(fake_capture, one_device):
    WinPcapUtils.capture_on_and_print("Loop*")
    (capture,) = fake_capture.instances
    assert capture.calls[1] == ("run", WinPcapUtils.packet_printer_callback, 0)


def test_compile_on_device_name_and_legacy_alias(fake_capture):
    assert WinPcapUtils.test_compile_on_device_name is WinPcapUtils.compile_on_device_name
    assert WinPcapUtils.test_compile_on_device_name("dev0", "tcp", netmask=0xFF) is True
    assert fake_capture.instances[0].calls[1] == ("compile", "tcp", 0xFF)


def test_compile_and_capture_success(fake_capture):
    assert WinPcapUtils.compile_and_capture_on_device_name("dev0", "udp", callback) is True
    calls = fake_capture.instances[0].calls
    assert calls[1:4] == [
        ("compile", "udp", core.DEFAULT_NETMASK),
        "setfilter",
        ("run", callback, 0),
    ]


@pytest.mark.parametrize("failing", ["compile_result", "setfilter_result"])
def test_compile_and_capture_does_not_run_when_filter_fails(monkeypatch, failing):
    class Failing(FakeCapture):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            setattr(self, failing, False)

    FakeCapture.instances = []
    monkeypatch.setattr(core, "WinPcap", Failing)
    assert WinPcapUtils.compile_and_capture_on_device_name("dev0", "udp", callback) is False
    assert not any(isinstance(c, tuple) and c[0] == "run" for c in FakeCapture.instances[0].calls)


def test_send_packet_without_callback(fake_capture, one_device):
    WinPcapUtils.send_packet("*Ethernet*", b"\x00\x01")
    calls = fake_capture.instances[0].calls
    assert calls == ["enter", ("send", b"\x00\x01"), "exit"]


def test_send_packet_with_callback_captures(fake_capture, one_device):
    WinPcapUtils.send_packet("*Ethernet*", b"\x00", callback=callback, limit=3)
    assert fake_capture.instances[0].calls[2] == ("run", callback, 3)


def test_send_packet_logs_failures(monkeypatch, one_device, caplog):
    class Failing(FakeCapture):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.send_result = False

    monkeypatch.setattr(core, "WinPcap", Failing)
    with caplog.at_level(logging.WARNING, logger="winpcapy"):
        WinPcapUtils.send_packet("*Ethernet*", b"\x00")
    assert "fake error" in caplog.text


def test_send_packet_without_match(fake_capture, one_device):
    WinPcapUtils.send_packet("*nothing*", b"\x00")
    assert fake_capture.instances == []


def test_packet_printer_callback_format(capsys):
    ts = 1_700_000_000
    header = wtypes.pcap_pkthdr(ts=wtypes.timeval(ts, 42), caplen=60, len=1514)
    WinPcapUtils.packet_printer_callback(None, None, ctypes.pointer(header), b"")
    expected = time.strftime("%H:%M:%S", time.localtime(ts)) + ",000042 len:1514\n"
    assert capsys.readouterr().out == expected
