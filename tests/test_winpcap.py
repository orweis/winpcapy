"""Tests for the WinPcap capture class."""

import ctypes
import logging

import pytest

from winpcapy import WinPcap, WinPcapException
from winpcapy import winpcapy as core
from winpcapy import winpcapy_types as wtypes


def null_handle():
    return ctypes.POINTER(wtypes.pcap_t)()


def make_packet(payload, wire_length=None, ts=(1_700_000_000, 123456)):
    """Return ``(header_pointer, data_pointer, keepalive)`` for a fake packet."""
    buf = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
    header = wtypes.pcap_pkthdr(
        ts=wtypes.timeval(*ts),
        caplen=len(payload),
        len=len(payload) if wire_length is None else wire_length,
    )
    return (
        ctypes.pointer(header),
        ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)),
        (buf, header),
    )


def deliver(packets):
    """pcap_loop side effect calling the native callback for each packet."""

    def loop(handle, limit, callback, user):
        for payload, wire_length in packets:
            header, data, _keep = make_packet(payload, wire_length)
            callback(None, header, data)
        return 0

    return loop


# --------------------------------------------------------------------------
# construction / open / close
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["\\Device\\NPF_{ABC}", b"\\Device\\NPF_{ABC}"])
def test_accepts_str_and_bytes_device_names(pcap, name):
    with WinPcap(name, snap_length=128, promiscuous=0, timeout=50):
        pass
    args = pcap.pcap_open_live.call_args.args
    assert args[:4] == (b"\\Device\\NPF_{ABC}", 128, 0, 50)


def test_rejects_invalid_device_name_type():
    with pytest.raises(TypeError):
        WinPcap(42)


def test_open_failure_raises_with_pcap_message(pcap):
    def fail(name, snaplen, promisc, timeout, errbuf):
        errbuf.value = b"No such device"
        return null_handle()

    pcap.pcap_open_live.side_effect = fail
    with pytest.raises(WinPcap.DeviceOpenError, match="No such device") as excinfo:
        with WinPcap("eth9"):
            pytest.fail("body must not run")
    assert isinstance(excinfo.value, WinPcapException)
    pcap.pcap_close.assert_not_called()


def test_close_releases_handle_and_allows_reopen(pcap):
    capture = WinPcap("eth0")
    with capture:
        handle = capture._handle
    pcap.pcap_close.assert_called_once_with(handle)
    assert capture._handle is None
    with capture:
        pass
    assert pcap.pcap_close.call_count == 2


def test_double_enter_raises(pcap):
    capture = WinPcap("eth0")
    with capture:
        with pytest.raises(WinPcap.DeviceAlreadyOpen):
            capture.__enter__()
        with pytest.raises(AssertionError):
            capture.__enter__()
    assert pcap.pcap_open_live.call_count == 1


def test_exit_closes_even_when_body_raises(pcap):
    with pytest.raises(RuntimeError):
        with WinPcap("eth0"):
            raise RuntimeError("boom")
    pcap.pcap_close.assert_called_once()


@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("run", (lambda *a: None,)),
        ("stop", ()),
        ("compile", ("tcp",)),
        ("setfilter", ()),
        ("send", (b"\x00",)),
    ],
)
def test_methods_require_open_device(pcap, method, args):
    capture = WinPcap("eth0")
    with pytest.raises(WinPcap.DeviceIsNotOpen):
        getattr(capture, method)(*args)
    # ... and the device is closed again after the with block (no use after free)
    with capture:
        pass
    with pytest.raises(WinPcap.DeviceIsNotOpen):
        getattr(capture, method)(*args)


def test_repr_shows_state():
    capture = WinPcap("eth0")
    assert "closed" in repr(capture) and "eth0" in repr(capture)
    with capture:
        assert "open" in repr(capture)


# --------------------------------------------------------------------------
# filters
# --------------------------------------------------------------------------


@pytest.mark.parametrize("expression", ["tcp port 80", b"tcp port 80"])
def test_compile_accepts_str_and_bytes(pcap, expression):
    with WinPcap("eth0") as capture:
        assert capture.compile(expression) is True
    args = pcap.pcap_compile.call_args.args
    assert args[2] == b"tcp port 80"
    assert args[4].value == core.DEFAULT_NETMASK


def test_compile_passes_custom_netmask(pcap):
    with WinPcap("eth0") as capture:
        capture.compile("ip", netmask=0xFFFFFF00)
    assert pcap.pcap_compile.call_args.args[4].value == 0xFFFFFF00


def test_compile_rejects_non_string():
    with WinPcap("eth0") as capture:
        with pytest.raises(TypeError):
            capture.compile(80)


def test_compile_failure_returns_false_and_exposes_error(pcap):
    pcap.pcap_compile.return_value = -1
    pcap.pcap_geterr.return_value = b"syntax error"
    with WinPcap("eth0") as capture:
        assert capture.compile("tcp port") is False
        assert capture.last_error == "syntax error"
    # Nothing was compiled, so nothing must be freed.
    pcap.pcap_freecode.assert_not_called()


def test_compiled_program_is_freed_on_recompile_and_close(pcap):
    with WinPcap("eth0") as capture:
        capture.compile("tcp")
        pcap.pcap_freecode.assert_not_called()
        capture.compile("udp")
        assert pcap.pcap_freecode.call_count == 1
    assert pcap.pcap_freecode.call_count == 2


@pytest.mark.parametrize(("rc", "expected"), [(0, True), (-1, False)])
def test_setfilter_result(pcap, rc, expected):
    pcap.pcap_setfilter.return_value = rc
    with WinPcap("eth0") as capture:
        assert capture.setfilter() is expected


# --------------------------------------------------------------------------
# send
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "buffer", [b"\x01\x02\x00\xff", bytearray(b"\x01\x02\x00\xff"), memoryview(b"\x01\x02\x00\xff")]
)
def test_send_passes_exact_bytes(pcap, buffer):
    sent = []
    pcap.pcap_sendpacket.side_effect = lambda h, buf, n: sent.append(bytes(buf[:n])) or 0
    with WinPcap("eth0") as capture:
        assert capture.send(buffer) is True
    assert sent == [b"\x01\x02\x00\xff"]
    assert pcap.pcap_sendpacket.call_args.args[2] == 4


def test_send_failure_returns_false(pcap, caplog):
    pcap.pcap_sendpacket.return_value = -1
    pcap.pcap_geterr.return_value = b"send error: adapter down"
    with caplog.at_level(logging.DEBUG, logger="winpcapy"):
        with WinPcap("eth0") as capture:
            assert capture.send(b"\x00" * 60) is False
            assert capture.last_error == "send error: adapter down"
    assert "adapter down" in caplog.text


def test_send_rejects_oversized_buffer(pcap, monkeypatch):
    monkeypatch.setattr(core, "_MAX_PACKET_LENGTH", 8)
    with WinPcap("eth0") as capture:
        with pytest.raises(ValueError):
            capture.send(b"\x00" * 9)
    pcap.pcap_sendpacket.assert_not_called()


@pytest.mark.parametrize("bad", ["text", 5, None])
def test_send_rejects_non_bytes_like(bad):
    with WinPcap("eth0") as capture:
        with pytest.raises(TypeError):
            capture.send(bad)


# --------------------------------------------------------------------------
# capture loop
# --------------------------------------------------------------------------


def test_packet_handler_reads_only_captured_bytes():
    """Regression test: the handler must use caplen, not the wire length."""
    received = []
    capture = WinPcap("eth0")
    capture._callback = lambda pcap_obj, param, header, data: received.append(
        (data, header.contents.len)
    )
    header, data, _keep = make_packet(b"ABCDEFGH", wire_length=1500)
    capture.packet_handler(None, header, data)
    assert received == [(b"ABCDEFGH", 1500)]


def test_run_delivers_packets_through_native_callback(pcap):
    pcap.pcap_loop.side_effect = deliver([(b"\x01" * 10, None), (b"\x02" * 4, 9000)])
    received = []

    def callback(win_pcap, param, header, data):
        received.append((win_pcap, data, header.contents.caplen, header.contents.len))

    with WinPcap("eth0") as capture:
        assert capture.run(callback, limit=2) == 0
    assert received == [(capture, b"\x01" * 10, 10, 10), (capture, b"\x02" * 4, 4, 9000)]
    assert pcap.pcap_loop.call_args.args[1] == 2


@pytest.mark.parametrize("bad", [None, "not callable", 3])
def test_run_rejects_non_callable_before_starting(pcap, bad):
    with WinPcap("eth0") as capture:
        with pytest.raises(WinPcap.CallbackIsNotCallable):
            capture.run(bad)
    pcap.pcap_loop.assert_not_called()


@pytest.mark.parametrize("exc_type", [ValueError, KeyboardInterrupt])
def test_callback_exception_stops_loop_and_propagates(pcap, exc_type):
    pcap.pcap_loop.side_effect = deliver([(b"a", None), (b"b", None), (b"c", None)])
    calls = []

    def callback(win_pcap, param, header, data):
        calls.append(data)
        raise exc_type("stop here")

    with WinPcap("eth0") as capture:
        with pytest.raises(exc_type, match="stop here"):
            capture.run(callback)
        # The loop was asked to stop; the stored error is cleared afterwards.
        pcap.pcap_breakloop.assert_called_with(capture._handle)
        assert capture._callback_error is None
    # Only the first exception is kept.
    assert calls[0] == b"a"


def test_run_returns_breakloop_code(pcap):
    pcap.pcap_loop.return_value = -2
    with WinPcap("eth0") as capture:
        assert capture.run(lambda *a: None) == -2


def test_run_raises_on_pcap_error(pcap):
    pcap.pcap_loop.return_value = -1
    pcap.pcap_geterr.return_value = b"The interface went down"
    with WinPcap("eth0") as capture:
        with pytest.raises(WinPcapException, match="interface went down"):
            capture.run(lambda *a: None)


def test_stop_breaks_loop(pcap):
    with WinPcap("eth0") as capture:
        capture.stop()
        pcap.pcap_breakloop.assert_called_once_with(capture._handle)
