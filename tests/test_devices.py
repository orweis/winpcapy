"""Tests for WinPcapDevices (device enumeration)."""

import ctypes

import pytest

from winpcapy import WinPcapDevices
from winpcapy import winpcapy_types as wtypes


def build_device_list(entries):
    """Build a real linked list of pcap_if structures.

    Returns ``(head_pointer, keepalive)``; *keepalive* must stay referenced
    while the list is used.
    """
    nodes = [
        wtypes.pcap_if(name=name, description=desc, flags=i)
        for i, (name, desc) in enumerate(entries)
    ]
    for current, following in zip(nodes, nodes[1:]):
        current.next = ctypes.pointer(following)
    head = ctypes.pointer(nodes[0]) if nodes else ctypes.POINTER(wtypes.pcap_if_t)()
    return head, nodes


@pytest.fixture
def devices(pcap):
    """Make pcap_findalldevs return the given entries."""
    keep = []

    def install(entries):
        head, nodes = build_device_list(entries)
        keep.append((head, nodes))

        def findalldevs(ref, errbuf):
            if head:
                ref._obj.contents = head.contents
            return 0

        pcap.pcap_findalldevs.side_effect = findalldevs
        return head

    return install


def test_iterates_devices_in_order(devices, pcap):
    devices([(b"dev0", b"First"), (b"dev1", b"Second"), (b"dev2", b"Third")])
    with WinPcapDevices() as devs:
        seen = [(d.name, d.description, d.flags) for d in devs]
    assert seen == [(b"dev0", b"First", 0), (b"dev1", b"Second", 1), (b"dev2", b"Third", 2)]
    pcap.pcap_freealldevs.assert_called_once()


def test_list_devices_handles_missing_and_invalid_descriptions(devices):
    devices([(b"eth0", None), (b"eth1", b"Caf\xe9 adapter"), (b"eth2", b"Intel(R) Ethernet")])
    assert WinPcapDevices.list_devices() == {
        "eth0": "",
        "eth1": "Caf� adapter",
        "eth2": "Intel(R) Ethernet",
    }


def test_empty_device_list_is_not_freed(devices, pcap):
    devices([])
    assert WinPcapDevices.list_devices() == {}
    pcap.pcap_freealldevs.assert_not_called()


def test_findalldevs_failure_reports_error_text(pcap):
    def fail(ref, errbuf):
        errbuf.value = b"permission denied"
        return -1

    pcap.pcap_findalldevs.side_effect = fail
    with pytest.raises(WinPcapDevices.PcapFindDevicesException, match="permission denied"):
        with WinPcapDevices():
            pass


def test_iteration_requires_context(devices):
    devices([(b"dev0", b"First")])
    devs = WinPcapDevices()
    with pytest.raises(WinPcapDevices.PcapFindDevicesException):
        list(devs)


def test_iteration_after_exit_is_refused(devices, pcap):
    devices([(b"dev0", b"First")])
    with WinPcapDevices() as devs:
        pass
    # The native list has been freed: iterating must not walk freed memory.
    with pytest.raises(WinPcapDevices.PcapFindDevicesException):
        list(devs)
    # Exiting twice must not double free.
    devs.__exit__(None, None, None)
    pcap.pcap_freealldevs.assert_called_once()


def test_double_enter_raises_assertion_compatible_error(devices):
    devices([(b"dev0", b"First")])
    devs = WinPcapDevices()
    with devs:
        with pytest.raises(WinPcapDevices.DevicesAlreadyOpen):
            devs.__enter__()
        with pytest.raises(AssertionError):
            devs.__enter__()


def test_context_can_be_reused(devices, pcap):
    devices([(b"dev0", b"First")])
    devs = WinPcapDevices()
    for _ in range(2):
        with devs:
            assert [d.name for d in devs] == [b"dev0"]
    assert pcap.pcap_freealldevs.call_count == 2


@pytest.mark.parametrize(
    ("glob", "expected"),
    [
        ("*Ethernet*", ("eth1", "Intel(R) Ethernet")),
        ("*wireless*", (None, None)),
        ("Loop*", ("lo", "Loopback")),
        (None, ("lo", "Loopback")),
    ],
)
def test_get_matching_device(devices, glob, expected):
    devices([(b"lo", b"Loopback"), (b"eth1", b"Intel(R) Ethernet")])
    assert WinPcapDevices.get_matching_device(glob) == expected
