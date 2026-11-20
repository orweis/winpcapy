"""High level, object oriented interface to pcap (Npcap / WinPcap / libpcap).

All native resources are guarded by context managers (``with`` statements):

* :class:`WinPcapDevices` - enumerate the capture devices of the machine.
* :class:`WinPcap` - open a device, filter, capture and send packets.
* :class:`WinPcapUtils` - convenience helpers and usage examples.

@author Or Weis 2015
"""

import ctypes
import fnmatch
import logging
import time

from . import winpcapy_types as wtypes

logger = logging.getLogger(__name__)

#: Default netmask passed to ``pcap_compile``. It is only relevant for filters
#: that test IPv4 broadcast addresses. Kept for backwards compatibility.
DEFAULT_NETMASK = 0xFFFFFF

_MAX_PACKET_LENGTH = 0x7FFFFFFF  # pcap_sendpacket() takes a C ``int`` size


def _decode(value):
    """Decode a C string returned by pcap (``bytes`` or ``None``) to ``str``."""
    if value is None:
        return ""
    return value.decode("utf-8", errors="replace")


def _to_bytes(value, what):
    """Return *value* as ``bytes``, encoding ``str`` as UTF-8."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError("%s must be str or bytes, not %s" % (what, type(value).__name__))


class WinPcapDevices:
    """Iterate over the capture devices (interfaces) available on this machine.

    Use as a context manager; the ``pcap_if`` structures yielded while
    iterating are owned by the native library and are only valid inside the
    ``with`` block::

        with WinPcapDevices() as devices:
            for device in devices:
                print(device.name, device.description)
    """

    class PcapFindDevicesException(Exception):
        """Raised when the device list cannot be retrieved or used."""

    class DevicesAlreadyOpen(PcapFindDevicesException, AssertionError):
        """Raised when entering a ``WinPcapDevices`` context twice.

        Subclasses :class:`AssertionError` for compatibility with releases
        that used an ``assert`` for this check.
        """

    def __init__(self):
        self._all_devices = None

    def __enter__(self):
        if self._all_devices is not None:
            raise self.DevicesAlreadyOpen("WinPcapDevices context is already active")
        all_devices = ctypes.POINTER(wtypes.pcap_if_t)()
        err_buffer = ctypes.create_string_buffer(wtypes.PCAP_ERRBUF_SIZE)
        if wtypes.pcap_findalldevs(ctypes.byref(all_devices), err_buffer) == -1:
            raise self.PcapFindDevicesException(
                "Error in WinPcapDevices: %s" % _decode(err_buffer.value)
            )
        self._all_devices = all_devices
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        all_devices, self._all_devices = self._all_devices, None
        # pcap_findalldevs() may legitimately return an empty (NULL) list.
        if all_devices:
            wtypes.pcap_freealldevs(all_devices)

    def pcap_interface_iterator(self):
        """Yield every ``pcap_if`` structure of the device list."""
        if self._all_devices is None:
            raise self.PcapFindDevicesException(
                "WinPcapDevices guard not called, use 'with statement'"
            )
        pcap_interface = self._all_devices
        while bool(pcap_interface):
            yield pcap_interface.contents
            pcap_interface = pcap_interface.contents.next

    def __iter__(self):
        return self.pcap_interface_iterator()

    @classmethod
    def list_devices(cls):
        """Return a ``{device_name: description}`` dict of all devices.

        Devices without a description map to an empty string.
        """
        res = {}
        with cls() as devices:
            for device in devices:
                res[_decode(device.name)] = _decode(device.description)
        return res

    @classmethod
    def get_matching_device(cls, glob=None):
        """Return ``(name, description)`` of the first device whose description
        matches the shell-style wildcard *glob* (e.g. ``"*Ethernet*"``).

        ``glob=None`` matches any device. Returns ``(None, None)`` when nothing
        matches.
        """
        pattern = "*" if glob is None else glob
        for name, description in cls.list_devices().items():
            if fnmatch.fnmatch(description, pattern):
                return name, description
        return None, None


class WinPcap:
    """Access a capture device (open, filter, capture, send).

    The device is opened when entering the ``with`` statement and closed when
    leaving it::

        with WinPcap(device_name) as capture:
            capture.run(callback=my_callback, limit=10)
    """

    # /* prototype of the packet handler */
    # void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
    HANDLER_SIGNATURE = ctypes.CFUNCTYPE(
        None,
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(wtypes.pcap_pkthdr),
        ctypes.POINTER(ctypes.c_ubyte),
    )

    class WinPcapException(Exception):
        """Base class of all errors raised by :class:`WinPcap`."""

    class CallbackIsNotCallable(WinPcapException):
        """Raised when :meth:`WinPcap.run` is given a non-callable callback."""

    class DeviceIsNotOpen(WinPcapException):
        """Raised when using the device without opening it first.

        Can be resolved by calling the method within a ``with`` statement.
        """

    class DeviceAlreadyOpen(WinPcapException, AssertionError):
        """Raised when entering the same ``WinPcap`` context twice.

        Subclasses :class:`AssertionError` for compatibility with releases
        that used an ``assert`` for this check.
        """

    class DeviceOpenError(WinPcapException):
        """Raised when the device cannot be opened (bad name, no privileges...)."""

    def __init__(self, device_name, snap_length=65536, promiscuous=1, timeout=1000):
        """
        :param device_name: the name of the device to open on context enter
            (``str`` or ``bytes``), as returned by
            :meth:`WinPcapDevices.list_devices`.
        :param snap_length: the snapshot length: at most this many bytes of
            each packet are captured.
        :param promiscuous: whether the interface is put into promiscuous mode
            (0 or 1).
        :param timeout: the read timeout in milliseconds.
        """
        self._handle = None
        self._fcode = ctypes.pointer(wtypes.bpf_program())
        self._fcode_compiled = False
        self._name = _to_bytes(device_name, "device_name")
        self._snap_length = snap_length
        self._promiscuous = promiscuous
        self._timeout = timeout
        self._err_buffer = ctypes.create_string_buffer(wtypes.PCAP_ERRBUF_SIZE)
        self._callback = None
        self._callback_error = None
        self._last_error = None
        # Keep a reference to the C callback for the lifetime of the object so
        # it is never garbage collected while the native loop runs.
        self._callback_wrapper = self.HANDLER_SIGNATURE(self.packet_handler)

    def __repr__(self):
        state = "open" if self._handle else "closed"
        return "<%s device=%r %s>" % (type(self).__name__, _decode(self._name), state)

    def __enter__(self):
        if self._handle is not None:
            raise self.DeviceAlreadyOpen("device is already open")
        handle = wtypes.pcap_open_live(
            self._name,
            self._snap_length,
            self._promiscuous,
            self._timeout,
            self._err_buffer,
        )
        # A failed open returns a NULL pointer, which is falsy but not None.
        if not handle:
            message = _decode(self._err_buffer.value) or "unknown error"
            raise self.DeviceOpenError(
                "Unable to open device %s: %s" % (_decode(self._name), message)
            )
        self._handle = handle
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        handle, self._handle = self._handle, None
        try:
            self._free_filter()
        finally:
            if handle:
                wtypes.pcap_close(handle)

    @property
    def last_error(self):
        """The last error message reported by pcap for this device, or ``None``."""
        return self._last_error

    def _check_open(self):
        if self._handle is None:
            raise self.DeviceIsNotOpen()

    def _record_error(self):
        message = _decode(wtypes.pcap_geterr(self._handle)) if self._handle else ""
        self._last_error = message or "unknown error"
        return self._last_error

    def _free_filter(self):
        if self._fcode_compiled:
            self._fcode_compiled = False
            wtypes.pcap_freecode(self._fcode)

    def packet_handler(self, param, header, pkt_pointer):
        """Native callback invoked by ``pcap_loop`` for each packet.

        Only ``header.caplen`` bytes are valid in the packet buffer; the
        original wire length is still available as ``header.contents.len``.

        Exceptions cannot cross the C boundary, so any exception raised here
        (including by the user callback, or ``KeyboardInterrupt``) is stored,
        the loop is stopped, and :meth:`run` re-raises it.
        """
        try:
            if not callable(self._callback):
                raise self.CallbackIsNotCallable()
            pkt_data = ctypes.string_at(pkt_pointer, header.contents.caplen)
            return self._callback(self, param, header, pkt_data)
        except BaseException as exc:  # re-raised by run()
            if self._callback_error is None:
                self._callback_error = exc
            if self._handle:
                wtypes.pcap_breakloop(self._handle)
            return None

    def stop(self):
        """Stop a running :meth:`run` loop (``pcap_breakloop``)."""
        self._check_open()
        wtypes.pcap_breakloop(self._handle)

    def run(self, callback=None, limit=0):
        """Start pcap's loop over the interface, calling *callback* for each packet.

        :param callback: a function receiving ``(win_pcap, param, header,
            pkt_data)`` for each packet intercepted. ``pkt_data`` is ``bytes``
            holding the captured part of the packet.
        :param limit: how many packets to capture (``-1`` or ``0`` means
            infinity).
        :return: the ``pcap_loop`` return value: ``0`` when *limit* packets
            were processed, ``-2`` when stopped with :meth:`stop`.
        :raises CallbackIsNotCallable: if *callback* is not callable.
        :raises WinPcapException: if pcap reports a capture error.
        Any exception raised by *callback* stops the capture and is re-raised.
        """
        self._check_open()
        if not callable(callback):
            raise self.CallbackIsNotCallable("callback must be callable, got %r" % (callback,))
        self._callback = callback
        self._callback_error = None
        result = wtypes.pcap_loop(self._handle, limit, self._callback_wrapper, None)
        error, self._callback_error = self._callback_error, None
        if error is not None:
            raise error
        if result == -1:
            raise self.WinPcapException("pcap_loop failed: %s" % self._record_error())
        return result

    def compile(self, packet_filter, netmask=DEFAULT_NETMASK):
        """Compile a filter expression (BPF / tcpdump syntax, e.g. ``"tcp port 80"``).

        Call :meth:`setfilter` afterwards to apply it to the capture.

        :param packet_filter: the filter expression (``str`` or ``bytes``).
        :param netmask: the IPv4 netmask of the network the packets are
            captured on; only used by filters that check for IPv4 broadcast
            addresses.
        :return: ``True`` on success, ``False`` on failure (see
            :attr:`last_error` for the reason).
        """
        self._check_open()
        expression = _to_bytes(packet_filter, "packet_filter")
        self._free_filter()
        if (
            wtypes.pcap_compile(
                self._handle,
                self._fcode,
                expression,
                ctypes.c_int(1),
                ctypes.c_uint(netmask),
            )
            < 0
        ):
            logger.debug("pcap_compile(%r) failed: %s", expression, self._record_error())
            return False
        self._fcode_compiled = True
        return True

    def setfilter(self):
        """Apply the filter compiled by :meth:`compile` to the capture.

        Once applied, only packets matching the filter are delivered.

        :return: ``True`` on success, ``False`` on failure (see
            :attr:`last_error`).
        """
        self._check_open()
        if wtypes.pcap_setfilter(self._handle, self._fcode) < 0:
            logger.debug("pcap_setfilter failed: %s", self._record_error())
            return False
        return True

    def send(self, packet_buffer):
        """Send a buffer as a raw packet on the network interface.

        :param packet_buffer: a bytes-like object holding the full frame
            (length must not exceed ``2**31 - 1``).
        :return: ``True`` if the packet was sent, ``False`` otherwise (see
            :attr:`last_error`).
        """
        self._check_open()
        data = memoryview(packet_buffer).tobytes()
        buffer_length = len(data)
        if buffer_length > _MAX_PACKET_LENGTH:
            raise ValueError("packet_buffer is too large (%d bytes)" % buffer_length)
        buf_send = (ctypes.c_ubyte * buffer_length).from_buffer_copy(data)
        if wtypes.pcap_sendpacket(self._handle, buf_send, buffer_length) != 0:
            logger.debug("pcap_sendpacket failed: %s", self._record_error())
            return False
        return True


class WinPcapUtils:
    """Utilities and usage examples."""

    @staticmethod
    def packet_printer_callback(win_pcap, param, header, pkt_data):
        """Print a timestamp and the wire length of each packet."""
        local_tv_sec = header.contents.ts.tv_sec
        ltime = time.localtime(local_tv_sec)
        timestr = time.strftime("%H:%M:%S", ltime)
        print("%s,%.6d len:%d" % (timestr, header.contents.ts.tv_usec, header.contents.len))

    @staticmethod
    def capture_on(pattern, callback):
        """Capture packets on the first device whose description matches *pattern*.

        :param pattern: a wildcard pattern to match the description of a
            network interface to capture packets on.
        :param callback: a function to call with each intercepted packet.

        Does nothing (but logs a warning) if no device matches.
        """
        device_name, _ = WinPcapDevices.get_matching_device(pattern)
        if device_name is None:
            logger.warning("No capture device matches %r", pattern)
            return
        with WinPcap(device_name) as capture:
            capture.run(callback=callback)

    @staticmethod
    def capture_on_device_name(device_name, callback):
        """
        :param device_name: the name (GUID) of a device as provided by
            :meth:`WinPcapDevices.list_devices`.
        :param callback: a function to call with each intercepted packet.
        """
        with WinPcap(device_name) as capture:
            capture.run(callback=callback)

    @classmethod
    def capture_on_and_print(cls, pattern):
        """Capture and print packets from the first device matching *pattern*.

        Example: ``capture_on_and_print("*Intel*Ethernet*")``. Stop with Ctrl+C.
        """
        cls.capture_on(pattern, cls.packet_printer_callback)

    @staticmethod
    def compile_on_device_name(device_name, packet_filter, netmask=DEFAULT_NETMASK):
        """Check that *packet_filter* compiles on *device_name*.

        :param device_name: the name (GUID) of a device as provided by
            :meth:`WinPcapDevices.list_devices`.
        :param packet_filter: a filter expression (BPF / tcpdump syntax).
        :return: ``True`` if the filter compiles, ``False`` otherwise.
        """
        with WinPcap(device_name) as c:
            return c.compile(packet_filter, netmask=netmask)

    #: Backwards compatible alias of :meth:`compile_on_device_name`.
    test_compile_on_device_name = compile_on_device_name

    @staticmethod
    def compile_and_capture_on_device_name(
        device_name, packet_filter, callback, netmask=DEFAULT_NETMASK
    ):
        """Compile and apply *packet_filter*, then capture on *device_name*.

        :param device_name: the name (GUID) of a device as provided by
            :meth:`WinPcapDevices.list_devices`.
        :param packet_filter: a filter expression (BPF / tcpdump syntax).
        :param callback: a function to call with each intercepted packet.
        :return: ``False`` if the filter could not be compiled or applied,
            ``True`` after the capture loop ends.
        """
        with WinPcap(device_name) as c:
            if not (c.compile(packet_filter, netmask=netmask) and c.setfilter()):
                return False
            c.run(callback)
            return True

    @classmethod
    def send_packet(cls, pattern, packet_buffer, callback=None, limit=10):
        """Send a packet on a device and optionally capture the responses.

        :param pattern: a wildcard pattern to match the description of the
            network interface to use.
        :param packet_buffer: a bytes-like buffer to send.
        :param callback: if not ``None``, a function to call with each
            intercepted packet.
        :param limit: how many packets to capture (``-1`` or ``0`` means
            infinity).

        Does nothing (but logs a warning) if no device matches.
        """
        device_name, _ = WinPcapDevices.get_matching_device(pattern)
        if device_name is None:
            logger.warning("No capture device matches %r", pattern)
            return
        with WinPcap(device_name) as capture:
            if not capture.send(packet_buffer):
                logger.warning("Failed to send packet: %s", capture.last_error)
            if callback is not None:
                capture.run(callback=callback, limit=limit)
