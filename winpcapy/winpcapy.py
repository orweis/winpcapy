"""
@author Or Weis 2015
"""
# Python 2 \ 3 compatibility
try:
    from . import winpcapy_types as wtypes
except ValueError:
    import winpcapy_types as wtypes
import ctypes
import fnmatch
import time
import sys
from collections import Callable


class WinPcapDevices(object):
    class PcapFindDevicesException(Exception):
        pass

    def __init__(self):
        self._all_devices = None

    def __enter__(self):
        assert self._all_devices is None
        all_devices = ctypes.POINTER(wtypes.pcap_if_t)()
        err_buffer = ctypes.create_string_buffer(wtypes.PCAP_ERRBUF_SIZE)
        if wtypes.pcap_findalldevs(ctypes.byref(all_devices), err_buffer) == -1:
            raise self.PcapFindDevicesException("Error in WinPcapDevices: %s\n" % err_buffer.value)
        self._all_devices = all_devices
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._all_devices is not None:
            wtypes.pcap_freealldevs(self._all_devices)

    def pcap_interface_iterator(self):
        if self._all_devices is None:
            raise self.PcapFindDevicesException("WinPcapDevices guard not called, use 'with statement'")
        pcap_interface = self._all_devices
        while bool(pcap_interface):
            yield pcap_interface.contents
            pcap_interface = pcap_interface.contents.next

    def __iter__(self):
        return self.pcap_interface_iterator()

    @classmethod
    def list_devices(cls):
        res = {}
        with cls() as devices:
            for device in devices:
                res[device.name.decode('utf-8')] = device.description.decode('utf-8')
        return res

    @classmethod
    def get_matching_device(cls, glob=None):
        for name, description in cls.list_devices().items():
            if fnmatch.fnmatch(description, glob):
                return name, description
        return None, None


class WinPcap(object):
    """
    A Class to access WinPcap interface functionality.
    Wrapping device opening / closing using the 'with' statement
    """
    # /* prototype of the packet handler */
    # void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
    HANDLER_SIGNATURE = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_ubyte),
                                         ctypes.POINTER(wtypes.pcap_pkthdr),
                                         ctypes.POINTER(ctypes.c_ubyte))

    class WinPcapException(Exception):
        pass

    class CallbackIsNotCallable(WinPcapException):
        pass

    class DeviceIsNotOpen(WinPcapException):
        """
        Exception raised when trying to use the underlying device without opening it first.
        Can eb resolved by calling the sought method within a 'with' statement.
        """
        pass

    def __init__(self, device_name, snap_length=65536, promiscuous=1, timeout=1000):
        """
        :param device_name: the name of the device to open on context enter
        :param snap_length: specifies the snapshot length to be set on the handle.
        :param promiscuous:  specifies if the interface is to be put into promiscuous mode(0 or 1).
        :param timeout: specifies the read timeout in milliseconds.
        """
        self._handle = None
        self._name = device_name.encode('utf-8')
        self._snap_length = snap_length
        self._promiscuous = promiscuous
        self._timeout = timeout
        self._err_buffer = ctypes.create_string_buffer(wtypes.PCAP_ERRBUF_SIZE)
        self._callback = None
        self._callback_wrapper = self.HANDLER_SIGNATURE(self.packet_handler)

    def __enter__(self):
        assert self._handle is None
        self._handle = wtypes.pcap_open_live(self._name, self._snap_length, self._promiscuous, self._timeout,
                                             self._err_buffer)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._handle is not None:
            wtypes.pcap_close(self._handle)

    def packet_handler(self, param, header, pkt_pointer):
        if not isinstance(self._callback, Callable):
            raise self.CallbackIsNotCallable()
        pkt_data = ctypes.string_at(pkt_pointer, header.contents.len)
        return self._callback(self, param, header, pkt_data)

    def stop(self):
        if self._handle is None:
            raise self.DeviceIsNotOpen()
        wtypes.pcap_breakloop(self._handle)

    def run(self, callback=None, limit=0):
        """
        Start pcap's loop over the interface, calling the given callback for each packet
        :param callback: a function receiving (win_pcap, param, header, pkt_data) for each packet intercepted
        :param limit: how many packets to capture (A value of -1 or 0 is equivalent to infinity)
        """
        if self._handle is None:
            raise self.DeviceIsNotOpen()
        # Set new callback
        self._callback = callback
        # Run loop with callback wrapper
        wtypes.pcap_loop(self._handle, limit, self._callback_wrapper, None)

    def send(self, packet_buffer):
        """
        send a buffer as a packet to the network interface
        :param packet_buffer: buffer to send (length shouldn't exceed MAX_INT)
        """
        if self._handle is None:
            raise self.DeviceIsNotOpen()
        buffer_length = len(packet_buffer)
        buf_send = ctypes.cast(ctypes.create_string_buffer(packet_buffer, buffer_length),
                               ctypes.POINTER(ctypes.c_ubyte))
        wtypes.pcap_sendpacket(self._handle, buf_send, buffer_length)


class WinPcapUtils(object):
    """
    Utilities and usage examples
    """

    @staticmethod
    def packet_printer_callback(win_pcap, param, header, pkt_data):
        try:
            local_tv_sec = header.contents.ts.tv_sec
            ltime = time.localtime(local_tv_sec)
            timestr = time.strftime("%H:%M:%S", ltime)
            print("%s,%.6d len:%d" % (timestr, header.contents.ts.tv_usec, header.contents.len))
        except KeyboardInterrupt:
            win_pcap.stop()
            sys.exit(0)

    @staticmethod
    def capture_on(pattern, callback):
        """
        :param pattern: a wildcard pattern to match the description of a network interface to capture packets on
        :param callback: a function to call with each intercepted packet
        """
        device_name, desc = WinPcapDevices.get_matching_device(pattern)
        if device_name is not None:
            with WinPcap(device_name) as capture:
                capture.run(callback=callback)

    @staticmethod
    def capture_on_device_name(device_name, callback):
        """
        :param device_name: the name (guid) of a device as provided by WinPcapDevices.list_devices()
        :param callback: a function to call with each intercepted packet
        """
        with WinPcap(device_name) as capture:
            capture.run(callback=callback)

    @classmethod
    def capture_on_and_print(cls, pattern):
        """
        Usage example capture_on_and_print("*Intel*Ethernet")
        will capture and print packets from an Intel Ethernet device
        """
        cls.capture_on(pattern, cls.packet_printer_callback)

    @classmethod
    def send_packet(self, pattern, packet_buffer, callback=None, limit=10):
        """
        Send a buffer as a packet to a network interface and optionally capture a response
        :param pattern: a wildcard pattern to match the description of a network interface to capture packets on
        :param packet_buffer: a buffer to send (length shouldn't exceed MAX_INT)
        :param callback: If not None, a function to call with each intercepted packet
        :param limit: how many packets to capture (A value of -1 or 0 is equivalent to infinity)
        """
        device_name, desc = WinPcapDevices.get_matching_device(pattern)
        if device_name is not None:
            with WinPcap(device_name) as capture:
                capture.send(packet_buffer)
                if callback is not None:
                    capture.run(callback=callback, limit=limit)
