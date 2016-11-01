"""
@author Or Weis 2015
"""

from . import winpcapy_types as wtypes
import ctypes
import inspect
import fnmatch
import time
import sys


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

    # /* prototype of the packet handler */
    # void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
    HANDLER_SIGNATURE = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_ubyte),
                                         ctypes.POINTER(wtypes.pcap_pkthdr),
                                         ctypes.POINTER(ctypes.c_ubyte))

    def __init__(self, device_name, snap_length=65536, promiscuous=1, timeout=1000):
        """
        @param device_name the name of the device to open on context enter
        @param snap_length specifies the snapshot length to be set on the handle.
        @param promiscuous  specifies if the interface is to be put into promiscuous mode(0 or 1).
        @param timeout specifies the read timeout in milliseconds.
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
        self._handle = wtypes.pcap_open_live(self._name, self._snap_length, self._promiscuous, self._timeout, self._err_buffer)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._handle is not None:
            wtypes.pcap_close(self._handle)

    def packet_handler(self, param, header, pkt_pointer):
        assert inspect.isfunction(self._callback) or inspect.ismethod(self._callback)
        pkt_data = ctypes.string_at(pkt_pointer, header.contents.len)
        return self._callback(self, param, header, pkt_data)

    def stop(self):
        wtypes.pcap_breakloop(self._handle)

    def run(self, callback=None,  limit=0):
        """
        Start pcap's loop over the interface, calling the given callback for each packet
        @param callback a function receiving
        """
        assert self._handle is not None
        # Set new callback
        self._callback = callback
        # Run loop with callback wrapper
        wtypes.pcap_loop(self._handle, limit, self._callback_wrapper, None)


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
            print(("%s,%.6d len:%d" % (timestr, header.contents.ts.tv_usec, header.contents.len)))
        except KeyboardInterrupt:
            win_pcap.stop()
            sys.exit(0)

    @staticmethod
    def capture_on(pattern, callback):
        device_name, desc = WinPcapDevices.get_matching_device(pattern)
        if device_name is not None:
            with WinPcap(device_name) as capture:
                capture.run(callback=callback)

    @classmethod
    def capture_on_and_print(cls, pattern):
        """
        Usage example capture_on_and_print("*Intel*Ethernet") will capture and print packets from an Intel Ethernet device
        """
        cls.capture_on(pattern, cls.packet_printer_callback)

    @staticmethod
    def capture_by_name(device_name, callback):
        if device_name is not None:
            with WinPcap(device_name) as capture:
                capture.run(callback=callback)