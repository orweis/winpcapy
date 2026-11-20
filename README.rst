winpcapy
========

.. image:: https://img.shields.io/pypi/v/winpcapy.svg
   :target: https://pypi.org/project/winpcapy/
   :alt: PyPI version

.. image:: https://img.shields.io/pypi/pyversions/winpcapy.svg
   :target: https://pypi.org/project/winpcapy/
   :alt: Supported Python versions

.. image:: https://github.com/orweis/winpcapy/actions/workflows/ci.yml/badge.svg
   :target: https://github.com/orweis/winpcapy/actions/workflows/ci.yml
   :alt: CI status

| A Modern Python wrapper for WinPcap / Npcap.
| Access the pcap packet capture API through ``ctypes``: no compiler and no
  third-party dependencies needed.

Based on Massimo Ciani's WinPcapy (https://code.google.com/p/winpcapy/).


Requirements
------------

* Python 3.9 or newer.
* A pcap library:

  * **Windows**: `Npcap <https://npcap.com/#download>`_. WinPcap, the
    original backend, has been unmaintained since 2013 and does not work on
    current Windows versions; use Npcap instead. Both the default Npcap
    install and the "WinPcap API-compatible mode" are supported: winpcapy
    looks for ``wpcap.dll`` in ``%SystemRoot%\System32\Npcap`` first, then in
    ``%SystemRoot%\System32``.
  * **Linux / macOS** (best effort): ``libpcap`` (for example
    ``apt install libpcap0.8`` or ``dnf install libpcap``; macOS ships it).

* Capturing and sending packets usually requires administrator rights (or,
  on Linux, the ``CAP_NET_RAW`` capability). If Npcap was installed with
  "Restrict Npcap driver's access to Administrators only", run Python from an
  elevated prompt.

If no library can be found, ``import winpcapy`` raises
``winpcapy.PcapLibraryNotFoundError`` (a subclass of ``OSError``).


Install
-------

.. code:: bash

    pip install winpcapy


Usage
-----

Quick packet live log printer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    >>> from winpcapy import WinPcapUtils
    # Capture on the first interface whose description matches "*Ethernet*"
    # and print a line for each packet (stop with Ctrl+C).
    >>> WinPcapUtils.capture_on_and_print("*Ethernet*")
    16:05:49,624258 len:199
    16:05:49,685950 len:60
    16:05:49,686022 len:54

Easy packet live callback
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    from winpcapy import WinPcapUtils

    # Example callback function to parse IPv4 packets.
    # pkt_data is ``bytes``; for real parsing use a module like dpkt or scapy.
    def packet_callback(win_pcap, param, header, pkt_data):
        ip_frame = pkt_data[14:]  # skip the Ethernet header
        src_ip = ".".join(str(b) for b in ip_frame[0xC:0x10])
        dst_ip = ".".join(str(b) for b in ip_frame[0x10:0x14])
        print("%s -> %s" % (src_ip, dst_ip))

    WinPcapUtils.capture_on("*Ethernet*", packet_callback)

The callback receives:

* ``win_pcap``: the ``WinPcap`` instance (call ``win_pcap.stop()`` to end the
  capture);
* ``param``: the user pointer passed to ``pcap_loop`` (unused, ``None``);
* ``header``: a pointer to a ``pcap_pkthdr``: ``header.contents.ts`` (timestamp),
  ``header.contents.caplen`` (captured bytes) and ``header.contents.len``
  (original length on the wire);
* ``pkt_data``: the captured bytes (``caplen`` bytes, at most ``snap_length``).

An exception raised by the callback (including ``KeyboardInterrupt``) stops
the capture and is re-raised by ``run()``.

Capture with a filter
~~~~~~~~~~~~~~~~~~~~~

Filters use the `pcap filter syntax
<https://npcap.com/guide/wpcap/pcap-filter.html>`_ (the same as tcpdump and
Wireshark capture filters).

.. code:: python

    from winpcapy import WinPcap, WinPcapDevices

    device_name, description = WinPcapDevices.get_matching_device("*Ethernet*")

    def on_packet(win_pcap, param, header, pkt_data):
        print(header.contents.len, pkt_data[:16].hex())

    with WinPcap(device_name, snap_length=65536, promiscuous=0, timeout=1000) as capture:
        if not (capture.compile("tcp port 443") and capture.setfilter()):
            raise RuntimeError(capture.last_error)
        capture.run(callback=on_packet, limit=10)  # 0 or -1: capture forever

    # or, in one call:
    # WinPcapUtils.compile_and_capture_on_device_name(device_name, "tcp port 443", on_packet)

Device/Interface enumeration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    >>> from winpcapy import WinPcapDevices
    # Return a dict of all the devices detected on the machine
    >>> WinPcapDevices.list_devices()
    {'\\Device\\NPF_{0A78B7C8-F023-1337-1337-84D448AA5126}': 'Microsoft',
     '\\Device\\NPF_{C2EAA982-F851-1337-1337-B8D2A9BCE406}': 'Intel(R) Ethernet Connection I218-LM',
     '\\Device\\NPF_Loopback': 'Adapter for loopback traffic capture'}

    # Iterate over devices (in memory), with full details access.
    # Note: the structures are only valid inside the "with" block, and the
    # string fields are bytes.
    >>> with WinPcapDevices() as devices:
    ...     for device in devices:
    ...         print(device.name, device.description, device.flags)
    b'\\Device\\NPF_{0A78B7C8-F023-1337-1337-84D448AA5126}' b'Microsoft' 0
    b'\\Device\\NPF_{C2EAA982-F851-1337-1337-B8D2A9BCE406}' b'Intel(R) Ethernet Connection I218-LM' 0

Easy packet sending
~~~~~~~~~~~~~~~~~~~

.. code:: python

    from winpcapy import WinPcapUtils

    # Build a packet buffer (an Ethernet frame holding an ARP request).
    # This example is for tutorial purposes; for real packet crafting use a
    # module like dpkt or scapy.
    arp_request_hex_template = (
        "%(dst_mac)s%(src_mac)s08060001080006040001"
        "%(sender_mac)s%(sender_ip)s%(target_mac)s%(target_ip)s" + "00" * 18
    )
    packet = arp_request_hex_template % {
        "dst_mac": "aa" * 6,
        "src_mac": "bb" * 6,
        "sender_mac": "bb" * 6,
        "target_mac": "cc" * 6,
        "sender_ip": "c0a80001",  # 192.168.0.1
        "target_ip": "c0a80002",  # 192.168.0.2
    }
    # Send the packet on the first interface matching "*Ethernet*"
    WinPcapUtils.send_packet("*Ethernet*", bytes.fromhex(packet))

    # With a device you opened yourself, send() reports success:
    # with WinPcap(device_name) as capture:
    #     if not capture.send(bytes.fromhex(packet)):
    #         print("send failed:", capture.last_error)


API overview
------------

============================================================ ===========================================================
``WinPcapDevices.list_devices()``                            ``{name: description}`` of all devices
``WinPcapDevices.get_matching_device(glob)``                 ``(name, description)`` of the first device whose
                                                             description matches a wildcard, or ``(None, None)``
``with WinPcapDevices() as devices: for d in devices``       iterate over raw ``pcap_if`` structures
``WinPcap(device_name, snap_length, promiscuous, timeout)``  a capture device, opened by ``with``
``WinPcap.run(callback, limit=0)``                           capture loop; returns the ``pcap_loop`` code
``WinPcap.stop()``                                           break out of ``run()``
``WinPcap.compile(filter, netmask)`` / ``setfilter()``       compile / apply a capture filter; return ``True``/``False``
``WinPcap.send(buffer)``                                     send a raw frame; returns ``True``/``False``
``WinPcap.last_error``                                       last error message reported by pcap
``WinPcapUtils.*``                                           one-call helpers (``capture_on``, ``send_packet``, ...)
``winpcapy.winpcapy_types``                                  raw ctypes declarations of the pcap C API
============================================================ ===========================================================

Errors derive from ``WinPcap.WinPcapException`` (also exported as
``winpcapy.WinPcapException``): ``DeviceOpenError``, ``DeviceIsNotOpen``,
``DeviceAlreadyOpen`` and ``CallbackIsNotCallable``.


Troubleshooting
---------------

``PcapLibraryNotFoundError: Could not load wpcap.dll``
    Npcap is not installed. Install it from https://npcap.com/#download.

``DeviceOpenError: Unable to open device ...``
    The message contains the reason given by pcap: usually a wrong device name
    (use ``WinPcapDevices.list_devices()``), or missing privileges (run as
    administrator).

No packets are captured
    Check the device (``list_devices()`` names on Windows look like
    ``\Device\NPF_{GUID}``), the filter, and that ``promiscuous`` is enabled
    if you expect traffic not addressed to this host.


Security notes
--------------

* Captures are opened in promiscuous mode by default (``promiscuous=1``),
  which shows traffic of other hosts on the segment. Pass ``promiscuous=0``
  when you do not need it.
* Prefer installing Npcap with "Restrict Npcap driver's access to
  Administrators only" so unprivileged programs cannot sniff traffic.
* winpcapy loads ``wpcap.dll`` from the Windows system directory by absolute
  path, so a DLL planted in the working directory is never picked up.
* See `SECURITY.md <SECURITY.md>`_ to report a vulnerability.


Upgrading from 1.x
------------------

Version 2.0.0 drops Python 2 and fixes several crashes. The public API
(``WinPcap``, ``WinPcapDevices``, ``WinPcapUtils`` and
``winpcapy.winpcapy_types``) is unchanged, but some error paths behave
differently:

* Python 3.9+ is required (``pip`` keeps installing 1.0.3 on older Pythons).
* Opening a device that cannot be opened raises ``WinPcap.DeviceOpenError``
  (1.x silently kept a NULL handle and crashed later).
* Exceptions raised in a capture callback, including ``KeyboardInterrupt``,
  now stop the capture and propagate out of ``run()``. In 1.x they were
  printed and the capture continued.
* ``run()`` raises ``CallbackIsNotCallable`` immediately for a non-callable
  callback, returns the ``pcap_loop`` result and raises ``WinPcapException``
  on a capture error.
* ``send()`` returns ``True``/``False`` (1.x returned ``None`` and ignored errors).
* ``compile()`` accepts ``str`` filters (1.x raised ``TypeError`` on Python 3).
* The packet data passed to callbacks is now ``caplen`` bytes long (the
  captured data). 1.x read ``len`` bytes, past the end of the buffer, when
  packets were truncated by ``snap_length``.
* ``compile_and_capture_on_device_name()`` returns ``True`` after a capture.
* ``WinPcapUtils.packet_printer_callback`` no longer calls ``sys.exit()``.

See `CHANGELOG.md <CHANGELOG.md>`_ for the full list.


Development
-----------

.. code:: bash

    python -m venv .venv && . .venv/bin/activate   # .venv\Scripts\activate on Windows
    pip install -e ".[dev]"
    ruff check . && ruff format --check .
    pytest --cov

The unit tests mock the native library, so they run on any OS without Npcap.
The integration tests (``tests/test_integration.py``) run against the real
library when it is installed (on Linux: ``apt install libpcap-dev``) and are
skipped otherwise; set ``WINPCAPY_TEST_FAKE_LIBRARY=1`` to force the mocked
library. See `CONTRIBUTING.md <CONTRIBUTING.md>`_.


License
-------

GPLv2, see `LICENSE <LICENSE>`_. ``winpcapy/winpcapy_types.py`` is derived
from Massimo Ciani's WinPcapy (2009).
