winpcapy
========

| A Modern Python wrapper for WinPcap
| Access WinPcap through ctypes.

Based on Massimo Ciani’s WinPcapy (https://code.google.com/p/winpcapy/)


Install
-------
pip install winpcapy

Usage
-----

Quick packet live log printer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    >>> from winpcapy import WinPcapUtils
    # run on the first Ethernert interface and print a log for each packet
    >>> WinPcapUtils.capture_on_and_print("*Ethernet*")
    16:05:49,624258 len:199
    16:05:49,685950 len:60
    16:05:49,686022 len:54
    16:05:49,767311 len:66
    16:05:49,819156 len:66
    16:05:50,052113 len:92
    16:05:50,128862 len:60

Easy Packet live callback
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    from winpcapy import WinPcapUtils

    # Example Callback function to parse IP packets
    def packet_callback(win_pcap, param, header, pkt_data):
        # Assuming IP (for real parsing use modules like dpkt)
        ip_frame = pkt_data[14:]
        # Parse ips
        src_ip = ".".join([str(ord(b)) for b in ip_frame[0xc:0x10]])
        dst_ip = ".".join([str(ord(b)) for b in ip_frame[0x10:0x14]])
        print("%s -> %s" % (src_ip, dst_ip))

    WinPcapUtils.capture_on("*Ethernet*", packet_callback)

Device/Interface enumeration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    >>> from winpcapy import WinPcapDevices
    # Return a list of all the devices detected on the machine
    >>> WinPcapDevices.list_devices()
    {'\\Device\\NPF_{0A78B7C8-F023-1337-1337-84D448AA5126}': 'Microsoft',
     '\\Device\\NPF_{2997B9BB-AA53-1337-1337-B862F874271C}': 'Microsoft',
     '\\Device\\NPF_{C2EAA982-F851-1337-1337-B8D2A9BCE406}': 'Intel(R) Ethernet Connection I218-LM',
     '\\Device\\NPF_{EAF47DBE-5B49-1337-1337-BD059E02666B}': 'Microsoft'}
     
     # Itearte over devices (in memory), with full details access
    >>> with WinPcapDevices() as devices:
    ...     for device in devices:
    ...         print device.name, device.description, device.flags ,device.addresses.contents.netmask.contents.sa_family
    ...         
    "\Device\NPF_{0A78B7C8-F023-1337-1337-84D448AA5126} Microsoft 0 0"
    "\Device\NPF_{C2EAA982-F851-1337-1337-B8D2A9BCE406} Intel(R) Ethernet Connection I218-LM 0 0"
    "\Device\NPF_{EAF47DBE-5B49-1337-1337-BD059E02666B} Microsoft 0 0"
    "\Device\NPF_{2997B9BB-AA53-1337-1337-B862F874271C} Microsoft 0 0"
