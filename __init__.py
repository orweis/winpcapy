"""
A Simple Object driven interface to WinPcap based on ctypes access.
Uses context ('with') to guard allocations.

WinPcap - main api & Capture
WinPcapDevices - interface iterator
WinPcapUtils - easy/quick usage and access methods

@Author Or Weis 2015
"""

__author__ = 'OrW'

from winpcapy import WinPcap, WinPcapDevices, WinPcapUtils

