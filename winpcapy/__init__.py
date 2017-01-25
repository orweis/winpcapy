"""
A Simple Object driven interface to WinPcap based on ctypes access.
Uses context ('with') to guard allocations.

WinPcap - main api & Capture
WinPcapDevices - interface iterator
WinPcapUtils - easy/quick usage and access methods

@Author Or Weis 2015
"""

from .winpcapy import WinPcap, WinPcapDevices, WinPcapUtils

__author__ = 'Or Weis'
__title__ = "WinPcapy"
__description__ = "A Modern Python wrapper for WinPcap"
__uri__ = "https://github.com/orweis/winpcapy"
__doc__ = __description__ + " <" + __uri__ + ">"
__email__ = "py@bitweis.com"
__version__ = "1.0.2"
__license__ = "GPLv2"
__copyright__ = "Copyright (c) 2015 Or Weis"


