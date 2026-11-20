"""A modern Python wrapper for Npcap / WinPcap (and libpcap), based on ctypes.

Uses context managers (``with``) to guard native allocations.

* :class:`WinPcap` - main API: open a device, filter, capture and send.
* :class:`WinPcapDevices` - interface iterator.
* :class:`WinPcapUtils` - easy/quick usage and access methods.

See https://github.com/orweis/winpcapy for documentation.
"""

from .winpcapy import WinPcap, WinPcapDevices, WinPcapUtils
from .winpcapy_types import PcapLibraryNotFoundError

# Convenience aliases for the exception classes nested in WinPcap.
WinPcapException = WinPcap.WinPcapException

__all__ = [
    "PcapLibraryNotFoundError",
    "WinPcap",
    "WinPcapDevices",
    "WinPcapException",
    "WinPcapUtils",
]

__author__ = "Or Weis"
__title__ = "WinPcapy"
__description__ = "A Modern Python wrapper for WinPcap/Npcap"
__uri__ = "https://github.com/orweis/winpcapy"
__email__ = "py@bitweis.com"
__version__ = "2.0.0"
__license__ = "GPLv2"
__copyright__ = "Copyright (c) 2015-2026 Or Weis"
