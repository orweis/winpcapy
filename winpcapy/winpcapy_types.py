# -------------------------------------------------------------------------------
# Name:        winpcapy_types.py
#
# Author:      Massimo Ciani
#
# Created:     01/09/2009
# Copyright:   (c) Massimo Ciani 2009
#
# Low-level ctypes declarations for the pcap API (Npcap / WinPcap ``wpcap.dll``
# on Windows, ``libpcap`` elsewhere). Based on Massimo Ciani's WinPcapy.
# -------------------------------------------------------------------------------
"""Low-level ctypes bindings for the pcap C API.

This module mirrors the C declarations of ``pcap.h`` (structures, constants and
function prototypes). Most users should use the high level classes exported by
:mod:`winpcapy` instead.

The native library is loaded when this module is imported:

* On Windows the loader prefers Npcap (``%SystemRoot%\\System32\\Npcap\\wpcap.dll``),
  then a ``wpcap.dll`` in ``System32`` (WinPcap, or Npcap installed in
  "WinPcap API-compatible mode"), and finally the plain name ``wpcap.dll``
  resolved with the default (safe) Windows DLL search order.
* On other platforms ``libpcap`` is located with :func:`ctypes.util.find_library`.

If no library can be found, :class:`PcapLibraryNotFoundError` (an
:class:`OSError`) is raised.
"""

# NOTE: the wildcard import is intentional and kept for backwards
# compatibility: historically every ctypes name (c_int, POINTER, ...) was
# reachable through this module's namespace and downstream code may rely on it.
import ctypes
import ctypes.util
import os
import sys
from ctypes import *

WIN32 = False
HAVE_REMOTE = False

if sys.platform.startswith("win") or sys.platform == "cygwin":
    WIN32 = True
    HAVE_REMOTE = True

NPCAP_DOWNLOAD_URL = "https://npcap.com/#download"


class PcapLibraryNotFoundError(OSError):
    """Raised when no usable pcap library (Npcap/WinPcap/libpcap) can be loaded."""


def _windows_system_directory():
    """Return the absolute path of the Windows system directory (``System32``).

    ``GetSystemDirectoryW`` is preferred over environment variables because
    the environment can be influenced by the caller.
    """
    try:
        buf = ctypes.create_unicode_buffer(260)
        length = ctypes.windll.kernel32.GetSystemDirectoryW(buf, len(buf))
        if 0 < length < len(buf):
            return buf.value
    except (AttributeError, OSError):
        pass
    system_root = os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"
    return os.path.join(system_root, "System32")


def _library_candidates(platform=None):
    """Return the ordered list of library names/paths to try for *platform*."""
    platform = sys.platform if platform is None else platform
    if platform.startswith("win"):
        system32 = _windows_system_directory()
        return [
            # Npcap (native mode). Loading by absolute path also lets Windows
            # resolve its Packet.dll dependency from the same directory.
            os.path.join(system32, "Npcap", "wpcap.dll"),
            # WinPcap, or Npcap installed in "WinPcap API-compatible mode".
            os.path.join(system32, "wpcap.dll"),
            # Last resort: default DLL search order. On Python 3.8+ this does
            # not include the current working directory or PATH.
            "wpcap.dll",
        ]
    if platform == "cygwin":
        return ["wpcap.dll"]
    found = ctypes.util.find_library("pcap")
    return [found] if found else []


def _load_library(platform=None):
    """Load and return the pcap shared library as a :class:`ctypes.CDLL`."""
    platform = sys.platform if platform is None else platform
    errors = []
    for candidate in _library_candidates(platform):
        if os.path.isabs(candidate) and not os.path.exists(candidate):
            continue
        try:
            return ctypes.CDLL(candidate)
        except OSError as exc:
            errors.append("%s: %s" % (candidate, exc))
    if platform.startswith("win") or platform == "cygwin":
        hint = (
            "Could not load wpcap.dll. Install Npcap (%s); WinPcap is no longer "
            "maintained." % NPCAP_DOWNLOAD_URL
        )
    else:
        hint = (
            "Could not find the libpcap shared library. Install libpcap "
            "(e.g. 'apt install libpcap0.8' or 'dnf install libpcap')."
        )
    if errors:
        hint += " Attempts: " + "; ".join(errors)
    raise PcapLibraryNotFoundError(hint)


class _MissingFunction:
    """Placeholder for a pcap function that the loaded library does not export.

    Older and newer pcap implementations differ in which (mostly Windows
    specific) extensions they provide. Instead of failing at import time, the
    missing function is replaced by this object, which raises
    :class:`NotImplementedError` when called and is falsy, so callers can test
    for availability with ``if winpcapy_types.pcap_setbuff: ...``.
    """

    def __init__(self, name):
        self.__name__ = name
        self.restype = None
        self.argtypes = None

    def __bool__(self):
        return False

    def __call__(self, *args, **kwargs):
        raise NotImplementedError("%s is not exported by the loaded pcap library" % self.__name__)

    def __repr__(self):
        return "<missing pcap function %s>" % self.__name__


def _bind(name, restype, argtypes):
    """Look up *name* in the loaded library and declare its prototype."""
    try:
        func = getattr(_lib, name)
    except AttributeError:
        return _MissingFunction(name)
    func.restype = restype
    if argtypes is not None:
        func.argtypes = argtypes
    return func


if WIN32:
    SOCKET = c_uint
else:
    SOCKET = c_int

_lib = _load_library()

##
## misc
##
u_short = c_ushort
bpf_int32 = c_int
u_int = c_uint
bpf_u_int32 = u_int
pcap = c_void_p
pcap_dumper = c_void_p
u_char = c_ubyte
FILE = c_void_p
STRING = c_char_p


class bpf_insn(Structure):
    _fields_ = [
        ("code", c_ushort),
        ("jt", c_ubyte),
        ("jf", c_ubyte),
        ("k", bpf_u_int32),
    ]


class bpf_program(Structure):
    _fields_ = [
        ("bf_len", u_int),
        ("bf_insns", POINTER(bpf_insn)),
    ]


class bpf_version(Structure):
    _fields_ = [
        ("bv_major", c_ushort),
        ("bv_minor", c_ushort),
    ]


class timeval(Structure):
    # ``long`` matches Windows (32-bit) and Linux/LP64 (64-bit). On macOS
    # ``suseconds_t`` is a 32-bit int.
    _fields_ = [
        ("tv_sec", c_long),
        ("tv_usec", c_int32 if sys.platform == "darwin" else c_long),
    ]


## sockaddr is used by pcap_addr.
## For example if sa_family == socket.AF_INET then we need to cast it to
## sockaddr_in.
class sockaddr(Structure):
    _fields_ = [
        ("sa_family", c_ushort),
        ("sa_data", c_char * 14),
    ]


##
## Data Structures
##


class pcap_file_header(Structure):
    """Header of a libpcap dump file."""

    _fields_ = [
        ("magic", bpf_u_int32),
        ("version_major", u_short),
        ("version_minor", u_short),
        ("thiszone", bpf_int32),
        ("sigfigs", bpf_u_int32),
        ("snaplen", bpf_u_int32),
        ("linktype", bpf_u_int32),
    ]


class pcap_pkthdr(Structure):
    """Per-packet header.

    ``caplen`` is the number of bytes actually captured (available in the
    packet buffer); ``len`` is the original length of the packet on the wire.
    """

    _fields_ = [
        ("ts", timeval),
        ("caplen", bpf_u_int32),
        ("len", bpf_u_int32),
    ]


class pcap_stat(Structure):
    """Statistical values on an interface."""

    _fields_ = [
        ("ps_recv", c_uint),
        ("ps_drop", c_uint),
        ("ps_ifdrop", c_uint),
    ] + (
        [
            ("ps_capt", c_uint),
            ("ps_sent", c_uint),
            ("ps_netdrop", c_uint),
        ]
        if HAVE_REMOTE
        else []
    )


class pcap_addr(Structure):
    """Representation of an interface address, used by pcap_findalldevs()."""


pcap_addr._fields_ = [
    ("next", POINTER(pcap_addr)),
    ("addr", POINTER(sockaddr)),
    ("netmask", POINTER(sockaddr)),
    ("broadaddr", POINTER(sockaddr)),
    ("dstaddr", POINTER(sockaddr)),
]


class pcap_if(Structure):
    """Item in a list of interfaces, used by pcap_findalldevs()."""


pcap_if._fields_ = [
    ("next", POINTER(pcap_if)),
    ("name", STRING),
    ("description", STRING),
    ("addresses", POINTER(pcap_addr)),
    ("flags", bpf_u_int32),
]

##
## Defines
##

# Major libpcap dump file version.
PCAP_VERSION_MAJOR = 2
# Minor libpcap dump file version.
PCAP_VERSION_MINOR = 4
# Size to use when allocating the buffer that contains the libpcap errors.
PCAP_ERRBUF_SIZE = 256
# Interface is loopback.
PCAP_IF_LOOPBACK = 1
# Capture mode, to be used when calling pcap_setmode().
MODE_CAPT = 0
# Statistical mode, to be used when calling pcap_setmode().
MODE_STAT = 1

##
## Typedefs
##

# Descriptor of an open capture instance (opaque).
pcap_t = pcap
# libpcap savefile descriptor.
pcap_dumper_t = pcap_dumper
# Item in a list of interfaces, see pcap_if.
pcap_if_t = pcap_if
# Representation of an interface address, see pcap_addr.
pcap_addr_t = pcap_addr

_p_pcap_t = POINTER(pcap_t)
_p_dumper_t = POINTER(pcap_dumper_t)
_p_u_char = POINTER(u_char)

##
## Unix-compatible Functions
## These functions are part of the libpcap library, and therefore work both on
## Windows and on Linux.
##

# typedef void (*pcap_handler)(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
pcap_handler = CFUNCTYPE(None, _p_u_char, POINTER(pcap_pkthdr), _p_u_char)

# pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *ebuf)
pcap_open_live = _bind("pcap_open_live", _p_pcap_t, [STRING, c_int, c_int, c_int, STRING])
# pcap_t *pcap_open_dead(int linktype, int snaplen)
pcap_open_dead = _bind("pcap_open_dead", _p_pcap_t, [c_int, c_int])
# pcap_t *pcap_open_offline(const char *fname, char *errbuf)
pcap_open_offline = _bind("pcap_open_offline", _p_pcap_t, [STRING, STRING])
# pcap_dumper_t *pcap_dump_open(pcap_t *p, const char *fname)
pcap_dump_open = _bind("pcap_dump_open", _p_dumper_t, [_p_pcap_t, STRING])
# int pcap_setnonblock(pcap_t *p, int nonblock, char *errbuf)
pcap_setnonblock = _bind("pcap_setnonblock", c_int, [_p_pcap_t, c_int, STRING])
# int pcap_getnonblock(pcap_t *p, char *errbuf)
pcap_getnonblock = _bind("pcap_getnonblock", c_int, [_p_pcap_t, STRING])
# int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf)
pcap_findalldevs = _bind(
    "pcap_findalldevs",
    c_int,
    [POINTER(POINTER(pcap_if_t)), STRING],
)
# void pcap_freealldevs(pcap_if_t *alldevsp)
pcap_freealldevs = _bind("pcap_freealldevs", None, [POINTER(pcap_if_t)])
# char *pcap_lookupdev(char *errbuf)  (deprecated upstream)
pcap_lookupdev = _bind("pcap_lookupdev", STRING, [STRING])
# int pcap_lookupnet(const char *device, bpf_u_int32 *netp, bpf_u_int32 *maskp, char *errbuf)
pcap_lookupnet = _bind(
    "pcap_lookupnet",
    c_int,
    [STRING, POINTER(bpf_u_int32), POINTER(bpf_u_int32), STRING],
)
# int pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
pcap_dispatch = _bind("pcap_dispatch", c_int, [_p_pcap_t, c_int, pcap_handler, _p_u_char])
# int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
pcap_loop = _bind("pcap_loop", c_int, [_p_pcap_t, c_int, pcap_handler, _p_u_char])
# u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h)
pcap_next = _bind("pcap_next", _p_u_char, [_p_pcap_t, POINTER(pcap_pkthdr)])
# int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header, const u_char **pkt_data)
pcap_next_ex = _bind(
    "pcap_next_ex",
    c_int,
    [_p_pcap_t, POINTER(POINTER(pcap_pkthdr)), POINTER(_p_u_char)],
)
# void pcap_breakloop(pcap_t *p)
pcap_breakloop = _bind("pcap_breakloop", None, [_p_pcap_t])
# int pcap_sendpacket(pcap_t *p, u_char *buf, int size)
pcap_sendpacket = _bind("pcap_sendpacket", c_int, [_p_pcap_t, _p_u_char, c_int])
# void pcap_dump(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
pcap_dump = _bind("pcap_dump", None, [_p_dumper_t, POINTER(pcap_pkthdr), _p_u_char])
# long pcap_dump_ftell(pcap_dumper_t *p)
pcap_dump_ftell = _bind("pcap_dump_ftell", c_long, [_p_dumper_t])
# int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize, bpf_u_int32 netmask)
pcap_compile = _bind(
    "pcap_compile",
    c_int,
    [_p_pcap_t, POINTER(bpf_program), STRING, c_int, bpf_u_int32],
)
# int pcap_compile_nopcap(int snaplen, int linktype, struct bpf_program *program, char *buf, int optimize, bpf_u_int32 mask)
pcap_compile_nopcap = _bind(
    "pcap_compile_nopcap",
    c_int,
    [c_int, c_int, POINTER(bpf_program), STRING, c_int, bpf_u_int32],
)
# int pcap_setfilter(pcap_t *p, struct bpf_program *fp)
pcap_setfilter = _bind("pcap_setfilter", c_int, [_p_pcap_t, POINTER(bpf_program)])
# void pcap_freecode(struct bpf_program *fp)
pcap_freecode = _bind("pcap_freecode", None, [POINTER(bpf_program)])
# int pcap_datalink(pcap_t *p)
pcap_datalink = _bind("pcap_datalink", c_int, [_p_pcap_t])
# int pcap_list_datalinks(pcap_t *p, int **dlt_buf)
# (argtypes intentionally left undeclared, as in previous releases)
pcap_list_datalinks = _bind("pcap_list_datalinks", c_int, None)
# int pcap_set_datalink(pcap_t *p, int dlt)
pcap_set_datalink = _bind("pcap_set_datalink", c_int, [_p_pcap_t, c_int])
# int pcap_datalink_name_to_val(const char *name)
pcap_datalink_name_to_val = _bind("pcap_datalink_name_to_val", c_int, [STRING])
# const char *pcap_datalink_val_to_name(int dlt)
pcap_datalink_val_to_name = _bind("pcap_datalink_val_to_name", STRING, [c_int])
# const char *pcap_datalink_val_to_description(int dlt)
pcap_datalink_val_to_description = _bind(
    "pcap_datalink_val_to_description",
    STRING,
    [c_int],
)
# int pcap_snapshot(pcap_t *p)
pcap_snapshot = _bind("pcap_snapshot", c_int, [_p_pcap_t])
# int pcap_is_swapped(pcap_t *p)
pcap_is_swapped = _bind("pcap_is_swapped", c_int, [_p_pcap_t])
# int pcap_major_version(pcap_t *p)
pcap_major_version = _bind("pcap_major_version", c_int, [_p_pcap_t])
# int pcap_minor_version(pcap_t *p)
pcap_minor_version = _bind("pcap_minor_version", c_int, [_p_pcap_t])
# FILE *pcap_file(pcap_t *p)
pcap_file = _bind("pcap_file", FILE, [_p_pcap_t])
# int pcap_stats(pcap_t *p, struct pcap_stat *ps)
pcap_stats = _bind("pcap_stats", c_int, [_p_pcap_t, POINTER(pcap_stat)])
# void pcap_perror(pcap_t *p, const char *prefix)
pcap_perror = _bind("pcap_perror", None, [_p_pcap_t, STRING])
# char *pcap_geterr(pcap_t *p)
pcap_geterr = _bind("pcap_geterr", STRING, [_p_pcap_t])
# const char *pcap_strerror(int error)
pcap_strerror = _bind("pcap_strerror", STRING, [c_int])
# const char *pcap_lib_version(void)
pcap_lib_version = _bind("pcap_lib_version", STRING, [])
# void pcap_close(pcap_t *p)
pcap_close = _bind("pcap_close", None, [_p_pcap_t])
# FILE *pcap_dump_file(pcap_dumper_t *p)
pcap_dump_file = _bind("pcap_dump_file", FILE, [_p_dumper_t])
# int pcap_dump_flush(pcap_dumper_t *p)
pcap_dump_flush = _bind("pcap_dump_flush", c_int, [_p_dumper_t])
# void pcap_dump_close(pcap_dumper_t *p)
pcap_dump_close = _bind("pcap_dump_close", None, [_p_dumper_t])

###########################################
## Windows-specific Extensions
## The functions in this section extend libpcap to offer advanced
## functionality (remote capture, kernel buffer size, packet injection
## queues...). They are only declared on Windows.
###########################################
if WIN32:
    HANDLE = c_void_p

    ## Identifiers related to the new source syntax
    PCAP_SRC_FILE = 2
    PCAP_SRC_IFLOCAL = 3
    PCAP_SRC_IFREMOTE = 4

    ## Strings related to the new source syntax
    PCAP_SRC_FILE_STRING = "file://"
    PCAP_SRC_IF_STRING = "rpcap://"

    ## Flags defined in the pcap_open() function
    # The adapter has to go in promiscuous mode.
    PCAP_OPENFLAG_PROMISCUOUS = 1
    # Data transfer (remote capture) uses UDP.
    PCAP_OPENFLAG_DATATX_UDP = 2
    # The remote probe will not capture its own generated traffic.
    PCAP_OPENFLAG_NOCAPTURE_RPCAP = 4
    # The local adapter will not capture its own generated traffic.
    PCAP_OPENFLAG_NOCAPTURE_LOCAL = 8
    # Configures the adapter for maximum responsiveness.
    PCAP_OPENFLAG_MAX_RESPONSIVENESS = 16

    ## Sampling methods defined in the pcap_setsampling() function
    PCAP_SAMP_NOSAMP = 0
    PCAP_SAMP_1_EVERY_N = 1
    PCAP_SAMP_FIRST_AFTER_N_MS = 2

    ## Authentication methods supported by the RPCAP protocol
    RPCAP_RMTAUTH_NULL = 0
    RPCAP_RMTAUTH_PWD = 1

    ## Remote struct and defines
    # Maximum buffer size in which address, port, interface names are kept.
    PCAP_BUF_SIZE = 1024
    # Maximum length of a host name (needed for the RPCAP active mode).
    RPCAP_HOSTLIST_SIZE = 1024

    class pcap_send_queue(Structure):
        _fields_ = [
            ("maxlen", c_uint),
            ("len", c_uint),
            ("buffer", c_char_p),
        ]

    class pcap_rmtauth(Structure):
        """Information needed to authenticate the user on a remote machine."""

        _fields_ = [
            ("type", c_int),
            ("username", c_char_p),
            ("password", c_char_p),
        ]

    class pcap_samp(Structure):
        """Information related to sampling."""

        _fields_ = [
            ("method", c_int),
            ("value", c_int),
        ]

    _p_send_queue = POINTER(pcap_send_queue)
    _p_rmtauth = POINTER(pcap_rmtauth)

    # int pcap_offline_filter(const struct bpf_program *fp, const struct pcap_pkthdr *h, const u_char *pkt)
    pcap_offline_filter = _bind(
        "pcap_offline_filter",
        c_bool,
        [POINTER(bpf_program), POINTER(pcap_pkthdr), _p_u_char],
    )
    # int pcap_live_dump(pcap_t *p, char *filename, int maxsize, int maxpacks)
    pcap_live_dump = _bind(
        "pcap_live_dump",
        c_int,
        [_p_pcap_t, POINTER(c_char), c_int, c_int],
    )
    # int pcap_live_dump_ended(pcap_t *p, int sync)
    pcap_live_dump_ended = _bind("pcap_live_dump_ended", c_int, [_p_pcap_t, c_int])
    # struct pcap_stat *pcap_stats_ex(pcap_t *p, int *pcap_stat_size)
    pcap_stats_ex = _bind(
        "pcap_stats_ex",
        POINTER(pcap_stat),
        [_p_pcap_t, POINTER(c_int)],
    )
    # int pcap_setbuff(pcap_t *p, int dim)
    pcap_setbuff = _bind("pcap_setbuff", c_int, [_p_pcap_t, c_int])
    # int pcap_setmode(pcap_t *p, int mode)
    pcap_setmode = _bind("pcap_setmode", c_int, [_p_pcap_t, c_int])
    # int pcap_setmintocopy(pcap_t *p, int size)
    pcap_setmintocopy = _bind("pcap_setmintocopy", c_int, [_p_pcap_t, c_int])
    # HANDLE pcap_getevent(pcap_t *p)
    pcap_getevent = _bind("pcap_getevent", HANDLE, [_p_pcap_t])
    # pcap_send_queue *pcap_sendqueue_alloc(u_int memsize)
    pcap_sendqueue_alloc = _bind("pcap_sendqueue_alloc", _p_send_queue, [c_uint])
    # void pcap_sendqueue_destroy(pcap_send_queue *queue)
    pcap_sendqueue_destroy = _bind("pcap_sendqueue_destroy", None, [_p_send_queue])
    # int pcap_sendqueue_queue(pcap_send_queue *queue, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
    pcap_sendqueue_queue = _bind(
        "pcap_sendqueue_queue",
        c_int,
        [_p_send_queue, POINTER(pcap_pkthdr), _p_u_char],
    )
    # u_int pcap_sendqueue_transmit(pcap_t *p, pcap_send_queue *queue, int sync)
    pcap_sendqueue_transmit = _bind(
        "pcap_sendqueue_transmit",
        u_int,
        [_p_pcap_t, _p_send_queue, c_int],
    )
    # int pcap_findalldevs_ex(const char *source, struct pcap_rmtauth *auth, pcap_if_t **alldevs, char *errbuf)
    pcap_findalldevs_ex = _bind(
        "pcap_findalldevs_ex",
        c_int,
        [STRING, _p_rmtauth, POINTER(POINTER(pcap_if_t)), STRING],
    )
    # int pcap_createsrcstr(char *source, int type, const char *host, const char *port, const char *name, char *errbuf)
    pcap_createsrcstr = _bind(
        "pcap_createsrcstr",
        c_int,
        [STRING, c_int, STRING, STRING, STRING, STRING],
    )
    # int pcap_parsesrcstr(const char *source, int *type, char *host, char *port, char *name, char *errbuf)
    pcap_parsesrcstr = _bind(
        "pcap_parsesrcstr",
        c_int,
        [STRING, POINTER(c_int), STRING, STRING, STRING, STRING],
    )
    # pcap_t *pcap_open(const char *source, int snaplen, int flags, int read_timeout, struct pcap_rmtauth *auth, char *errbuf)
    pcap_open = _bind(
        "pcap_open",
        _p_pcap_t,
        [STRING, c_int, c_int, c_int, _p_rmtauth, STRING],
    )
    # struct pcap_samp *pcap_setsampling(pcap_t *p)
    pcap_setsampling = _bind("pcap_setsampling", POINTER(pcap_samp), [_p_pcap_t])
    # SOCKET pcap_remoteact_accept(const char *address, const char *port, const char *hostlist, char *connectinghost, struct pcap_rmtauth *auth, char *errbuf)
    pcap_remoteact_accept = _bind(
        "pcap_remoteact_accept",
        SOCKET,
        [STRING, STRING, STRING, STRING, _p_rmtauth, STRING],
    )
    # int pcap_remoteact_close(const char *host, char *errbuf)
    pcap_remoteact_close = _bind("pcap_remoteact_close", c_int, [STRING, STRING])
    # void pcap_remoteact_cleanup(void)
    pcap_remoteact_cleanup = _bind("pcap_remoteact_cleanup", None, [])
    # int pcap_remoteact_list(char *hostlist, char sep, int size, char *errbuf)
    pcap_remoteact_list = _bind(
        "pcap_remoteact_list",
        c_int,
        [STRING, c_char, c_int, STRING],
    )
