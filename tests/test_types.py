"""Tests for the low-level ctypes declarations and the library loader."""

import ctypes
import ctypes.util
import importlib.util
import os
import sys

import pytest
from conftest import FakeLibrary

import winpcapy
from winpcapy import winpcapy_types as wtypes

# Public names of winpcapy_types in release 1.0.3, which must keep existing.
LEGACY_NAMES = """
FILE HAVE_REMOTE MODE_CAPT MODE_STAT PCAP_ERRBUF_SIZE PCAP_IF_LOOPBACK
PCAP_VERSION_MAJOR PCAP_VERSION_MINOR SOCKET STRING WIN32 _lib bpf_insn
bpf_int32 bpf_program bpf_u_int32 bpf_version pcap pcap_addr pcap_addr_t
pcap_breakloop pcap_close pcap_compile pcap_compile_nopcap pcap_datalink
pcap_datalink_name_to_val pcap_datalink_val_to_description
pcap_datalink_val_to_name pcap_dispatch pcap_dump pcap_dump_close
pcap_dump_file pcap_dump_flush pcap_dump_ftell pcap_dump_open pcap_dumper
pcap_dumper_t pcap_file pcap_file_header pcap_findalldevs pcap_freealldevs
pcap_freecode pcap_geterr pcap_getnonblock pcap_handler pcap_if pcap_if_t
pcap_is_swapped pcap_lib_version pcap_list_datalinks pcap_lookupdev
pcap_lookupnet pcap_loop pcap_major_version pcap_minor_version pcap_next
pcap_next_ex pcap_open_dead pcap_open_live pcap_open_offline pcap_perror
pcap_pkthdr pcap_sendpacket pcap_set_datalink pcap_setfilter
pcap_setnonblock pcap_snapshot pcap_stat pcap_stats pcap_strerror pcap_t
sockaddr timeval u_char u_int u_short
c_int c_char_p POINTER Structure CFUNCTYPE byref
""".split()

LEGACY_WINDOWS_NAMES = """
HANDLE PCAP_BUF_SIZE PCAP_OPENFLAG_DATATX_UDP PCAP_OPENFLAG_MAX_RESPONSIVENESS
PCAP_OPENFLAG_NOCAPTURE_LOCAL PCAP_OPENFLAG_NOCAPTURE_RPCAP
PCAP_OPENFLAG_PROMISCUOUS PCAP_SAMP_1_EVERY_N PCAP_SAMP_FIRST_AFTER_N_MS
PCAP_SAMP_NOSAMP PCAP_SRC_FILE PCAP_SRC_FILE_STRING PCAP_SRC_IFLOCAL
PCAP_SRC_IFREMOTE PCAP_SRC_IF_STRING RPCAP_HOSTLIST_SIZE RPCAP_RMTAUTH_NULL
RPCAP_RMTAUTH_PWD pcap_createsrcstr pcap_findalldevs_ex pcap_getevent
pcap_live_dump pcap_live_dump_ended pcap_offline_filter pcap_open
pcap_parsesrcstr pcap_remoteact_accept pcap_remoteact_cleanup
pcap_remoteact_close pcap_remoteact_list pcap_rmtauth pcap_samp
pcap_send_queue pcap_sendqueue_alloc pcap_sendqueue_destroy
pcap_sendqueue_queue pcap_sendqueue_transmit pcap_setbuff pcap_setmintocopy
pcap_setmode pcap_setsampling pcap_stats_ex
""".split()

TYPES_PATH = wtypes.__file__


def load_types_copy(monkeypatch, platform, library, find_library=None):
    """Execute a fresh copy of winpcapy_types as if running on *platform*."""
    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setattr(ctypes, "CDLL", lambda name, *a, **kw: library)
    if find_library is not None:
        monkeypatch.setattr(ctypes.util, "find_library", find_library)
    spec = importlib.util.spec_from_file_location("_winpcapy_types_copy", TYPES_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------
# public API compatibility
# --------------------------------------------------------------------------


def test_package_public_api():
    assert {"WinPcap", "WinPcapDevices", "WinPcapUtils"} <= set(winpcapy.__all__)
    for name in winpcapy.__all__:
        assert hasattr(winpcapy, name)
    assert winpcapy.WinPcapException is winpcapy.WinPcap.WinPcapException
    assert issubclass(winpcapy.PcapLibraryNotFoundError, OSError)
    assert winpcapy.__version__.count(".") == 2


@pytest.mark.parametrize("name", LEGACY_NAMES)
def test_legacy_module_names_still_exist(name):
    assert hasattr(wtypes, name)


def test_windows_branch_declares_legacy_names_and_fixed_prototypes(monkeypatch):
    module = load_types_copy(monkeypatch, "win32", FakeLibrary())
    assert module.WIN32 and module.HAVE_REMOTE
    for name in LEGACY_WINDOWS_NAMES:
        assert hasattr(module, name), name
    # These prototypes were misspelled (argtype/retype) in 1.0.3.
    assert module.pcap_setmintocopy.argtypes == [ctypes.POINTER(module.pcap_t), ctypes.c_int]
    assert module.pcap_sendqueue_transmit.restype is module.u_int
    assert module.SOCKET is ctypes.c_uint
    assert [f[0] for f in module.pcap_stat._fields_][-3:] == ["ps_capt", "ps_sent", "ps_netdrop"]


def test_missing_symbols_do_not_break_import(monkeypatch):
    module = load_types_copy(
        monkeypatch, "win32", FakeLibrary(missing={"pcap_setsampling", "pcap_live_dump"})
    )
    assert not module.pcap_setsampling
    assert "pcap_setsampling" in repr(module.pcap_setsampling)
    with pytest.raises(NotImplementedError, match="pcap_live_dump"):
        module.pcap_live_dump()
    assert module.pcap_open_live  # present symbols are bound normally


# --------------------------------------------------------------------------
# structure layouts
# --------------------------------------------------------------------------


def test_structure_layouts():
    ptr = ctypes.sizeof(ctypes.c_void_p)
    long_size = ctypes.sizeof(ctypes.c_long)
    assert ctypes.sizeof(wtypes.bpf_insn) == 8
    assert ctypes.sizeof(wtypes.sockaddr) == 16
    assert ctypes.sizeof(wtypes.pcap_file_header) == 24
    assert wtypes.pcap_pkthdr.caplen.offset == ctypes.sizeof(wtypes.timeval)
    assert wtypes.pcap_pkthdr.len.offset == wtypes.pcap_pkthdr.caplen.offset + 4
    assert wtypes.timeval.tv_usec.offset == long_size
    assert wtypes.bpf_program.bf_insns.offset == ptr
    # struct pcap_if { next; name; description; addresses; flags }
    assert [
        getattr(wtypes.pcap_if, f).offset
        for f in ("next", "name", "description", "addresses", "flags")
    ] == [
        0,
        ptr,
        2 * ptr,
        3 * ptr,
        4 * ptr,
    ]
    assert ctypes.sizeof(wtypes.pcap_addr) == 5 * ptr


def test_handler_prototype_matches_pcap_handler():
    assert wtypes.pcap_handler._restype_ is None
    assert wtypes.pcap_handler._argtypes_[1] is ctypes.POINTER(wtypes.pcap_pkthdr)


# --------------------------------------------------------------------------
# library loader
# --------------------------------------------------------------------------


def test_windows_candidates_prefer_npcap(monkeypatch):
    system32 = os.path.join("C:" + os.sep, "Windows", "System32")
    monkeypatch.setattr(wtypes, "_windows_system_directory", lambda: system32)
    assert wtypes._library_candidates("win32") == [
        os.path.join(system32, "Npcap", "wpcap.dll"),
        os.path.join(system32, "wpcap.dll"),
        "wpcap.dll",
    ]


def test_windows_loader_skips_missing_absolute_paths(monkeypatch, tmp_path):
    npcap_dir = tmp_path / "Npcap"
    npcap_dir.mkdir()
    (npcap_dir / "wpcap.dll").write_bytes(b"")
    monkeypatch.setattr(wtypes, "_windows_system_directory", lambda: str(tmp_path))
    loaded = []
    monkeypatch.setattr(ctypes, "CDLL", lambda name: loaded.append(name) or name)
    assert wtypes._load_library("win32") == str(npcap_dir / "wpcap.dll")
    assert loaded == [str(npcap_dir / "wpcap.dll")]


def test_windows_loader_falls_back_to_default_search(monkeypatch, tmp_path):
    monkeypatch.setattr(wtypes, "_windows_system_directory", lambda: str(tmp_path))
    monkeypatch.setattr(ctypes, "CDLL", lambda name: "loaded:" + name)
    assert wtypes._load_library("win32") == "loaded:wpcap.dll"


def test_windows_loader_error_recommends_npcap(monkeypatch, tmp_path):
    monkeypatch.setattr(wtypes, "_windows_system_directory", lambda: str(tmp_path))

    def fail(name):
        raise OSError("module not found")

    monkeypatch.setattr(ctypes, "CDLL", fail)
    with pytest.raises(wtypes.PcapLibraryNotFoundError, match="Npcap") as excinfo:
        wtypes._load_library("win32")
    assert "module not found" in str(excinfo.value)
    assert isinstance(excinfo.value, OSError)


def test_posix_loader_requires_libpcap(monkeypatch):
    monkeypatch.setattr(ctypes.util, "find_library", lambda name: None)
    monkeypatch.setattr(ctypes, "CDLL", lambda name: pytest.fail("CDLL(None) must not be called"))
    with pytest.raises(wtypes.PcapLibraryNotFoundError, match="libpcap"):
        wtypes._load_library("linux")


def test_posix_loader_uses_find_library(monkeypatch):
    monkeypatch.setattr(ctypes.util, "find_library", lambda name: "libpcap.so.1")
    monkeypatch.setattr(ctypes, "CDLL", lambda name: "loaded:" + name)
    assert wtypes._load_library("linux") == "loaded:libpcap.so.1"


def test_cygwin_uses_plain_dll_name():
    assert wtypes._library_candidates("cygwin") == ["wpcap.dll"]


def test_import_fails_cleanly_without_library(monkeypatch):
    def fail(name):
        raise OSError("not found")

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(ctypes.util, "find_library", lambda name: None)
    monkeypatch.setattr(ctypes, "CDLL", fail)
    spec = importlib.util.spec_from_file_location("_winpcapy_types_nolib", TYPES_PATH)
    with pytest.raises(OSError, match="libpcap"):
        spec.loader.exec_module(importlib.util.module_from_spec(spec))
