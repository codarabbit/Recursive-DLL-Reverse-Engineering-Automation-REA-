#!/usr/bin/env python3
"""
rea_batch_v2.py - Recursive managed + native DLL reverse-engineering pipeline
(ILSpy + Ghidra) with incremental analysis, deep PE metadata, function
intelligence, graph generation and structured failure recovery.

Typical use
-----------
  python rea_batch_v2.py --input D:\\dlls --output D:\\out --temp-dir C:\\re\\tmp
  python rea_batch_v2.py --input D:\\dlls --output D:\\out --status          # progress report
  python rea_batch_v2.py --input D:\\dlls --output D:\\out --only-failed     # retry failures only
  python rea_batch_v2.py --input D:\\dlls --output D:\\out --debug           # keep failed temp dirs

Output layout (per DLL, mirrors the input tree):
  <out>/<rel dir>/<dll stem>/
      analysis_summary.json  pe_metadata.json  processing_result.json
      Original/        <copy of the source DLL, SHA-256 verified>
      Logs/            pipeline.log  ilspy.log  ghidra.log
      Generated_CSharp/  Source/*.cs  all_methods_il.txt
      Generated_Native/  decompiled/*.c  functions.json  functions.txt
                         function_inventory.csv  program.json
      Graphs/          dependencies.dot  imports.dot  call_graph.dot
                       api_calls.dot  entry_paths.dot  entry_paths.json (+ .svg with --svg)
Global files in <out>:
  manifest.db   - resume state (SHA-256, per-stage status, tool versions)
  inventory.db  - searchable SQLite index (dlls, imports, exports, functions, api_calls, FTS)
  events.jsonl  - structured event log     batch.log - full text log
  batch_summary.json   graphs/dll_dependencies.dot
"""

import argparse
import csv
import fnmatch
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import signal
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections import Counter, deque
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

PIPELINE_VERSION = "2.0.0"
GHIDRA_SCRIPT_VERSION = "2"          # bump when the Java export script changes
IS_WINDOWS = os.name == "nt"
GHIDRA_DEFAULT = r"C:\re\GHIDRA\support\analyzeHeadless.bat"

LOG = logging.getLogger("rea")
EVENTS_FILE = None                   # set in main()
STOP = threading.Event()             # set by SIGINT/SIGTERM


# =========================================================
# Errors, categories, interruption
# =========================================================

class Interrupted(Exception):
    pass


RETRYABLE = {"TIMEOUT", "PROJECT_LOCK", "IO_ERROR", "OUTPUT_MISSING", "UNKNOWN"}
PERMANENT = {"INVALID_BINARY"}       # skipped on later runs unless --retry-failed


class StageError(Exception):
    def __init__(self, category, message):
        super().__init__(message)
        self.category = category
        self.message = message
        self.retryable = category in RETRYABLE


_CATEGORY_RULES = [
    ("OUT_OF_MEMORY", ("outofmemoryerror", "java heap space", "gc overhead limit",
                       "out of memory", "memoryerror")),
    ("PROJECT_LOCK", ("lockexception", "unable to lock project", "project is locked",
                      "cannot lock project")),
    ("INVALID_BINARY", ("no load spec found", "unsupported file", "not a valid pe",
                        "could not identify a valid pe", "badimageformat",
                        "is not a .net", "invalid pe", "not a valid .net")),
    ("SCRIPT_ERROR", ("script error", "ghidrascriptloadexception", "compilation failed",
                      "cannot find symbol", "error report script")),
    ("IO_ERROR", ("permission denied", "access is denied", "no space left",
                  "filename too long", "the system cannot find the path",
                  "winerror", "ioerror", "oserror", "errno")),
]


def categorize(text, default="UNKNOWN"):
    low = (text or "").lower()
    for category, needles in _CATEGORY_RULES:
        if any(n in low for n in needles):
            return category
    return default


def _on_signal(signum, frame):
    if STOP.is_set():
        LOG.warning("Second interrupt - exiting immediately.")
        os._exit(130)
    STOP.set()
    LOG.warning("Interrupt received - stopping current work safely. "
                "Press Ctrl+C again to force quit. Re-run the same command to resume.")


def install_signal_handlers():
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                signal.signal(sig, _on_signal)
            except (ValueError, OSError):
                pass


# =========================================================
# Logging / events
# =========================================================

def iso_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def setup_logging(output_root, debug):
    LOG.setLevel(logging.DEBUG)
    LOG.handlers.clear()
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if debug else logging.INFO)
    console.setFormatter(logging.Formatter("[%(levelname).1s] %(message)s"))
    LOG.addHandler(console)
    fh = logging.FileHandler(output_root / "batch.log", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOG.addHandler(fh)


@contextmanager
def dll_log(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOG.addHandler(handler)
    try:
        yield
    finally:
        LOG.removeHandler(handler)
        handler.close()


def emit(event, **fields):
    """Append one structured event to events.jsonl."""
    if EVENTS_FILE is None:
        return
    record = {"ts": iso_now(), "event": event}
    record.update(fields)
    try:
        with EVENTS_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


# =========================================================
# Generic helpers
# =========================================================

def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_original(dll, dll_out, sha):
    """Copy the source DLL to <dll_out>/Original/ and verify it by SHA-256.
    Skips the copy when an identical file is already there."""
    dest_dir = dll_out / "Original"
    dest = dest_dir / dll.name
    dest_dir.mkdir(parents=True, exist_ok=True)
    if dest.is_file() and dest.stat().st_size == dll.stat().st_size \
            and sha256_file(dest) == sha:
        return dest
    tmp = dest.with_name(dest.name + ".part")
    shutil.copy2(dll, tmp)
    if sha256_file(tmp) != sha:
        tmp.unlink(missing_ok=True)
        raise StageError("IO_ERROR", f"Copy of {dll.name} failed SHA-256 verification")
    os.replace(tmp, dest)
    return dest


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def safe_filename(name):
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    return name[:120] or "unnamed"


def tail_text(path, nbytes=20000):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - nbytes))
            return f.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def kill_tree(proc):
    try:
        if IS_WINDOWS:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True)
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def run_logged(cmd, log_path, timeout, stdout_path=None, cwd=None):
    """
    Run a command, streaming output to disk (never held in memory).
    stdout_path: if given, stdout goes there and stderr to log_path;
                 otherwise stdout+stderr both go to log_path.
    Polls for interruption and timeout; kills the whole process tree.
    Returns the exit code.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    kwargs = {}
    if IS_WINDOWS:
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True

    out_f = None
    proc = None
    with open(log_path, "ab") as logf:
        logf.write(f"\n===== {iso_now()} :: {' '.join(str(c) for c in cmd)}\n"
                   .encode("utf-8", errors="replace"))
        logf.flush()
        try:
            if stdout_path:
                out_f = open(stdout_path, "wb")
            try:
                proc = subprocess.Popen(
                    [str(c) for c in cmd],
                    stdout=out_f or logf,
                    stderr=logf if out_f else subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    cwd=cwd,
                    **kwargs
                )
            except FileNotFoundError as e:
                raise StageError("TOOL_MISSING", f"Cannot launch {cmd[0]}: {e}")

            deadline = time.monotonic() + timeout
            while True:
                try:
                    return proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
                if STOP.is_set():
                    kill_tree(proc)
                    proc.wait()
                    raise Interrupted()
                if time.monotonic() > deadline:
                    kill_tree(proc)
                    proc.wait()
                    raise StageError("TIMEOUT", f"Timed out after {timeout}s")
        finally:
            if proc is not None and proc.poll() is None:
                kill_tree(proc)
            if out_f:
                out_f.close()


# =========================================================
# Tool detection and versions
# =========================================================

def find_ilspy():
    return shutil.which("ilspycmd")


def ilspy_version(exe):
    if not exe:
        return None
    try:
        r = subprocess.run([exe, "--version"], capture_output=True, text=True,
                           errors="replace", timeout=60)
        text = (r.stdout or r.stderr or "").strip().splitlines()
        return text[0].strip() if text else "unknown"
    except Exception:
        return "unknown"


def find_ghidra(path):
    p = Path(path)
    return str(p) if p.is_file() else None


def ghidra_version(exe):
    if not exe:
        return None
    props = Path(exe).resolve().parent.parent / "Ghidra" / "application.properties"
    try:
        for line in props.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("application.version="):
                return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return "unknown"


# =========================================================
# P1: Advanced PE metadata extraction (pure Python)
# =========================================================

class PEParseError(Exception):
    pass


MACHINES = {0x014C: "x86", 0x8664: "x64", 0x01C0: "ARM", 0x01C4: "ARMv7",
            0xAA64: "ARM64", 0x0200: "IA64"}
SUBSYSTEMS = {0: "Unknown", 1: "Native", 2: "Windows GUI", 3: "Windows CUI",
              5: "OS/2 CUI", 7: "POSIX CUI", 9: "Windows CE GUI",
              10: "EFI Application", 11: "EFI Boot Service Driver",
              12: "EFI Runtime Driver", 13: "EFI ROM", 14: "Xbox",
              16: "Windows Boot Application"}
DLL_CHAR_FLAGS = {0x20: "HIGH_ENTROPY_VA", 0x40: "DYNAMIC_BASE", 0x80: "FORCE_INTEGRITY",
                  0x100: "NX_COMPAT", 0x200: "NO_ISOLATION", 0x400: "NO_SEH",
                  0x800: "NO_BIND", 0x1000: "APPCONTAINER", 0x2000: "WDM_DRIVER",
                  0x4000: "GUARD_CF", 0x8000: "TERMINAL_SERVER_AWARE"}
RES_TYPES = {1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING",
             7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR", 10: "RCDATA",
             11: "MESSAGETABLE", 12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION",
             17: "DLGINCLUDE", 19: "PLUGPLAY", 20: "VXD", 21: "ANICURSOR",
             22: "ANIICON", 23: "HTML", 24: "MANIFEST"}
DEBUG_TYPES = {1: "COFF", 2: "CODEVIEW", 3: "FPO", 4: "MISC", 5: "EXCEPTION",
               6: "FIXUP", 9: "BORLAND", 10: "RESERVED10", 11: "CLSID", 12: "VC_FEATURE",
               13: "POGO", 14: "ILTCG", 15: "MPX", 16: "REPRO", 20: "EX_DLLCHARACTERISTICS"}

# Heuristic API groupings used for triage (not verdicts).
API_CATEGORIES = {
    "process_injection": {"writeprocessmemory", "createremotethread", "createremotethreadex",
                          "ntcreatethreadex", "queueuserapc", "ntqueueapcthread",
                          "setthreadcontext", "ntunmapviewofsection", "ntmapviewofsection",
                          "ntwritevirtualmemory", "rtlcreateuserthread", "virtualallocex",
                          "openprocess", "ntallocatevirtualmemory"},
    "memory": {"virtualalloc", "virtualprotect", "virtualprotectex", "ntprotectvirtualmemory"},
    "process": {"createprocessa", "createprocessw", "createprocessinternalw", "winexec",
                "shellexecutea", "shellexecutew", "shellexecuteexw", "ntcreateuserprocess",
                "terminateprocess"},
    "network": {"wsastartup", "socket", "connect", "send", "recv", "internetopena",
                "internetopenw", "internetopenurla", "internetopenurlw",
                "internetconnecta", "internetconnectw", "internetreadfile",
                "httpsendrequesta", "httpsendrequestw", "winhttpopen", "winhttpconnect",
                "winhttpsendrequest", "urldownloadtofilea", "urldownloadtofilew",
                "getaddrinfo", "gethostbyname"},
    "crypto": {"cryptencrypt", "cryptdecrypt", "cryptacquirecontexta", "cryptacquirecontextw",
               "cryptgenkey", "cryptderivekey", "cryptimportkey", "cryptcreatehash",
               "cryptprotectdata", "cryptunprotectdata", "bcryptencrypt", "bcryptdecrypt",
               "bcryptopenalgorithmprovider", "bcryptgeneratesymmetrickey"},
    "registry": {"regopenkeyexa", "regopenkeyexw", "regsetvalueexa", "regsetvalueexw",
                 "regcreatekeyexa", "regcreatekeyexw", "regdeletekeya", "regdeletekeyw",
                 "regqueryvalueexa", "regqueryvalueexw"},
    "file": {"createfilea", "createfilew", "writefile", "readfile", "deletefilea",
             "deletefilew", "movefileexa", "movefileexw", "copyfilea", "copyfilew",
             "findfirstfilea", "findfirstfilew", "ntcreatefile"},
    "anti_debug": {"isdebuggerpresent", "checkremotedebuggerpresent",
                   "ntqueryinformationprocess", "outputdebugstringa", "outputdebugstringw"},
    "service": {"createservicea", "createservicew", "openscmanagera", "openscmanagerw",
                "startservicea", "startservicew"},
    "dynamic_loading": {"loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw",
                        "getprocaddress", "ldrloaddll"},
    "hooking_input": {"setwindowshookexa", "setwindowshookexw", "getasynckeystate",
                      "getkeystate", "getforegroundwindow"},
}
_API_LOOKUP = {api: cat for cat, apis in API_CATEGORIES.items() for api in apis}


def api_category(name):
    if not name:
        return None
    n = name.lower().lstrip("_")
    n = re.sub(r"@\d+$", "", n)
    return _API_LOOKUP.get(n)


def _align4(v):
    return (v + 3) & ~3


def _entropy(data):
    if not data:
        return 0.0
    import math
    counts = Counter(data)
    total = len(data)
    return round(-sum((c / total) * math.log2(c / total) for c in counts.values()), 3)


def compute_imphash(imports):
    """Classic imphash over the normal import table (delay imports excluded).
    Ordinal-only imports from ws2_32/oleaut32 use 'ord<N>' rather than pefile's
    ordinal-to-name tables, so those few cases can differ from pefile."""
    parts = []
    for imp in imports:
        if imp["delay"]:
            continue
        lib = imp["dll"].lower()
        for ext in (".dll", ".ocx", ".sys"):
            if lib.endswith(ext):
                lib = lib[:-len(ext)]
        for fn in imp["functions"]:
            name = fn["name"].lower() if fn.get("name") else f"ord{fn.get('ordinal')}"
            parts.append(f"{lib}.{name}")
    if not parts:
        return None
    try:
        h = hashlib.md5(",".join(parts).encode(), usedforsecurity=False)
    except TypeError:
        h = hashlib.md5(",".join(parts).encode())
    return h.hexdigest()


def _ver_header(b, off, limit):
    if off + 6 > limit:
        return None
    length, vlen, typ = struct.unpack_from("<HHH", b, off)
    if length < 6:
        return None
    end = min(off + length, limit)
    p = off + 6
    start = p
    while p + 1 < end and not (b[p] == 0 and b[p + 1] == 0):
        p += 2
    key = b[start:p].decode("utf-16le", errors="replace")
    p = _align4(p + 2)
    return key, vlen, typ, p, end


def parse_version_info(b):
    """Parse a VS_VERSIONINFO resource blob."""
    h = _ver_header(b, 0, len(b))
    if not h or h[0] != "VS_VERSION_INFO":
        return None
    _, vlen, _, p, end = h
    out = {"fixed": None, "strings": {}, "translations": []}
    if vlen >= 52 and p + 24 <= end:
        sig, _, fvh, fvl, pvh, pvl = struct.unpack_from("<IIIIII", b, p)
        if sig == 0xFEEF04BD:
            out["fixed"] = {
                "file_version": f"{fvh >> 16}.{fvh & 0xFFFF}.{fvl >> 16}.{fvl & 0xFFFF}",
                "product_version": f"{pvh >> 16}.{pvh & 0xFFFF}.{pvl >> 16}.{pvl & 0xFFFF}",
            }
    child = _align4(p + vlen)
    while child < end:
        ch = _ver_header(b, child, end)
        if not ch:
            break
        key, _, _, cp, cend = ch
        if key == "StringFileInfo":
            t = cp
            first_table = True
            while t < cend:
                th = _ver_header(b, t, cend)
                if not th:
                    break
                _, _, _, tp, tend = th
                s = tp
                while s < tend:
                    sh = _ver_header(b, s, tend)
                    if not sh:
                        break
                    sk, svl, _, sp, send = sh
                    val = b[sp:sp + svl * 2].decode("utf-16le", errors="replace").rstrip("\x00")
                    if first_table or sk not in out["strings"]:
                        out["strings"][sk] = val
                    s = _align4(send)
                first_table = False
                t = _align4(tend)
        elif key == "VarFileInfo":
            t = cp
            while t < cend:
                th = _ver_header(b, t, cend)
                if not th:
                    break
                tk, tvl, _, tp, tend = th
                if tk == "Translation":
                    for i in range(0, tvl - 3, 4):
                        lang, cpg = struct.unpack_from("<HH", b, tp + i)
                        out["translations"].append(f"{lang:04x}:{cpg:04x}")
                t = _align4(tend)
        child = _align4(cend)
    return out


class _PE:
    def __init__(self, data):
        self.d = data
        n = len(data)
        if n < 0x40 or data[:2] != b"MZ":
            raise PEParseError("no MZ")
        self.pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if self.pe_off + 24 > n or data[self.pe_off:self.pe_off + 4] != b"PE\x00\x00":
            raise PEParseError("no PE signature")
        coff = self.pe_off + 4
        (self.machine, self.nsec, self.timestamp, _sym, _nsym,
         self.optsize, self.characteristics) = struct.unpack_from("<HHIIIHH", data, coff)
        o = self.opt = coff + 20
        self.magic = struct.unpack_from("<H", data, o)[0]
        if self.magic == 0x10B:
            self.is64 = False
        elif self.magic == 0x20B:
            self.is64 = True
        else:
            raise PEParseError("unknown optional header magic")
        u16 = lambda x: struct.unpack_from("<H", data, x)[0]
        u32 = lambda x: struct.unpack_from("<I", data, x)[0]
        self.linker = (data[o + 2], data[o + 3])
        self.entry_rva = u32(o + 16)
        self.image_base = (struct.unpack_from("<Q", data, o + 24)[0] if self.is64
                           else u32(o + 28))
        self.os_version = (u16(o + 40), u16(o + 42))
        self.subsys_version = (u16(o + 48), u16(o + 50))
        self.size_of_image = u32(o + 56)
        self.size_of_headers = u32(o + 60)
        self.checksum = u32(o + 64)
        self.subsystem = u16(o + 68)
        self.dll_chars = u16(o + 70)
        self.ndirs = min(u32(o + (108 if self.is64 else 92)), 16)
        self.dd_off = o + (112 if self.is64 else 96)

        self.sections = []
        table = o + self.optsize
        for i in range(self.nsec):
            off = table + 40 * i
            if off + 40 > n:
                break
            name, vsize, vaddr, rsize, roff, _, _, _, _, ch = struct.unpack_from(
                "<8sIIIIIIHHI", data, off)
            raw = data[roff:roff + min(rsize, 8 * 1024 * 1024)] if roff < n else b""
            self.sections.append({
                "name": name.split(b"\x00")[0].decode("ascii", errors="replace"),
                "virtual_address": vaddr, "virtual_size": vsize,
                "raw_offset": roff, "raw_size": rsize,
                "characteristics": hex(ch),
                "executable": bool(ch & 0x20000000),
                "writable": bool(ch & 0x80000000),
                "entropy": _entropy(raw),
            })

    # -- low-level readers ---------------------------------
    def u16(self, off):
        return struct.unpack_from("<H", self.d, off)[0]

    def u32(self, off):
        return struct.unpack_from("<I", self.d, off)[0]

    def u64(self, off):
        return struct.unpack_from("<Q", self.d, off)[0]

    def dd(self, index):
        if index >= self.ndirs:
            return 0, 0
        off = self.dd_off + index * 8
        if off + 8 > len(self.d):
            return 0, 0
        return struct.unpack_from("<II", self.d, off)

    def rva_to_off(self, rva):
        if rva is None:
            return None
        if rva < self.size_of_headers and (not self.sections
                                           or rva < self.sections[0]["virtual_address"]):
            return rva if rva < len(self.d) else None
        for s in self.sections:
            va = s["virtual_address"]
            span = max(s["virtual_size"], s["raw_size"])
            if va <= rva < va + span:
                delta = rva - va
                if delta >= s["raw_size"]:
                    return None
                off = s["raw_offset"] + delta
                return off if off < len(self.d) else None
        return None

    def section_for_rva(self, rva):
        for s in self.sections:
            if s["virtual_address"] <= rva < s["virtual_address"] + max(
                    s["virtual_size"], s["raw_size"]):
                return s["name"]
        return None

    def cstr(self, off, maxlen=2048):
        if off is None or off < 0 or off >= len(self.d):
            return ""
        end = self.d.find(b"\x00", off, off + maxlen)
        if end < 0:
            end = min(off + maxlen, len(self.d))
        return self.d[off:end].decode("ascii", errors="replace")

    # -- directories ---------------------------------------
    def exports(self, limit=100000):
        dir_rva, dir_size = self.dd(0)
        if not dir_rva:
            return None
        off = self.rva_to_off(dir_rva)
        if off is None:
            return None
        (_, ts, _, _, name_rva, base, nfunc, nnames, aof, aon, aono) = struct.unpack_from(
            "<IIHHIIIIIII", self.d, off)
        funcs_off, names_off, ords_off = (self.rva_to_off(aof), self.rva_to_off(aon),
                                          self.rva_to_off(aono))
        nfunc, nnames = min(nfunc, limit), min(nnames, limit)
        names = {}
        if names_off is not None and ords_off is not None:
            for i in range(nnames):
                n_rva = self.u32(names_off + 4 * i)
                idx = self.u16(ords_off + 2 * i)
                names[idx] = self.cstr(self.rva_to_off(n_rva))
        entries = []
        if funcs_off is not None:
            for i in range(nfunc):
                frva = self.u32(funcs_off + 4 * i)
                if frva == 0:
                    continue
                e = {"ordinal": base + i, "name": names.get(i), "rva": hex(frva)}
                if dir_rva <= frva < dir_rva + dir_size:
                    e["forwarder"] = self.cstr(self.rva_to_off(frva))
                entries.append(e)
        return {"name": self.cstr(self.rva_to_off(name_rva)), "timestamp": ts,
                "count": len(entries), "entries": entries}

    def _thunks(self, rva, limit=20000):
        off = self.rva_to_off(rva)
        step = 8 if self.is64 else 4
        flag = (1 << 63) if self.is64 else (1 << 31)
        items = []
        while off is not None and off + step <= len(self.d) and len(items) < limit:
            v = self.u64(off) if self.is64 else self.u32(off)
            if v == 0:
                break
            if v & flag:
                items.append({"name": None, "ordinal": v & 0xFFFF})
            else:
                no = self.rva_to_off(v & 0x7FFFFFFF)
                if no is None or no + 2 > len(self.d):
                    items.append({"name": None, "ordinal": None})
                else:
                    items.append({"name": self.cstr(no + 2), "hint": self.u16(no)})
            off += step
        return items

    def imports(self):
        out = []
        rva, _ = self.dd(1)
        off = self.rva_to_off(rva) if rva else None
        count = 0
        while off is not None and off + 20 <= len(self.d) and count < 4096:
            oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", self.d, off)
            if name_rva == 0 and ft == 0:
                break
            name = self.cstr(self.rva_to_off(name_rva))
            out.append({"dll": name, "delay": False,
                        "functions": self._thunks(oft or ft)})
            off += 20
            count += 1
        rva, _ = self.dd(13)
        off = self.rva_to_off(rva) if rva else None
        count = 0
        while off is not None and off + 32 <= len(self.d) and count < 4096:
            attrs, name_v, _, _, int_v, _, _, _ = struct.unpack_from("<8I", self.d, off)
            if name_v == 0:
                break
            if not attrs & 1:   # old-style VAs
                name_v = name_v - self.image_base if name_v else 0
                int_v = int_v - self.image_base if int_v else 0
            out.append({"dll": self.cstr(self.rva_to_off(name_v)), "delay": True,
                        "functions": self._thunks(int_v)})
            off += 32
            count += 1
        return out

    def debug(self):
        rva, size = self.dd(6)
        off = self.rva_to_off(rva) if rva else None
        out = []
        if off is None:
            return out
        for i in range(min(size // 28, 64)):
            e = off + i * 28
            if e + 28 > len(self.d):
                break
            _, ts, _, _, typ, dsize, _, raw_ptr = struct.unpack_from("<IIHHIIII", self.d, e)
            item = {"type": DEBUG_TYPES.get(typ, typ), "timestamp": ts, "size": dsize}
            if typ == 2 and raw_ptr and raw_ptr + 24 <= len(self.d) \
                    and self.d[raw_ptr:raw_ptr + 4] == b"RSDS":
                item["guid"] = str(uuid.UUID(bytes_le=self.d[raw_ptr + 4:raw_ptr + 20])).upper()
                item["age"] = self.u32(raw_ptr + 20)
                end = self.d.find(b"\x00", raw_ptr + 24, raw_ptr + 24 + 1024)
                end = end if end >= 0 else raw_ptr + 24
                item["pdb_path"] = self.d[raw_ptr + 24:end].decode("utf-8", errors="replace")
            out.append(item)
        return out

    def tls(self):
        rva, _ = self.dd(9)
        off = self.rva_to_off(rva) if rva else None
        if off is None:
            return None
        try:
            cb_va = self.u64(off + 24) if self.is64 else self.u32(off + 12)
        except struct.error:
            return {"callbacks": []}
        callbacks = []
        cb_off = self.rva_to_off(cb_va - self.image_base) if cb_va else None
        step = 8 if self.is64 else 4
        while cb_off is not None and cb_off + step <= len(self.d) and len(callbacks) < 64:
            v = self.u64(cb_off) if self.is64 else self.u32(cb_off)
            if v == 0:
                break
            callbacks.append(hex(v - self.image_base))
            cb_off += step
        return {"callbacks": callbacks}

    def resources(self):
        rva, _ = self.dd(2)
        base = self.rva_to_off(rva) if rva else None
        if base is None:
            return None
        leaves = []

        def label_of(nid):
            if nid & 0x80000000:
                so = base + (nid & 0x7FFFFFFF)
                n = self.u16(so)
                return self.d[so + 2:so + 2 + n * 2].decode("utf-16le", errors="replace")
            return nid

        def walk(dir_off, depth, path):
            if depth > 3 or len(leaves) > 5000:
                return
            named, idn = struct.unpack_from("<HH", self.d, base + dir_off + 12)
            for i in range(min(named + idn, 2048)):
                nid, off = struct.unpack_from("<II", self.d, base + dir_off + 16 + 8 * i)
                label = label_of(nid)
                if off & 0x80000000:
                    walk(off & 0x7FFFFFFF, depth + 1, path + [label])
                else:
                    data_rva, size, cp, _ = struct.unpack_from("<IIII", self.d, base + off)
                    leaves.append((path + [label], data_rva, size, cp))

        try:
            walk(0, 0, [])
        except (struct.error, IndexError):
            pass

        entries, counts = [], Counter()
        manifest = None
        version_info = None
        for path, data_rva, size, cp in leaves:
            rtype = path[0] if path else None
            tname = RES_TYPES.get(rtype, rtype) if isinstance(rtype, int) else rtype
            counts[str(tname)] += 1
            if len(entries) < 500:
                entries.append({"type": tname, "name": path[1] if len(path) > 1 else None,
                                "language": path[2] if len(path) > 2 else None,
                                "size": size, "rva": hex(data_rva), "codepage": cp})
            off = self.rva_to_off(data_rva)
            if off is None or size <= 0:
                continue
            blob = self.d[off:off + min(size, 1024 * 1024)]
            try:
                if rtype == 24 and manifest is None:
                    manifest = blob[:65536].decode("utf-8-sig", errors="replace")
                elif rtype == 16 and version_info is None:
                    version_info = parse_version_info(blob)
            except Exception:
                pass
        return {"total": len(leaves), "type_counts": dict(counts), "entries": entries,
                "manifest": manifest, "version_info": version_info}

    def clr(self):
        rva, size = self.dd(14)
        if not rva or not size:
            return None
        off = self.rva_to_off(rva)
        if off is None:
            return {"unresolved": True}
        _, maj, minr, md_rva, _, flags = struct.unpack_from("<IHHIII", self.d, off)
        info = {"flags": hex(flags), "il_only": bool(flags & 1),
                "requires_32bit": bool(flags & 2), "strong_name_signed": bool(flags & 8),
                "prefer_32bit": bool(flags & 0x20000), "runtime_version": f"{maj}.{minr}",
                "entry_point_token": hex(self.u32(off + 20))}
        mo = self.rva_to_off(md_rva)
        if mo is not None and self.d[mo:mo + 4] == b"BSJB":
            vlen = self.u32(mo + 12)
            info["metadata_version"] = (self.d[mo + 16:mo + 16 + vlen]
                                        .split(b"\x00")[0].decode("ascii", errors="replace"))
        return info


def inspect_pe(path):
    """Deep PE inspection. Never raises; problems are recorded in 'warnings'."""
    result = {
        "valid_pe": False, "architecture": "Unknown", "managed": False,
        "mixed_mode": False, "binary_type": "INVALID_OR_UNKNOWN", "clr_flags": None,
        "sections": [], "warnings": [],
    }
    try:
        data = Path(path).read_bytes()
        pe = _PE(data)
    except PEParseError:
        return result
    except Exception as e:
        result["inspection_error"] = str(e)
        return result

    def safe(label, fn, default=None):
        try:
            return fn()
        except Exception as e:
            result["warnings"].append(f"{label}: {type(e).__name__}: {e}")
            return default

    result["valid_pe"] = True
    result["architecture"] = MACHINES.get(pe.machine, hex(pe.machine))
    result["machine"] = hex(pe.machine)
    result["is_dll"] = bool(pe.characteristics & 0x2000)
    result["image_base"] = hex(pe.image_base)
    result["entry_point_rva"] = hex(pe.entry_rva)
    result["entry_point_section"] = pe.section_for_rva(pe.entry_rva) if pe.entry_rva else None
    result["size_of_image"] = pe.size_of_image
    result["timestamp"] = pe.timestamp
    try:
        result["timestamp_utc"] = datetime.fromtimestamp(pe.timestamp, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        result["timestamp_utc"] = None
    result["subsystem"] = pe.subsystem
    result["subsystem_name"] = SUBSYSTEMS.get(pe.subsystem, "Unknown")
    result["os_version"] = "%d.%d" % pe.os_version
    result["subsystem_version"] = "%d.%d" % pe.subsys_version
    result["linker_version"] = "%d.%d" % pe.linker
    result["checksum"] = hex(pe.checksum)
    result["characteristics"] = hex(pe.characteristics)
    result["dll_characteristics"] = hex(pe.dll_chars)
    result["dll_characteristic_flags"] = [n for b, n in DLL_CHAR_FLAGS.items() if pe.dll_chars & b]
    result["sections"] = pe.sections
    end_raw = max([s["raw_offset"] + s["raw_size"] for s in pe.sections] or [0])
    result["overlay_size"] = max(0, len(data) - end_raw)

    sec_off, sec_size = pe.dd(4)
    result["authenticode"] = ({"offset": hex(sec_off), "size": sec_size}
                              if sec_off and sec_size else None)

    exports = safe("exports", pe.exports)
    result["exports"] = exports

    imports = safe("imports", pe.imports, [])
    deps = []
    for imp in imports:
        deps.append({"dll": imp["dll"], "delay": imp["delay"],
                     "function_count": len(imp["functions"])})
    result["imports"] = {
        "dll_count": len(imports),
        "function_count": sum(len(i["functions"]) for i in imports),
        "imphash": compute_imphash(imports),
        "dependencies": deps,
        "entries": imports,
    }
    cats = {}
    for imp in imports:
        for fn in imp["functions"]:
            c = api_category(fn.get("name"))
            if c:
                cats.setdefault(c, set()).add(fn["name"])
    result["api_categories"] = {k: sorted(v) for k, v in sorted(cats.items())}

    result["debug"] = safe("debug", pe.debug, [])
    result["tls"] = safe("tls", pe.tls)
    res = safe("resources", pe.resources)
    if res:
        result["manifest"] = res.pop("manifest")
        result["version_info"] = res.pop("version_info")
    else:
        result["manifest"] = None
        result["version_info"] = None
    result["resources"] = res

    # ---- managed / native classification (same rules as v1) ----
    clr = safe("clr", pe.clr)
    result["clr"] = clr
    if pe.ndirs <= 14 or clr is None:
        result["binary_type"] = "NATIVE"
    elif clr.get("unresolved"):
        result["binary_type"] = "CLR_HEADER_UNRESOLVED"
    else:
        result["managed"] = True
        result["clr_flags"] = clr["flags"]
        if clr["il_only"]:
            result["binary_type"] = "MANAGED_DOTNET"
        else:
            result["mixed_mode"] = True
            result["binary_type"] = "MIXED_MODE"
    return result


def load_analysis(analysis_dir):
    """Optional legacy managed-info.json / managed-members.json next to the DLL."""
    info, members = {}, {}
    for filename, target in (("managed-info.json", "info"), ("managed-members.json", "members")):
        fp = analysis_dir / filename
        if not fp.exists():
            continue
        try:
            content = json.loads(fp.read_text(encoding="utf-8-sig"))
            if target == "info":
                info = content
            else:
                members = content
        except Exception as e:
            LOG.warning("Could not read %s: %s", filename, e)
    return info, members


# =========================================================
# ILSpy
# =========================================================

def decompile_managed(dll, csharp_dir, ilspy, log_path, timeout):
    source_dir = csharp_dir / "Source"
    if csharp_dir.exists():
        shutil.rmtree(csharp_dir, ignore_errors=True)
    source_dir.mkdir(parents=True, exist_ok=True)

    LOG.info("ILSpy decompilation: %s", dll.name)
    rc = run_logged([ilspy, "-p", "-o", source_dir, dll], log_path, timeout)
    if rc != 0:
        tail = tail_text(log_path)
        raise StageError(categorize(tail, "UNKNOWN"),
                         f"ilspycmd exit code {rc}: {tail[-400:].strip()}")
    count = sum(1 for _ in source_dir.rglob("*.cs"))
    LOG.info("C# files generated: %d", count)
    if count == 0:
        raise StageError("OUTPUT_MISSING", "ILSpy produced no .cs files")
    return count


def export_il(dll, csharp_dir, ilspy, log_path, timeout):
    il_file = csharp_dir / "all_methods_il.txt"
    try:
        rc = run_logged([ilspy, "-il", dll], log_path, timeout, stdout_path=il_file)
    except StageError as e:
        LOG.warning("IL export failed (%s): %s", e.category, e.message)
        return False
    if rc != 0:
        LOG.warning("IL export failed (exit %s); see ilspy.log", rc)
        return False
    LOG.info("IL exported")
    return True


# =========================================================
# Ghidra (function intelligence script)
# =========================================================

GHIDRA_SCRIPT = r'''
//@category BatchReverseEngineering

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

public class ExportDecompiled extends GhidraScript {

    private static final int MAX_XREFS = 50;
    private static final int MAX_LINKS = 500;

    private static String safe(String v) {
        String s = v.replaceAll("[^A-Za-z0-9_.-]+", "_");
        if (s.length() > 120) s = s.substring(0, 120);
        return s.isEmpty() ? "unnamed" : s;
    }

    private static String q(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"':  b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    private static String hex(long v) { return "0x" + Long.toHexString(v); }

    private static void put(StringBuilder sb, String k, String jsonValue) {
        sb.append('"').append(k).append("\":").append(jsonValue).append(',');
    }

    private ExternalLocation externalOf(Reference r) {
        try {
            if (r.isExternalReference()) {
                return ((ExternalReference) r).getExternalLocation();
            }
            Address to = r.getToAddress();
            if (to == null) return null;
            Function tf = currentProgram.getFunctionManager().getFunctionAt(to);
            if (tf != null) {
                if (tf.isExternal()) return tf.getExternalLocation();
                if (tf.isThunk()) {
                    Function t = tf.getThunkedFunction(true);
                    if (t != null && t.isExternal()) return t.getExternalLocation();
                }
            }
            if (to.isMemoryAddress()) {
                Data d = currentProgram.getListing().getDataAt(to);
                if (d != null) {
                    for (Reference r2 : d.getReferencesFrom()) {
                        if (r2.isExternalReference()) {
                            return ((ExternalReference) r2).getExternalLocation();
                        }
                    }
                }
            }
        } catch (Exception e) { }
        return null;
    }

    private List<String[]> externalCalls(Function f) {
        LinkedHashMap<String, String[]> found = new LinkedHashMap<String, String[]>();
        try {
            ReferenceManager rm = currentProgram.getReferenceManager();
            AddressIterator srcs = rm.getReferenceSourceIterator(f.getBody(), true);
            int guard = 0;
            while (srcs.hasNext() && guard++ < 200000) {
                Address a = srcs.next();
                for (Reference r : rm.getReferencesFrom(a)) {
                    ExternalLocation el = externalOf(r);
                    if (el == null) continue;
                    String lib = el.getLibraryName() == null ? "" : el.getLibraryName();
                    String api = el.getOriginalImportedName() != null
                        ? el.getOriginalImportedName() : el.getLabel();
                    if (api == null) api = "unknown";
                    found.put(lib + "!" + api, new String[] { lib, api });
                }
            }
        } catch (Exception e) { }
        return new ArrayList<String[]>(found.values());
    }

    private int[] blockStats(SimpleBlockModel model, Function f) {
        int blocks = 0, edges = 0;
        try {
            AddressSetView body = f.getBody();
            CodeBlockIterator bi = model.getCodeBlocksContaining(body, monitor);
            while (bi.hasNext()) {
                CodeBlock b = bi.next();
                blocks++;
                CodeBlockReferenceIterator di = b.getDestinations(monitor);
                while (di.hasNext()) {
                    CodeBlockReference r = di.next();
                    if (body.contains(r.getDestinationAddress())) edges++;
                }
            }
        } catch (Exception e) { }
        return new int[] { blocks, edges };
    }

    private String funcList(Set<Function> fs) {
        StringBuilder b = new StringBuilder("[");
        int n = 0;
        for (Function g : fs) {
            if (n >= MAX_LINKS) break;
            if (n > 0) b.append(',');
            b.append("{\"name\":").append(q(g.getName()))
             .append(",\"address\":").append(q(hex(g.getEntryPoint().getOffset())))
             .append(",\"external\":").append(g.isExternal()).append('}');
            n++;
        }
        return b.append(']').toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            throw new IllegalArgumentException("Output directory argument missing");
        }
        Path out = Paths.get(args[0]);
        boolean doDecomp = args.length < 2 || !args[1].equals("0");
        int decompTimeout = args.length > 2 ? Integer.parseInt(args[2]) : 120;

        Path pseudo = out.resolve("decompiled");
        if (doDecomp) Files.createDirectories(pseudo);
        Files.createDirectories(out);

        Set<Address> entryPoints = new HashSet<Address>();
        AddressIterator eit = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        while (eit.hasNext()) entryPoints.add(eit.next());

        SimpleBlockModel bbm = new SimpleBlockModel(currentProgram);
        ReferenceManager rm = currentProgram.getReferenceManager();

        DecompInterface decomp = null;
        if (doDecomp) {
            decomp = new DecompInterface();
            decomp.openProgram(currentProgram);
        }

        int index = 0, decompiled = 0, errors = 0;
        BufferedWriter w = Files.newBufferedWriter(out.resolve("functions.jsonl"),
                                                   StandardCharsets.UTF_8);
        try {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (monitor.isCancelled()) break;
                index++;
                StringBuilder sb = new StringBuilder("{");
                try {
                    boolean ext = f.isExternal();
                    Address ep = f.getEntryPoint();
                    put(sb, "index", String.valueOf(index));
                    put(sb, "name", q(f.getName()));
                    put(sb, "address", q(hex(ep.getOffset())));
                    put(sb, "entry_point", q(ep.toString()));
                    put(sb, "namespace", q(f.getParentNamespace().toString()));
                    put(sb, "is_external", String.valueOf(ext));
                    put(sb, "is_thunk", String.valueOf(f.isThunk()));
                    put(sb, "is_entry_point", String.valueOf(entryPoints.contains(ep)));
                    put(sb, "signature", q(f.getPrototypeString(false, false)));
                    put(sb, "calling_convention", q(f.getCallingConventionName()));
                    put(sb, "return_type", q(f.getReturnType().getDisplayName()));
                    put(sb, "has_varargs", String.valueOf(f.hasVarArgs()));
                    put(sb, "no_return", String.valueOf(f.hasNoReturn()));

                    StringBuilder ps = new StringBuilder("[");
                    Parameter[] params = f.getParameters();
                    for (int i = 0; i < params.length; i++) {
                        if (i > 0) ps.append(',');
                        Parameter p = params[i];
                        ps.append("{\"name\":").append(q(p.getName()))
                          .append(",\"type\":").append(q(p.getDataType().getDisplayName()))
                          .append(",\"storage\":").append(q(p.getVariableStorage().toString()))
                          .append('}');
                    }
                    ps.append(']');
                    put(sb, "parameters", ps.toString());
                    put(sb, "param_count", String.valueOf(params.length));

                    long size = ext ? 0 : f.getBody().getNumAddresses();
                    put(sb, "size", String.valueOf(size));
                    int frame = -1;
                    try { frame = f.getStackFrame().getFrameSize(); } catch (Exception e) { }
                    put(sb, "stack_frame_size", String.valueOf(frame));

                    int blocks = 0, edges = 0;
                    if (!ext) {
                        int[] st = blockStats(bbm, f);
                        blocks = st[0];
                        edges = st[1];
                    }
                    put(sb, "basic_blocks", String.valueOf(blocks));
                    put(sb, "cfg_edges", String.valueOf(edges));
                    put(sb, "cyclomatic_complexity",
                        String.valueOf(blocks > 0 ? Math.max(1, edges - blocks + 2) : 0));

                    int xrefTotal = 0;
                    StringBuilder xs = new StringBuilder("[");
                    ReferenceIterator ri = rm.getReferencesTo(ep);
                    while (ri.hasNext()) {
                        Reference r = ri.next();
                        if (xrefTotal < MAX_XREFS) {
                            if (xrefTotal > 0) xs.append(',');
                            Function from = getFunctionContaining(r.getFromAddress());
                            xs.append("{\"from\":").append(q(hex(r.getFromAddress().getOffset())))
                              .append(",\"type\":").append(q(r.getReferenceType().getName()))
                              .append(",\"from_function\":")
                              .append(from == null ? "null" : q(from.getName())).append('}');
                        }
                        xrefTotal++;
                    }
                    xs.append(']');
                    put(sb, "xref_count", String.valueOf(xrefTotal));
                    put(sb, "xrefs", xs.toString());

                    Set<Function> callers = f.getCallingFunctions(monitor);
                    Set<Function> callees = f.getCalledFunctions(monitor);
                    put(sb, "caller_count", String.valueOf(callers.size()));
                    put(sb, "callee_count", String.valueOf(callees.size()));
                    put(sb, "callers", funcList(callers));
                    put(sb, "callees", funcList(callees));

                    StringBuilder es = new StringBuilder("[");
                    if (!ext) {
                        List<String[]> calls = externalCalls(f);
                        for (int i = 0; i < calls.size(); i++) {
                            if (i > 0) es.append(',');
                            es.append("{\"library\":").append(q(calls.get(i)[0]))
                              .append(",\"api\":").append(q(calls.get(i)[1])).append('}');
                        }
                    }
                    es.append(']');
                    put(sb, "external_calls", es.toString());

                    String file = null;
                    boolean ok = false;
                    String error = null;
                    if (doDecomp && !ext) {
                        try {
                            DecompileResults r = decomp.decompileFunction(f, decompTimeout, monitor);
                            if (r.decompileCompleted()) {
                                String fn = String.format("%05d_%s.c", index, safe(f.getName()));
                                Files.write(pseudo.resolve(fn),
                                    r.getDecompiledFunction().getC().getBytes(StandardCharsets.UTF_8));
                                file = fn;
                                ok = true;
                                decompiled++;
                            } else {
                                error = r.getErrorMessage();
                            }
                        } catch (Exception e) {
                            error = e.toString();
                        }
                    }
                    put(sb, "decompiled", String.valueOf(ok));
                    put(sb, "file", q(file));
                    put(sb, "error", q(error));
                } catch (Exception e) {
                    errors++;
                    put(sb, "export_error", q(e.toString()));
                }
                sb.setLength(sb.length() - 1);  // drop trailing comma
                sb.append('}');
                w.write(sb.toString());
                w.write('\n');
                if (index % 500 == 0) {
                    w.flush();
                    println("Processed " + index + " functions");
                }
            }
        } finally {
            w.close();
            if (decomp != null) decomp.dispose();
        }

        StringBuilder pj = new StringBuilder("{");
        put(pj, "script_version", q("2"));
        put(pj, "name", q(currentProgram.getName()));
        put(pj, "image_base", q(currentProgram.getImageBase().toString()));
        put(pj, "language", q(currentProgram.getLanguageID().toString()));
        put(pj, "compiler", q(currentProgram.getCompilerSpec().getCompilerSpecID().toString()));
        put(pj, "executable_format", q(currentProgram.getExecutableFormat()));
        put(pj, "function_records", String.valueOf(index));
        put(pj, "decompile_enabled", String.valueOf(doDecomp));
        put(pj, "decompiled", String.valueOf(decompiled));
        put(pj, "export_errors", String.valueOf(errors));
        put(pj, "cancelled", String.valueOf(monitor.isCancelled()));
        pj.setLength(pj.length() - 1);
        pj.append('}');
        // program.json is written last: it doubles as the "export complete" marker.
        Files.write(out.resolve("program.json"), pj.toString().getBytes(StandardCharsets.UTF_8));
        println("Exported " + index + " function records");
    }
}
'''


def assemble_native_outputs(native_dir):
    """Turn functions.jsonl into functions.json / .txt / function_inventory.csv."""
    jl = native_dir / "functions.jsonl"
    functions, bad = [], 0
    with jl.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                functions.append(json.loads(line))
            except ValueError:
                bad += 1
    program = json.loads((native_dir / "program.json").read_text(encoding="utf-8"))
    write_json(native_dir / "functions.json", {"program": program, "functions": functions})

    with (native_dir / "functions.txt").open("w", encoding="utf-8") as f:
        for fn in functions:
            f.write(f"{fn.get('address')}  {fn.get('name')}  "
                    f"decompiled={fn.get('decompiled')}  "
                    f"blocks={fn.get('basic_blocks')}  "
                    f"cc={fn.get('cyclomatic_complexity')}\n")

    cols = ["name", "address", "namespace", "signature", "calling_convention", "return_type",
            "param_count", "size", "basic_blocks", "cyclomatic_complexity", "xref_count",
            "caller_count", "callee_count", "is_thunk", "is_external", "is_entry_point",
            "decompiled", "file"]
    with (native_dir / "function_inventory.csv").open("w", encoding="utf-8", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(cols + ["external_api_count", "external_apis"])
        for fn in functions:
            apis = [f"{c.get('library')}!{c.get('api')}" for c in fn.get("external_calls", [])]
            wr.writerow([fn.get(c) for c in cols] + [len(apis), ";".join(apis)])
    jl.unlink()
    return program, functions, bad


def run_ghidra(dll, native_dir, logs_dir, ghidra, args, timeout):
    """
    Run Ghidra headless in a short local temp folder, copy the results into
    native_dir on success. Failed workspaces are preserved with --debug /
    --keep-failed-temp (and always with --keep-temp).
    """
    temp_base = Path(args.temp_dir).resolve() if args.temp_dir else None
    if temp_base:
        temp_base.mkdir(parents=True, exist_ok=True)
    temp_root = Path(tempfile.mkdtemp(prefix="rea_", dir=str(temp_base) if temp_base else None))
    LOG.info("Ghidra temp folder: %s", temp_root)

    temp_input, temp_project = temp_root / "input", temp_root / "project"
    temp_scripts, temp_out = temp_root / "scripts", temp_root / "out"
    for folder in (temp_input, temp_project, temp_scripts, temp_out):
        folder.mkdir(parents=True, exist_ok=True)

    local_dll = temp_input / dll.name
    shutil.copy2(dll, local_dll)
    script_file = temp_scripts / "ExportDecompiled.java"
    script_file.write_text(GHIDRA_SCRIPT, encoding="utf-8")
    project_name = safe_filename(dll.stem)[:40] + "_Analysis"
    log_path = logs_dir / "ghidra.log"

    ghidra_args = [
        "-scriptPath", temp_scripts, "-import", local_dll,
        "-postScript", "ExportDecompiled.java", temp_out,
        "0" if args.no_decompile else "1", str(args.decompile_timeout),
    ]
    if args.ghidra_analysis_timeout:
        ghidra_args += ["-analysisTimeoutPerFile", str(args.ghidra_analysis_timeout)]
    ghidra_args += ["-deleteProject"]

    ok = False
    try:
        if IS_WINDOWS:
            def q(v):
                return '"' + str(v).replace('"', '""') + '"'
            launcher = temp_root / "run_ghidra.cmd"
            line = (f"call {q(ghidra)} {q(temp_project)} {q(project_name)} "
                    + " ".join(q(a) for a in ghidra_args))
            launcher.write_text("@echo off\r\nsetlocal\r\n" + line + "\r\nexit /b %ERRORLEVEL%\r\n",
                                encoding="utf-8")
            cmd = ["cmd.exe", "/d", "/c", launcher]
        else:
            cmd = [ghidra, temp_project, project_name] + ghidra_args

        rc = run_logged(cmd, log_path, timeout)
        tail = tail_text(log_path)

        if not (temp_out / "program.json").exists():
            raise StageError(categorize(tail, "OUTPUT_MISSING"),
                             f"Ghidra exit {rc}; export did not complete. "
                             f"Last log lines: {tail[-400:].strip()}")
        if rc != 0:
            LOG.warning("Ghidra exit code %s but export completed", rc)

        if native_dir.exists():
            shutil.rmtree(native_dir, ignore_errors=True)
        shutil.copytree(temp_out, native_dir)
        (native_dir / "GhidraScripts").mkdir(exist_ok=True)
        shutil.copy2(script_file, native_dir / "GhidraScripts" / script_file.name)

        program, functions, bad = assemble_native_outputs(native_dir)
        if bad:
            LOG.warning("%d unreadable function records skipped", bad)
        decompiled = sum(1 for f in functions if f.get("decompiled"))
        LOG.info("Ghidra functions: %d | Decompiled: %d", len(functions), decompiled)
        ok = True
        return {"program": program, "functions": functions,
                "total": len(functions), "decompiled": decompiled}
    except StageError as e:
        e.workspace = str(temp_root)
        raise
    finally:
        keep = args.keep_temp or (args.keep_failed_temp and not ok)
        if keep:
            LOG.info("Temp workspace preserved: %s", temp_root)
            emit("workspace_preserved", dll=str(dll), path=str(temp_root), ok=ok)
        else:
            shutil.rmtree(temp_root, ignore_errors=True)


# =========================================================
# P1: Dependency and call graph generation
# =========================================================

def dq(s):
    return (str(s).replace("\\", "\\\\").replace('"', '\\"')
            .replace("\n", "\\n").replace("\r", ""))


def write_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def render_svg(dot_file, engine, timeout=120):
    exe = shutil.which(engine)
    if not exe:
        return False
    svg = dot_file.with_suffix(".svg")
    try:
        r = subprocess.run([exe, "-Tsvg", str(dot_file), "-o", str(svg)],
                           capture_output=True, timeout=timeout)
        return r.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        LOG.warning("Graphviz failed or timed out for %s", dot_file.name)
        return False


def graph_dependencies(dll_name, meta, analysed_names, graphs_dir):
    lines = ["digraph dependencies {", "  rankdir=LR;",
             '  node [shape=box,fontname="Helvetica",fontsize=10];',
             f'  "{dq(dll_name)}" [style=filled,fillcolor="#ffd966"];']
    for d in meta.get("imports", {}).get("dependencies", []):
        name = d["dll"]
        fill = ',style=filled,fillcolor="#bdd7ee"' if name.lower() in analysed_names else ""
        style = ",style=dashed" if d["delay"] else ""
        lines.append(f'  "{dq(name)}" [label="{dq(name)}"{fill}];')
        lines.append(f'  "{dq(dll_name)}" -> "{dq(name)}" '
                     f'[label="{d["function_count"]}"{style}];')
    lines.append("}")
    path = graphs_dir / "dependencies.dot"
    write_text(path, "\n".join(lines) + "\n")
    return path


def graph_pe_imports(dll_name, meta, graphs_dir, max_nodes):
    """DLL -> imported library -> API (PE import table)."""
    lines = ["digraph imports {", "  rankdir=LR;",
             '  node [fontname="Helvetica",fontsize=9];',
             f'  "{dq(dll_name)}" [shape=box,style=filled,fillcolor="#ffd966"];']
    budget = max_nodes
    for i, imp in enumerate(meta.get("imports", {}).get("entries", [])):
        if budget <= 0:
            lines.append('  "truncated" [shape=note,label="graph truncated"];')
            break
        lib = imp["dll"]
        lines.append(f'  subgraph cluster_{i} {{ label="{dq(lib)}"; style=rounded;')
        for fn in imp["functions"]:
            if budget <= 0:
                break
            nm = fn.get("name") or f"#{fn.get('ordinal')}"
            cat = api_category(fn.get("name"))
            fill = ',style=filled,fillcolor="#f4b6b6"' if cat else ""
            lines.append(f'    "{dq(lib)}!{dq(nm)}" [label="{dq(nm)}",shape=ellipse{fill}];')
            budget -= 1
        lines.append("  }")
        lines.append(f'  "{dq(dll_name)}" -> "{dq(lib)}!{dq(imp["functions"][0].get("name") or "#" + str(imp["functions"][0].get("ordinal")))}" '
                     f'[ltail=cluster_{i}];' if imp["functions"] else "")
    lines.append("}")
    path = graphs_dir / "imports.dot"
    write_text(path, "\n".join(l for l in lines if l) + "\n")
    return path


def _fid(addr):
    return "f_" + str(addr).replace("0x", "")


def _select_nodes(by_addr, adj, roots, max_nodes):
    if len(by_addr) <= max_nodes:
        return set(by_addr), ""
    seen, order, dq_ = set(), [], deque(roots)
    while dq_ and len(order) < max_nodes:
        a = dq_.popleft()
        if a in seen or a not in by_addr:
            continue
        seen.add(a)
        order.append(a)
        dq_.extend(adj.get(a, []))
    if not order:
        ranked = sorted(by_addr, key=lambda a: -(by_addr[a].get("caller_count", 0)
                                                 + by_addr[a].get("callee_count", 0)))
        order = ranked[:max_nodes]
    return set(order), f"truncated: {len(order)} of {len(by_addr)} functions shown"


def graph_functions(functions, graphs_dir, max_nodes):
    """call_graph.dot, api_calls.dot, entry_paths.dot/json. Returns list of dot paths."""
    internal = [f for f in functions if not f.get("is_external")]
    by_addr = {f["address"]: f for f in internal}
    adj = {a: [] for a in by_addr}
    for f in internal:
        for c in f.get("callees", []):
            if not c.get("external") and c["address"] in by_addr:
                adj[f["address"]].append(c["address"])
    roots = [a for a, f in by_addr.items() if f.get("is_entry_point")]
    nodes, note = _select_nodes(by_addr, adj, roots, max_nodes)
    produced = []

    # ---- call graph ----
    lines = ["digraph calls {", "  rankdir=LR;",
             '  node [shape=box,fontname="Helvetica",fontsize=9];',
             f'  label="{dq(note)}"; labelloc=t;' if note else ""]
    for a in nodes:
        f = by_addr[a]
        attrs = f'label="{dq(f["name"][:60])}"'
        if f.get("is_entry_point"):
            attrs += ',style=filled,fillcolor="#c6efce",penwidth=2'
        elif any(api_category(c.get("api")) for c in f.get("external_calls", [])):
            attrs += ',style=filled,fillcolor="#f4b6b6"'
        elif f.get("is_thunk"):
            attrs += ",style=dashed"
        lines.append(f'  {_fid(a)} [{attrs}];')
    for a in nodes:
        for b in adj[a]:
            if b in nodes:
                lines.append(f"  {_fid(a)} -> {_fid(b)};")
    lines.append("}")
    p = graphs_dir / "call_graph.dot"
    write_text(p, "\n".join(l for l in lines if l) + "\n")
    produced.append(p)

    # ---- function -> imported API relationships ----
    lines = ["digraph api_calls {", "  rankdir=LR;",
             '  node [fontname="Helvetica",fontsize=9];']
    libs, edge_lines, budget = {}, [], 3000
    for a in nodes:
        f = by_addr[a]
        for c in f.get("external_calls", []):
            if budget <= 0:
                break
            api_id = f'api_{c.get("library")}!{c.get("api")}'
            libs.setdefault(c.get("library") or "?", set()).add((api_id, c.get("api")))
            edge_lines.append(f'  {_fid(a)} -> "{dq(api_id)}";')
            budget -= 1
    used = {e.split(" -> ")[0].strip() for e in edge_lines}
    for a in nodes:
        if _fid(a) in used:
            lines.append(f'  {_fid(a)} [shape=box,label="{dq(by_addr[a]["name"][:60])}"];')
    for i, (lib, apis) in enumerate(sorted(libs.items())):
        lines.append(f'  subgraph cluster_{i} {{ label="{dq(lib)}"; style=rounded;')
        for api_id, api in sorted(apis):
            fill = ',style=filled,fillcolor="#f4b6b6"' if api_category(api) else ""
            lines.append(f'    "{dq(api_id)}" [label="{dq(api)}",shape=ellipse{fill}];')
        lines.append("  }")
    lines += edge_lines
    lines.append("}")
    p = graphs_dir / "api_calls.dot"
    write_text(p, "\n".join(lines) + "\n")
    produced.append(p)

    # ---- entry points -> API execution paths ----
    entry_report, union_edges, union_nodes, union_apis = [], set(), set(), set()
    for r in roots:
        parent, depth = {r: None}, {r: 0}
        queue = deque([r])
        while queue:
            cur = queue.popleft()
            if depth[cur] >= 12:
                continue
            for nxt in adj.get(cur, []):
                if nxt not in parent:
                    parent[nxt] = cur
                    depth[nxt] = depth[cur] + 1
                    queue.append(nxt)
        paths = []
        for a in parent:
            chain, cur = [], a
            while cur is not None:
                chain.append(cur)
                cur = parent[cur]
            chain.reverse()
            for c in by_addr[a].get("external_calls", []):
                paths.append({"api": f'{c.get("library")}!{c.get("api")}',
                              "category": api_category(c.get("api")),
                              "depth": len(chain),
                              "path": [by_addr[x]["name"] for x in chain],
                              "_chain": chain})
        paths.sort(key=lambda p: (p["category"] is None, p["depth"]))
        kept = paths[:100]
        for p_ in kept:
            ch = p_["_chain"]
            union_nodes.update(ch)
            union_edges.update(zip(ch, ch[1:]))
            union_apis.add((ch[-1], p_["api"], p_["category"]))
        for p_ in kept:
            del p_["_chain"]
        entry_report.append({"entry": {"name": by_addr[r]["name"], "address": r},
                             "reachable_functions": len(parent),
                             "api_path_count": len(paths), "paths": kept})
    write_json(graphs_dir / "entry_paths.json", entry_report)

    lines = ["digraph entry_paths {", "  rankdir=LR;",
             '  node [fontname="Helvetica",fontsize=9];']
    for a in union_nodes:
        extra = ',style=filled,fillcolor="#c6efce",penwidth=2' if a in roots else ""
        lines.append(f'  {_fid(a)} [shape=box,label="{dq(by_addr[a]["name"][:60])}"{extra}];')
    for a, b in union_edges:
        lines.append(f"  {_fid(a)} -> {_fid(b)};")
    for fa, api, cat in union_apis:
        fill = ',style=filled,fillcolor="#f4b6b6"' if cat else ""
        lines.append(f'  "{dq(api)}" [shape=ellipse{fill}];')
        lines.append(f'  {_fid(fa)} -> "{dq(api)}";')
    lines.append("}")
    p = graphs_dir / "entry_paths.dot"
    write_text(p, "\n".join(lines) + "\n")
    produced.append(p)
    return produced


def graph_global_dependencies(inv, analysed_names, out_root, include_external, args):
    rows = inv.dependency_edges()
    lines = ["digraph dll_dependencies {", "  rankdir=LR;",
             '  node [shape=box,fontname="Helvetica",fontsize=8];']
    nodes, edges = set(), []
    for src, dst, delay, count in rows:
        if not include_external and dst.lower() not in analysed_names:
            continue
        nodes.update((src, dst))
        edges.append((src, dst, delay, count))
    for n in sorted(nodes):
        fill = '[style=filled,fillcolor="#bdd7ee"]' if n.lower() in analysed_names else ""
        lines.append(f'  "{dq(n)}" {fill};')
    for src, dst, delay, count in edges:
        style = " [style=dashed]" if delay else ""
        lines.append(f'  "{dq(src)}" -> "{dq(dst)}"{style};')
    lines.append("}")
    path = out_root / "graphs" / "dll_dependencies.dot"
    write_text(path, "\n".join(lines) + "\n")
    LOG.info("Global dependency graph: %d nodes, %d edges -> %s", len(nodes), len(edges), path)
    if args.svg:
        if len(nodes) > args.graph_max_nodes * 2:
            LOG.info("Global graph too large for SVG (%d nodes); render manually, e.g. "
                     "sfdp -Tsvg dll_dependencies.dot -o out.svg", len(nodes))
        else:
            render_svg(path, args.dot_engine, 300)
    return path


# =========================================================
# P1: Incremental manifest (resume state)
# =========================================================

STAGES = ("ilspy", "ghidra")
STAGE_VERSION_KEYS = {"ilspy": ("ilspy",), "ghidra": ("ghidra", "script", "decompile")}


class Manifest:
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS dlls (
        rel_path TEXT PRIMARY KEY,
        sha256 TEXT, size INTEGER, mtime_ns INTEGER,
        binary_type TEXT, architecture TEXT,
        status TEXT DEFAULT 'PENDING',
        ilspy_status TEXT DEFAULT 'PENDING',
        ghidra_status TEXT DEFAULT 'PENDING',
        tool_versions TEXT, pipeline_version TEXT,
        output_dir TEXT, attempts INTEGER DEFAULT 0,
        last_error TEXT, error_category TEXT,
        csharp_files INTEGER DEFAULT 0,
        native_functions INTEGER DEFAULT 0,
        native_decompiled INTEGER DEFAULT 0,
        preserved_workspace TEXT,
        started_at TEXT, finished_at TEXT, duration REAL, updated_at TEXT
    );
    """

    def __init__(self, path):
        self.conn = sqlite3.connect(str(path), isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(self.SCHEMA)

    def get(self, rel):
        r = self.conn.execute("SELECT * FROM dlls WHERE rel_path=?", (rel,)).fetchone()
        return dict(r) if r else None

    def upsert(self, rel, **fields):
        fields["updated_at"] = iso_now()
        self.conn.execute("INSERT OR IGNORE INTO dlls(rel_path) VALUES(?)", (rel,))
        cols = ", ".join(f"{k}=?" for k in fields)
        self.conn.execute(f"UPDATE dlls SET {cols} WHERE rel_path=?", (*fields.values(), rel))

    def mark_stale_running(self):
        cur = self.conn.execute(
            "UPDATE dlls SET status='INTERRUPTED' WHERE status='RUNNING'")
        if cur.rowcount:
            LOG.info("Recovered %d DLL(s) left RUNNING by a previous crash", cur.rowcount)

    def all_rows(self):
        return [dict(r) for r in self.conn.execute("SELECT * FROM dlls ORDER BY rel_path")]

    def counts(self):
        return {r[0]: r[1] for r in self.conn.execute(
            "SELECT status, COUNT(*) FROM dlls GROUP BY status")}


def stage_applicable(binary_type):
    if binary_type == "MANAGED_DOTNET":
        return {"ilspy"}
    if binary_type == "MIXED_MODE":
        return {"ilspy", "ghidra"}
    if binary_type in ("NATIVE", "CLR_HEADER_UNRESOLVED"):
        return {"ghidra"}
    return set()


def artifact_ok(stage, dll_out):
    if stage == "ilspy":
        src = dll_out / "Generated_CSharp" / "Source"
        return src.is_dir() and any(src.rglob("*.cs"))
    return (dll_out / "Generated_Native" / "functions.json").is_file()


def stale_stages(row, ctx):
    """Stages whose recorded tool versions no longer match."""
    old = json.loads(row.get("tool_versions") or "{}")
    new, stale = ctx.versions, set()
    if old.get("script") != new["script"]:
        stale.add("ghidra")                      # output format changed
    if new["decompile"] and old.get("decompile") is False:
        stale.add("ghidra")                      # decompilation newly requested
    if ctx.args.reanalyse_on_tool_change:
        if old.get("ilspy") not in (None, new["ilspy"]):
            stale.add("ilspy")
        if old.get("ghidra") not in (None, new["ghidra"]):
            stale.add("ghidra")
    return stale


def decide(row, sha, dll_out, ctx):
    a = ctx.args
    failed_like = ("FAILED", "PARTIAL", "INTERRUPTED", "RUNNING", "PENDING")
    if a.only_failed and (row is None or row["status"] not in failed_like):
        return "skip", "not failed"
    if row is None:
        return "run", "new"
    if row["sha256"] != sha:
        return "run", "hash changed"
    if a.force:
        return "run", "forced"
    applicable = stage_applicable(row.get("binary_type"))
    stale = stale_stages(row, ctx) & applicable
    if (row["status"] == "SUCCESS" and not stale
            and all(artifact_ok(s, dll_out) for s in applicable)
            and (dll_out / "analysis_summary.json").exists()
            and (a.no_copy_original or (dll_out / "Original" / Path(row["rel_path"]).name).is_file())):
        return "skip", "up to date"
    if (row["status"] == "FAILED" and row.get("error_category") in PERMANENT
            and not a.retry_failed):
        return "skip", f"permanent failure ({row['error_category']}); use --retry-failed"
    return "run", "resume/retry"


# =========================================================
# P1: Searchable inventory
# =========================================================

class Inventory:
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS dlls (
        id INTEGER PRIMARY KEY, rel_path TEXT UNIQUE, name TEXT, sha256 TEXT,
        binary_type TEXT, arch TEXT, imphash TEXT, timestamp_utc TEXT, image_base TEXT,
        entry_point_rva TEXT, subsystem TEXT, pdb_path TEXT, pdb_guid TEXT,
        file_version TEXT, product_version TEXT, company TEXT, original_filename TEXT,
        description TEXT, tls_callbacks INTEGER, import_count INTEGER,
        export_count INTEGER, function_count INTEGER);
    CREATE TABLE IF NOT EXISTS exports (dll_id INTEGER, ordinal INTEGER, name TEXT,
        rva TEXT, forwarder TEXT);
    CREATE TABLE IF NOT EXISTS imports (dll_id INTEGER, dll_name TEXT, function TEXT,
        ordinal INTEGER, delay INTEGER);
    CREATE TABLE IF NOT EXISTS dependencies (dll_id INTEGER, depends_on TEXT,
        delay INTEGER, function_count INTEGER);
    CREATE TABLE IF NOT EXISTS functions (id INTEGER PRIMARY KEY, dll_id INTEGER,
        name TEXT, address TEXT, namespace TEXT, signature TEXT, calling_convention TEXT,
        return_type TEXT, param_count INTEGER, params_json TEXT, size INTEGER,
        basic_blocks INTEGER, complexity INTEGER, xref_count INTEGER, caller_count INTEGER,
        callee_count INTEGER, is_thunk INTEGER, is_external INTEGER, is_entry_point INTEGER,
        decompiled INTEGER, decompiled_file TEXT);
    CREATE TABLE IF NOT EXISTS api_calls (dll_id INTEGER, function_address TEXT,
        function_name TEXT, library TEXT, api TEXT, category TEXT);
    CREATE INDEX IF NOT EXISTS ix_imports_fn ON imports(function);
    CREATE INDEX IF NOT EXISTS ix_exports_name ON exports(name);
    CREATE INDEX IF NOT EXISTS ix_functions_name ON functions(name);
    CREATE INDEX IF NOT EXISTS ix_functions_dll ON functions(dll_id);
    CREATE INDEX IF NOT EXISTS ix_api_api ON api_calls(api);
    CREATE INDEX IF NOT EXISTS ix_dep_on ON dependencies(depends_on);
    """

    def __init__(self, path):
        self.conn = sqlite3.connect(str(path), isolation_level=None)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(self.SCHEMA)
        try:
            self.conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS functions_fts "
                              "USING fts5(name, signature, namespace)")
            self.fts = True
        except sqlite3.OperationalError:
            self.fts = False
            LOG.warning("SQLite FTS5 unavailable; function search falls back to LIKE")

    def count(self):
        return self.conn.execute("SELECT COUNT(*) FROM dlls").fetchone()[0]

    def _delete(self, dll_id):
        c = self.conn
        if self.fts:
            c.execute("DELETE FROM functions_fts WHERE rowid IN "
                      "(SELECT id FROM functions WHERE dll_id=?)", (dll_id,))
        for t in ("exports", "imports", "dependencies", "functions", "api_calls"):
            c.execute(f"DELETE FROM {t} WHERE dll_id=?", (dll_id,))
        c.execute("DELETE FROM dlls WHERE id=?", (dll_id,))

    def index_dll(self, rel, name, sha, meta, functions):
        c = self.conn
        vi = (meta.get("version_info") or {})
        strings, fixed = vi.get("strings", {}), vi.get("fixed") or {}
        dbg = next((d for d in meta.get("debug", []) if d.get("pdb_path")), {})
        imports = meta.get("imports", {})
        exports = meta.get("exports") or {}
        c.execute("BEGIN")
        try:
            row = c.execute("SELECT id FROM dlls WHERE rel_path=?", (rel,)).fetchone()
            if row:
                self._delete(row[0])
            cur = c.execute(
                "INSERT INTO dlls(rel_path,name,sha256,binary_type,arch,imphash,timestamp_utc,"
                "image_base,entry_point_rva,subsystem,pdb_path,pdb_guid,file_version,"
                "product_version,company,original_filename,description,tls_callbacks,"
                "import_count,export_count,function_count) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (rel, name, sha, meta.get("binary_type"), meta.get("architecture"),
                 imports.get("imphash"), meta.get("timestamp_utc"), meta.get("image_base"),
                 meta.get("entry_point_rva"), meta.get("subsystem_name"),
                 dbg.get("pdb_path"), dbg.get("guid"),
                 strings.get("FileVersion") or fixed.get("file_version"),
                 strings.get("ProductVersion") or fixed.get("product_version"),
                 strings.get("CompanyName"), strings.get("OriginalFilename"),
                 strings.get("FileDescription"),
                 len((meta.get("tls") or {}).get("callbacks", [])),
                 imports.get("function_count", 0), exports.get("count", 0),
                 len(functions)))
            dll_id = cur.lastrowid
            c.executemany("INSERT INTO exports VALUES(?,?,?,?,?)",
                          [(dll_id, e.get("ordinal"), e.get("name"), e.get("rva"),
                            e.get("forwarder")) for e in exports.get("entries", [])])
            c.executemany("INSERT INTO imports VALUES(?,?,?,?,?)",
                          [(dll_id, imp["dll"], fn.get("name"), fn.get("ordinal"),
                            int(imp["delay"]))
                           for imp in imports.get("entries", []) for fn in imp["functions"]])
            c.executemany("INSERT INTO dependencies VALUES(?,?,?,?)",
                          [(dll_id, d["dll"], int(d["delay"]), d["function_count"])
                           for d in imports.get("dependencies", [])])
            api_rows = []
            for f in functions:
                cur = c.execute(
                    "INSERT INTO functions(dll_id,name,address,namespace,signature,"
                    "calling_convention,return_type,param_count,params_json,size,basic_blocks,"
                    "complexity,xref_count,caller_count,callee_count,is_thunk,is_external,"
                    "is_entry_point,decompiled,decompiled_file) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (dll_id, f.get("name"), f.get("address"), f.get("namespace"),
                     f.get("signature"), f.get("calling_convention"), f.get("return_type"),
                     f.get("param_count"), json.dumps(f.get("parameters", [])),
                     f.get("size"), f.get("basic_blocks"), f.get("cyclomatic_complexity"),
                     f.get("xref_count"), f.get("caller_count"), f.get("callee_count"),
                     int(bool(f.get("is_thunk"))), int(bool(f.get("is_external"))),
                     int(bool(f.get("is_entry_point"))), int(bool(f.get("decompiled"))),
                     f.get("file")))
                if self.fts:
                    c.execute("INSERT INTO functions_fts(rowid,name,signature,namespace) "
                              "VALUES(?,?,?,?)",
                              (cur.lastrowid, f.get("name"), f.get("signature"),
                               f.get("namespace")))
                for call in f.get("external_calls", []):
                    api_rows.append((dll_id, f.get("address"), f.get("name"),
                                     call.get("library"), call.get("api"),
                                     api_category(call.get("api"))))
            c.executemany("INSERT INTO api_calls VALUES(?,?,?,?,?,?)", api_rows)
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise

    def dependency_edges(self):
        return self.conn.execute(
            "SELECT d.name, x.depends_on, x.delay, x.function_count "
            "FROM dependencies x JOIN dlls d ON d.id = x.dll_id").fetchall()


def load_functions(dll_out):
    fp = dll_out / "Generated_Native" / "functions.json"
    if not fp.is_file():
        return []
    try:
        return json.loads(fp.read_text(encoding="utf-8")).get("functions", [])
    except (OSError, ValueError):
        return []


def reindex_all(manifest, inv, output_root, input_root):
    LOG.info("Rebuilding inventory.db from existing outputs ...")
    n = 0
    for row in manifest.all_rows():
        if row["status"] not in ("SUCCESS", "PARTIAL"):
            continue
        dll_out = Path(row["output_dir"]) if row.get("output_dir") else None
        if not dll_out or not (dll_out / "pe_metadata.json").is_file():
            continue
        try:
            meta = json.loads((dll_out / "pe_metadata.json").read_text(encoding="utf-8"))
            inv.index_dll(row["rel_path"], Path(row["rel_path"]).name, row["sha256"],
                          meta, load_functions(dll_out))
            n += 1
        except Exception as e:
            LOG.warning("Reindex failed for %s: %s", row["rel_path"], e)
    LOG.info("Reindexed %d DLLs", n)


# =========================================================
# P1: Per-DLL processing with retries
# =========================================================

def run_stage(name, fn, ctx, base_timeout, dll_name):
    """Run one stage with retry policy. Returns (result, attempts)."""
    a = ctx.args
    timeout, attempt = base_timeout, 0
    while True:
        attempt += 1
        t0 = time.monotonic()
        try:
            result = fn(timeout)
            emit("stage_ok", dll=dll_name, stage=name, attempt=attempt,
                 duration=round(time.monotonic() - t0, 1))
            return result, attempt
        except Interrupted:
            emit("stage_interrupted", dll=dll_name, stage=name, attempt=attempt)
            raise
        except StageError as e:
            err = e
        except Exception as e:
            err = StageError(categorize(f"{type(e).__name__}: {e}"),
                             f"{type(e).__name__}: {e}")
            LOG.debug("Unexpected exception in %s", name, exc_info=True)
        LOG.error("%s failed [%s] attempt %d: %s", name, err.category, attempt,
                  err.message[:300])
        emit("stage_failed", dll=dll_name, stage=name, attempt=attempt,
             category=err.category, message=err.message[:500],
             workspace=getattr(err, "workspace", None))
        if err.retryable and attempt <= a.retries and not STOP.is_set():
            if err.category == "TIMEOUT":
                timeout = int(timeout * a.timeout_multiplier)
            delay = a.retry_backoff * (2 ** (attempt - 1))
            LOG.info("Retrying %s in %.0fs (timeout now %ss)", name, delay, timeout)
            if STOP.wait(delay):
                raise Interrupted()
            continue
        raise err


def process_dll(dll, rel, sha, row, dll_out, ctx):
    a = ctx.args
    rel_s = rel.as_posix()
    logs_dir = dll_out / "Logs"
    graphs_dir = dll_out / "Graphs"
    dll_out.mkdir(parents=True, exist_ok=True)
    t_start = time.monotonic()

    hash_same = bool(row) and row["sha256"] == sha and not a.force
    prev_stage = {s: (row.get(f"{s}_status") if hash_same else "PENDING") for s in STAGES} \
        if row else {s: "PENDING" for s in STAGES}
    old_versions = json.loads(row.get("tool_versions") or "{}") if hash_same else {}
    stale = stale_stages(row, ctx) if hash_same else set()

    result = {"dll": str(dll), "rel_path": rel_s, "sha256": sha, "status": "FAILED",
              "binary_type": "UNKNOWN", "csharp_files": 0, "native_functions": 0,
              "native_decompiled_functions": 0, "output": str(dll_out),
              "stages": {}, "errors": [], "warnings": []}

    with dll_log(logs_dir / "pipeline.log"):
        LOG.info("=" * 70)
        LOG.info("[DLL] %s", dll)
        LOG.info("[OUT] %s", dll_out)
        ctx.manifest.upsert(rel_s, status="RUNNING", sha256=sha,
                            size=dll.stat().st_size, mtime_ns=dll.stat().st_mtime_ns,
                            output_dir=str(dll_out), started_at=iso_now(),
                            attempts=(row["attempts"] if row else 0) + 1,
                            pipeline_version=PIPELINE_VERSION)
        emit("dll_start", dll=rel_s, sha256=sha)

        stage_status = dict(prev_stage)
        stage_attempts_err = []
        first_category = None
        new_versions = dict(old_versions)
        workspace = None
        interrupted = False

        try:
            meta = inspect_pe(dll)
            binary_type = meta["binary_type"]
            result["binary_type"] = binary_type
            LOG.info("Binary type: %s | Architecture: %s", binary_type, meta["architecture"])
            for w in meta.get("warnings", []):
                LOG.warning("PE parse warning: %s", w)
            write_json(dll_out / "pe_metadata.json", meta)
            if not a.no_copy_original:
                try:
                    copy_original(dll, dll_out, sha)
                    LOG.info("Original DLL copied to %s", dll_out / "Original")
                except Exception as e:
                    LOG.warning("Could not copy original DLL: %s", e)
                    result["warnings"].append(f"copy_original: {e}")

            candidates = [dll.parent, dll.parent / "DLL_Analysis",
                          dll.parent / f"{dll.stem}_Analysis"]
            analysis_dir = next((p for p in candidates
                                 if (p / "managed-info.json").exists()
                                 or (p / "managed-members.json").exists()), dll.parent)
            info, members = load_analysis(analysis_dir)

            applicable = stage_applicable(binary_type)
            for s in STAGES:
                if s not in applicable:
                    stage_status[s] = "NA"

            if binary_type == "INVALID_OR_UNKNOWN":
                result["errors"].append(
                    {"stage": "pe", "category": "INVALID_BINARY",
                     "message": "Could not identify a valid PE binary"})
                first_category = "INVALID_BINARY"

            done = {s for s in applicable
                    if prev_stage.get(s) == "DONE" and s not in stale and artifact_ok(s, dll_out)}
            todo = [s for s in STAGES if s in applicable and s not in done]
            for s in done:
                LOG.info("Stage %s already complete - skipped", s)
                stage_status[s] = "DONE"
            if row and hash_same:
                result["csharp_files"] = row.get("csharp_files") or 0
                result["native_functions"] = row.get("native_functions") or 0
                result["native_decompiled_functions"] = row.get("native_decompiled") or 0

            functions = None
            ran_ghidra = False

            # ---- managed ----
            if "ilspy" in todo:
                csharp_dir = dll_out / "Generated_CSharp"
                try:
                    if not ctx.ilspy:
                        raise StageError("TOOL_MISSING",
                                         "ilspycmd not found (dotnet tool install --global ilspycmd)")

                    def _ilspy(timeout):
                        n = decompile_managed(dll, csharp_dir, ctx.ilspy,
                                              logs_dir / "ilspy.log", timeout)
                        export_il(dll, csharp_dir, ctx.ilspy, logs_dir / "ilspy.log", timeout)
                        return n

                    result["csharp_files"], _ = run_stage("ilspy", _ilspy, ctx,
                                                          a.ilspy_timeout, rel_s)
                    stage_status["ilspy"] = "DONE"
                    for k in STAGE_VERSION_KEYS["ilspy"]:
                        new_versions[k] = ctx.versions[k]
                except Interrupted:
                    stage_status["ilspy"] = "INTERRUPTED"
                    raise
                except StageError as e:
                    stage_status["ilspy"] = "FAILED"
                    first_category = first_category or e.category
                    result["errors"].append({"stage": "ilspy", "category": e.category,
                                             "message": e.message[:1000]})

            # ---- native ----
            if "ghidra" in todo:
                native_dir = dll_out / "Generated_Native"
                try:
                    if not ctx.ghidra:
                        raise StageError("TOOL_MISSING",
                                         f"Ghidra launcher not found: {a.ghidra}")

                    def _ghidra(timeout):
                        return run_ghidra(dll, native_dir, logs_dir, ctx.ghidra, a, timeout)

                    g, _ = run_stage("ghidra", _ghidra, ctx, a.ghidra_timeout, rel_s)
                    result["native_functions"] = g["total"]
                    result["native_decompiled_functions"] = g["decompiled"]
                    functions = g["functions"]
                    ran_ghidra = True
                    stage_status["ghidra"] = "DONE"
                    for k in STAGE_VERSION_KEYS["ghidra"]:
                        new_versions[k] = ctx.versions[k]
                except Interrupted:
                    stage_status["ghidra"] = "INTERRUPTED"
                    raise
                except StageError as e:
                    stage_status["ghidra"] = "FAILED"
                    first_category = first_category or e.category
                    workspace = getattr(e, "workspace", None) if (
                        a.keep_failed_temp or a.keep_temp) else None
                    result["errors"].append({"stage": "ghidra", "category": e.category,
                                             "message": e.message[:1000],
                                             "workspace": workspace})

            # ---- reports, graphs, index (best-effort, never fail the DLL) ----
            try:
                if functions is None and "ghidra" in applicable and \
                        stage_status.get("ghidra") == "DONE":
                    functions = load_functions(dll_out)
                functions = functions or []

                write_json(dll_out / "analysis_summary.json", {
                    "dll": dll.name, "dll_path": str(dll), "sha256": sha,
                    "file_size": dll.stat().st_size, "binary_type": binary_type,
                    "architecture": meta["architecture"],
                    "timestamp_utc": meta.get("timestamp_utc"),
                    "imphash": meta["imports"]["imphash"] if "imports" in meta else None,
                    "export_count": (meta.get("exports") or {}).get("count", 0),
                    "import_function_count": meta.get("imports", {}).get("function_count", 0),
                    "dependencies": [d["dll"] for d in
                                     meta.get("imports", {}).get("dependencies", [])],
                    "api_categories": meta.get("api_categories", {}),
                    "native_function_count": len(functions),
                    "managed_info": info, "managed_members": members})

                if not a.no_graphs and meta["valid_pe"]:
                    produced = [graph_dependencies(dll.name, meta, ctx.analysed_names, graphs_dir),
                                graph_pe_imports(dll.name, meta, graphs_dir, a.graph_max_nodes)]
                    if functions and (ran_ghidra or not (graphs_dir / "call_graph.dot").exists()):
                        produced += graph_functions(functions, graphs_dir, a.graph_max_nodes)
                    elif functions:
                        produced += [p for p in graphs_dir.glob("*.dot")]
                    if a.svg:
                        if not shutil.which(a.dot_engine):
                            LOG.warning("Graphviz '%s' not on PATH - skipping SVG", a.dot_engine)
                        else:
                            for p in set(produced):
                                render_svg(p, a.dot_engine)

                if meta["valid_pe"]:
                    ctx.inventory.index_dll(rel_s, dll.name, sha, meta, functions)
            except Exception as e:
                LOG.warning("Post-processing problem (non-fatal): %s", e)
                LOG.debug("post-processing traceback", exc_info=True)
                result["warnings"].append(f"post-processing: {e}")

        except Interrupted:
            interrupted = True

        # ---- final status ----
        applicable_now = {s for s in STAGES if stage_status.get(s) not in ("NA",)}
        done_now = {s for s in applicable_now if stage_status[s] == "DONE"}
        if interrupted:
            status = "INTERRUPTED"
        elif result["binary_type"] == "INVALID_OR_UNKNOWN":
            status = "FAILED"
        elif applicable_now and done_now == applicable_now:
            status = "SUCCESS"
        elif done_now:
            status = "PARTIAL"
        else:
            status = "FAILED"
        result["status"] = status
        result["stages"] = stage_status
        duration = round(time.monotonic() - t_start, 1)

        last_error = "; ".join(f"{e['stage']}[{e['category']}]: {e['message'][:200]}"
                               for e in result["errors"]) or None
        ctx.manifest.upsert(
            rel_s, status=status, binary_type=result["binary_type"],
            architecture=locals().get("meta", {}).get("architecture"),
            ilspy_status=stage_status["ilspy"], ghidra_status=stage_status["ghidra"],
            tool_versions=json.dumps(new_versions),
            error_category=first_category if status in ("FAILED", "PARTIAL") else None,
            last_error=last_error if status in ("FAILED", "PARTIAL") else None,
            csharp_files=result["csharp_files"], native_functions=result["native_functions"],
            native_decompiled=result["native_decompiled_functions"],
            preserved_workspace=workspace, finished_at=iso_now(), duration=duration)
        write_json(dll_out / "processing_result.json", result)
        emit("dll_end", dll=rel_s, status=status, category=first_category, duration=duration)
        LOG.info("Result: %s (%.1fs)", status, duration)

    if interrupted:
        raise Interrupted()
    result["category"] = first_category
    return result


# =========================================================
# Main
# =========================================================

def print_status(manifest):
    counts = manifest.counts()
    rows = manifest.all_rows()
    print("\nManifest status")
    print("-" * 40)
    for k in sorted(counts):
        print(f"  {k:<12} {counts[k]}")
    print(f"  {'TOTAL':<12} {sum(counts.values())}")
    cats = Counter(r["error_category"] for r in rows if r["status"] in ("FAILED", "PARTIAL"))
    if cats:
        print("\nFailure categories")
        for k, v in cats.most_common():
            print(f"  {k or 'UNKNOWN':<16} {v}")
    failed = [r for r in rows if r["status"] in ("FAILED", "PARTIAL", "INTERRUPTED")]
    if failed:
        print("\nNeeding attention (first 25)")
        for r in failed[:25]:
            print(f"  {r['status']:<11} {r['error_category'] or '-':<15} {r['rel_path']}")


def parse_args():
    p = argparse.ArgumentParser(
        description="Recursive managed + native DLL reverse engineering (ILSpy + Ghidra), "
                    "incremental and resumable")
    p.add_argument("--input", required=True, help="Root folder containing DLL files")
    p.add_argument("--output", required=True, help="Output root folder")
    p.add_argument("--ghidra", default=GHIDRA_DEFAULT, help="Path to analyzeHeadless(.bat)")
    p.add_argument("--temp-dir", default=None,
                   help="Short local base folder for Ghidra work dirs, e.g. C:\\re\\tmp")
    p.add_argument("--filter", default=None,
                   help="Only process DLLs whose relative path matches this glob (case-insensitive)")

    g = p.add_argument_group("incremental / resume")
    g.add_argument("--force", action="store_true", help="Reanalyse everything")
    g.add_argument("--only-failed", action="store_true",
                   help="Process only DLLs that previously failed / were interrupted")
    g.add_argument("--retry-failed", action="store_true",
                   help="Also retry permanent failures (e.g. INVALID_BINARY)")
    g.add_argument("--reanalyse-on-tool-change", action="store_true",
                   help="Reanalyse when ILSpy/Ghidra version differs from the recorded one")
    g.add_argument("--verify-hashes", action="store_true",
                   help="Always re-hash files (default trusts size+mtime to skip hashing)")
    g.add_argument("--reindex", action="store_true", help="Rebuild inventory.db from outputs")
    g.add_argument("--status", action="store_true", help="Show manifest status and exit")

    g = p.add_argument_group("reliability")
    g.add_argument("--retries", type=int, default=1, help="Retries per stage for retryable errors")
    g.add_argument("--retry-backoff", type=float, default=10.0, help="Seconds; doubles each retry")
    g.add_argument("--timeout-multiplier", type=float, default=1.5,
                   help="Timeout growth after a TIMEOUT failure")
    g.add_argument("--ilspy-timeout", type=int, default=1800)
    g.add_argument("--ghidra-timeout", type=int, default=3600)
    g.add_argument("--ghidra-analysis-timeout", type=int, default=None,
                   help="Pass -analysisTimeoutPerFile <sec> to Ghidra")
    g.add_argument("--no-decompile", action="store_true",
                   help="Export function metadata only (much faster)")
    g.add_argument("--decompile-timeout", type=int, default=120, help="Per-function seconds")
    g.add_argument("--keep-temp", action="store_true", help="Never delete Ghidra temp folders")
    g.add_argument("--keep-failed-temp", action="store_true",
                   help="Keep temp folders of failed Ghidra runs for troubleshooting")
    g.add_argument("--debug", action="store_true",
                   help="Verbose console + --keep-failed-temp")

    p.add_argument("--no-copy-original", action="store_true",
                   help="Do not copy the source DLL into its output folder (default: copy)")

    g = p.add_argument_group("graphs")
    g.add_argument("--no-graphs", action="store_true")
    g.add_argument("--svg", action="store_true", help="Also render SVG via Graphviz")
    g.add_argument("--dot-engine", default="dot", help="Graphviz engine (dot, sfdp, ...)")
    g.add_argument("--graph-max-nodes", type=int, default=800)
    g.add_argument("--graph-include-external", action="store_true",
                   help="Global dependency graph includes DLLs outside the input set")
    args = p.parse_args()
    if args.debug:
        args.keep_failed_temp = True
    return args


def main():
    global EVENTS_FILE
    args = parse_args()
    root_dir = Path(args.input).resolve()
    output_root = Path(args.output).resolve()
    if not root_dir.is_dir():
        sys.exit("[-] Input directory does not exist")
    output_root.mkdir(parents=True, exist_ok=True)

    setup_logging(output_root, args.debug)
    EVENTS_FILE = output_root / "events.jsonl"
    install_signal_handlers()

    manifest = Manifest(output_root / "manifest.db")
    if args.status:
        print_status(manifest)
        return 0
    manifest.mark_stale_running()
    inventory = Inventory(output_root / "inventory.db")

    ilspy = find_ilspy()
    ghidra = find_ghidra(args.ghidra)
    if not ilspy:
        LOG.warning("ilspycmd not found - managed DLLs will fail with TOOL_MISSING "
                    "(dotnet tool install --global ilspycmd)")
    if not ghidra:
        LOG.warning("Ghidra launcher not found at %s - native DLLs will fail with TOOL_MISSING",
                    args.ghidra)
    versions = {"pipeline": PIPELINE_VERSION, "python": platform.python_version(),
                "ilspy": ilspy_version(ilspy), "ghidra": ghidra_version(ghidra),
                "script": GHIDRA_SCRIPT_VERSION, "decompile": not args.no_decompile}
    LOG.info("Tools: %s", json.dumps(versions))
    LOG.info("Input: %s | Output: %s", root_dir, output_root)

    dll_files = sorted(
        p for p in root_dir.rglob("*")
        if p.is_file() and p.suffix.lower() == ".dll"
        and output_root not in p.parents and p.parent != output_root)
    if args.filter:
        pat = args.filter.lower()
        dll_files = [p for p in dll_files
                     if fnmatch.fnmatch(p.relative_to(root_dir).as_posix().lower(), pat)]
    if not dll_files:
        sys.exit("[-] No DLL files found")

    analysed_names = {p.name.lower() for p in dll_files}

    if not args.filter:
        present = {p.relative_to(root_dir).as_posix() for p in dll_files}
        gone = [r["rel_path"] for r in manifest.all_rows() if r["rel_path"] not in present]
        for rel_gone in gone:
            manifest.conn.execute("DELETE FROM dlls WHERE rel_path=?", (rel_gone,))
        if gone:
            LOG.info("Removed %d manifest entries for DLLs no longer in the input tree "
                     "(their output folders are left untouched)", len(gone))
    ctx = SimpleNamespace(args=args, manifest=manifest, inventory=inventory, ilspy=ilspy,
                          ghidra=ghidra, versions=versions, analysed_names=analysed_names,
                          output_root=output_root)

    if args.reindex or inventory.count() == 0:
        if any(r["status"] in ("SUCCESS", "PARTIAL") for r in manifest.all_rows()):
            reindex_all(manifest, inventory, output_root, root_dir)

    LOG.info("DLL count: %d", len(dll_files))
    results, skipped, interrupted = [], Counter(), False
    t_batch = time.monotonic()

    for index, dll in enumerate(dll_files, start=1):
        if STOP.is_set():
            interrupted = True
            break
        rel = dll.relative_to(root_dir)
        rel_s = rel.as_posix()
        dll_out = output_root / rel.parent / dll.stem
        row = manifest.get(rel_s)
        st = dll.stat()
        if (row and row.get("sha256") and row["size"] == st.st_size
                and row["mtime_ns"] == st.st_mtime_ns and not args.verify_hashes):
            sha = row["sha256"]
        else:
            sha = sha256_file(dll)

        action, reason = decide(row, sha, dll_out, ctx)
        if action == "skip":
            skipped[reason] += 1
            LOG.debug("[%d/%d] skip %s (%s)", index, len(dll_files), rel_s, reason)
            if row and row["sha256"] != sha:
                pass
            continue

        LOG.info("[%d/%d] %s (%s)", index, len(dll_files), rel_s, reason)
        try:
            results.append(process_dll(dll, rel, sha, row, dll_out, ctx))
        except Interrupted:
            interrupted = True
            break

    # ---- global graph + summary ----
    if not args.no_graphs:
        try:
            graph_global_dependencies(inventory, analysed_names, output_root,
                                      args.graph_include_external, args)
        except Exception as e:
            LOG.warning("Global graph failed: %s", e)

    counts = manifest.counts()
    cats = Counter(r.get("category") for r in results if r["status"] in ("FAILED", "PARTIAL"))
    summary = {
        "input_directory": str(root_dir), "output_directory": str(output_root),
        "finished_at": iso_now(), "interrupted": interrupted,
        "elapsed_seconds": round(time.monotonic() - t_batch, 1),
        "tool_versions": versions, "dlls_discovered": len(dll_files),
        "processed_this_run": len(results), "skipped_this_run": dict(skipped),
        "manifest_totals": counts, "failure_categories_this_run": dict(cats),
        "results": results}
    write_json(output_root / "batch_summary.json", summary)

    print("\n" + "=" * 70)
    print("  BATCH INTERRUPTED - re-run the same command to resume" if interrupted
          else "  BATCH COMPLETE")
    print("=" * 70)
    print(f"[+] Processed this run : {len(results)}")
    for reason, n in skipped.items():
        print(f"[=] Skipped            : {n}  ({reason})")
    print(f"[+] Manifest totals    : {json.dumps(counts)}")
    if cats:
        print(f"[!] Failure categories : {json.dumps(dict(cats))}")
    print(f"[+] Summary            : {output_root / 'batch_summary.json'}")
    if interrupted:
        return 130
    return 1 if any(r["status"] in ("FAILED", "PARTIAL") for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
