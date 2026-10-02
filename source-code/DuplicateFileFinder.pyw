#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Duplicate File Finder & Cleaner for Windows — tabbed edition.

Tabs:
  🗂 Duplicates — find files with identical content and remove the extra
                 copies safely to the Recycle Bin.
  🧹 Cleaner    — cleanup of known browser caches and Windows temp data;
                 history (installed browsers only), temp files, thumbnails,
                 recent documents, crash dumps, Recycle Bin, DNS cache.
                 whitelist-only; protects Downloads and unknown AppData folders.
  🛡 Security   — quick, full local-disk, and custom ClamAV scans.
                 FreshClam signature updates, warm multi-threaded ClamD
                 scans, selectable detections, quarantine, and
                 permanent-delete actions.
                 Scans only list findings; selected actions need confirmation.
  🎨 Themes     — 16 color themes, custom accent color, font sizes, zebra
                 stripes, colorful title bar, live preview. Settings persist.
  🕒 Clock      — a big theme-aware analog clock with a smooth second hand,
                 12-hour digital caption, date and always-on-top toggle.

The UI uses Python's standard library. Bundled ClamAV handles on-demand
full local-disk scanning; first-time and stale signature updates need internet.
Run: double-click this file (pythonw runs it without a console window).
"""

from __future__ import annotations

import atexit
import ctypes
from ctypes import wintypes
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import csv
import glob
import hashlib
import json
import locale
import math
import os
import queue
import re
import shutil
import socket
import stat as statmod
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
import uuid
import zipfile
import winreg
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from tkinter import colorchooser, filedialog, messagebox, simpledialog, ttk

APP_TITLE = "Duplicate File Finder"
CHUNK = 1 << 20
PARTIAL_BYTES = 64 * 1024
SKIP_DIRS = {"$recycle.bin", "system volume information"}
SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "settings.json")
APP_DIR = os.path.dirname(os.path.abspath(__file__))
CLAMAV_APP_NAME = "DuplicateFileFinder"


def human(n: float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024.0 or unit == "TB":
            return f"{int(n)} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024.0


def current_disk_usage(path: str | None = None) -> dict | None:
    """Read current OS-reported free/used space for the system drive."""
    target = path or os.environ.get("WINDIR") or os.path.expanduser("~")
    try:
        usage = shutil.disk_usage(target)
        drive = os.path.splitdrive(os.path.abspath(target))[0] or target
        return {"path": drive, "total": usage.total, "used": usage.used,
                "free": usage.free}
    except OSError:
        return None


# --------------------------------------------------------------------------
# ClamAV on-demand scanner
# --------------------------------------------------------------------------

SECURITY_SCAN_EXTENSIONS = frozenset({
    ".exe", ".dll", ".sys", ".ocx", ".com", ".scr", ".cpl", ".drv",
    ".efi", ".msi", ".msp", ".mst", ".appx", ".appxbundle", ".msix",
    ".msixbundle", ".hta", ".jar", ".class", ".pyc", ".pyd", ".so",
    ".ko", ".bin", ".elf", ".wasm", ".ps1", ".psm1", ".psd1",
    ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".sh", ".bash", ".zsh", ".fish", ".py", ".pyw", ".rb", ".pl",
    ".php", ".lua", ".tcl", ".reg", ".inf", ".au3", ".ahk", ".scf",
    ".lnk", ".url", ".doc", ".docm", ".docx", ".dot", ".dotm", ".xls",
    ".xlsm", ".xlsx", ".xlsb", ".xltm", ".ppt", ".pptm", ".pptx",
    ".potm", ".ppam", ".pdf", ".rtf", ".odt", ".ods", ".odp", ".one",
    ".pub", ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".zst",
    ".cab", ".iso", ".img", ".vhd", ".vhdx", ".wim", ".esd", ".arj",
    ".lzh", ".lz", ".lzma", ".ace", ".apk", ".xapk", ".aab", ".deb",
    ".rpm", ".pkg", ".dmg", ".appimage", ".crx", ".xpi", ".json",
    ".sqlite", ".db", ".dat", ".pak", ".asar", ".ini", ".cfg", ".conf",
    ".yaml", ".yml", ".toml", ".xml", ".sqlite3", ".mdb", ".ttf", ".otf",
    ".woff", ".woff2", ".svg", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
    ".webp", ".mp3", ".wav", ".flac", ".ogg", ".mp4", ".mkv", ".avi",
    ".mov", ".webm", ".eml", ".msg", ".pst", ".ost", ".cer", ".crt",
    ".pem", ".pfx", ".p12", ".rom", ".cap", ".fd", ".dmp", ".mdmp",
    ".log", ".etl",
})
_SECURITY_SCAN_EXCLUDED_PATHS = frozenset({
    os.path.normcase(os.path.abspath(os.path.join(
        os.environ.get("WINDIR", r"C:\Windows"), "System32",
        "vmfirmwarehcl.dll"))),
})
_SECURITY_SCAN_SKIP_DIRS = frozenset({
    "$recycle.bin", "system volume information",
})

_AUTHENTICODE_SCAN_EXTENSIONS = frozenset({
    ".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".drv",
    ".msi", ".msp", ".mst", ".cab",
})
_LOW_CONFIDENCE_SIGNATURE_PREFIXES = (
    "pua.", "heuristics.", "hacktool.", "adware.", "toolbar.",
    "riskware.", "joke.", "spamtool.", "nettool.",
)


def _security_scan_skip_path(path: str) -> bool:
    parts = os.path.normpath(os.path.abspath(path)).split(os.sep)
    return any(part.casefold() in _SECURITY_SCAN_SKIP_DIRS for part in parts)


def _is_access_denied(error) -> bool:
    if isinstance(error, OSError):
        if (getattr(error, "winerror", None) in (5, 1314) or
                getattr(error, "errno", None) in (1, 13)):
            return True
    message = str(error).casefold()
    return any(token in message for token in (
        "access is denied", "access denied", "permission denied",
        "operation not permitted", "winerror 5", "error 5 (0x5)",
    ))


def _is_clamav_limit_signature(signature: str) -> bool:
    return signature.casefold().startswith("heuristics.limits.exceeded")


def _is_low_confidence_detection(signature: str) -> bool:
    """Identify ClamAV PUA/heuristic classes that commonly flag legitimate tools."""
    name = (signature or "").casefold()
    return (not name.startswith("heuristics.limits.exceeded") and
            name.startswith(_LOW_CONFIDENCE_SIGNATURE_PREFIXES))


def suppress_trusted_low_confidence_findings(findings) -> tuple[list[dict], int]:
    """Use Windows' live Authenticode trust check, never a list of app names.

    Lower-confidence PUA/heuristic matches on files with a valid code-signing
    chain are suppressed. Direct malware signature matches remain visible.
    ClamAV's own trusted/revoked certificate rules remain enabled as well.
    """
    candidates = [
        finding for finding in findings
        if _is_low_confidence_detection(finding.get("signature", ""))
        and os.path.splitext(finding.get("path", ""))[1].casefold()
        in _AUTHENTICODE_SCAN_EXTENSIONS
    ]
    if not candidates or os.name != "nt":
        return list(findings), 0
    powershell = os.path.join(
        os.environ.get("WINDIR", r"C:\Windows"), "System32",
        "WindowsPowerShell", "v1.0", "powershell.exe")
    if not os.path.isfile(powershell):
        return list(findings), 0
    script = (
        "$paths = @(ConvertFrom-Json -InputObject ([Console]::In.ReadToEnd())); "
        "$results = foreach ($path in $paths) { try { "
        "$sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop; "
        "[pscustomobject]@{Path=$path; Status=[string]$sig.Status} "
        "} catch { [pscustomobject]@{Path=$path; Status='Error'} } }; "
        "ConvertTo-Json -InputObject @($results) -Compress"
    )
    verified = set()
    try:
        result = subprocess.run(
            [powershell, "-NoLogo", "-NoProfile", "-NonInteractive",
             "-Command", script],
            input=json.dumps([finding["path"] for finding in candidates]),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", errors="replace", timeout=60,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False)
        if result.returncode == 0 and result.stdout.strip():
            rows = json.loads(result.stdout)
            if isinstance(rows, dict):
                rows = [rows]
            verified = {
                os.path.normcase(os.path.abspath(row.get("Path", "")))
                for row in rows if isinstance(row, dict) and
                row.get("Status") == "Valid"
            }
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        return list(findings), 0

    visible = []
    suppressed = 0
    for finding in findings:
        identity = os.path.normcase(os.path.abspath(finding.get("path", "")))
        if (_is_low_confidence_detection(finding.get("signature", "")) and
                identity in verified):
            suppressed += 1
        else:
            visible.append(finding)
    return visible, suppressed


def security_data_dir() -> str:
    """Per-user writable location for signatures and quarantined files."""
    base = (os.environ.get("LOCALAPPDATA") or
            os.path.join(os.path.expanduser("~"), "AppData", "Local"))
    return os.path.join(base, CLAMAV_APP_NAME)


def security_scan_roots(include_removable: bool = True) -> list[str]:
    """Return every mounted local disk for a full computer scan."""
    if os.name != "nt":
        return [os.path.abspath(os.sep)]
    try:
        kernel32 = ctypes.windll.kernel32
        mask = kernel32.GetLogicalDrives()
        get_drive_type = kernel32.GetDriveTypeW
        get_drive_type.argtypes = [wintypes.LPCWSTR]
        get_drive_type.restype = wintypes.UINT
    except (AttributeError, OSError):
        mask = 0
        get_drive_type = None
    roots = []
    for index in range(26):
        if not mask & (1 << index):
            continue
        root = f"{chr(ord('A') + index)}:\\"
        try:
            if get_drive_type is None:
                continue
            drive_type = get_drive_type(root)
        except (AttributeError, OSError):
            continue
        if drive_type == 3 or (include_removable and drive_type == 2):
            roots.append(root)
    if not roots:
        system_root = os.environ.get("WINDIR") or os.path.expanduser("~")
        drive = os.path.splitdrive(os.path.abspath(system_root))[0]
        if drive:
            roots.append(drive + "\\")
    return roots


def security_quick_scan_roots() -> list[str]:
    """Return critical persistence/temp locations and running app binaries."""
    profile = os.path.expanduser("~")
    roaming = os.environ.get("APPDATA") or os.path.join(
        profile, "AppData", "Roaming")
    local = os.environ.get("LOCALAPPDATA") or os.path.join(
        profile, "AppData", "Local")
    windows = os.environ.get("WINDIR", r"C:\Windows")
    program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
    candidates = [
        os.path.join(local, "Temp"),
        os.path.join(windows, "Temp"),
        os.path.join(windows, "System32"),
        os.path.join(roaming, "Microsoft", "Windows", "Start Menu",
                     "Programs", "Startup"),
        os.path.join(program_data, "Microsoft", "Windows", "Start Menu",
                     "Programs", "Startup"),
    ]
    roots = []
    seen = set()
    for path in candidates:
        path = os.path.abspath(os.path.expanduser(path))
        key = os.path.normcase(path)
        if key not in seen and os.path.isdir(path):
            seen.add(key)
            roots.append(path)
    # A quick scan checks the images of currently running programs too. The
    # shared extension allowlist is applied by the count and scan iterators.
    for _name, path in _running_process_executable_paths():
        path = os.path.abspath(path)
        key = os.path.normcase(path)
        if key in seen or not os.path.isfile(path):
            continue
        try:
            already_covered = any(
                os.path.normcase(os.path.commonpath((path, root))) ==
                os.path.normcase(root)
                for root in roots if os.path.isdir(root))
        except ValueError:
            already_covered = False
        if not already_covered:
            seen.add(key)
            roots.append(path)
    return roots


def find_clamav_archive() -> list:
    """All bundled ClamAV engine archives, biggest first (the full engine
    ships complete; trimmed runtime zips are only fallbacks)."""
    patterns = (
        os.path.join(APP_DIR, "clamav", "clamav-*.win.x64.zip"),
        os.path.join(APP_DIR, "..", "clamav", "clamav-*.win.x64.zip"),
    )
    candidates = sorted({os.path.abspath(p) for pattern in patterns
                         for p in glob.glob(pattern)},
                        key=lambda p: -os.path.getsize(p))
    return candidates


def find_clamav_dir(prepare: bool = False) -> str | None:
    """Find the ClamD scanner and FreshClam updater, extracting if needed."""
    required = ("freshclam.exe", "clamd.exe")
    patterns = (
        os.path.join(APP_DIR, "clamav", "engine", "clamav-*.win.x64"),
        os.path.join(APP_DIR, "..", "clamav", "engine", "clamav-*.win.x64"),
        os.path.join(security_data_dir(), "engine", "clamav-*.win.x64"),
    )
    candidates = sorted({os.path.abspath(p) for pattern in patterns
                         for p in glob.glob(pattern)}, reverse=True)
    for folder in candidates:
        if all(os.path.isfile(os.path.join(folder, name))
               for name in required):
            return folder
    if not prepare:
        return None
    archives = find_clamav_archive()
    if not archives:
        return None
    errors = []
    for archive_path in archives:
        try:
            return _extract_clamav_archive(archive_path, required)
        except Exception as e:
            errors.append(f"{os.path.basename(archive_path)}: {e}")
    raise RuntimeError("No usable bundled ClamAV archive ("
                       + "; ".join(errors) + ")")


def _extract_clamav_archive(archive_path: str, required) -> str:
    with zipfile.ZipFile(archive_path) as zf:
        roots = {info.filename.replace("\\", "/").split("/", 1)[0]
                 for info in zf.infolist() if "/" in info.filename}
    version_roots = sorted(r for r in roots
                           if re.fullmatch(r"clamav-.*\.win\.x64", r))
    if not version_roots:
        raise RuntimeError("The bundled ClamAV archive has an unknown layout.")
    version_folder = version_roots[0]
    engine_root = os.path.join(security_data_dir(), "engine")
    destination = os.path.join(engine_root, version_folder)
    if all(os.path.isfile(os.path.join(destination, name))
           for name in required):
        return destination
    if os.path.exists(destination):
        base = version_folder[:-len(".win.x64")]
        destination = os.path.join(engine_root, base + "-parallel.win.x64")
        if all(os.path.isfile(os.path.join(destination, name))
               for name in required):
            return destination
        if os.path.exists(destination):
            destination = os.path.join(
                engine_root, base + "-parallel-" + uuid.uuid4().hex[:8] +
                ".win.x64")
    os.makedirs(engine_root, exist_ok=True)
    staging = destination + ".extract-" + uuid.uuid4().hex
    os.makedirs(staging, exist_ok=False)
    try:
        with zipfile.ZipFile(archive_path) as zf:
            for info in zf.infolist():
                parts = info.filename.replace("\\", "/").split("/")
                if not parts or parts[0] != version_folder:
                    continue
                if (len(parts) == 2 and
                        (parts[1].lower().endswith(".dll") or
                         parts[1].lower() in required)):
                    relative = parts[1]
                elif len(parts) == 3 and parts[1:] == ["certs", "clamav.crt"]:
                    relative = os.path.join("certs", "clamav.crt")
                else:
                    continue
                if info.is_dir():
                    continue
                output_path = os.path.join(staging, relative)
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                with zf.open(info) as src, open(output_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)
        if not all(os.path.isfile(os.path.join(staging, name))
                   for name in required):
            raise RuntimeError("The bundled ClamAV archive is incomplete.")
        os.replace(staging, destination)
        return destination
    except Exception:
        # Keep no partial engine visible to later scans.
        shutil.rmtree(staging, ignore_errors=True)
        raise


def signature_database_status(database_dir: str | None = None) -> dict:
    """Report whether ClamAV has both required official signature databases."""
    directory = database_dir or os.path.join(security_data_dir(), "database")
    try:
        names = os.listdir(directory)
    except OSError:
        names = []
    present = {os.path.splitext(name)[0].lower() for name in names
               if os.path.isfile(os.path.join(directory, name)) and
               os.path.splitext(name)[1].lower() in (".cvd", ".cld")}
    ready = "main" in present and "daily" in present
    daily_paths = [os.path.join(directory, "daily" + ext)
                   for ext in (".cvd", ".cld")
                   if os.path.isfile(os.path.join(directory, "daily" + ext))]
    stale_days = None
    if daily_paths:
        try:
            stale_days = max(0, int((time.time() - max(
                os.path.getmtime(p) for p in daily_paths)) // 86400))
        except OSError:
            pass
    return {"ready": ready, "directory": directory,
            "database_count": len(present), "stale_days": stale_days}


def write_freshclam_config(database_dir: str, config_path: str,
                           certs_dir: str | None = None) -> str:
    """Create a minimal config for a per-user FreshClam signature download."""
    os.makedirs(database_dir, exist_ok=True)
    log_path = os.path.join(os.path.dirname(database_dir), "freshclam.log")
    def quote(path):
        return '"' + os.path.abspath(path).replace("\\", "/") + '"'
    with open(config_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("DatabaseMirror database.clamav.net\n")
        f.write(f"DatabaseDirectory {quote(database_dir)}\n")
        f.write(f"UpdateLogFile {quote(log_path)}\n")
        if certs_dir:
            f.write(f"CVDCertsDirectory {quote(certs_dir)}\n")
        f.write("ConnectTimeout 30\nReceiveTimeout 60\n")
    return config_path


def update_clamav_database(cancel=None, log=None) -> None:
    """Download current official ClamAV signatures using bundled FreshClam."""
    engine = find_clamav_dir(prepare=True)
    if not engine:
        raise RuntimeError("The bundled ClamAV engine was not found.")
    root = security_data_dir()
    database_dir = os.path.join(root, "database")
    config_path = write_freshclam_config(
        database_dir, os.path.join(root, "freshclam.conf"),
        os.path.join(engine, "certs"))
    enc = locale.getpreferredencoding(False) or "utf-8"
    proc = subprocess.Popen(
        [os.path.join(engine, "freshclam.exe"),
         f"--config-file={config_path}", "--stdout", "--show-progress"],
        cwd=engine, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding=enc, errors="replace", bufsize=1,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    tail = []
    def read_output():
        if proc.stdout is None:
            return
        for line in proc.stdout:
            line = line.rstrip()
            if not line:
                continue
            tail.append(line)
            del tail[:-12]
            if log:
                log(line)
    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    was_cancelled = False
    while proc.poll() is None:
        if cancel is not None and cancel.is_set():
            was_cancelled = True
            proc.terminate()
            break
        time.sleep(0.15)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    reader.join(timeout=2)
    if was_cancelled:
        raise RuntimeError("Signature update cancelled.")
    if proc.returncode != 0:
        details = "\n".join(tail[-8:]) or "FreshClam did not provide details."
        raise RuntimeError(f"FreshClam exited with code {proc.returncode}.\n{details}")
    status = signature_database_status(database_dir)
    if not status["ready"]:
        details = "\n".join(tail[-8:])
        raise RuntimeError("FreshClam finished, but main/daily signatures "
                           "are still missing.\n" + details)


def parse_clamav_output(lines) -> tuple[list[dict], dict]:
    """Parse ClamDScan detections and any file-count summary it provides."""
    findings = []
    stats = {"scanned": None, "infected": 0, "errors": 0}
    finding_re = re.compile(r"^(.*):\s*(.+?)\s+(FOUND|ERROR)$", re.IGNORECASE)
    summary_re = {
        "scanned": re.compile(r"^Scanned files:\s*(\d+)", re.IGNORECASE),
        "infected": re.compile(r"^Infected files:\s*(\d+)", re.IGNORECASE),
        "errors": re.compile(r"^Total errors:\s*(\d+)", re.IGNORECASE),
    }
    seen = set()
    for raw in lines:
        line = raw.strip()
        for key, pattern in summary_re.items():
            match = pattern.match(line)
            if match:
                value = int(match.group(1))
                stats[key] = (value if stats[key] is None
                              else max(stats[key], value))
                break
        match = finding_re.match(line)
        if match and match.group(3).upper() == "ERROR":
            stats["errors"] += 1
        elif match and match.group(3).upper() == "FOUND":
            path = os.path.normpath(match.group(1).strip())
            signature = match.group(2).strip()
            key = (os.path.normcase(path), signature)
            if key not in seen:
                findings.append({"path": path, "signature": signature,
                                 "status": "Detected"})
                seen.add(key)
    stats["infected"] = max(
        stats["infected"], sum(
            not _is_clamav_limit_signature(item["signature"])
            for item in findings))
    return findings, stats


class _ClamDSession:
    """App-scoped ClamD process; keeps signatures warm and scans in parallel."""

    def __init__(self, engine: str, database_dir: str, detect_pua: bool,
                 progress=None, cancel=None):
        self.engine = engine
        self.database_dir = database_dir
        self.detect_pua = detect_pua
        self.workers = max(2, min(16, os.cpu_count() or 4))
        self.host = "127.0.0.1"
        self.port = self._free_loopback_port()
        self.tempdir = tempfile.TemporaryDirectory(prefix="dff-clamd-")
        self.config_path = os.path.join(self.tempdir.name, "clamd.conf")
        self.process = None
        self.output = []
        self.reader = None
        self._closed = False
        try:
            self._write_config()
            args = [os.path.join(engine, "clamd.exe"), "--foreground",
                    f"--config-file={self.config_path}",
                    f"--cvdcertsdir={os.path.join(engine, 'certs')}"]
            self.process = subprocess.Popen(
                args, cwd=engine, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding=locale.getpreferredencoding(False) or "utf-8",
                errors="replace", bufsize=1,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            self.reader = threading.Thread(target=self._drain_output, daemon=True)
            self.reader.start()
            if not self._wait_ready(progress, cancel):
                if cancel is not None and cancel.is_set():
                    raise InterruptedError("ClamAV startup cancelled.")
                details = "\n".join(self.output[-12:])
                raise RuntimeError(
                    "The parallel ClamAV engine did not become ready. "
                    + ("\n" + details if details else ""))
        except Exception:
            self.close()
            raise

    @staticmethod
    def _free_loopback_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            return probe.getsockname()[1]

    @staticmethod
    def _quoted(value: str) -> str:
        # Windows paths cannot contain a quote, so double-quoting is enough.
        return '"' + os.path.abspath(value) + '"'

    def _write_config(self):
        threads = self.workers
        config = [
            f"DatabaseDirectory {self._quoted(self.database_dir)}",
            f"TemporaryDirectory {self._quoted(self.tempdir.name)}",
            # Keep ClamAV's built-in signed-PE trusted/revoked certificate
            # rules enabled; safe assessment comes from current trust data,
            # not a hard-coded publisher or application list.
            "DisableCertCheck no",
            f"TCPAddr {self.host}",
            f"TCPSocket {self.port}",
            f"MaxThreads {threads}",
            f"MaxQueue {max(32, threads * 4)}",
            "ReadTimeout 600",
            "CommandReadTimeout 60",
            "StreamMaxLength 2000M",
            # Let ClamAV scan archives past its normal aggregate-byte and
            # embedded-file-count limits. Zero disables these two ClamAV
            # thresholds; it prevents large installers/JARs/disk images from
            # being reported as limit detections before their contents finish.
            "MaxScanTime 0",
            "MaxScanSize 0",
            "MaxFileSize 2000M",
            "MaxRecursion 100",
            "MaxFiles 0",
            "AlertExceedsMax yes",
            "CacheSize 65536",
            "ScanArchive yes",
            f"DetectPUA {'yes' if self.detect_pua else 'no'}",
            "Foreground yes",
        ]
        with open(self.config_path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(config) + "\n")

    def _drain_output(self):
        if self.process is None or self.process.stdout is None:
            return
        for raw in self.process.stdout:
            self.output.append(raw.rstrip())
            del self.output[:-40]

    def _ping(self) -> bool:
        with socket.create_connection((self.host, self.port), timeout=0.6) as conn:
            conn.settimeout(0.6)
            conn.sendall(b"zPING\0")
            response = bytearray()
            while b"\0" not in response and len(response) < 256:
                chunk = conn.recv(256)
                if not chunk:
                    break
                response.extend(chunk)
            return b"PONG" in response

    def _wait_ready(self, progress=None, cancel=None) -> bool:
        deadline = time.monotonic() + 180
        started = time.monotonic()
        last_update = started
        while time.monotonic() < deadline:
            if cancel is not None and cancel.is_set():
                return False
            if self.process is None or self.process.poll() is not None:
                return False
            try:
                if self._ping():
                    return True
            except OSError:
                pass
            now = time.monotonic()
            if progress and now - last_update >= 10:
                progress("Loading ClamAV signatures for the parallel scanner… "
                         f"{int(now - started)} seconds")
                last_update = now
            time.sleep(0.25)
        return False

    def close(self):
        if self._closed:
            return
        self._closed = True
        process = self.process
        self.process = None
        if process is not None and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                    process.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        if self.reader is not None:
            self.reader.join(timeout=1)
        if process is not None and process.stdout is not None:
            try:
                process.stdout.close()
            except OSError:
                pass
        self.tempdir.cleanup()


_CLAMD_SESSION = None
_CLAMD_SESSION_LOCK = threading.RLock()


def _stop_clamd_session(session=None):
    """Stop the app's daemon, or just the supplied session if it is stale."""
    global _CLAMD_SESSION
    with _CLAMD_SESSION_LOCK:
        current = _CLAMD_SESSION
        if session is not None and current is not session:
            session.close()
            return
        _CLAMD_SESSION = None
        if current is not None:
            current.close()


def _get_clamd_session(engine: str, database_dir: str, detect_pua: bool,
                       progress=None, cancel=None):
    global _CLAMD_SESSION
    with _CLAMD_SESSION_LOCK:
        if cancel is not None and cancel.is_set():
            return None
        current = _CLAMD_SESSION
        if (current is not None and current.process is not None and
                current.process.poll() is None and
                current.database_dir == database_dir and
                current.detect_pua == detect_pua):
            return current
        if current is not None:
            current.close()
            _CLAMD_SESSION = None
        session = _ClamDSession(engine, database_dir, detect_pua,
                                progress=progress, cancel=cancel)
        _CLAMD_SESSION = session
        return session


def _scan_extension_allowed(path: str, file_extensions) -> bool:
    if os.path.normcase(os.path.abspath(path)) in _SECURITY_SCAN_EXCLUDED_PATHS:
        return False
    return (file_extensions is None or
            os.path.splitext(path)[1].casefold() in file_extensions)


def _count_scan_files(targets, cancel=None, progress=None,
                      file_extensions=None) -> int:
    """Count eligible regular files before scanning for exact progress totals."""
    total = 0
    directories = []
    for target in targets:
        if _security_scan_skip_path(target):
            continue
        if os.path.isfile(target) and _scan_extension_allowed(
                target, file_extensions):
            total += 1
        elif os.path.isdir(target):
            directories.append(target)
    last_update = time.monotonic()
    while directories:
        if cancel is not None and cancel.is_set():
            return total
        current = directories.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    if cancel is not None and cancel.is_set():
                        return total
                    try:
                        entry_stat = entry.stat(follow_symlinks=False)
                        if (getattr(entry_stat, "st_file_attributes", 0) &
                                0x400):  # FILE_ATTRIBUTE_REPARSE_POINT
                            continue
                        if statmod.S_ISDIR(entry_stat.st_mode):
                            if not _security_scan_skip_path(entry.path):
                                directories.append(entry.path)
                        elif (statmod.S_ISREG(entry_stat.st_mode) and
                              _scan_extension_allowed(entry.path,
                                                      file_extensions)):
                            total += 1
                    except OSError:
                        continue
                    now = time.monotonic()
                    if progress and now - last_update >= 0.35:
                        progress(total)
                        last_update = now
        except OSError:
            continue
        now = time.monotonic()
        if progress and now - last_update >= 0.35:
            progress(total)
            last_update = now
    if progress:
        progress(total)
    return total


def _iter_scan_files(targets, cancel=None, on_error=None,
                     file_extensions=None):
    """Yield regular files without following reparse points or symlinks."""
    for target in targets:
        if cancel is not None and cancel.is_set():
            return
        if _security_scan_skip_path(target):
            continue
        if os.path.isfile(target):
            if _scan_extension_allowed(target, file_extensions):
                yield target
            continue
        if not os.path.isdir(target):
            continue
        directories = [target]
        while directories:
            if cancel is not None and cancel.is_set():
                return
            current = directories.pop()
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        if cancel is not None and cancel.is_set():
                            return
                        try:
                            entry_stat = entry.stat(follow_symlinks=False)
                            if (getattr(entry_stat, "st_file_attributes", 0) &
                                    0x400):  # FILE_ATTRIBUTE_REPARSE_POINT
                                continue
                            if statmod.S_ISDIR(entry_stat.st_mode):
                                if not _security_scan_skip_path(entry.path):
                                    directories.append(entry.path)
                            elif (statmod.S_ISREG(entry_stat.st_mode) and
                                  _scan_extension_allowed(entry.path,
                                                          file_extensions)):
                                yield entry.path
                        except OSError as exc:
                            if on_error:
                                on_error(entry.path, exc)
            except OSError as exc:
                if on_error:
                    on_error(current, exc)


def _scan_one_clamd_file(session: _ClamDSession, target: str,
                         cancel=None, progress=None, status_progress=None
                         ) -> tuple[list[dict], dict, bool]:
    """Scan one file over the warm daemon socket; callers parallelize files."""
    target_name = os.path.basename(os.path.normpath(target)) or target
    target_kind = "file" if os.path.isfile(target) else "folder"
    target_size = None
    if target_kind == "file":
        try:
            target_size = human(os.path.getsize(target))
        except OSError:
            pass
    target_description = f"{target_kind} {target_name}"
    if target_size:
        target_description += f" · {target_size}"
    if os.path.isfile(target):
        # Reuse the warm daemon; a worker pool submits different files at once.
        findings = []
        stats = {"scanned": 0, "infected": 0, "errors": 0,
                 "inaccessible": 0}
        started = time.monotonic()
        last_status = started
        if status_progress:
            status_progress(f"Scanning {target_description}…")
        try:
            with socket.create_connection((session.host, session.port),
                                          timeout=2) as conn:
                conn.settimeout(0.5)
                conn.sendall(("zSCAN " + target + "\0").encode("utf-8"))
                response = bytearray()
                while b"\0" not in response and len(response) < 65536:
                    if cancel is not None and cancel.is_set():
                        return findings, stats, True
                    try:
                        chunk = conn.recv(4096)
                    except socket.timeout:
                        now = time.monotonic()
                        if status_progress and now - last_status >= 1:
                            status_progress(
                                f"Scanning {target_description} · "
                                f"{int(now - started)} seconds")
                            last_status = now
                        continue
                    if not chunk:
                        break
                    response.extend(chunk)
        except OSError as exc:
            raise RuntimeError(f"ClamD could not scan {target}: {exc}") from exc
        if cancel is not None and cancel.is_set():
            return findings, stats, True
        raw_result = bytes(response).split(b"\0", 1)[0]
        result = raw_result.decode("utf-8", errors="replace").strip()
        found, _parsed = parse_clamav_output((result,))
        if found:
            findings.extend(found)
            stats["scanned"] = 1
            stats["infected"] = sum(
                not _is_clamav_limit_signature(finding["signature"])
                for finding in found)
            if progress:
                for finding in found:
                    event = ("Scan limit reached" if
                             _is_clamav_limit_signature(finding["signature"])
                             else "Detection")
                    progress(f"{event}: {finding['signature']} · "
                             f"{finding['path']}")
            return findings, stats, False
        if result.upper().endswith(": OK"):
            stats["scanned"] = 1
            return findings, stats, False
        if result.upper().endswith(": ERROR") or result.upper() == "ERROR":
            if _is_access_denied(result):
                stats["inaccessible"] = 1
            else:
                stats["errors"] = 1
            return findings, stats, False
        raise RuntimeError(
            f"ClamD returned an unexpected result for {target}: "
            f"{result or 'empty response'}")

    raise FileNotFoundError(f"Scan file is no longer available: {target}")



def scan_with_clamav(target: str | list[str] | tuple[str, ...], detect_pua: bool = False,
                     cancel=None, progress=None, scan_progress=None,
                     file_extensions=None
                     ) -> tuple[list[dict], dict]:
    """Use ClamAV's warm, multi-threaded daemon for real signature scans."""
    engine = find_clamav_dir(prepare=True)
    if not engine:
        raise RuntimeError("The bundled ClamAV engine was not found.")
    database_dir = os.path.join(security_data_dir(), "database")
    if not signature_database_status(database_dir)["ready"]:
        raise RuntimeError("ClamAV signatures are missing. Use Update "
                           "definitions before scanning.")
    targets = [target] if isinstance(target, str) else list(target)
    targets = [os.path.abspath(os.path.expanduser(path)) for path in targets]
    if not targets:
        raise ValueError("No scan locations were selected.")
    for path in targets:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Scan location is unavailable: {path}")
        if not (os.path.isfile(path) or os.path.isdir(path)):
            raise ValueError(f"Cannot scan this location: {path}")
    if cancel is not None and cancel.is_set():
        return [], {"scanned": 0, "infected": 0, "errors": 0,
                    "cancelled": True}

    if scan_progress:
        scan_progress(0, None, "Counting files to scan…")

    def report_file_count(count):
        if scan_progress:
            scan_progress(0, None,
                          f"Counting files to scan… {count:,} found")

    total_files = _count_scan_files(
        targets, cancel=cancel,
        progress=report_file_count if scan_progress else None,
        file_extensions=file_extensions)
    if cancel is not None and cancel.is_set():
        return [], {"scanned": 0, "infected": 0, "errors": 0,
                    "counting_cancelled": True,
                    "cancelled": True}
    if scan_progress:
        scan_progress(0, total_files, "")

    def report_engine_progress(line):
        if progress:
            progress(line)
        if scan_progress:
            scan_progress(0, total_files, line)

    if scan_progress:
        scan_progress(0, total_files, "Starting ClamAV scan engine…")

    try:
        session = _get_clamd_session(
            engine, database_dir, detect_pua,
            progress=report_engine_progress, cancel=cancel)
    except InterruptedError:
        return [], {"scanned": 0, "infected": 0, "errors": 0,
                    "cancelled": True}
    if session is None:
        return [], {"scanned": 0, "infected": 0, "errors": 0,
                    "cancelled": True}

    findings = []
    seen = set()
    totals = {"scanned": 0, "infected": 0, "errors": 0,
              "inaccessible": 0, "inaccessible_examples": [],
              "error_examples": []}
    completed_files = 0
    progress_lock = threading.Lock()
    last_scan_update = time.monotonic()

    def file_processed(_path: str):
        nonlocal completed_files, last_scan_update, total_files
        with progress_lock:
            completed_files += 1
            total_files = max(total_files, completed_files)
            now = time.monotonic()
            if (scan_progress and
                    (completed_files == total_files or
                     now - last_scan_update >= 0.12)):
                scan_progress(completed_files, total_files, "")
                last_scan_update = now

    def target_status(detail: str):
        if scan_progress:
            with progress_lock:
                scanned_now = completed_files
                current_total = total_files
            scan_progress(scanned_now, current_total, detail)

    def report_walk_error(path: str, error: OSError):
        key = "inaccessible" if _is_access_denied(error) else "errors"
        totals[key] += 1
        examples = totals[f"{key}_examples"]
        if len(examples) < 3 and path not in examples:
            examples.append(path)

    if progress:
        progress(f"ClamAV scanner ready · {session.workers} workers · "
                 "signatures stay loaded for this app session")

    file_iterator = iter(_iter_scan_files(
        targets, cancel=cancel, on_error=report_walk_error,
        file_extensions=file_extensions))
    pool = ThreadPoolExecutor(max_workers=session.workers,
                              thread_name_prefix="ClamAV-file")
    pending = {}
    queue_limit = max(session.workers, session.workers * 2)
    exhausted = False
    cancelled = False

    def fill_pending():
        nonlocal exhausted
        while (not exhausted and len(pending) < queue_limit and
               (cancel is None or not cancel.is_set())):
            try:
                path = next(file_iterator)
            except StopIteration:
                exhausted = True
                break
            future = pool.submit(
                _scan_one_clamd_file, session, path, cancel, progress,
                target_status)
            pending[future] = path

    try:
        fill_pending()
        while pending:
            if cancel is not None and cancel.is_set():
                cancelled = True
                _stop_clamd_session(session)
                for future in pending:
                    future.cancel()
                break
            finished, _waiting = wait(
                pending, timeout=0.25, return_when=FIRST_COMPLETED)
            if not finished:
                continue
            for future in finished:
                path = pending.pop(future)
                try:
                    local_findings, local_stats, was_cancelled = future.result()
                except Exception as exc:
                    if cancel is not None and cancel.is_set():
                        cancelled = True
                        break
                    if (session.process is None or
                            session.process.poll() is not None):
                        _stop_clamd_session(session)
                        raise RuntimeError(
                            "The ClamAV scan engine stopped unexpectedly.") from exc
                    # Keep scanning after an unreadable file and summarize
                    # access failures at the end instead of flooding the log.
                    local_findings = []
                    inaccessible = _is_access_denied(exc)
                    local_stats = {
                        "scanned": 0, "infected": 0,
                        "errors": 0 if inaccessible else 1,
                        "inaccessible": 1 if inaccessible else 0,
                    }
                    example_key = ("inaccessible_examples" if inaccessible
                                   else "error_examples")
                    if path not in totals[example_key] and len(
                            totals[example_key]) < 3:
                        totals[example_key].append(path)
                    was_cancelled = False
                if was_cancelled:
                    cancelled = True
                    break
                totals["scanned"] += local_stats["scanned"] or 0
                totals["errors"] += local_stats["errors"]
                totals["inaccessible"] += local_stats.get("inaccessible", 0)
                if (local_stats.get("inaccessible") and
                        path not in totals["inaccessible_examples"] and
                        len(totals["inaccessible_examples"]) < 3):
                    totals["inaccessible_examples"].append(path)
                file_processed(path)
                for finding in local_findings:
                    key = (os.path.normcase(finding["path"]),
                           finding["signature"])
                    if key not in seen:
                        seen.add(key)
                        findings.append(finding)
            if cancelled:
                _stop_clamd_session(session)
                for future in pending:
                    future.cancel()
                break
            fill_pending()
        if cancel is not None and cancel.is_set() and not cancelled:
            cancelled = True
            _stop_clamd_session(session)
            for future in pending:
                future.cancel()
    finally:
        pool.shutdown(wait=True, cancel_futures=cancelled)

    totals["infected"] = sum(
        not _is_clamav_limit_signature(finding["signature"])
        for finding in findings)
    totals["incomplete"] = len(findings) - totals["infected"]
    if cancelled:
        totals.update({"total": total_files,
                       "remaining": max(0, total_files - completed_files),
                       "cancelled": True})
        return findings, totals

    if completed_files < total_files:
        missed = total_files - completed_files
        totals["errors"] += missed
        totals["error_examples"].append(
            f"{missed:,} files changed or disappeared before scanning")
    totals["processed"] = completed_files
    totals["total"] = total_files
    totals["remaining"] = max(0, total_files - completed_files)
    if scan_progress:
        scan_progress(completed_files, total_files, "")
    return findings, totals


atexit.register(_stop_clamd_session)


def file_identity(path: str) -> tuple[int, int, int] | None:
    """Lightweight identity for preventing action on a file changed after scan."""
    try:
        st = os.lstat(path)
        if not statmod.S_ISREG(st.st_mode):
            return None
        return (st.st_size, getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)),
                getattr(st, "st_ino", 0))
    except OSError:
        return None


def quarantine_files(paths, quarantine_dir: str,
                     expected: dict | None = None) -> tuple[list[dict], list[tuple[str, str]]]:
    """Move selected detections out of place and record original paths."""
    os.makedirs(quarantine_dir, exist_ok=True)
    manifest_path = os.path.join(quarantine_dir, "quarantine-manifest.json")
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            records = json.load(f)
        if not isinstance(records, list):
            records = []
    except (OSError, ValueError):
        records = []
    moved, failed = [], []
    for path in paths:
        source = os.path.abspath(path)
        if not os.path.isfile(source) or os.path.islink(source):
            failed.append((path, "file is missing, inaccessible, or not a regular file"))
            continue
        wanted = (expected or {}).get(os.path.normcase(source))
        if wanted is not None and file_identity(source) != wanted:
            failed.append((path, "file changed since the scan; scan it again before removal"))
            continue
        destination = os.path.join(
            quarantine_dir, f"{uuid.uuid4().hex}_{os.path.basename(source)}")
        try:
            shutil.move(source, destination)
            entry = {"original_path": source, "quarantined_path": destination,
                     "quarantined_at": datetime.now().isoformat(timespec="seconds")}
            records.append(entry)
            tmp_manifest = manifest_path + ".tmp"
            try:
                with open(tmp_manifest, "w", encoding="utf-8") as f:
                    json.dump(records, f, indent=2)
                os.replace(tmp_manifest, manifest_path)
            except OSError:
                records.pop()
                shutil.move(destination, source)
                raise
            moved.append(entry)
        except OSError as e:
            failed.append((path, str(e)))
    return moved, failed


def load_quarantine_records(quarantine_dir: str) -> list[dict]:
    manifest = os.path.join(quarantine_dir, "quarantine-manifest.json")
    try:
        with open(manifest, "r", encoding="utf-8") as f:
            records = json.load(f)
        return [r for r in records if isinstance(r, dict)] if isinstance(records, list) else []
    except (OSError, ValueError):
        return []


def restore_quarantined_files(quarantine_dir: str, selected_paths) -> tuple[list[dict], list[tuple[str, str]]]:
    """Restore selected quarantined files without overwriting existing files."""
    root = os.path.normcase(os.path.realpath(os.path.abspath(quarantine_dir)))
    manifest = os.path.join(quarantine_dir, "quarantine-manifest.json")
    records = load_quarantine_records(quarantine_dir)
    selected = {os.path.normcase(os.path.abspath(p)) for p in selected_paths}
    restored, failed = [], []
    for entry in records:
        source = os.path.abspath(entry.get("quarantined_path", ""))
        original = os.path.abspath(entry.get("original_path", ""))
        key = os.path.normcase(source)
        if key not in selected:
            continue
        resolved_source = os.path.normcase(os.path.realpath(source))
        if not (resolved_source == root or resolved_source.startswith(root + os.sep)):
            failed.append((source, "quarantine entry points outside the quarantine folder"))
            continue
        if not os.path.isfile(source) or os.path.islink(source):
            failed.append((source, "quarantined file is missing or not a regular file"))
            continue
        if not original or os.path.exists(original):
            failed.append((source, "original path is empty or already occupied"))
            continue
        try:
            os.makedirs(os.path.dirname(original), exist_ok=True)
            shutil.move(source, original)
            # Remove this record only after moving; restore the move if the
            # manifest update fails so the quarantine remains recoverable.
            remaining = [r for r in records if r is not entry]
            tmp_manifest = manifest + ".tmp"
            try:
                with open(tmp_manifest, "w", encoding="utf-8") as f:
                    json.dump(remaining, f, indent=2)
                os.replace(tmp_manifest, manifest)
            except OSError:
                shutil.move(original, source)
                raise
            records = remaining
            restored.append(entry)
        except OSError as e:
            failed.append((source, str(e)))
    return restored, failed


def delete_detected_files(paths, expected: dict | None = None) -> tuple[list[str], list[tuple[str, str]]]:
    """Permanently delete only explicitly selected regular-file detections."""
    deleted, failed = [], []
    for path in paths:
        try:
            if not os.path.isfile(path) or os.path.islink(path):
                raise OSError("file is missing or not a regular file")
            wanted = (expected or {}).get(os.path.normcase(os.path.abspath(path)))
            if wanted is not None and file_identity(path) != wanted:
                raise OSError("file changed since the scan; scan it again before removal")
            os.remove(path)
            deleted.append(path)
        except OSError as e:
            failed.append((path, str(e)))
    return deleted, failed


# --------------------------------------------------------------------------
# Color helpers and the theme catalog
# --------------------------------------------------------------------------

def _rgb(hexstr: str) -> tuple[int, int, int]:
    hexstr = hexstr.lstrip("#")
    return int(hexstr[0:2], 16), int(hexstr[2:4], 16), int(hexstr[4:6], 16)


def _hex(r: int, g: int, b: int) -> str:
    return f"#{max(0, min(255, r)):02x}{max(0, min(255, g)):02x}{max(0, min(255, b)):02x}"


def shade(hexstr: str, k: float) -> str:
    """k > 0 lightens toward white, k < 0 darkens toward black."""
    r, g, b = _rgb(hexstr)
    if k >= 0:
        return _hex(int(r + (255 - r) * k), int(g + (255 - g) * k),
                    int(b + (255 - b) * k))
    f = 1 + k
    return _hex(int(r * f), int(g * f), int(b * f))


def mix(a: str, b: str, t: float) -> str:
    ra, ga, ba = _rgb(a)
    rb, gb, bb = _rgb(b)
    return _hex(int(ra + (rb - ra) * t), int(ga + (gb - ga) * t),
                int(ba + (bb - ba) * t))


def luminance(hexstr: str) -> float:
    r, g, b = _rgb(hexstr)
    return 0.299 * r + 0.587 * g + 0.114 * b


def _theme(name: str, bg: str, fg: str, accent: str, accent_fg: str) -> dict:
    """Derive a full palette from four base colors."""
    dark = luminance(bg) < 140
    panel = shade(bg, 0.10 if dark else -0.045)
    field = shade(bg, 0.16 if dark else -0.09)
    border = shade(bg, 0.28 if dark else -0.18)
    return {
        "name": name, "bg": bg, "fg": fg, "accent": accent,
        "accent_fg": accent_fg,
        "panel": panel, "field": field, "border": border,
        "sub_fg": mix(fg, bg, 0.42),
        "zebra": shade(bg, 0.06 if dark else -0.05),
        "danger": "#c73e3a",
        "danger_fg": "#ffffff",
        "face": field, "face_edge": border,
        "ticks": mix(fg, bg, 0.2), "hands": fg, "second": accent,
        "caption_bg": bg,
    }


THEMES: dict[str, dict] = {t["name"]: t for t in [
    _theme("Windows Light", "#f0f0f0", "#1a1a1a", "#0078d7", "#ffffff"),
    _theme("Windows Dark", "#202020", "#f3f3f3", "#4cc2ff", "#083344"),
    _theme("Midnight", "#171c2c", "#dfe6ff", "#5b8cff", "#0a1330"),
    _theme("Carbon", "#1b1b1f", "#e8e8ea", "#e0443e", "#ffffff"),
    _theme("Nord", "#2e3440", "#eceff4", "#88c0d0", "#22303c"),
    _theme("Dracula", "#282a36", "#f8f8f2", "#bd93f9", "#21222c"),
    _theme("Solarized Dark", "#002b36", "#eee8d5", "#268bd2", "#ffffff"),
    _theme("Solarized Light", "#fdf6e3", "#073642", "#268bd2", "#ffffff"),
    _theme("Forest", "#14251a", "#d8efdd", "#58c470", "#0c2413"),
    _theme("Sakura", "#fdf0f4", "#4a2c38", "#e75480", "#ffffff"),
    _theme("Ocean Deep", "#0e2233", "#d7e9f7", "#2ec4b6", "#062a28"),
    _theme("Mocha", "#2b211c", "#f3e6dc", "#d9954a", "#2b1a0c"),
    _theme("Retro Terminal", "#0a0f0a", "#33ff66", "#33ff66", "#04140a"),
    _theme("Sunset", "#241527", "#ffe3ec", "#ff8c42", "#331303"),
    _theme("Grape Soda", "#241a33", "#efe4ff", "#b967ff", "#241033"),
    _theme("High Contrast", "#000000", "#ffffff", "#ffd400", "#000000"),
]}

DEFAULT_SETTINGS = {
    "theme": "Windows Light",
    "font": "M",          # S / M / L / XL
    "zebra": True,
    "titlebar": True,
    "smooth": True,
    "date": True,
    "topmost": False,
    "accent": None,       # None = use the theme's accent
}

FONT_SIZES = {"S": 9, "M": 10, "L": 12, "XL": 14}


def load_settings(path: str | None = None) -> dict:
    path = path or SETTINGS_FILE
    allowed = {"theme": str, "font": str, "zebra": bool, "titlebar": bool,
               "smooth": bool, "date": bool, "topmost": bool,
               "accent": (str, type(None))}
    s = dict(DEFAULT_SETTINGS)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for k, v in data.items():
            if k in allowed and isinstance(v, allowed[k]):
                s[k] = v
    except (OSError, ValueError):
        pass
    if s["theme"] not in THEMES:
        s["theme"] = DEFAULT_SETTINGS["theme"]
    if s["font"] not in FONT_SIZES:
        s["font"] = DEFAULT_SETTINGS["font"]
    return s


def save_settings(settings: dict, path: str | None = None) -> None:
    path = path or SETTINGS_FILE
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
    except OSError:
        pass


# --------------------------------------------------------------------------
# Scanning core (no tkinter here, so it is unit-testable on its own)
# --------------------------------------------------------------------------

def _md5():
    try:
        return hashlib.md5(usedforsecurity=False)
    except TypeError:
        return hashlib.md5()


def _file_hash(path: str, nbytes: int | None) -> str | None:
    try:
        h = _md5()
        read = 0
        with open(path, "rb") as f:
            while True:
                block = f.read(CHUNK if nbytes is None else min(CHUNK, nbytes - read))
                if not block:
                    break
                h.update(block)
                read += len(block)
                if nbytes is not None and read >= nbytes:
                    break
        return h.hexdigest()
    except OSError:
        return None


@dataclass(eq=False)  # identity hash: groups are used as dict keys in the GUI
class DupGroup:
    size: int
    paths: list
    mtimes: dict = field(default_factory=dict)

    @property
    def wasted(self) -> int:
        return self.size * (len(self.paths) - 1)


@dataclass
class ScanResult:
    root: str
    files_seen: int
    groups: list


def run_scan(root, min_size, recursive, progress, cancel) -> ScanResult | None:
    """Two-phase duplicate scan. Calls progress(kind, *args) and returns
    None if cancel.is_set() becomes true."""
    files_by_size: dict[int, list[str]] = defaultdict(list)
    seen_dirs: set[str] = set()
    files_seen = 0
    bytes_seen = 0

    for dirpath, dirnames, filenames in os.walk(root):
        if not recursive:
            dirnames[:] = []
        else:
            # Do not follow junction/symlink loops (e.g. "Application Data").
            real = os.path.realpath(dirpath).lower()
            if real in seen_dirs:
                dirnames[:] = []
                continue
            seen_dirs.add(real)
            dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
        for name in filenames:
            if cancel is not None and cancel.is_set():
                return None
            p = os.path.join(dirpath, name)
            try:
                st = os.stat(p)
            except OSError:
                continue
            if not os.path.isfile(p):
                continue
            files_seen += 1
            bytes_seen += st.st_size
            if st.st_size >= min_size and st.st_size > 0:
                files_by_size[st.st_size].append(p)
            if files_seen % 250 == 0:
                progress("walk", files_seen, bytes_seen)

    candidates = [(s, ps) for s, ps in files_by_size.items() if len(ps) > 1]
    candidates.sort(key=lambda kv: -kv[0])  # biggest files first
    total = sum(len(ps) for _, ps in candidates)
    progress("hash_total", total)

    groups: list[DupGroup] = []
    hashed = 0
    for size, paths in candidates:
        by_partial: dict[str, list[str]] = defaultdict(list)
        for p in paths:
            if cancel is not None and cancel.is_set():
                return None
            h = _file_hash(p, PARTIAL_BYTES)
            if h is not None:
                by_partial[h].append(p)
        for h, ps in by_partial.items():
            if len(ps) < 2:
                continue
            by_full: dict[str, list[str]] = defaultdict(list)
            for p in ps:
                if cancel is not None and cancel.is_set():
                    return None
                fh = _file_hash(p, None)
                if fh is not None:
                    by_full[fh].append(p)
            for fh, fps in by_full.items():
                if len(fps) > 1:
                    mtimes = {}
                    for p in fps:
                        try:
                            mtimes[p] = os.stat(p).st_mtime
                        except OSError:
                            mtimes[p] = 0.0
                    groups.append(DupGroup(size=size, paths=fps, mtimes=mtimes))
        hashed += len(paths)
        progress("hash", hashed, total, paths[0])

    groups.sort(key=lambda g: -g.wasted)
    return ScanResult(root=root, files_seen=files_seen, groups=groups)


# --------------------------------------------------------------------------
# Recycle Bin (shell API, so deletion is reversible)
# --------------------------------------------------------------------------

class _SHFILEOPSTRUCTW(ctypes.Structure):
    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("wFunc", ctypes.c_uint),
        ("pFrom", ctypes.c_void_p),
        ("pTo", ctypes.c_void_p),
        ("fFlags", ctypes.c_ushort),
        ("fAnyOperationsAborted", wintypes.BOOL),
        ("hNameMappings", ctypes.c_void_p),
        ("lpszProgressTitle", ctypes.c_void_p),
    ]


def recycle_paths(paths) -> tuple[list, bool]:
    """Move files to the Recycle Bin. Returns (survivors, aborted);
    survivors are paths that still exist afterwards (i.e. failed)."""
    paths = [os.path.abspath(p) for p in paths]
    buf = ctypes.create_unicode_buffer("\0".join(paths) + "\0")
    op = _SHFILEOPSTRUCTW()
    op.hwnd = None
    op.wFunc = 3  # FO_DELETE
    op.pFrom = ctypes.cast(buf, ctypes.c_void_p)
    op.pTo = None
    op.fFlags = 0x40 | 0x10 | 0x4 | 0x400  # ALLOWUNDO | NOCONFIRMATION | SILENT | NOERRORUI
    op.fAnyOperationsAborted = False
    try:
        ctypes.windll.ole32.CoInitialize(None)
    except Exception:
        pass
    code = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
    if code != 0:
        raise OSError(f"SHFileOperationW failed with code {code}")
    survivors = [p for p in paths if os.path.exists(p)]
    return survivors, bool(op.fAnyOperationsAborted)


# --------------------------------------------------------------------------
# Cleaner core (BleachBit-style; no tkinter here, fully unit-testable)
# --------------------------------------------------------------------------

@dataclass(eq=False)
class CleanItem:
    cid: str            # unique id, also the tree row id
    category: str
    name: str
    desc: str
    destructive: bool = False     # loses data: logins, history, passwords…
    contents: tuple = ()          # dir globs: wipe contents, keep folder
    contents_files_only: bool = False  # leave arbitrary temp subfolders intact
    dirs: tuple = ()              # dir globs: remove folder entirely
    file_globs: tuple = ()        # file globs: remove each file
    special: str = ""             # "", "recyclebin", "clipboard", "dns"
    browser_exes: tuple = ()      # processes that must be closed first


# Items that are pre-checked because they cannot lose personal data.
SAFE_DEFAULT_CLEANERS = {"temp", "thumbs", "wer", "d3d", "dumps", "dns",
                         "clipboard"}


def _protected_roots() -> list:
    """Folders the cleaner must NEVER touch, even by accident: personal
    data (Downloads, Documents, …) — in the home profile and its OneDrive
    twin. The whitelist already excludes them; this is the safety net."""
    home = os.path.expanduser("~")
    names = ("Downloads", "Documents", "Desktop", "Pictures", "Videos",
             "Music", "Saved Games")
    roots = []
    for base in (home, os.path.join(home, "OneDrive")):
        for n in names:
            roots.append(os.path.join(base, n))
    # Downloads may be redirected away from the usual profile folder.
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") as key:
            for name in ("Downloads",
                    "{374DE290-123F-4565-9164-39C4925E467B}"):
                try:
                    value, _kind = winreg.QueryValueEx(key, name)
                    value = os.path.expandvars(value)
                    if value:
                        roots.append(value)
                except OSError:
                    pass
    except OSError:
        pass
    return roots


PROTECTED = _protected_roots()


def is_protected(path: str) -> bool:
    np = os.path.normcase(os.path.realpath(os.path.abspath(path)))
    for r in PROTECTED:
        nr = os.path.normcase(os.path.realpath(os.path.abspath(r)))
        if np == nr or np.startswith(nr + os.sep):
            return True
    return False


def _safe_expand(patterns) -> list:
    """Expand globs but drop anything that resolves into a protected
    personal folder (Downloads, Documents, …)."""
    return [p for p in (pat for g in patterns for pat in glob.glob(g))
            if not is_protected(p)]

_FRIENDLY = {"chrome.exe": "Google Chrome", "msedge.exe": "Microsoft Edge",
             "firefox.exe": "Firefox", "brave.exe": "Brave",
             "opera.exe": "Opera", "waterfox.exe": "Waterfox",
             "vivaldi.exe": "Vivaldi", "browser.exe": "Yandex Browser",
             "librewolf.exe": "LibreWolf", "floorp.exe": "Floorp",
             "zen.exe": "Zen Browser", "mullvadbrowser.exe": "Mullvad Browser",
             "palemoon.exe": "Pale Moon", "seamonkey.exe": "SeaMonkey",
             "dragon.exe": "Comodo Dragon", "slimjet.exe": "Slimjet",
             "iron.exe": "SRWare Iron", "arc.exe": "Arc Browser",
             "avastbrowser.exe": "Avast Secure Browser",
             "avgbrowser.exe": "AVG Secure Browser",
             "epicprivacybrowser.exe": "Epic Privacy Browser",
             "duckduckgo.exe": "DuckDuckGo Browser",
             "duckduckgo.webview.exe": "DuckDuckGo Browser",
             "ecosiabrowser.exe": "Ecosia Browser",
             "ecosia.exe": "Ecosia Browser",
             "tor.exe": "Tor Browser"}


def default_roots() -> dict:
    profile = os.path.expanduser("~")
    local = os.environ.get("LOCALAPPDATA") or os.path.join(
        profile, "AppData", "Local")
    roaming = os.environ.get("APPDATA") or os.path.join(
        profile, "AppData", "Roaming")
    windows = os.environ.get("WINDIR", r"C:\Windows")
    return {
        "TEMP": os.environ.get("TEMP") or os.environ.get("TMP") or
                os.path.join(local, "Temp"),
        "WTEMP": os.path.join(windows, "Temp"),
        "LOCAL": local,
        "APPDATA": roaming,
    }


def browser_is_installed(exe: str, roots: dict | None = None) -> bool:
    """Find browsers in common paths, install records, or Store registration."""
    exe = exe.lower()
    r = roots or default_roots()
    LOC, APP = r["LOCAL"], r["APPDATA"]
    program_roots = [os.environ.get(k, "") for k in
                     ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432")]
    system_drive = os.environ.get("SystemDrive", "C:\\").rstrip("\\/")
    system_root = system_drive + "\\"
    program_roots.extend((os.path.join(system_root, "Program Files"),
                          os.path.join(system_root, "Program Files (x86)")))
    candidates = []
    if exe == "chrome.exe":
        candidates = [os.path.join(LOC, "Google", "Chrome", "Application", exe)]
        candidates += [os.path.join(p, "Google", "Chrome", "Application", exe)
                       for p in program_roots if p]
    elif exe == "msedge.exe":
        candidates = [os.path.join(LOC, "Microsoft", "Edge", "Application", exe)]
        candidates += [os.path.join(p, "Microsoft", "Edge", "Application", exe)
                      for p in program_roots if p]
    elif exe == "brave.exe":
        candidates = [os.path.join(LOC, "BraveSoftware", "Brave-Browser",
                                   "Application", exe)]
        candidates += [os.path.join(p, "BraveSoftware", "Brave-Browser",
                                    "Application", exe)
                       for p in program_roots if p]
    elif exe == "firefox.exe":
        candidates = [os.path.join(p, "Mozilla Firefox", exe)
                      for p in program_roots if p]
        candidates.extend((os.path.join(APP, "Programs", "Mozilla Firefox", exe),
                           os.path.join(LOC, "Mozilla Firefox", exe),
                           os.path.join(LOC, "Programs", "Mozilla Firefox", exe)))
    elif exe == "opera.exe":
        candidates = [os.path.join(APP, "Opera Software", "Opera Stable",
                                   "launcher.exe"),
                      os.path.join(LOC, "Programs", "Opera", "launcher.exe")]
        candidates += [os.path.join(p, "Opera", "launcher.exe")
                       for p in program_roots if p]
    elif exe == "waterfox.exe":
        candidates = [os.path.join(p, "Waterfox", "waterfox.exe")
                      for p in program_roots if p]
        candidates.extend((os.path.join(LOC, "Programs", "Waterfox",
                                       "waterfox.exe"),
                           os.path.join(APP, "Programs", "Waterfox",
                                        "waterfox.exe")))
    browser_names = {
        "chrome.exe": ("google chrome",),
        "msedge.exe": ("microsoft edge",),
        "brave.exe": ("brave",),
        "firefox.exe": ("firefox",),
        "opera.exe": ("opera stable", "opera browser",
                      "opera internet browser"),
        "waterfox.exe": ("waterfox",),
    }
    executable_names = (("opera.exe", "launcher.exe") if exe == "opera.exe"
                        else (exe,))
    registry_views = [0]
    for name in ("KEY_WOW64_32KEY", "KEY_WOW64_64KEY"):
        view = getattr(winreg, name, 0)
        if view and view not in registry_views:
            registry_views.append(view)
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in registry_views:
            access = winreg.KEY_READ | view
            app_path_key = (rf"Software\Microsoft\Windows\CurrentVersion\App Paths\{exe}")
            try:
                with winreg.OpenKey(hive, app_path_key, 0, access) as key:
                    path, _kind = winreg.QueryValueEx(key, None)
                    candidates.append(os.path.expandvars(path.strip().strip('"')))
            except OSError:
                pass
            uninstall_root = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
            try:
                with winreg.OpenKey(hive, uninstall_root, 0, access) as root_key:
                    index = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(root_key, index)
                            index += 1
                        except OSError:
                            break
                        try:
                            with winreg.OpenKey(root_key, subkey_name, 0, access) as entry:
                                display, _ = winreg.QueryValueEx(entry, "DisplayName")
                                if not isinstance(display, str):
                                    continue
                                if not any(n in display.lower()
                                           for n in browser_names.get(exe, ())):
                                    continue
                                location, _ = winreg.QueryValueEx(entry, "InstallLocation")
                                if not isinstance(location, str):
                                    continue
                                location = os.path.expandvars(location.strip().strip('"'))
                                if location:
                                    for executable in executable_names:
                                        candidates.extend((
                                            os.path.join(location, executable),
                                            os.path.join(location, "Application", executable)))
                        except (OSError, AttributeError):
                            continue
            except OSError:
                pass
    if (bool(shutil.which(exe)) or
            any(os.path.isfile(path) for path in candidates if path)):
        return True

    # The Microsoft Store Edge package can be registered as an app proxy while
    # its browser binary is managed outside the package folder. In that case
    # the classic msedge.exe path is absent even though Edge and its profile
    # are installed. Confirm the current user's actual Edge package registration
    # and install root; do not mistake WebView2 for the browser.
    if exe == "msedge.exe":
        package_root = (r"Software\Classes\Local Settings\Software\Microsoft"
                        r"\Windows\CurrentVersion\AppModel\Repository\Packages")
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, package_root) as root:
                index = 0
                while True:
                    try:
                        package_name = winreg.EnumKey(root, index)
                        index += 1
                    except OSError:
                        break
                    if not package_name.lower().startswith(
                            "microsoft.microsoftedge.stable_"):
                        continue
                    try:
                        with winreg.OpenKey(root, package_name) as package:
                            display, _ = winreg.QueryValueEx(package, "DisplayName")
                            location, _ = winreg.QueryValueEx(
                                package, "PackageRootFolder")
                        if (isinstance(display, str) and
                                display.strip().lower() == "microsoft edge" and
                                isinstance(location, str) and
                                os.path.isdir(os.path.expandvars(location))):
                            return True
                    except OSError:
                        continue
        except OSError:
            pass
    return False


def _additional_browser_specs(roots: dict | None = None) -> list[dict]:
    """Known Windows browser profiles outside the original cleaner catalog."""
    r = roots or default_roots()
    local, app = r["LOCAL"], r["APPDATA"]
    program_roots = []
    for key in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        value = os.environ.get(key)
        if value and value not in program_roots:
            program_roots.append(value)
    system_drive = os.environ.get("SystemDrive", "C:\\").rstrip("\\/")
    for value in (os.path.join(system_drive + "\\", "Program Files"),
                  os.path.join(system_drive + "\\", "Program Files (x86)")):
        if value not in program_roots:
            program_roots.append(value)

    def pf(*parts):
        return [os.path.join(base, *parts) for base in program_roots]

    home = os.path.expanduser("~")
    user_folders = [os.path.join(home, "Desktop"),
                    os.path.join(home, "Downloads"),
                    os.path.join(home, "OneDrive", "Desktop"),
                    os.path.join(home, "OneDrive", "Downloads")]
    shell_folder_values = (
        ("Desktop", "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"),
        ("Downloads", "{374DE290-123F-4565-9164-39C4925E467B}"))
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") as key:
            for value_names in shell_folder_values:
                for value_name in value_names:
                    try:
                        value, _kind = winreg.QueryValueEx(key, value_name)
                    except OSError:
                        continue
                    if isinstance(value, str) and value:
                        user_folders.append(os.path.expandvars(value))
                        break
    except OSError:
        pass
    user_folders = list(dict.fromkeys(user_folders))
    tor_roots = [os.path.join(folder, "Tor Browser")
                 for folder in user_folders]
    tor_roots.extend((os.path.join(home, "Tor Browser"),
                      os.path.join(local, "Programs", "Tor Browser")))
    tor_install = [path for root in tor_roots for path in (
        os.path.join(root, "Start Tor Browser.exe"),
        os.path.join(root, "Browser", "firefox.exe"),
        os.path.join(root, "Browser", "TorBrowser", "Tor", "tor.exe"))]
    tor_install.extend(pf("Tor Browser", "Start Tor Browser.exe"))
    tor_install.extend(pf("Tor Browser", "Browser", "firefox.exe"))
    tor_profiles = [os.path.join(root, "Browser", "TorBrowser", "Data",
                                 "Browser") for root in tor_roots]
    tor_profiles.extend(pf("Tor Browser", "Browser", "TorBrowser", "Data",
                           "Browser"))

    return [
        {"id": "duckduckgo", "name": "DuckDuckGo Browser",
         "family": "chromium",
         "processes": ("duckduckgo.exe", "duckduckgo.webview.exe"),
         "display": ("duckduckgo browser", "duckduckgo.desktopbrowser",
                     "duckduckgo"),
         "install": [os.path.join(local, "Programs", "DuckDuckGo",
                                   "DuckDuckGo.exe")],
         "profiles": [os.path.join(local, "Packages",
                                    "DuckDuckGo.DesktopBrowser_*",
                                    "LocalCache", "Local",
                                    "DuckDuckGo.WebView.Published",
                                    "User Data"),
                      os.path.join(local, "Packages",
                                   "DuckDuckGo.DesktopBrowser_*",
                                   "LocalState", "EBWebView", "Default")],
         "cache_only": True},
        {"id": "ecosia", "name": "Ecosia Browser", "family": "chromium",
         "processes": ("ecosiabrowser.exe", "ecosia.exe"),
         "detect_processes": ("ecosiabrowser.exe", "ecosia.exe",
                              "browser.exe"),
         "process_path_tokens": ("ecosiabrowser",),
         "display": ("ecosia browser", "ecosiabrowser", "ecosia"),
         "install": [os.path.join(local, "EcosiaBrowser", "Application",
                                   "browser.exe"),
                     os.path.join(local, "Programs", "Ecosia Browser",
                                   "Application", "browser.exe")] +
                    pf("EcosiaBrowser", "Application", "browser.exe"),
         "profiles": [os.path.join(local, "EcosiaBrowser", "User Data"),
                      os.path.join(local, "Ecosia", "Browser", "User Data")]},
        {"id": "waterfox", "name": "Waterfox", "family": "gecko",
         "processes": ("waterfox.exe",), "display": ("waterfox",),
         "install": pf("Waterfox", "waterfox.exe") + [
             os.path.join(local, "Programs", "Waterfox", "waterfox.exe")],
         "profiles": [os.path.join(app, "Waterfox", "Profiles")],
         "cache_profiles": [os.path.join(local, "Waterfox", "Profiles")]},
        {"id": "opera-gx", "name": "Opera GX", "family": "chromium",
         "processes": ("opera.exe",), "display": ("opera gx",),
         "process_path_tokens": ("opera gx",),
         "install": pf("Opera GX", "launcher.exe") + [
             os.path.join(local, "Programs", "Opera GX", "launcher.exe")],
         "profiles": [os.path.join(app, "Opera Software", "Opera GX Stable")]},
        {"id": "opera-air", "name": "Opera Air", "family": "chromium",
         "processes": ("opera.exe",), "display": ("opera air",),
         "process_path_tokens": ("opera air",),
         "install": [os.path.join(local, "Programs", "Opera Air", "*",
                                   "opera.exe")],
         "markers": [os.path.join(local, "Programs", "Opera Air", "*",
                                   "assistant_package")],
         "profiles": [os.path.join(app, "Opera Software", "Opera Air Stable")],
         "profile_marker_required": True},
        {"id": "vivaldi", "name": "Vivaldi", "family": "chromium",
         "processes": ("vivaldi.exe",), "display": ("vivaldi",),
         "install": [os.path.join(local, "Vivaldi", "Application",
                                   "vivaldi.exe"),
                     os.path.join(local, "Programs", "Vivaldi", "Application",
                                   "vivaldi.exe")] +
                    pf("Vivaldi", "Application", "vivaldi.exe"),
         "profiles": [os.path.join(local, "Vivaldi", "User Data")]},
        {"id": "chromium", "name": "Chromium", "family": "chromium",
         "processes": ("chrome.exe",), "display": ("chromium",),
         "process_path_tokens": ("chromium",),
         "install": [os.path.join(local, "Chromium", "Application",
                                   "chrome.exe")] +
                    pf("Chromium", "Application", "chrome.exe"),
         "profiles": [os.path.join(local, "Chromium", "User Data")]},
        {"id": "yandex-browser", "name": "Yandex Browser",
         "family": "chromium", "processes": ("browser.exe",),
         "display": ("yandex browser", "yandex"),
         "process_path_tokens": ("yandex",),
         "install": [os.path.join(local, "Yandex", "YandexBrowser",
                                   "Application", "browser.exe")] +
                    pf("Yandex", "YandexBrowser", "Application", "browser.exe"),
         "profiles": [os.path.join(local, "Yandex", "YandexBrowser",
                                   "User Data")]},
        {"id": "avast-secure-browser", "name": "Avast Secure Browser",
         "family": "chromium", "processes": ("avastbrowser.exe",),
         "display": ("avast secure browser",),
         "install": [os.path.join(local, "AVAST Software", "Browser",
                                   "Application", "AvastBrowser.exe")] +
                    pf("AVAST Software", "Browser", "Application",
                       "AvastBrowser.exe"),
         "profiles": [os.path.join(local, "AVAST Software", "Browser",
                                   "User Data")]},
        {"id": "avg-secure-browser", "name": "AVG Secure Browser",
         "family": "chromium", "processes": ("avgbrowser.exe",),
         "display": ("avg secure browser",),
         "install": [os.path.join(local, "AVG", "Browser", "Application",
                                   "AVGBrowser.exe")] +
                    pf("AVG", "Browser", "Application", "AVGBrowser.exe"),
         "profiles": [os.path.join(local, "AVG", "Browser", "User Data")]},
        {"id": "librewolf", "name": "LibreWolf", "family": "gecko",
         "processes": ("librewolf.exe",), "display": ("librewolf",),
         "install": [os.path.join(local, "LibreWolf", "librewolf.exe"),
                     os.path.join(local, "Programs", "LibreWolf",
                                  "librewolf.exe")] + pf("LibreWolf", "librewolf.exe"),
         "profiles": [os.path.join(app, "LibreWolf", "Profiles"),
                      os.path.join(app, "librewolf", "Profiles")],
         "cache_profiles": [os.path.join(local, "LibreWolf", "Profiles"),
                            os.path.join(local, "librewolf", "Profiles")]},
        {"id": "floorp", "name": "Floorp", "family": "gecko",
         "processes": ("floorp.exe",), "display": ("floorp",),
         "install": [os.path.join(local, "Programs", "Floorp", "floorp.exe"),
                     os.path.join(local, "Floorp", "floorp.exe")] +
                    pf("Floorp", "floorp.exe"),
         "profiles": [os.path.join(app, "Floorp", "Profiles")],
         "cache_profiles": [os.path.join(local, "Floorp", "Profiles")]},
        {"id": "zen-browser", "name": "Zen Browser", "family": "gecko",
         "processes": ("zen.exe",), "display": ("zen browser",),
         "install": [os.path.join(local, "Programs", "Zen Browser", "zen.exe"),
                     os.path.join(local, "Zen", "zen.exe")] +
                    pf("Zen Browser", "zen.exe"),
         "profiles": [os.path.join(app, "zen", "Profiles")],
         "cache_profiles": [os.path.join(local, "zen", "Profiles")]},
        {"id": "mullvad-browser", "name": "Mullvad Browser",
         "family": "gecko", "processes": ("mullvadbrowser.exe",),
         "display": ("mullvad browser",),
         "install": [os.path.join(local, "Programs", "Mullvad Browser",
                                   "Browser", "firefox.exe")] +
                    pf("Mullvad Browser", "Browser", "firefox.exe"),
         "profiles": [os.path.join(app, "Mullvad Browser", "Profiles")],
         "cache_profiles": [os.path.join(local, "Mullvad Browser", "Profiles")]},
        {"id": "pale-moon", "name": "Pale Moon", "family": "gecko",
         "processes": ("palemoon.exe",),
         "install_executables": ("palemoon-portable.exe",),
         "display": ("pale moon",),
         "install": [os.path.join(local, "Programs", "Pale Moon",
                                   "palemoon.exe"),
                     os.path.join(local, "Programs", "Pale Moon",
                                  "palemoon-portable.exe")] +
                    pf("Pale Moon", "palemoon.exe") +
                    pf("Pale Moon", "palemoon-portable.exe"),
         "profiles": [os.path.join(app, "Moonchild Productions", "Pale Moon",
                                   "Profiles")],
         "cache_profiles": [os.path.join(local, "Moonchild Productions",
                                         "Pale Moon", "Profiles")]},
        {"id": "tor-browser", "name": "Tor Browser", "family": "gecko",
         "processes": ("firefox.exe", "tor.exe"),
         "detect_processes": ("tor.exe",),
         "install_executables": ("start tor browser.exe",),
         "process_path_tokens": ("tor browser", "torbrowser"),
         "display": ("tor browser",),
         "install": tor_install, "profiles": tor_profiles,
         "cache_profiles": tor_profiles,
         "cache_only": True, "running_location_profiles": True},
        {"id": "seamonkey", "name": "SeaMonkey", "family": "gecko",
         "processes": ("seamonkey.exe",), "display": ("seamonkey",),
         "install": [os.path.join(local, "Programs", "SeaMonkey",
                                   "seamonkey.exe")] + pf("SeaMonkey", "seamonkey.exe"),
         "profiles": [os.path.join(app, "Mozilla", "SeaMonkey", "Profiles"),
                      os.path.join(app, "SeaMonkey", "Profiles")],
         "cache_profiles": [os.path.join(local, "Mozilla", "SeaMonkey",
                                         "Profiles")]},
    ]


def _registered_store_browser_names() -> list[str]:
    """Read Store-package identities so packaged browsers are discoverable."""
    names = []
    package_root = (r"Software\Classes\Local Settings\Software\Microsoft"
                    r"\Windows\CurrentVersion\AppModel\Repository\Packages")
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(hive, package_root) as root:
                index = 0
                while True:
                    try:
                        package_name = winreg.EnumKey(root, index)
                        index += 1
                    except OSError:
                        break
                    try:
                        with winreg.OpenKey(root, package_name) as package:
                            display, _ = winreg.QueryValueEx(package,
                                                              "DisplayName")
                        if isinstance(display, str):
                            names.extend((display.casefold(),
                                          package_name.casefold()))
                    except OSError:
                        # Package identities are still useful when Windows
                        # withholds the display-name value.
                        names.append(package_name.casefold())
        except OSError:
            continue
    return names


def _installed_program_browser_names() -> list[str]:
    displays = _registered_store_browser_names()
    views = [0]
    for name in ("KEY_WOW64_32KEY", "KEY_WOW64_64KEY"):
        view = getattr(winreg, name, 0)
        if view and view not in views:
            views.append(view)
    uninstall = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in views:
            try:
                with winreg.OpenKey(hive, uninstall, 0,
                                    winreg.KEY_READ | view) as root:
                    index = 0
                    while True:
                        try:
                            subkey = winreg.EnumKey(root, index)
                            index += 1
                        except OSError:
                            break
                        try:
                            with winreg.OpenKey(root, subkey) as entry:
                                display, _ = winreg.QueryValueEx(entry,
                                                                  "DisplayName")
                            if isinstance(display, str):
                                displays.append(display.casefold())
                        except OSError:
                            continue
            except OSError:
                continue
    return displays


def _registered_browser_app_paths(specs: list[dict]) -> list[tuple[str, str]]:
    """Find custom install locations registered in Windows App Paths."""
    executable_names = {
        str(name).casefold()
        for spec in specs
        for name in (*spec.get("processes", ()),
                     *spec.get("detect_processes", ()),
                     *spec.get("install_executables", ()))
    }
    views = [0]
    for name in ("KEY_WOW64_32KEY", "KEY_WOW64_64KEY"):
        view = getattr(winreg, name, 0)
        if view and view not in views:
            views.append(view)
    root = r"Software\Microsoft\Windows\CurrentVersion\App Paths"
    found = []
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in views:
            for executable in executable_names:
                try:
                    with winreg.OpenKey(hive, root + "\\" + executable, 0,
                                        winreg.KEY_READ | view) as key:
                        value, _kind = winreg.QueryValueEx(key, None)
                    if isinstance(value, str):
                        path = os.path.expandvars(value.strip().strip('"'))
                        found.append((executable, path))
                except OSError:
                    continue
    return found


def _running_browser_process_paths(specs: list[dict]) -> list[tuple[str, str]]:
    """Get executable paths for known browser processes without disk crawling."""
    if os.name != "nt":
        return []
    process_names = {
        str(name).casefold()
        for spec in specs
        for name in (*spec.get("processes", ()),
                     *spec.get("detect_processes", ()))
    }
    if not process_names:
        return []

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD),
                    ("szExeFile", wintypes.WCHAR * 260)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    snapshot_fn = kernel32.CreateToolhelp32Snapshot
    snapshot_fn.argtypes = (wintypes.DWORD, wintypes.DWORD)
    snapshot_fn.restype = wintypes.HANDLE
    first_fn = kernel32.Process32FirstW
    first_fn.argtypes = (wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
    first_fn.restype = wintypes.BOOL
    next_fn = kernel32.Process32NextW
    next_fn.argtypes = first_fn.argtypes
    next_fn.restype = wintypes.BOOL
    open_fn = kernel32.OpenProcess
    open_fn.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    open_fn.restype = wintypes.HANDLE
    image_fn = kernel32.QueryFullProcessImageNameW
    image_fn.argtypes = (wintypes.HANDLE, wintypes.DWORD,
                         wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD))
    image_fn.restype = wintypes.BOOL
    close_fn = kernel32.CloseHandle
    close_fn.argtypes = (wintypes.HANDLE,)
    close_fn.restype = wintypes.BOOL

    snapshot = snapshot_fn(0x00000002, 0)  # TH32CS_SNAPPROCESS
    if not snapshot or snapshot == wintypes.HANDLE(-1).value:
        return []
    found = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        if not first_fn(snapshot, ctypes.byref(entry)):
            return found
        while True:
            name = entry.szExeFile.casefold()
            if name in process_names:
                handle = open_fn(0x1000, False, entry.th32ProcessID)
                if handle:
                    try:
                        buffer = ctypes.create_unicode_buffer(32768)
                        size = wintypes.DWORD(len(buffer))
                        if image_fn(handle, 0, buffer, ctypes.byref(size)):
                            found.append((name, buffer.value))
                    finally:
                        close_fn(handle)
            if not next_fn(snapshot, ctypes.byref(entry)):
                break
    finally:
        close_fn(snapshot)
    return found


def _running_process_executable_paths() -> list[tuple[str, str]]:
    """Return accessible executable paths for currently running processes."""
    if os.name != "nt":
        return []

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD),
                    ("szExeFile", wintypes.WCHAR * 260)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    snapshot_fn = kernel32.CreateToolhelp32Snapshot
    snapshot_fn.argtypes = (wintypes.DWORD, wintypes.DWORD)
    snapshot_fn.restype = wintypes.HANDLE
    first_fn = kernel32.Process32FirstW
    first_fn.argtypes = (wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
    first_fn.restype = wintypes.BOOL
    next_fn = kernel32.Process32NextW
    next_fn.argtypes = first_fn.argtypes
    next_fn.restype = wintypes.BOOL
    open_fn = kernel32.OpenProcess
    open_fn.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    open_fn.restype = wintypes.HANDLE
    image_fn = kernel32.QueryFullProcessImageNameW
    image_fn.argtypes = (wintypes.HANDLE, wintypes.DWORD,
                         wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD))
    image_fn.restype = wintypes.BOOL
    close_fn = kernel32.CloseHandle
    close_fn.argtypes = (wintypes.HANDLE,)
    close_fn.restype = wintypes.BOOL

    snapshot = snapshot_fn(0x00000002, 0)  # TH32CS_SNAPPROCESS
    if not snapshot or snapshot == wintypes.HANDLE(-1).value:
        return []
    found = []
    seen = set()
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        if not first_fn(snapshot, ctypes.byref(entry)):
            return found
        while True:
            handle = open_fn(0x1000, False, entry.th32ProcessID)
            if handle:
                try:
                    buffer = ctypes.create_unicode_buffer(32768)
                    size = wintypes.DWORD(len(buffer))
                    if image_fn(handle, 0, buffer, ctypes.byref(size)):
                        path = buffer.value
                        key = os.path.normcase(os.path.abspath(path))
                        if key not in seen:
                            seen.add(key)
                            found.append((entry.szExeFile.casefold(), path))
                finally:
                    close_fn(handle)
            if not next_fn(snapshot, ctypes.byref(entry)):
                break
    finally:
        close_fn(snapshot)
    return found


def _detect_additional_browsers(roots: dict | None = None) -> list[dict]:
    """Detect installed browsers, including Store and running portable apps."""
    displays = _installed_program_browser_names()
    specs = _additional_browser_specs(roots)
    app_paths = _registered_browser_app_paths(specs)
    running = _running_browser_process_paths(specs)
    detected = []
    for spec in specs:
        registered = any(
            any(term in display for term in spec["display"]) and
            "webview" not in display for display in displays)
        registered = registered or any(
            family.casefold() in display
            for family in spec.get("appx_families", ())
            for display in displays)
        installed_exe = any(
            os.path.isfile(path)
            for pattern in spec.get("install", ())
            for path in glob.glob(pattern))
        marker_exists = any(
            os.path.exists(path)
            for pattern in spec.get("markers", ())
            for path in glob.glob(pattern))
        profile_exists = any(
            os.path.isdir(path)
            for pattern in spec.get("profiles", ())
            for path in glob.glob(pattern))
        process_names = {str(name).casefold() for name in
                         spec.get("detect_processes", spec["processes"])}
        app_path_names = {
            str(name).casefold()
            for name in (*spec["processes"],
                         *spec.get("detect_processes", ()),
                         *spec.get("install_executables", ()))
        }
        path_tokens = tuple(str(token).casefold() for token in
                            spec.get("process_path_tokens", ()))
        app_path_hits = [path for name, path in app_paths
                         if name in app_path_names and os.path.isfile(path) and
                         (not path_tokens or any(token in path.casefold()
                                                 for token in path_tokens))]
        process_hits = [path for name, path in running
                        if name in process_names and
                        (not path_tokens or any(token in path.casefold()
                                                for token in path_tokens))]
        if spec.get("running_location_profiles") and process_hits:
            runtime_spec = dict(spec)
            runtime_profiles = []
            for executable in process_hits:
                folder = os.path.dirname(executable)
                normalized = os.path.normcase(executable)
                marker = os.path.normcase(os.sep + "Browser" + os.sep +
                                          "TorBrowser" + os.sep)
                position = normalized.find(marker)
                if position >= 0:
                    browser_root = executable[:position]
                    browser_data = os.path.join(browser_root, "Browser",
                                                "TorBrowser", "Data", "Browser")
                else:
                    browser_data = os.path.join(folder, "TorBrowser", "Data",
                                                "Browser")
                runtime_profiles.append(browser_data)
            runtime_spec["profiles"] = runtime_profiles
            runtime_spec["cache_profiles"] = runtime_profiles
            spec = runtime_spec
        if spec.get("profile_marker_required"):
            installed = installed_exe or registered or (
                marker_exists and profile_exists) or bool(process_hits) or bool(app_path_hits)
        else:
            installed = (installed_exe or registered or bool(process_hits) or
                         bool(app_path_hits) or
                         (marker_exists and profile_exists))
        if installed:
            detected.append(spec)
    return detected


def _add_chromium_browser_cleaners(items: list, spec: dict) -> None:
    roots = tuple(spec.get("profiles", ()))
    if not roots:
        return
    profiles = tuple(os.path.join(root, "*") for root in roots)
    processes = tuple(spec["processes"])
    cid, category = spec["id"], "🌐 " + spec["name"]
    cache_dirs = [os.path.join(root, name) for root in roots
                  for name in ("Cache", "Code Cache", "GPUCache")]
    for profile in profiles:
        cache_dirs.extend(os.path.join(profile, name)
                          for name in ("Cache", "Code Cache", "GPUCache"))
        cache_dirs.append(os.path.join(profile, "Service Worker",
                                       "CacheStorage"))
    if spec.get("cache_only"):
        items.append(CleanItem(
            f"{cid}-cache", category, "Cache",
            "Browser cache only; browser data, settings and downloads are left alone",
            dirs=tuple(cache_dirs), browser_exes=processes))
        return
    network_cookies = tuple(os.path.join(profile, "Network", name)
                            for profile in profiles
                            for name in ("Cookies", "Cookies-journal"))
    old_cookies = tuple(os.path.join(profile, name)
                        for profile in profiles
                        for name in ("Cookies", "Cookies-journal"))
    items.extend((
        CleanItem(f"{cid}-cache", category, "Cache",
                  "Browser cache only; settings and downloads are left alone",
                  dirs=tuple(cache_dirs), browser_exes=processes),
        CleanItem(f"{cid}-cookies", category, "Cookies",
                  "⚠ Clears site logins and signs you out",
                  destructive=True, file_globs=network_cookies + old_cookies,
                  browser_exes=processes),
        CleanItem(f"{cid}-history", category, "Browsing history",
                  "⚠ Removes visit and address-bar history",
                  destructive=True,
                  file_globs=tuple(os.path.join(profile, name)
                                   for profile in profiles
                                   for name in ("History", "History-journal",
                                                "Visited Links", "Top Sites",
                                                "DownloadMetadata")),
                  browser_exes=processes),
        CleanItem(f"{cid}-sessions", category, "Open tabs & sessions",
                  "⚠ Removes saved open-tab session data",
                  destructive=True,
                  file_globs=tuple(path for profile in profiles for path in
                                   (os.path.join(profile, "Sessions", "*"),
                                    os.path.join(profile, "Current Session"),
                                    os.path.join(profile, "Current Tabs"))),
                  browser_exes=processes),
        CleanItem(f"{cid}-passwords", category, "Saved passwords",
                  "⚠ Deletes saved browser passwords",
                  destructive=True,
                  file_globs=tuple(os.path.join(profile, name)
                                   for profile in profiles
                                   for name in ("Login Data",
                                                "Login Data For Account")),
                  browser_exes=processes),
        CleanItem(f"{cid}-forms", category, "Form history & autofill",
                  "⚠ Removes saved address and form autofill data",
                  destructive=True,
                  file_globs=tuple(os.path.join(profile, "Web Data")
                                   for profile in profiles),
                  browser_exes=processes),
    ))


def _add_gecko_browser_cleaners(items: list, spec: dict) -> None:
    roots = tuple(spec.get("profiles", ()))
    if not roots:
        return
    profiles = tuple(os.path.join(root, "*") for root in roots)
    cache_roots = tuple(spec.get("cache_profiles", roots))
    cache_dirs = tuple(path for root in cache_roots
                       for profile in (os.path.join(root, "*"),)
                       for path in (os.path.join(profile, "cache2"),
                                    os.path.join(profile, "startupCache")))
    processes = tuple(spec["processes"])
    cid, category = spec["id"], "🦊 " + spec["name"]
    if spec.get("cache_only"):
        items.append(CleanItem(
            f"{cid}-cache", category, "Cache",
            "Browser cache only; profiles and downloads are left alone",
            dirs=cache_dirs, browser_exes=processes))
        return
    items.extend((
        CleanItem(f"{cid}-cache", category, "Cache",
                  "Browser cache only; profiles and downloads are left alone",
                  dirs=cache_dirs, browser_exes=processes),
        CleanItem(f"{cid}-cookies", category, "Cookies",
                  "⚠ Clears site logins and signs you out",
                  destructive=True,
                  file_globs=tuple(os.path.join(profile, name)
                                   for profile in profiles
                                   for name in ("cookies.sqlite",
                                                "cookies.sqlite-wal",
                                                "cookies.sqlite-shm")),
                  browser_exes=processes),
        CleanItem(f"{cid}-history", category, "Browsing history",
                  "⚠ Removes visit and address-bar history",
                  destructive=True,
                  file_globs=tuple(os.path.join(profile, name)
                                   for profile in profiles
                                   for name in ("places.sqlite",
                                                "places.sqlite-wal",
                                                "places.sqlite-shm")),
                  browser_exes=processes),
        CleanItem(f"{cid}-sessions", category, "Open tabs & sessions",
                  "⚠ Removes saved open-tab session data",
                  destructive=True,
                  file_globs=tuple(path for profile in profiles for path in
                                   (os.path.join(profile, "sessionstore.jsonlz4"),
                                    os.path.join(profile, "sessionstore-backups",
                                                 "*.lz4"))),
                  browser_exes=processes),
        CleanItem(f"{cid}-passwords", category, "Saved passwords",
                  "⚠ Deletes saved browser passwords",
                  destructive=True,
                  file_globs=tuple(path for profile in profiles for path in
                                   (os.path.join(profile, "logins.json"),
                                    os.path.join(profile, "key4.db"))),
                  browser_exes=processes),
        CleanItem(f"{cid}-forms", category, "Form history",
                  "⚠ Removes saved form history",
                  destructive=True,
                  file_globs=tuple(os.path.join(profile, "formhistory.sqlite")
                                   for profile in profiles),
                  browser_exes=processes),
    ))


def build_catalog(roots: dict | None = None,
                  only_installed: bool = True) -> list:
    """Build the cleaner catalog. Paths stay as glob patterns and are only
    resolved at preview/clean time, so nothing is touched here. With
    only_installed=True, a browser appears only when its installation is
    found. Missing browser profiles simply produce zero-byte preview items."""
    r = roots or default_roots()
    TEMP, WTEMP, LOC, APP = r["TEMP"], r["WTEMP"], r["LOCAL"], r["APPDATA"]
    items: list[CleanItem] = []
    A = items.append

    # ---- Windows system --------------------------------------------------
    A(CleanItem("temp", "🪟 Windows system", "Temporary files",
                "Loose files directly in TEMP; personal subfolders are left alone",
                contents=(TEMP,), contents_files_only=True))
    A(CleanItem("wtemp", "🪟 Windows system", "Windows temp folder",
                "System temp junk (some files need admin)",
                contents=(WTEMP,)))
    A(CleanItem("recycle", "🪟 Windows system", "Empty Recycle Bin",
                "⚠ Permanently erases everything currently in the bin "
                "(restore your deleted duplicates first!)",
                destructive=True, special="recyclebin"))
    A(CleanItem("thumbs", "🪟 Windows system", "Thumbnail cache",
                "Explorer rebuilds these automatically",
                file_globs=(os.path.join(LOC, "Microsoft", "Windows",
                                         "Explorer", "thumbcache_*.db"),
                            os.path.join(LOC, "Microsoft", "Windows",
                                         "Explorer", "iconcache_*.db"))))
    A(CleanItem("recent", "🪟 Windows system", "Recent documents list",
                "Clears the jump-list history of opened files",
                destructive=True,
                contents=(os.path.join(APP, "Microsoft", "Windows",
                                       "Recent"),)))
    A(CleanItem("wer", "🪟 Windows system", "Windows Error Reports",
                "Crash reports queued for sending to Microsoft",
                contents=(os.path.join(LOC, "Microsoft", "Windows", "WER",
                                       "ReportQueue"),
                          os.path.join(LOC, "Microsoft", "Windows", "WER",
                                       "ReportArchive"))))
    A(CleanItem("d3d", "🪟 Windows system", "DirectX shader cache",
                "Games recompile shaders on next launch",
                dirs=(os.path.join(LOC, "D3DSCache"),)))
    A(CleanItem("dumps", "🪟 Windows system", "Application crash dumps",
                "Memory dumps saved by crashing programs",
                contents=(os.path.join(LOC, "CrashDumps"),)))
    A(CleanItem("dns", "🪟 Windows system", "DNS cache",
                "Flushes the resolver cache (ipconfig /flushdns)",
                special="dns"))
    A(CleanItem("clipboard", "🪟 Windows system", "Clipboard",
                "Clears whatever is currently copied",
                special="clipboard"))

    # ---- Chromium-based browsers ------------------------------------------
    def chromium(user_data: str, exe: str, cat: str):
        if only_installed and not browser_is_installed(exe, r):
            return
        net = os.path.join(user_data, "*", "Network")
        legacy = os.path.join(user_data, "*")
        items.extend([
            CleanItem(f"{exe}-cache", cat, "Cache",
                      "Downloaded images and scripts — safe, sites "
                      "re-download them",
                      dirs=tuple(os.path.join(user_data, "*", d) for d in
                                 ("Cache", "Code Cache", "GPUCache",
                                  os.path.join("Service Worker",
                                               "CacheStorage"))),
                      browser_exes=(exe,)),
            CleanItem(f"{exe}-cookies", cat, "Cookies",
                      "⚠ Saved logins deleted — you get logged out of "
                      "everywhere",
                      destructive=True,
                      file_globs=(os.path.join(net, "Cookies"),
                                  os.path.join(net, "Cookies-journal"),
                                  os.path.join(legacy, "Cookies"),
                                  os.path.join(legacy, "Cookies-journal")),
                      browser_exes=(exe,)),
            CleanItem(f"{exe}-history", cat, "Browsing history",
                      "⚠ Visited sites, downloads and address-bar history",
                      destructive=True,
                      file_globs=tuple(
                          os.path.join(user_data, "*", f)
                          for f in ("History", "History-journal",
                                    "Visited Links", "Top Sites",
                                    "DownloadMetadata")),
                      browser_exes=(exe,)),
            CleanItem(f"{exe}-sessions", cat, "Open tabs & sessions",
                      "⚠ Closes saved tab sessions and restore data",
                      destructive=True,
                      file_globs=(os.path.join(user_data, "*", "Sessions",
                                               "*"),
                                  os.path.join(user_data, "*",
                                               "Current Session"),
                                  os.path.join(user_data, "*",
                                               "Current Tabs")),
                      browser_exes=(exe,)),
            CleanItem(f"{exe}-passwords", cat, "Saved passwords",
                      "⚠ Deletes ALL saved passwords — export them first!",
                      destructive=True,
                      file_globs=(os.path.join(user_data, "*", "Login Data"),
                                  os.path.join(user_data, "*",
                                               "Login Data For Account")),
                      browser_exes=(exe,)),
            CleanItem(f"{exe}-forms", cat, "Form history & autofill",
                      "⚠ Saved addresses, card and form autofill data",
                      destructive=True,
                      file_globs=(os.path.join(user_data, "*", "Web Data"),),
                      browser_exes=(exe,)),
        ])

    chromium(os.path.join(LOC, "Google", "Chrome", "User Data"),
             "chrome.exe", "🌐 Google Chrome")
    chromium(os.path.join(LOC, "Microsoft", "Edge", "User Data"),
             "msedge.exe", "🌐 Microsoft Edge")
    chromium(os.path.join(LOC, "BraveSoftware", "Brave-Browser", "User Data"),
             "brave.exe", "🌐 Brave")

    # Opera keeps its profile directly in "Opera Stable"
    opera = os.path.join(APP, "Opera Software", "Opera Stable")
    if not only_installed or browser_is_installed("opera.exe", r):
        items.extend([
        CleanItem("opera.exe-cache", "🌐 Opera", "Cache",
                  "Downloaded images and scripts — safe",
                  dirs=(os.path.join(opera, "Cache"),
                        os.path.join(opera, "Code Cache")),
                  browser_exes=("opera.exe",)),
        CleanItem("opera.exe-cookies", "🌐 Opera", "Cookies",
                  "⚠ Saved logins deleted — you get logged out of everywhere",
                  destructive=True,
                  file_globs=(os.path.join(opera, "Network", "Cookies"),
                              os.path.join(opera, "Network",
                                           "Cookies-journal")),
                  browser_exes=("opera.exe",)),
        CleanItem("opera.exe-history", "🌐 Opera", "Browsing history",
                  "⚠ Visited sites and address-bar history",
                  destructive=True,
                  file_globs=(os.path.join(opera, "History"),
                              os.path.join(opera, "History-journal")),
                  browser_exes=("opera.exe",)),
        CleanItem("opera.exe-passwords", "🌐 Opera", "Saved passwords",
                  "⚠ Deletes ALL saved passwords — export them first!",
                  destructive=True,
                  file_globs=(os.path.join(opera, "Login Data"),),
                  browser_exes=("opera.exe",)),
        CleanItem("opera.exe-forms", "🌐 Opera", "Form history & autofill",
                  "⚠ Saved form autofill data",
                  destructive=True,
                  file_globs=(os.path.join(opera, "Web Data"),),
                  browser_exes=("opera.exe",)),
    ])

    # ---- Firefox -----------------------------------------------------------
    if not only_installed or browser_is_installed("firefox.exe", r):
        ff_prof = os.path.join(APP, "Mozilla", "Firefox", "Profiles", "*")
        ff_cache = os.path.join(LOC, "Mozilla", "Firefox", "Profiles", "*")
        items.extend([
        CleanItem("firefox.exe-cache", "🦊 Firefox", "Cache",
                  "Downloaded images and scripts — safe",
                  dirs=(os.path.join(ff_cache, "cache2"),
                        os.path.join(ff_cache, "startupCache")),
                  browser_exes=("firefox.exe",)),
        CleanItem("firefox.exe-cookies", "🦊 Firefox", "Cookies",
                  "⚠ Saved logins deleted — you get logged out of everywhere",
                  destructive=True,
                  file_globs=tuple(os.path.join(ff_prof, f) for f in
                                   ("cookies.sqlite", "cookies.sqlite-wal",
                                    "cookies.sqlite-shm")),
                  browser_exes=("firefox.exe",)),
        CleanItem("firefox.exe-history", "🦊 Firefox", "Browsing history",
                  "⚠ Visited sites and address-bar history",
                  destructive=True,
                  file_globs=tuple(os.path.join(ff_prof, f) for f in
                                   ("places.sqlite", "places.sqlite-wal",
                                    "places.sqlite-shm")),
                  browser_exes=("firefox.exe",)),
        CleanItem("firefox.exe-sessions", "🦊 Firefox", "Open tabs & sessions",
                  "⚠ Closes saved tab sessions and restore data",
                  destructive=True,
                  file_globs=(os.path.join(ff_prof, "sessionstore.jsonlz4"),
                              os.path.join(ff_prof, "sessionstore-backups",
                                           "*.lz4")),
                  browser_exes=("firefox.exe",)),
        CleanItem("firefox.exe-passwords", "🦊 Firefox", "Saved passwords",
                  "⚠ Deletes ALL saved passwords — export them first!",
                  destructive=True,
                  file_globs=(os.path.join(ff_prof, "logins.json"),
                              os.path.join(ff_prof, "key4.db")),
                  browser_exes=("firefox.exe",)),
        CleanItem("firefox.exe-forms", "🦊 Firefox", "Form history",
                  "⚠ Saved form autofill data",
                  destructive=True,
                  file_globs=(os.path.join(ff_prof, "formhistory.sqlite"),),
                  browser_exes=("firefox.exe",)),
    ])
    extra_browsers = (_detect_additional_browsers(r) if only_installed
                      else _additional_browser_specs(r))
    for spec in extra_browsers:
        if spec["family"] == "chromium":
            _add_chromium_browser_cleaners(items, spec)
        elif spec["family"] == "gecko":
            _add_gecko_browser_cleaners(items, spec)
    return items


def _expand(patterns) -> list:
    return _safe_expand(patterns)


def _try_remove(fp: str) -> bool:
    """Remove one file; clears the read-only flag and retries, and falls
    back to the long-path (\\\\?\\) form so deletion actually succeeds."""
    for candidate in (fp, "\\\\?\\" + os.path.abspath(fp)):
        try:
            os.remove(candidate)
            return True
        except PermissionError:
            try:
                os.chmod(candidate, statmod.S_IWRITE)
                os.remove(candidate)
                return True
            except OSError:
                continue
        except OSError:
            continue
    return False


def _try_rmdir(dp: str) -> bool:
    for candidate in (dp, "\\\\?\\" + os.path.abspath(dp)):
        try:
            os.rmdir(candidate)
            return True
        except OSError:
            continue
    return False


def _wipe_path(path: str) -> tuple:
    """Delete a file or a whole tree. Returns (freed, removed, skipped)."""
    if is_protected(path):
        return (0, 0, 1)
    freed = removed = skipped = 0
    is_junction = getattr(os.path, "isjunction", lambda _p: False)(path)
    if os.path.isdir(path) and not os.path.islink(path) and not is_junction:
        for root, dirs, files in os.walk(path, topdown=False):
            for name in files:
                fp = os.path.join(root, name)
                try:
                    size = os.lstat(fp).st_size
                except OSError:
                    size = 0
                if _try_remove(fp):
                    removed += 1
                    freed += size
                else:
                    skipped += 1
            for name in dirs:
                if not _try_rmdir(os.path.join(root, name)):
                    skipped += 1
        if not _try_rmdir(path):
            skipped += 1
    else:
        try:
            size = os.lstat(path).st_size
        except OSError:
            size = 0
        if _try_remove(path):
            removed += 1
            freed += size
        else:
            skipped += 1
    return freed, removed, skipped


def preview_items(items, progress=None, cancel=None) -> dict:
    """READ-ONLY analysis: count files and bytes each item would remove.
    Never deletes anything."""
    out = {}
    for i, it in enumerate(items):
        if cancel is not None and cancel.is_set():
            break
        count = total = 0
        if it.special == "recyclebin":
            count, total = query_recycle_bin()
        elif it.special in ("dns", "clipboard"):
            pass
        else:
            for d in _expand(it.contents):
                try:
                    entries = list(os.scandir(d))
                except OSError:
                    continue
                for e in entries:
                    try:
                        if (e.is_file(follow_symlinks=False) or
                                (not it.contents_files_only and e.is_symlink())):
                            count += 1
                            total += e.stat(follow_symlinks=False).st_size
                        elif e.is_dir(follow_symlinks=False) and not it.contents_files_only:
                            for root, _dirs, files in os.walk(e.path):
                                for f in files:
                                    try:
                                        count += 1
                                        total += os.lstat(
                                            os.path.join(root, f)).st_size
                                    except OSError:
                                        pass
                    except OSError:
                        continue
            for d in _expand(it.dirs):
                if os.path.islink(d) or getattr(os.path, "isjunction",
                                                lambda _p: False)(d):
                    try:
                        count += 1
                        total += os.lstat(d).st_size
                    except OSError:
                        pass
                    continue
                for root, _dirs, files in os.walk(d):
                    for f in files:
                        try:
                            count += 1
                            total += os.lstat(
                                os.path.join(root, f)).st_size
                        except OSError:
                            pass
            for f in _expand(it.file_globs):
                if os.path.isfile(f):
                    try:
                        count += 1
                        total += os.lstat(f).st_size
                    except OSError:
                        pass
        out[it.cid] = {"count": count, "bytes": total, "item": it}
        if progress:
            progress(i + 1, len(items), it)
    return out


def clean_items(items, log, cancel=None) -> dict:
    """Run the selected cleaners. `log(msg)` receives progress lines.
    Returns totals. Deletion is permanent (except the Recycle Bin item,
    which empties the bin)."""
    grand = {"freed": 0, "removed": 0, "skipped": 0}
    for it in items:
        if cancel is not None and cancel.is_set():
            break
        if it.special == "recyclebin":
            before_count, before_bytes = query_recycle_bin()
            empty_recycle_bin()
            after_count, after_bytes = query_recycle_bin()
            freed = max(0, before_bytes - after_bytes)
            removed = max(0, before_count - after_count)
            grand["freed"] += freed
            grand["removed"] += removed
            log(f"♻ {it.name}: removed {removed}, freed {human(freed)}")
            continue
        if it.special == "dns":
            flush_dns()
            log(f"🌐 {it.name}: flushed")
            continue
        if it.special == "clipboard":
            clear_clipboard_win()
            log(f"📋 {it.name}: cleared")
            continue
        freed = removed = skipped = 0
        for d in _expand(it.contents):
            try:
                entries = list(os.scandir(d))
            except OSError:
                continue
            for e in entries:
                if it.contents_files_only:
                    try:
                        if not e.is_file(follow_symlinks=False):
                            continue
                    except OSError:
                        skipped += 1
                        continue
                f, r, s = _wipe_path(e.path)
                freed += f
                removed += r
                skipped += s
        for d in _expand(it.dirs):
            f, r, s = _wipe_path(d)
            freed += f
            removed += r
            skipped += s
        for path in _expand(it.file_globs):
            if os.path.isfile(path):
                f, r, s = _wipe_path(path)
                freed += f
                removed += r
                skipped += s
        mark = "✓" if skipped == 0 else "○"
        extra = f", {skipped} skipped (in use)" if skipped else ""
        log(f"{mark} {it.category} · {it.name}: removed {removed}, "
            f"freed {human(freed)}{extra}")
        grand["freed"] += freed
        grand["removed"] += removed
        grand["skipped"] += skipped
    return grand


# ---- Windows specials ----------------------------------------------------

class _SHQUERYRBINFO(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.UINT),
                ("i64Size", ctypes.c_longlong),
                ("i64NumItems", ctypes.c_longlong)]


def query_recycle_bin() -> tuple:
    info = _SHQUERYRBINFO()
    info.cbSize = ctypes.sizeof(_SHQUERYRBINFO)
    hr = ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info))
    if hr != 0:
        return (0, 0)
    return (info.i64NumItems, info.i64Size)


def empty_recycle_bin() -> None:
    # SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND
    hr = ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 0x1 | 0x2 | 0x4)
    if hr != 0:
        raise OSError(f"SHEmptyRecycleBinW failed with code {hr}")


def flush_dns() -> None:
    try:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True,
                       creationflags=getattr(subprocess,
                                              "CREATE_NO_WINDOW", 0))
    except OSError:
        pass


def clear_clipboard_win() -> None:
    try:
        user32 = ctypes.windll.user32
        if user32.OpenClipboard(None):
            user32.EmptyClipboard()
            user32.CloseClipboard()
    except Exception:
        pass


def running_exes() -> set:
    """Names (lowercase) of currently running processes."""
    try:
        out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                             capture_output=True,
                             creationflags=getattr(subprocess,
                                                    "CREATE_NO_WINDOW", 0))
        data = out.stdout or b""
        # tasklist emits the console codepage or UTF-16 — never assume UTF-8
        if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            text = data.decode("utf-16", errors="replace")
        else:
            text = data.decode(errors="replace")
        names = set()
        for line in text.splitlines():
            if line.startswith('"'):
                names.add(line.split('","')[0].strip('"').lower())
        return names
    except OSError:
        return set()


def blockers_for(items) -> list:
    """Friendly names of browsers that must be closed before cleaning."""
    running = running_exes()
    return sorted({_FRIENDLY.get(exe, exe)
                   for it in items for exe in it.browser_exes
                   if exe in running})


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1180x760")
        self.minsize(1000, 650)

        self._q: queue.Queue = queue.Queue()
        self._cancel = threading.Event()
        self._scan_thread = None
        self._result: ScanResult | None = None
        self._checked: set[str] = set()
        self._group_of: dict[str, DupGroup] = {}
        self._gid: dict[DupGroup, str] = {}
        self._security_cancel = threading.Event()
        self._security_prewarm_cancel = threading.Event()
        self._security_engine_warming = False
        self._security_busy = False
        self._security_scan_after_update = False
        self._security_scan_targets: list[str] = []
        self._security_scan_mode = "Full system scan"
        self._security_findings: list[dict] = []
        self._security_checked: set[str] = set()

        self.settings = load_settings()
        self._custom_accent: str | None = self.settings.get("accent")

        self._build_fonts()
        self._build_notebook()
        self._build_duplicates_tab()
        self._build_cleaner_tab()
        self._build_security_tab()
        self._build_themes_tab()
        self._build_clock_tab()

        try:
            style = ttk.Style(self)
            style.theme_use("clam")  # clam is fully recolorable
        except Exception:
            pass

        self._theme_cards = []
        self._build_theme_cards()
        self.apply_settings()
        self._security_refresh_status()
        self._refresh_clean_storage()
        self._notebook.select(0)

        self.after(80, self._poll)
        self.after(100, self._tick_clock)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._flash("Pick a folder and press Scan.")
        self.after(250, lambda: self._cleaner_preview(all_items=True))
        self.after(900, self._security_prewarm_engine)

    # ---- fonts ------------------------------------------------------------

    def _build_fonts(self):
        size = FONT_SIZES[self.settings["font"]]
        self._font_base = tkfont.Font(family="Segoe UI", size=size)
        self._font_bold = tkfont.Font(family="Segoe UI", size=size, weight="bold")
        self._font_clock = tkfont.Font(family="Segoe UI", size=int(size * 1.9),
                                       weight="bold")
        self._font_caption = tkfont.Font(family="Segoe UI", size=int(size * 1.25))
        self.option_add("*Font", self._font_base)

    def _change_font(self):
        self.settings["font"] = self._font_var.get()
        size = FONT_SIZES[self.settings["font"]]
        self._font_base.configure(size=size)
        self._font_bold.configure(size=size)
        self._font_clock.configure(size=int(size * 1.9))
        self._font_caption.configure(size=int(size * 1.25))
        try:
            ttk.Style(self).configure("Treeview",
                                      rowheight=int(size * 2.1 + 8))
        except Exception:
            pass
        self._style_tree_tags()
        self._save()

    # ---- notebook ----------------------------------------------------------

    def _build_notebook(self):
        self._notebook = ttk.Notebook(self)
        self._notebook.pack(fill="both", expand=True, padx=8, pady=8)
        self._tab_dup = ttk.Frame(self._notebook, padding=8)
        self._tab_theme = ttk.Frame(self._notebook, padding=8)
        self._tab_clock = ttk.Frame(self._notebook, padding=8)
        self._tab_clean = ttk.Frame(self._notebook, padding=8)
        self._tab_security = ttk.Frame(self._notebook, padding=8)
        self._notebook.add(self._tab_dup, text="🗂  Duplicates")
        self._notebook.add(self._tab_clean, text="🧹  Cleaner")
        self._notebook.add(self._tab_security, text="🛡  Security")
        self._notebook.add(self._tab_theme, text="🎨  Themes")
        self._notebook.add(self._tab_clock, text="🕒  Clock")

    # ---- tab 1: duplicates --------------------------------------------------

    def _build_duplicates_tab(self):
        top = ttk.LabelFrame(self._tab_dup, text="1 · Choose what to scan",
                             padding=8)
        top.pack(fill="x")

        row1 = ttk.Frame(top)
        row1.pack(fill="x")
        ttk.Label(row1, text="Folder:").pack(side="left")
        self._folder_var = tk.StringVar(
            value=os.path.join(os.path.expanduser("~"), "Downloads"))
        ttk.Entry(row1, textvariable=self._folder_var).pack(
            side="left", fill="x", expand=True, padx=(6, 6))
        ttk.Button(row1, text="Browse…", command=self._browse).pack(side="left")

        row2 = ttk.Frame(top)
        row2.pack(fill="x", pady=(8, 0))
        self._recursive_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(row2, text="Include subfolders",
                        variable=self._recursive_var).pack(side="left")
        ttk.Label(row2, text="Ignore files smaller than:").pack(
            side="left", padx=(18, 4))
        self._minsize_var = tk.IntVar(value=1024)  # KB
        ttk.Spinbox(row2, from_=0, to=10_000_000, increment=256,
                    textvariable=self._minsize_var, width=8).pack(side="left")
        ttk.Label(row2, text="KB").pack(side="left", padx=(2, 0))
        self._scan_btn = ttk.Button(row2, text="🔍 Scan", command=self._start_scan)
        self._scan_btn.pack(side="right")
        self._stop_btn = ttk.Button(row2, text="Stop", command=self._stop_scan,
                                    state="disabled")
        self._stop_btn.pack(side="right", padx=(0, 6))

        prog = ttk.Frame(self._tab_dup)
        prog.pack(fill="x", pady=(8, 2))
        self._status = ttk.Label(prog, text="", style="Status.TLabel")
        self._status.pack(side="left", fill="x", expand=True)
        self._bar = ttk.Progressbar(prog, length=260, mode="determinate")

        mid = ttk.LabelFrame(self._tab_dup,
                             text="2 · Duplicate groups (biggest waste first)",
                             padding=4)
        mid.pack(fill="both", expand=True, pady=6)

        cols = ("check", "size", "modified", "folder")
        self._tree = ttk.Treeview(mid, columns=cols, show="tree headings",
                                  selectmode="browse")
        self._tree.heading("#0", text="File", anchor="w")
        self._tree.heading("check", text="Delete?")
        self._tree.heading("size", text="Size")
        self._tree.heading("modified", text="Modified")
        self._tree.heading("folder", text="Folder")
        self._tree.column("#0", width=300, stretch=True)
        self._tree.column("check", width=64, anchor="center", stretch=False)
        self._tree.column("size", width=90, anchor="e", stretch=False)
        self._tree.column("modified", width=140, anchor="w", stretch=False)
        self._tree.column("folder", width=340, anchor="w", stretch=False)
        vsb = ttk.Scrollbar(mid, orient="vertical", command=self._tree.yview)
        hsb = ttk.Scrollbar(mid, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        mid.rowconfigure(0, weight=1)
        mid.columnconfigure(0, weight=1)
        self._tree.bind("<Button-1>", self._on_click)
        self._tree.bind("<space>", self._on_space)

        bottom = ttk.Frame(self._tab_dup)
        bottom.pack(fill="x", pady=(2, 0))
        self._keep_new_btn = ttk.Button(bottom, text="Keep newest per group",
                                        command=lambda: self._auto_keep(newest=True))
        self._keep_old_btn = ttk.Button(bottom, text="Keep oldest per group",
                                        command=lambda: self._auto_keep(newest=False))
        self._clear_btn = ttk.Button(bottom, text="Uncheck all",
                                     command=self._uncheck_all)
        self._open_btn = ttk.Button(bottom, text="Open location",
                                    command=self._open_location)
        self._csv_btn = ttk.Button(bottom, text="Save report…",
                                   command=self._save_report)
        self._delete_btn = ttk.Button(bottom, text="Move to Recycle Bin",
                                      style="Danger.TButton",
                                      command=self._delete_selected)
        for b in (self._keep_new_btn, self._keep_old_btn, self._clear_btn,
                  self._open_btn, self._csv_btn):
            b.pack(side="left", padx=(0, 6))
        self._delete_btn.pack(side="right")

        # Buttons that only make sense once results exist:
        for b in (self._keep_new_btn, self._keep_old_btn, self._clear_btn,
                  self._open_btn, self._csv_btn, self._delete_btn):
            b.state(["disabled"])

    # ---- tab 2: themes -------------------------------------------------------

    def _build_themes_tab(self):
        t = self._tab_theme
        t.columnconfigure(0, weight=1)
        t.rowconfigure(0, weight=1)

        gal = ttk.LabelFrame(t, text="Theme gallery — click a card to apply",
                             padding=8)
        gal.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self._gallery = gal

        opts = ttk.LabelFrame(t, text="Options", padding=10)
        opts.grid(row=0, column=1, sticky="ns")

        # --- accent color ---
        ttk.Label(opts, text="Accent color").grid(row=0, column=0,
                                                  columnspan=2, sticky="w")
        ttk.Button(opts, text="Pick custom…", command=self._pick_accent,
                   style="Accent.TButton").grid(row=1, column=0, sticky="ew",
                                                pady=(4, 2))
        ttk.Button(opts, text="Use theme color",
                   command=self._reset_accent).grid(row=2, column=0,
                                                    sticky="ew", pady=2)

        # --- font size ---
        ttk.Label(opts, text="Font size").grid(row=3, column=0, columnspan=2,
                                               sticky="w", pady=(12, 0))
        self._font_var = tk.StringVar(value=self.settings["font"])
        for i, (label, val) in enumerate((("Small", "S"), ("Medium", "M"),
                                          ("Large", "L"), ("X-Large", "XL"))):
            ttk.Radiobutton(opts, text=label, value=val,
                            variable=self._font_var,
                            command=self._change_font).grid(
                row=4 + i // 2, column=i % 2, sticky="w", pady=1)

        # --- toggles ---
        self._zebra_var = tk.BooleanVar(value=self.settings["zebra"])
        ttk.Checkbutton(opts, text="Zebra-striped rows", variable=self._zebra_var,
                        command=self._on_zebra_toggle).grid(
            row=7, column=0, columnspan=2, sticky="w", pady=(12, 1))
        self._titlebar_var = tk.BooleanVar(value=self.settings["titlebar"])
        ttk.Checkbutton(opts, text="Colorful title bar (Win 11)",
                        variable=self._titlebar_var,
                        command=self._on_titlebar_toggle).grid(
            row=8, column=0, columnspan=2, sticky="w", pady=1)

        ttk.Button(opts, text="🎲  Random theme",
                   command=self._random_theme).grid(row=9, column=0,
                                                    sticky="ew", pady=(14, 2))
        ttk.Button(opts, text="Reset everything to defaults",
                   command=self._reset_all).grid(row=10, column=0, sticky="ew",
                                                 pady=2)
        opts.columnconfigure(0, weight=1)

        # --- live preview ---
        prev = ttk.LabelFrame(t, text="Live preview", padding=8)
        prev.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        ttk.Label(prev, text="Sample text").pack(side="left", padx=(0, 8))
        ttk.Entry(prev, width=18).pack(side="left", padx=(0, 8))
        ttk.Button(prev, text="Button").pack(side="left", padx=(0, 8))
        ttk.Button(prev, text="Delete", style="Danger.TButton").pack(
            side="left", padx=(0, 8))
        ttk.Checkbutton(prev, text="Option").pack(side="left", padx=(0, 8))
        ttk.Progressbar(prev, length=140, value=65).pack(side="left")

    def _build_theme_cards(self):
        for w in self._gallery.winfo_children():
            w.destroy()
        self._theme_cards = []
        for i, (name, th) in enumerate(THEMES.items()):
            card = tk.Frame(self._gallery, highlightthickness=2,
                            cursor="hand2")
            name_lbl = tk.Label(card, text=name, font=self._font_bold,
                                cursor="hand2")
            chips = tk.Frame(card, cursor="hand2")
            chip_widgets = []
            for color in (th["bg"], th["panel"], th["field"], th["accent"],
                          th["fg"]):
                chip = tk.Label(chips, bg=color, width=3, height=1,
                                cursor="hand2")
                chip.pack(side="left", padx=1, pady=2)
                chip_widgets.append(chip)
            name_lbl.pack(pady=(6, 2))
            chips.pack(pady=(0, 6))
            card.grid(row=i // 4, column=i % 4, padx=5, pady=5, sticky="nsew")
            for w in (card, name_lbl, chips, *chip_widgets):
                w.bind("<Button-1>", lambda e, n=name: self._select_theme(n))
            self._theme_cards.append((card, name_lbl, chips))

    # ---- tab 3: clock ---------------------------------------------------------

    def _build_clock_tab(self):
        c = self._tab_clock
        wrap = ttk.Frame(c)
        wrap.pack(expand=True)

        self._clock = tk.Canvas(wrap, width=380, height=380,
                                highlightthickness=0)
        self._clock.pack(pady=(4, 0))
        self._draw_clock_face()

        self._caption = tk.Label(wrap, font=self._font_caption, cursor="arrow")
        self._caption.pack(pady=(6, 0))
        self._datelbl = tk.Label(wrap, font=self._font_base, cursor="arrow")
        self._datelbl.pack()

        opts = ttk.Frame(wrap)
        opts.pack(pady=(10, 4))
        self._smooth_var = tk.BooleanVar(value=self.settings["smooth"])
        self._showdate_var = tk.BooleanVar(value=self.settings["date"])
        ttk.Checkbutton(opts, text="Smooth second hand",
                        variable=self._smooth_var,
                        command=self._save).pack(side="left", padx=6)
        ttk.Checkbutton(opts, text="Show date", variable=self._showdate_var,
                        command=self._on_showdate).pack(side="left", padx=6)
        self._topmost_var = tk.BooleanVar(value=self.settings["topmost"])
        ttk.Checkbutton(opts, text="Always on top", variable=self._topmost_var,
                        command=self._on_topmost).pack(side="left", padx=6)

        cx = cy = 190
        r = 168
        # hands (created once; coords updated every tick)
        self._hand_hour = self._clock.create_line(cx, cy, cx, cy - r * 0.5,
                                                  width=8, capstyle="round",
                                                  tags="hands")
        self._hand_min = self._clock.create_line(cx, cy, cx, cy - r * 0.74,
                                                 width=5, capstyle="round",
                                                 tags="hands")
        self._hand_sec = self._clock.create_line(cx, cy, cx, cy - r * 0.82,
                                                 width=2, capstyle="round",
                                                 tags="hands")
        self._clock.tag_raise("hands")
        self._center = self._clock.create_oval(cx - 7, cy - 7, cx + 7, cy + 7,
                                               width=0, tags="hands")

    def _draw_clock_face(self):
        cv = self._clock
        cv.delete("face")
        cx = cy = 190
        r = 168
        cv.create_oval(cx - r, cy - r, cx + r, cy + r,
                       tags=("face", "face_oval"), width=3)
        for i in range(60):
            ang = math.radians(i * 6)
            inner = r - (14 if i % 5 == 0 else 7)
            outer = r - 2
            width = 3 if i % 5 == 0 else 1
            cv.create_line(cx + inner * math.sin(ang),
                           cy - inner * math.cos(ang),
                           cx + outer * math.sin(ang),
                           cy - outer * math.cos(ang),
                           width=width, tags=("face", "tick"))
        for num, ang_deg in ((12, 0), (3, 90), (6, 180), (9, 270)):
            ang = math.radians(ang_deg)
            x = cx + (r - 34) * math.sin(ang)
            y = cy - (r - 34) * math.cos(ang)
            cv.create_text(x, y, text=str(num), font=self._font_clock,
                           tags=("face", "num"))

    # ---- theming --------------------------------------------------------------

    def _theme(self) -> dict:
        return THEMES[self.settings["theme"]]

    def _accent(self) -> str:
        return self._custom_accent or self._theme()["accent"]

    def apply_settings(self):
        """Apply theme + accent + toggles to every widget."""
        th = self._theme()
        accent = self._accent()
        style = ttk.Style(self)
        bg, fg = th["bg"], th["fg"]
        field, panel, border = th["field"], th["panel"], th["border"]
        sub, zebra = th["sub_fg"], th["zebra"]

        self.configure(background=bg)
        style.configure(".", background=bg, foreground=fg,
                        font=self._font_base, bordercolor=border,
                        lightcolor=panel, darkcolor=border,
                        troughcolor=field, focuscolor=accent)

        style.configure("TFrame", background=bg)
        style.configure("TLabel", background=bg, foreground=fg)
        style.configure("Status.TLabel", background=bg, foreground=sub)
        style.configure("TLabelframe", background=bg, foreground=fg,
                        bordercolor=border, lightcolor=bg, darkcolor=bg)
        style.configure("TLabelframe.Label", background=bg, foreground=accent,
                        font=self._font_bold)

        style.configure("TNotebook", background=bg, bordercolor=border,
                        lightcolor=bg, darkcolor=border, tabmargins=[6, 4, 6, 0])
        style.configure("TNotebook.Tab", background=panel, foreground=fg,
                        padding=[16, 7], bordercolor=border,
                        lightcolor=panel, darkcolor=border)
        style.map("TNotebook.Tab",
                  background=[("selected", accent)],
                  foreground=[("selected", th["accent_fg"])])

        for name in ("TButton", "Accent.TButton"):
            style.configure(name, background=accent, foreground=th["accent_fg"],
                            bordercolor=border, lightcolor=accent,
                            darkcolor=shade(accent, -0.2), focusthickness=0,
                            padding=[10, 4])
        style.map("TButton",
                  background=[("disabled", field), ("pressed",
                              shade(accent, -0.15)), ("active",
                              shade(accent, 0.10))],
                  foreground=[("disabled", sub)])
        style.map("Accent.TButton",
                  background=[("disabled", field), ("pressed",
                              shade(accent, -0.15)), ("active",
                              shade(accent, 0.10))],
                  foreground=[("disabled", sub)])
        style.configure("Danger.TButton", background=th["danger"],
                        foreground=th["danger_fg"], bordercolor=border,
                        lightcolor=th["danger"],
                        darkcolor=shade(th["danger"], -0.2), focusthickness=0,
                        padding=[10, 4])
        style.map("Danger.TButton",
                  background=[("disabled", field), ("pressed",
                              shade(th["danger"], -0.15)), ("active",
                              shade(th["danger"], 0.10))],
                  foreground=[("disabled", sub)])

        for name in ("TCheckbutton", "TRadiobutton"):
            style.configure(name, background=bg, foreground=fg,
                            focuscolor=accent)
            try:
                style.map(name, indicatorcolor=[
                    ("selected", accent), ("!selected", field)],
                    background=[("active", bg)])
            except Exception:
                pass

        style.configure("TEntry", fieldbackground=field, foreground=fg,
                        insertcolor=fg, bordercolor=border, lightcolor=border,
                        darkcolor=border, padding=3)
        style.map("TEntry", lightcolor=[("focus", accent)],
                  darkcolor=[("focus", accent)])
        style.configure("TSpinbox", fieldbackground=field, foreground=fg,
                        background=panel, arrowcolor=fg, bordercolor=border,
                        lightcolor=border, darkcolor=border, insertcolor=fg,
                        padding=2)

        style.configure("Treeview", background=field, foreground=fg,
                        fieldbackground=field, bordercolor=border)
        style.configure("Treeview.Heading", background=panel, foreground=fg,
                        font=self._font_bold, bordercolor=border,
                        relief="flat")
        style.map("Treeview", background=[("selected", accent)],
                  foreground=[("selected", th["accent_fg"])])
        style.map("Treeview.Heading", background=[("active", panel)])
        self._style_tree_tags()

        style.configure("Vertical.TScrollbar", background=panel,
                        troughcolor=bg, bordercolor=bg, arrowcolor=sub)
        style.configure("Horizontal.TScrollbar", background=panel,
                        troughcolor=bg, bordercolor=bg, arrowcolor=sub)
        style.configure("Horizontal.TProgressbar", background=accent,
                        troughcolor=field, bordercolor=bg,
                        lightcolor=accent, darkcolor=accent)

        # clock canvas
        self._clock.configure(background=bg)
        self._clock.itemconfigure("face_oval", fill=th["face"],
                                  outline=th["face_edge"])
        self._clock.itemconfigure("tick", fill=th["ticks"])
        self._clock.itemconfigure("num", fill=th["hands"])
        self._clock.itemconfigure("hands", fill=th["hands"])
        self._clock.itemconfigure(self._hand_sec, fill=th["second"])
        self._clock.itemconfigure(self._center, fill=th["second"])
        self._caption.configure(bg=bg, fg=th["second"])
        self._datelbl.configure(bg=bg, fg=sub)

        # theme cards
        for card, name_lbl, chips in self._theme_cards:
            sel = name_lbl.cget("text") == self.settings["theme"]
            card.configure(bg=panel, highlightbackground=accent if sel
                           else border,
                           highlightcolor=accent if sel else border)
            name_lbl.configure(bg=panel, fg=fg if not sel else accent)
            chips.configure(bg=panel)

        self._retag_rows()
        self._apply_titlebar()

    def _style_tree_tags(self):
        self._tree.tag_configure("group", font=self._font_bold,
                                 foreground=self._theme()["fg"])
        if hasattr(self, "_clean_tree"):
            self._clean_tree.tag_configure(
                "group", font=self._font_bold, foreground=self._theme()["fg"])
            self._clean_tree.tag_configure(
                "destructive", foreground=self._theme()["danger"])
        if hasattr(self, "_clean_log"):
            th = self._theme()
            self._clean_log.configure(
                bg=th["field"], fg=th["fg"], insertbackground=th["fg"],
                font=("Consolas", max(9, FONT_SIZES[self.settings["font"]]
                                      - 1)))
        if hasattr(self, "_security_tree"):
            self._security_tree.tag_configure(
                "detected", foreground=self._theme()["danger"])
            self._security_tree.tag_configure(
                "handled", foreground=self._theme()["sub_fg"])
        if hasattr(self, "_security_log"):
            th = self._theme()
            self._security_log.configure(
                bg=th["field"], fg=th["fg"], insertbackground=th["fg"],
                font=("Consolas", max(9, FONT_SIZES[self.settings["font"]] - 1)))

    def _apply_titlebar(self):
        if not sys.platform == "win32":
            return
        try:
            hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
            th = self._theme()
            dark = 1 if luminance(th["bg"]) < 128 else 0
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 20, ctypes.byref(ctypes.c_int(dark)), 4)
            if self.settings.get("titlebar"):
                r, g, b = _rgb(self._accent())
                val = ctypes.c_uint((b << 16) | (g << 8) | r)
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, 35, ctypes.byref(val), 4)
        except Exception:
            pass

    # ---- settings plumbing -----------------------------------------------------

    def _save(self):
        self.settings["accent"] = self._custom_accent
        self.settings["smooth"] = bool(self._smooth_var.get())
        self.settings["date"] = bool(self._showdate_var.get())
        self.settings["topmost"] = bool(self._topmost_var.get())
        self.settings["zebra"] = bool(self._zebra_var.get())
        self.settings["titlebar"] = bool(self._titlebar_var.get())
        self.settings["font"] = self._font_var.get()
        save_settings(self.settings)

    def _on_close(self):
        self._security_cancel.set()
        self._security_prewarm_cancel.set()
        _stop_clamd_session()
        self._save()
        self.destroy()

    def _select_theme(self, name: str):
        self.settings["theme"] = name
        self.apply_settings()
        self._save()
        self._flash(f"Theme applied: {name}")

    def _random_theme(self):
        import random
        others = [n for n in THEMES if n != self.settings["theme"]]
        self._select_theme(random.choice(others))

    def _pick_accent(self):
        rgb, hexstr = colorchooser.askcolor(color=self._accent(), parent=self)
        if hexstr:
            self._custom_accent = hexstr
            self.apply_settings()
            self._save()

    def _reset_accent(self):
        self._custom_accent = None
        self.apply_settings()
        self._save()

    def _on_zebra_toggle(self):
        self._retag_rows()
        self._save()

    def _on_titlebar_toggle(self):
        self._apply_titlebar()
        self._save()

    def _on_showdate(self):
        self._datelbl.configure(
            text="" if not self._showdate_var.get() else self._last_date)
        self._save()

    def _on_topmost(self):
        try:
            self.attributes("-topmost", bool(self._topmost_var.get()))
        except Exception:
            pass
        self._save()

    def _reset_all(self):
        self.settings = dict(DEFAULT_SETTINGS)
        self._custom_accent = None
        self._font_var.set(self.settings["font"])
        self._zebra_var.set(self.settings["zebra"])
        self._titlebar_var.set(self.settings["titlebar"])
        self._smooth_var.set(self.settings["smooth"])
        self._showdate_var.set(self.settings["date"])
        self._topmost_var.set(self.settings["topmost"])
        self._change_font()
        self.apply_settings()
        save_settings(self.settings)
        self._flash("All appearance settings reset to defaults.")

    # ---- clock ticking -----------------------------------------------------------

    _last_date = ""

    def _tick_clock(self):
        try:
            now = time.localtime()
            frac = time.time() - int(time.time())
            sec = now.tm_sec + (frac if self._smooth_var.get() else 0.0)
            minute = now.tm_min + sec / 60.0
            hour = (now.tm_hour % 12) + minute / 60.0
            cx = cy = 190
            r = 168

            def hand(item, angle_deg, length, tail=0.0):
                ang = math.radians(angle_deg)
                x2 = cx + length * math.sin(ang)
                y2 = cy - length * math.cos(ang)
                x1 = cx - tail * math.sin(ang)
                y1 = cy + tail * math.cos(ang)
                self._clock.coords(item, x1, y1, x2, y2)

            hand(self._hand_hour, hour * 30, r * 0.50)
            hand(self._hand_min, minute * 6, r * 0.74)
            hand(self._hand_sec, sec * 6, r * 0.82, tail=r * 0.16)

            self._caption.configure(
                text=time.strftime("%I:%M:%S %p").lstrip("0"))
            self._last_date = time.strftime("%A, %B %d, %Y")
            if self._showdate_var.get():
                self._datelbl.configure(text=self._last_date)
        except Exception:
            pass  # widgets may be gone while the app is shutting down
        self.after(100, self._tick_clock)

    # ---- tab 4: cleaner (BleachBit-style) -----------------------------------

    def _build_cleaner_tab(self):
        t = self._tab_clean

        intro = ttk.Label(
            t, style="Status.TLabel",
            text="Preview first! Cleaning deletes permanently — only the "
                 "⚠ items touch personal data (logins, history, passwords); "
                 "they are OFF by default.")
        intro.pack(fill="x", pady=(0, 6))
        storage = ttk.Frame(t)
        storage.pack(fill="x", pady=(0, 6))
        self._clean_storage_lbl = ttk.Label(storage, style="Status.TLabel",
                                             text="Checking free space…")
        self._clean_storage_lbl.pack(side="left", fill="x", expand=True)
        ttk.Button(storage, text="Refresh / detect browsers",
                   command=self._cleaner_refresh).pack(
            side="right")

        mid = ttk.LabelFrame(t, text="What do you want to clean?", padding=4)
        mid.pack(fill="both", expand=True)
        cols = ("check", "details", "size")
        self._clean_tree = ttk.Treeview(mid, columns=cols,
                                        show="tree headings",
                                        selectmode="browse")
        self._clean_tree.heading("#0", text="Item", anchor="w")
        self._clean_tree.heading("check", text="Clean?")
        self._clean_tree.heading("details", text="Details")
        self._clean_tree.heading("size", text="Recoverable")
        self._clean_tree.column("#0", width=230, stretch=True)
        self._clean_tree.column("check", width=60, anchor="center",
                                stretch=False)
        self._clean_tree.column("details", width=430, anchor="w")
        self._clean_tree.column("size", width=110, anchor="e", stretch=False)
        vsb = ttk.Scrollbar(mid, orient="vertical",
                            command=self._clean_tree.yview)
        self._clean_tree.configure(yscrollcommand=vsb.set)
        self._clean_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        mid.rowconfigure(0, weight=1)
        mid.columnconfigure(0, weight=1)
        self._clean_tree.bind("<Button-1>", self._clean_on_click)
        self._clean_tree.bind("<space>", self._clean_on_space)

        self._clean_catalog = build_catalog()
        self._clean_by_id = {it.cid: it for it in self._clean_catalog}
        self._clean_checked = set()
        self._clean_sizes: dict = {}
        self._clean_cleaning = False
        self._clean_previewing = False
        last_cat = None
        for it in self._clean_catalog:
            if it.category != last_cat:
                last_cat = it.category
                self._clean_tree.insert("", "end", iid="cat:" + it.category,
                                        open=True, tags=("group",),
                                        text=it.category,
                                        values=("", "", ""))
            tags = ("destructive",) if it.destructive else ()
            self._clean_tree.insert("cat:" + it.category, "end", iid=it.cid,
                                    text="  " + it.name, tags=tags,
                                    values=("", it.desc, "Previewing…"))
        for cid in SAFE_DEFAULT_CLEANERS:
            if cid in self._clean_by_id:
                self._clean_checked.add(cid)
                self._clean_tree.set(cid, "check", "✓")

        btns = ttk.Frame(t)
        btns.pack(fill="x", pady=(8, 4))
        self._clean_preview_btn = ttk.Button(btns, text="🔍 Preview",
                                             command=self._cleaner_preview)
        self._clean_run_btn = ttk.Button(btns, text="🧹 Clean selected",
                                         style="Danger.TButton",
                                         command=self._cleaner_clean)
        ttk.Button(btns, text="Safe items only",
                   command=lambda: self._cleaner_select(safe=True)).pack(
            side="left", padx=(0, 6))
        ttk.Button(btns, text="Uncheck all",
                   command=lambda: self._cleaner_select(safe=False)).pack(
            side="left")
        self._clean_preview_btn.pack(side="right", padx=(6, 0))
        self._clean_run_btn.pack(side="right")

        logf = ttk.LabelFrame(t, text="Log", padding=4)
        logf.pack(fill="both")
        self._clean_log = tk.Text(logf, height=7, wrap="word", state="disabled",
                                  relief="flat")
        lsb = ttk.Scrollbar(logf, orient="vertical",
                            command=self._clean_log.yview)
        self._clean_log.configure(yscrollcommand=lsb.set)
        self._clean_log.pack(side="left", fill="both", expand=True)
        lsb.pack(side="right", fill="y")

    def _clean_log_line(self, msg: str):
        stamp = time.strftime("%H:%M:%S")
        self._clean_log.configure(state="normal")
        self._clean_log.insert("end", f"[{stamp}] {msg}\n")
        self._clean_log.see("end")
        self._clean_log.configure(state="disabled")

    def _refresh_clean_storage(self):
        if not hasattr(self, "_clean_storage_lbl"):
            return
        usage = current_disk_usage()
        if usage is None:
            self._clean_storage_lbl.configure(
                text="System drive free space: unavailable")
            return
        self._clean_storage_lbl.configure(
            text=(f"System drive {usage['path']}: {human(usage['free'])} free "
                  f"of {human(usage['total'])} · {human(usage['used'])} used"))

    def _cleaner_refresh(self):
        """Re-read disk capacity and installed browser registrations."""
        if self._clean_cleaning or self._clean_previewing:
            self._flash("Cleaner: wait for the current operation to finish.",
                        busy=True)
            return
        self._refresh_clean_storage()
        checked = set(self._clean_checked)
        self._clean_catalog = build_catalog()
        self._clean_by_id = {item.cid: item for item in self._clean_catalog}
        self._clean_checked = checked.intersection(self._clean_by_id)
        self._clean_sizes = {}
        self._clean_sizes_time = 0
        self._clean_tree.delete(*self._clean_tree.get_children(""))
        last_cat = None
        for item in self._clean_catalog:
            if item.category != last_cat:
                last_cat = item.category
                self._clean_tree.insert(
                    "", "end", iid="cat:" + item.category, open=True,
                    tags=("group",), text=item.category,
                    values=("", "", ""))
            tags = ("destructive",) if item.destructive else ()
            self._clean_tree.insert(
                "cat:" + item.category, "end", iid=item.cid,
                text="  " + item.name, tags=tags,
                values=("", item.desc, "Previewing…"))
            if item.cid in self._clean_checked:
                self._clean_tree.set(item.cid, "check", "✓")
        self._cleaner_preview(all_items=True)

    def _clean_on_click(self, event):
        row = self._clean_tree.identify_row(event.y)
        if not row:
            return
        col = self._clean_tree.identify_column(event.x)
        if row.startswith("cat:"):
            self._clean_toggle_parent(row)
        elif col in ("#0", "#1"):
            self._clean_toggle_child(row)
        return "break"

    def _clean_on_space(self, _event):
        row = self._clean_tree.focus()
        if row and not row.startswith("cat:"):
            self._clean_toggle_child(row)

    def _clean_toggle_child(self, cid: str):
        if cid not in self._clean_by_id:
            return
        if cid in self._clean_checked:
            self._clean_checked.discard(cid)
            self._clean_tree.set(cid, "check", "")
        else:
            self._clean_checked.add(cid)
            self._clean_tree.set(cid, "check", "✓")

    def _clean_toggle_parent(self, cat_row: str):
        cat = cat_row[4:]
        kids = self._clean_tree.get_children(cat_row)
        if not kids:
            return
        if any(k in self._clean_checked for k in kids):
            for k in kids:
                self._clean_checked.discard(k)
                self._clean_tree.set(k, "check", "")
        else:
            for k in kids:
                self._clean_checked.add(k)
                self._clean_tree.set(k, "check", "✓")

    def _cleaner_select(self, safe: bool):
        for it in self._clean_catalog:
            on = safe and it.cid in SAFE_DEFAULT_CLEANERS
            if on:
                self._clean_checked.add(it.cid)
                self._clean_tree.set(it.cid, "check", "✓")
            else:
                self._clean_checked.discard(it.cid)
                self._clean_tree.set(it.cid, "check", "")

    def _clean_selected_items(self) -> list:
        return [self._clean_by_id[c] for c in sorted(self._clean_checked)
                if c in self._clean_by_id]

    # ---- preview / clean threads ---------------------------------------------

    def _cleaner_preview(self, all_items: bool = False):
        if self._clean_cleaning or self._clean_previewing:
            return
        items = self._clean_catalog if all_items else self._clean_selected_items()
        if not items:
            self._flash("Cleaner: tick at least one item to preview.")
            return
        self._clean_previewing = True
        self._clean_sizes_time = 0
        self._clean_preview_btn.state(["disabled"])

        def progress(done, total, item):
            self._q.put(("cprog", f"Analyzing {item.name}… ({done}/{total})"))

        def worker():
            try:
                res = preview_items(items, progress=progress)
                self._q.put(("cprev", res))
            except Exception as e:
                self._q.put(("cerror", f"{type(e).__name__}: {e}"))
        threading.Thread(target=worker, daemon=True).start()

    def _cleaner_clean(self):
        if self._clean_cleaning:
            return
        items = self._clean_selected_items()
        if not items:
            self._flash("Cleaner: tick at least one item to clean.")
            return
        if (self._clean_previewing or
                any(it.cid not in self._clean_sizes for it in items) or
                time.time() - getattr(self, "_clean_sizes_time", 0) > 60):
            self._cleaner_preview()
            self._flash("Cleaner: previewing the selected items before deletion.",
                        busy=True)
            return
        # Browsers lock their files while running.
        blockers = blockers_for(items)
        if blockers:
            messagebox.showwarning(
                APP_TITLE,
                "Close these browsers first — their files are locked "
                "while running:\n\n  " + "\n  ".join(blockers))
            return
        # Saved passwords get an extra typed confirmation.
        pw = [it for it in items if it.cid.endswith("-passwords")]
        if pw:
            ans = simpledialog.askstring(
                APP_TITLE,
                "You selected SAVED PASSWORDS.\n\n"
                "This permanently deletes every saved password and cannot "
                "be undone.\nType YES (capital letters) to continue:",
                parent=self)
            if (ans or "").strip().upper() != "YES":
                for it in pw:
                    items.remove(it)
                self._clean_log_line("⚠ Saved-password items skipped "
                                     "(confirmation declined).")
                if not items:
                    return
        lines = []
        for it in items:
            sz = self._clean_sizes.get(it.cid)
            size_txt = human(sz["bytes"]) if sz else "?"
            warn = "  ⚠" if it.destructive else ""
            lines.append(f"  • {it.category}: {it.name} — {size_txt}{warn}")
        total = sum(v["bytes"] for v in self._clean_sizes.values()
                    if v["item"] in items) if self._clean_sizes else None
        warn_txt = ("\n\n⚠ WARNING: the items marked ⚠ destroy personal "
                    "data (logins / history / passwords). This cannot be "
                    "undone.") if any(it.destructive for it in items) else ""
        total_txt = f"  Total ≈ {human(total)}\n" if total is not None else ""
        if not messagebox.askyesno(
                APP_TITLE,
                f"Clean {len(items)} item(s)?\n{total_txt}\n"
                + "\n".join(lines) + warn_txt +
                "\n\nFiles are deleted PERMANENTLY (not moved to the "
                "Recycle Bin).\n\nContinue?"):
            return
        self._clean_cleaning = True
        self._clean_run_btn.state(["disabled"])
        self._clean_preview_btn.state(["disabled"])
        self._clean_log_line(f"— cleaning {len(items)} item(s)…")

        def log(msg):
            self._q.put(("clog", msg))

        def worker():
            try:
                totals = clean_items(items, log)
                self._q.put(("cdone", totals))
            except Exception as e:
                self._q.put(("cerror", f"{type(e).__name__}: {e}"))
        threading.Thread(target=worker, daemon=True).start()

    def _cleaner_done_ui(self):
        self._clean_cleaning = False
        self._clean_run_btn.state(["!disabled"])
        self._clean_preview_btn.state(["!disabled"])

    # ---- ClamAV security scanner -------------------------------------------

    def _build_security_tab(self):
        t = self._tab_security
        intro = ttk.Label(
            t, style="Status.TLabel",
            text=("ClamAV security scanner: quick scan, full local-disk scan, "
                  "or an optional custom file/folder scan. Findings are only "
                  "listed until you select an action. Every scan mode filters "
                  "files by the security extension allowlist. Quick scan "
                  "focuses on persistence/temp locations and running programs; "
                  "full scan covers selected disks. Windows-managed recycle "
                  "and restore-point folders are skipped."))
        intro.pack(fill="x", pady=(0, 6))

        scope = ttk.LabelFrame(t, text="Scan options", padding=8)
        scope.pack(fill="x")
        self._security_scope_lbl = ttk.Label(
            scope, style="Status.TLabel",
            text="Quick scan checks persistence and temporary locations plus "
                 "running programs. Quick, full, and custom scans only inspect "
                 "files whose extensions are on the security allowlist. "
                 "Quick scan skips personal Documents and Downloads folders; "
                 "full scan recursively checks selected disks. The Windows "
                 "protected vmfirmwarehcl.dll is excluded from scan counts. "
                 "ClamAV uses its current certificate trust/revocation data. "
                 "Lower-confidence PUA/heuristic hits on files with valid "
                 "Windows code signatures are suppressed automatically; "
                 "direct malware matches remain listed. PUA scanning is "
                 "optional and off by default. No app-name allowlist is used. "
                 "Access-denied paths are summarized after the scan.")
        self._security_scope_lbl.pack(fill="x")

        scan_buttons = ttk.Frame(scope)
        scan_buttons.pack(fill="x", pady=(7, 0))
        self._security_quick_btn = ttk.Button(
            scan_buttons, text="Quick scan",
            command=lambda: self._security_start_scan("quick"))
        self._security_quick_btn.pack(side="left", padx=(0, 5))
        self._security_scan_btn = ttk.Button(
            scan_buttons, text="Full system scan",
            command=lambda: self._security_start_scan("full"))
        self._security_scan_btn.pack(side="left", padx=(0, 5))
        self._security_custom_folder_btn = ttk.Button(
            scan_buttons, text="Scan folder…",
            command=lambda: self._security_custom_scan("folder"))
        self._security_custom_folder_btn.pack(side="left", padx=(0, 5))
        self._security_custom_file_btn = ttk.Button(
            scan_buttons, text="Scan file…",
            command=lambda: self._security_custom_scan("file"))
        self._security_custom_file_btn.pack(side="left")
        self._security_scan_buttons = (
            self._security_quick_btn, self._security_scan_btn,
            self._security_custom_folder_btn, self._security_custom_file_btn)

        controls = ttk.Frame(scope)
        controls.pack(fill="x", pady=(8, 0))
        self._security_pua_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(controls, text="Include potentially unwanted apps (PUA)",
                        variable=self._security_pua_var).pack(side="left")
        self._security_removable_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(controls, text="Full scan: include USB/removable disks",
                        variable=self._security_removable_var).pack(
                            side="left", padx=(10, 0))
        self._security_status_lbl = ttk.Label(controls, style="Status.TLabel",
                                               text="Checking ClamAV…")
        self._security_status_lbl.pack(side="left", fill="x", expand=True,
                                       padx=10)
        self._security_update_btn = ttk.Button(
            controls, text="Update definitions", command=self._security_start_update)
        self._security_update_btn.pack(side="right", padx=(6, 0))
        self._security_cancel_btn = ttk.Button(
            controls, text="Stop", command=self._security_stop,
            state="disabled")
        self._security_cancel_btn.pack(side="right", padx=(0, 6))

        self._security_progress_lbl = ttk.Label(
            t, style="Status.TLabel", text="Ready to scan")
        self._security_progress_lbl.pack(fill="x", pady=(5, 0))
        self._security_progress = ttk.Progressbar(t, mode="indeterminate")
        self._security_progress.pack(fill="x", pady=(6, 6))
        result_frame = ttk.LabelFrame(
            t, text="Detections — nothing changes until you select files and act", padding=4)
        result_frame.pack(fill="both", expand=True)
        cols = ("check", "status", "signature", "size", "path")
        self._security_tree = ttk.Treeview(
            result_frame, columns=cols, show="headings", selectmode="browse")
        self._security_tree.heading("check", text="Review")
        self._security_tree.heading("status", text="State")
        self._security_tree.heading("signature", text="ClamAV detection")
        self._security_tree.heading("size", text="Size")
        self._security_tree.heading("path", text="File path")
        self._security_tree.column("check", width=64, anchor="center", stretch=False)
        self._security_tree.column("status", width=105, anchor="w", stretch=False)
        self._security_tree.column("signature", width=250, anchor="w", stretch=False)
        self._security_tree.column("size", width=90, anchor="e", stretch=False)
        self._security_tree.column("path", width=500, anchor="w")
        vsb = ttk.Scrollbar(result_frame, orient="vertical",
                            command=self._security_tree.yview)
        hsb = ttk.Scrollbar(result_frame, orient="horizontal",
                            command=self._security_tree.xview)
        self._security_tree.configure(yscrollcommand=vsb.set,
                                      xscrollcommand=hsb.set)
        self._security_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        result_frame.rowconfigure(0, weight=1)
        result_frame.columnconfigure(0, weight=1)
        self._security_tree.bind("<Button-1>", self._security_on_click)
        self._security_tree.bind("<space>", self._security_on_space)

        actions = ttk.Frame(t)
        actions.pack(fill="x", pady=(6, 4))
        ttk.Button(actions, text="Select all detections",
                   command=lambda: self._security_select_all(True)).pack(
            side="left", padx=(0, 5))
        ttk.Button(actions, text="Clear selection",
                   command=lambda: self._security_select_all(False)).pack(side="left")
        ttk.Button(actions, text="Clear list",
                   command=self._security_clear_results).pack(side="left", padx=(6, 0))
        ttk.Button(actions, text="Manage quarantine…",
                   command=self._security_manage_quarantine).pack(side="left", padx=8)
        self._security_delete_btn = ttk.Button(
            actions, text="Delete selected permanently",
            style="Danger.TButton",
            command=lambda: self._security_action("delete"))
        self._security_delete_btn.pack(side="right")
        self._security_quarantine_btn = ttk.Button(
            actions, text="Quarantine selected",
            command=lambda: self._security_action("quarantine"))
        self._security_quarantine_btn.pack(side="right", padx=(0, 6))

        log_frame = ttk.LabelFrame(t, text="Scanner log", padding=4)
        log_frame.pack(fill="x")
        self._security_log = tk.Text(log_frame, height=4, wrap="word",
                                     state="disabled", relief="flat")
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical",
                                   command=self._security_log.yview)
        self._security_log.configure(yscrollcommand=log_scroll.set)
        self._security_log.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")
        self._security_sync_actions()

    def _security_prewarm_engine(self):
        """Load signatures in the background so scans are ready on demand."""
        if (self._security_engine_warming or self._security_busy or
                self._security_cancel.is_set()):
            return
        db = signature_database_status()
        if not db["ready"]:
            return
        current = _CLAMD_SESSION
        if (current is not None and current.process is not None and
                current.process.poll() is None):
            self._security_refresh_status()
            return
        if not find_clamav_dir() and not find_clamav_archive():
            return
        self._security_prewarm_cancel.clear()
        self._security_engine_warming = True
        self._security_refresh_status()
        self._security_log_line(
            "— loading ClamAV into memory in the background for fast scans")
        database_dir = db["directory"]
        detect_pua = bool(self._security_pua_var.get())

        def worker():
            try:
                engine = find_clamav_dir(prepare=True)
                if not engine:
                    raise RuntimeError("The bundled ClamAV engine was not found.")
                session = _get_clamd_session(
                    engine, database_dir, detect_pua,
                    progress=lambda line: self._q.put(("seclog", line)),
                    cancel=self._security_prewarm_cancel)
                if session is None:
                    self._q.put(("secengine_cancelled",))
                else:
                    self._q.put(("secengine_ready", session.workers))
            except InterruptedError:
                self._q.put(("secengine_cancelled",))
            except Exception as e:
                self._q.put(("secengine_error", f"{type(e).__name__}: {e}"))
        threading.Thread(target=worker, daemon=True).start()

    def _security_refresh_status(self):
        if not hasattr(self, "_security_status_lbl"):
            return
        engine = find_clamav_dir()
        bundled = bool(engine or find_clamav_archive())
        db = signature_database_status()
        session = _CLAMD_SESSION
        if not bundled:
            status = "ClamAV engine missing"
        elif not db["ready"]:
            status = ("ClamAV is bundled · definitions missing — they will "
                      "download automatically when you scan")
        elif self._security_engine_warming:
            status = "ClamAV scan engine is loading in the background…"
        elif (session is not None and session.process is not None and
              session.process.poll() is None):
            age = (" · definitions age unknown" if db["stale_days"] is None
                   else f" · definitions {db['stale_days']} day(s) old")
            status = f"ClamAV ready · scan engine warm{age}"
        elif db["stale_days"] is not None and db["stale_days"] > 7:
            status = f"Definitions are {db['stale_days']} days old — update recommended"
        elif db["stale_days"] is None:
            status = "ClamAV ready · signature age unavailable"
        else:
            status = f"ClamAV ready · definitions {db['stale_days']} day(s) old"
        self._security_status_lbl.configure(text=status)
        if self._security_busy:
            for button in self._security_scan_buttons:
                button.state(["disabled"])
            self._security_update_btn.state(["disabled"])
        else:
            for button in self._security_scan_buttons:
                button.state(["!disabled"] if bundled else ["disabled"])
            if bundled:
                self._security_update_btn.state(["!disabled"])
            else:
                self._security_update_btn.state(["disabled"])

    def _security_start_update(self, scan_after: bool = False):
        if self._security_busy:
            return
        if not (find_clamav_dir() or find_clamav_archive()):
            messagebox.showerror(APP_TITLE, "The bundled ClamAV engine was not found.")
            return
        self._security_scan_after_update = scan_after
        self._security_prewarm_cancel.set()
        self._security_cancel.clear()
        self._security_set_busy("Updating ClamAV signatures…")
        self._security_log_line("— updating official virus definitions with FreshClam")
        def worker():
            try:
                # Release the warm daemon's open signature files before FreshClam
                # replaces any definitions, then start it again only if needed.
                _stop_clamd_session()
                update_clamav_database(
                    self._security_cancel,
                    lambda line: self._q.put(("seclog", line)))
                self._q.put(("secupdate_done", None))
            except Exception as e:
                self._q.put(("secupdate_error", f"{type(e).__name__}: {e}"))
        threading.Thread(target=worker, daemon=True).start()

    def _security_custom_scan(self, kind: str):
        initial = os.path.expanduser("~")
        if kind == "folder":
            selected = filedialog.askdirectory(
                title="Choose a folder to scan", initialdir=initial,
                parent=self)
        else:
            selected = filedialog.askopenfilename(
                title="Choose a file to scan", initialdir=initial,
                parent=self)
        if selected:
            self._security_start_scan(
                f"Custom {kind} scan", targets=[selected])

    def _security_start_scan(self, mode: str = "full", targets=None):
        if self._security_busy:
            return
        if targets is None:
            if mode == "quick":
                targets = security_quick_scan_roots()
                scan_mode = "Quick scan"
            else:
                targets = security_scan_roots(
                    include_removable=self._security_removable_var.get())
                scan_mode = "Full system scan"
        else:
            targets = list(targets)
            scan_mode = mode
        if not targets:
            messagebox.showerror(APP_TITLE,
                "No locations were found for this scan. Check that the "
                "selected disk or folder is available.")
            return
        self._security_scan_targets = targets
        self._security_scan_mode = scan_mode
        # A fresh scan never carries a prior removal selection forward.
        self._security_select_all(False)
        self._security_cancel.clear()
        db = signature_database_status()
        if not db["ready"]:
            self._security_log_line(
                "— ClamAV definitions are missing; downloading definitions "
                "before scan")
            self._security_start_update(scan_after=True)
            return
        if db["stale_days"] is not None and db["stale_days"] >= 1:
            self._security_log_line(
                f"— definitions are {db['stale_days']} day(s) old; scanning "
                "now with the installed signatures. Use Update definitions "
                "to refresh them.")
        self._security_run_scan()

    def _security_run_scan(self):
        targets = list(self._security_scan_targets)
        if not targets:
            return
        self._security_cancel.clear()
        self._security_set_busy(f"{self._security_scan_mode}: scanning with ClamAV…")
        self._security_log_line(
            f"— {self._security_scan_mode} started: " + ", ".join(targets))
        detect_pua = self._security_pua_var.get()
        file_extensions = SECURITY_SCAN_EXTENSIONS
        def worker():
            try:
                findings, stats = scan_with_clamav(
                    targets, detect_pua=detect_pua, cancel=self._security_cancel,
                    progress=lambda line: self._q.put(("seclog", line)),
                    file_extensions=file_extensions,
                    scan_progress=lambda scanned, total, detail: self._q.put(
                        ("secscan_progress", scanned, total, detail)))
                if findings and not self._security_cancel.is_set():
                    self._q.put(("secscan_progress", stats.get("processed", 0),
                                 stats.get("total", 0),
                                 "Checking Windows code-signing trust for lower-confidence matches…"))
                    raw_infected = sum(
                        not _is_clamav_limit_signature(
                            finding.get("signature", ""))
                        for finding in findings)
                    findings, suppressed = suppress_trusted_low_confidence_findings(
                        findings)
                    stats["trusted_low_confidence_suppressed"] = suppressed
                    stats["infected"] = sum(
                        not _is_clamav_limit_signature(
                            finding.get("signature", ""))
                        for finding in findings)
                    stats["clamav_matches_before_trust_filter"] = raw_infected
                self._q.put(("secscan_done", findings, stats))
            except Exception as e:
                self._q.put(("secscan_error", f"{type(e).__name__}: {e}"))
        threading.Thread(target=worker, daemon=True).start()

    def _security_set_busy(self, message: str, cancellable: bool = True):
        self._security_busy = True
        self._security_status_lbl.configure(text=message)
        self._security_progress_lbl.configure(text=message)
        self._security_progress.configure(mode="indeterminate", value=0)
        self._security_progress.start(12)
        self._security_cancel_btn.state(["!disabled"] if cancellable else ["disabled"])
        for button in self._security_scan_buttons:
            button.state(["disabled"])
        self._security_update_btn.state(["disabled"])
        self._security_sync_actions()

    def _security_stop(self):
        if self._security_busy:
            self._security_cancel.set()
            self._security_status_lbl.configure(text="Stopping ClamAV…")

    def _security_finish_busy(self):
        self._security_busy = False
        self._security_progress.stop()
        self._security_cancel_btn.state(["disabled"])
        self._security_refresh_status()
        self._security_sync_actions()

    def _security_clear_results(self):
        self._security_findings.clear()
        self._security_checked.clear()
        self._security_tree.delete(*self._security_tree.get_children(""))
        self._security_sync_actions()

    def _security_display_findings(self, findings):
        def row_status(finding, identity):
            if _is_clamav_limit_signature(finding.get("signature", "")):
                return "Incomplete"
            if identity is None:
                return "Unavailable"
            return "Detected"

        existing = {
            (os.path.normcase(os.path.abspath(item["path"])), item["signature"]): str(i)
            for i, item in enumerate(self._security_findings)
        }
        for finding in findings:
            key = (os.path.normcase(os.path.abspath(finding["path"])),
                   finding["signature"])
            existing_iid = existing.get(key)
            if existing_iid is not None:
                finding_index = int(existing_iid)
                old = self._security_findings[finding_index]
                old.update(finding)
                old["identity"] = file_identity(finding["path"])
                old["status"] = row_status(old, old["identity"])
                if old["status"] != "Detected":
                    self._security_checked.discard(existing_iid)
                    self._security_tree.set(existing_iid, "check", "")
                self._security_tree.set(existing_iid, "status", old["status"])
                self._security_tree.set(
                    existing_iid, "size",
                    human(old["identity"][0]) if old["identity"] else "unavailable")
                self._security_tree.item(existing_iid, tags=("detected",))
                continue
            finding = dict(finding)
            identity = file_identity(finding["path"])
            finding["identity"] = identity
            finding["status"] = row_status(finding, identity)
            size = human(identity[0]) if identity is not None else "unavailable"
            iid = str(len(self._security_findings))
            self._security_findings.append(finding)
            existing[key] = iid
            self._security_tree.insert(
                "", "end", iid=iid, tags=("detected",),
                values=("", finding.get("status", "Detected"),
                        finding["signature"], size, finding["path"]))
        self._security_sync_actions()

    def _security_sync_actions(self):
        if not hasattr(self, "_security_quarantine_btn"):
            return
        enabled = bool(self._security_checked) and not self._security_busy
        for button in (self._security_quarantine_btn, self._security_delete_btn):
            button.state(["!disabled"] if enabled else ["disabled"])

    def _security_on_click(self, event):
        iid = self._security_tree.identify_row(event.y)
        if iid and self._security_tree.identify_column(event.x) == "#1":
            self._security_toggle(iid)
            return "break"

    def _security_on_space(self, _event):
        iid = self._security_tree.focus()
        if iid:
            self._security_toggle(iid)

    def _security_toggle(self, iid: str):
        finding_index = int(iid)
        finding = self._security_findings[finding_index]
        if (finding.get("identity") is None or
                finding.get("status") != "Detected"):
            return
        if iid in self._security_checked:
            self._security_checked.discard(iid)
            self._security_tree.set(iid, "check", "")
        else:
            self._security_checked.add(iid)
            self._security_tree.set(iid, "check", "✓")
        self._security_sync_actions()

    def _security_select_all(self, selected: bool):
        eligible = {
            str(i) for i, finding in enumerate(self._security_findings)
            if finding.get("identity") is not None and
            finding.get("status") == "Detected"
        }
        self._security_checked = eligible if selected else set()
        for iid in self._security_tree.get_children(""):
            self._security_tree.set(
                iid, "check", "✓" if iid in self._security_checked else "")
        self._security_sync_actions()

    def _security_selected(self):
        rows = sorted(self._security_checked, key=int)
        return [(iid, self._security_findings[int(iid)]) for iid in rows]

    def _security_action(self, action: str):
        if self._security_busy:
            return
        if action not in ("quarantine", "delete"):
            self._flash("Security: unknown file action was blocked.")
            return
        selected = self._security_selected()
        if not selected:
            self._flash("Security: select at least one detected file.")
            return
        paths = list(dict.fromkeys(finding["path"] for _iid, finding in selected))
        expected = {
            os.path.normcase(os.path.abspath(finding["path"])):
                (finding["identity"] if finding.get("identity") is not None else False)
            for _iid, finding in selected
        }
        if action == "delete":
            prompt = (f"Permanently delete {len(paths)} selected file(s)?\n\n"
                      "This cannot be undone. Continue?")
        else:
            prompt = (f"Move {len(paths)} selected file(s) to the local "
                      "quarantine folder?\n\n"
                      "Quarantined files leave their original locations. "
                      "Review them before deleting. Continue?")
        if not messagebox.askyesno(APP_TITLE, prompt, parent=self):
            return
        self._security_cancel.clear()
        self._security_set_busy("Removing selected detections…", cancellable=False)
        def worker():
            try:
                if action == "quarantine":
                    result, failures = quarantine_files(
                        paths, os.path.join(security_data_dir(), "Quarantine"),
                        expected=expected)
                else:
                    result, failures = delete_detected_files(paths,
                                                            expected=expected)
                self._q.put(("secaction_done", action, paths, result, failures))
            except Exception as e:
                self._q.put(("secaction_error", f"{type(e).__name__}: {e}"))
        threading.Thread(target=worker, daemon=True).start()

    def _security_log_line(self, msg: str):
        stamp = time.strftime("%H:%M:%S")
        self._security_log.configure(state="normal")
        self._security_log.insert("end", f"[{stamp}] {msg}\n")
        self._security_log.see("end")
        self._security_log.configure(state="disabled")

    def _security_open_quarantine(self):
        path = os.path.join(security_data_dir(), "Quarantine")
        os.makedirs(path, exist_ok=True)
        try:
            os.startfile(path)
        except (AttributeError, OSError) as e:
            messagebox.showerror(APP_TITLE, f"Could not open quarantine folder:\n{e}")

    def _security_manage_quarantine(self):
        folder = os.path.join(security_data_dir(), "Quarantine")
        os.makedirs(folder, exist_ok=True)
        win = tk.Toplevel(self)
        win.title("ClamAV quarantine")
        win.geometry("940x430")
        win.transient(self)
        ttk.Label(win, text=("Quarantined files have been moved out of their "
                             "original folders. Restore puts a file back only "
                             "when its original path is still free.")).pack(
            fill="x", padx=10, pady=(10, 6))
        frame = ttk.Frame(win, padding=(10, 0, 10, 6))
        frame.pack(fill="both", expand=True)
        cols = ("check", "date", "original", "quarantined")
        tree = ttk.Treeview(frame, columns=cols, show="headings")
        for col, title, width in (("check", "Restore?", 65),
                                  ("date", "Quarantined", 150),
                                  ("original", "Original path", 360),
                                  ("quarantined", "Stored file", 280)):
            tree.heading(col, text=title)
            tree.column(col, width=width, anchor="w",
                        stretch=(col in ("original", "quarantined")))
        tree.column("check", anchor="center", stretch=False)
        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        restore_checked: set[str] = set()

        def populate():
            restore_checked.clear()
            tree.delete(*tree.get_children(""))
            for i, entry in enumerate(load_quarantine_records(folder)):
                stored = os.path.basename(entry.get("quarantined_path", ""))
                tree.insert("", "end", iid=str(i),
                            values=("", entry.get("quarantined_at", ""),
                                    entry.get("original_path", ""), stored))

        def click(event):
            iid = tree.identify_row(event.y)
            if iid and tree.identify_column(event.x) == "#1":
                if iid in restore_checked:
                    restore_checked.discard(iid)
                    tree.set(iid, "check", "")
                else:
                    restore_checked.add(iid)
                    tree.set(iid, "check", "✓")
                return "break"

        tree.bind("<Button-1>", click)
        buttons = ttk.Frame(win, padding=(10, 0, 10, 10))
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Open folder",
                   command=self._security_open_quarantine).pack(side="left")
        restore_btn = ttk.Button(buttons, text="Restore checked",
                                 command=lambda: restore())
        restore_btn.pack(side="right", padx=(0, 6))
        ttk.Button(buttons, text="Close", command=win.destroy).pack(side="right")

        def restore():
            if not restore_checked:
                return
            records = load_quarantine_records(folder)
            chosen = [records[int(i)]["quarantined_path"]
                      for i in sorted(restore_checked, key=int)
                      if int(i) < len(records) and
                      records[int(i)].get("quarantined_path")]
            if not chosen:
                return
            restore_btn.state(["disabled"])
            def worker():
                try:
                    restored, failures = restore_quarantined_files(folder, chosen)
                    self._q.put(("secrestore_done", win, restore_btn, populate,
                                 restored, failures))
                except Exception as e:
                    self._q.put(("secrestore_error", win, restore_btn,
                                 f"{type(e).__name__}: {e}"))
            threading.Thread(target=worker, daemon=True).start()

        populate()
        return win

    # ---- duplicates tab behavior (unchanged logic) -------------------------------

    def _flash(self, msg: str, busy: bool = False):
        self._status.configure(text=msg)
        if not busy:
            self._bar.pack_forget()

    def _browse(self):
        d = filedialog.askdirectory(
            initialdir=self._folder_var.get() or os.path.expanduser("~"))
        if d:
            self._folder_var.set(os.path.normpath(d))

    def _start_scan(self):
        if self._scan_thread and self._scan_thread.is_alive():
            return
        root_dir = self._folder_var.get().strip()
        if not os.path.isdir(root_dir):
            messagebox.showerror(APP_TITLE, f"Folder does not exist:\n{root_dir}")
            return
        try:
            min_kb = max(0, int(self._minsize_var.get()))
        except Exception:
            min_kb = 0
        self._clear_results()
        self._cancel.clear()
        self._scan_btn.state(["disabled"])
        self._stop_btn.state(["!disabled"])
        self._bar.configure(value=0, maximum=100, mode="indeterminate")
        self._bar.pack(side="right")
        self._bar.start(12)
        self._flash(f"Scanning {root_dir} …", busy=True)
        self._scan_thread = threading.Thread(target=self._scan_worker, args=(
            root_dir, min_kb * 1024, self._recursive_var.get()), daemon=True)
        self._scan_thread.start()

    def _scan_worker(self, root_dir, min_size, recursive):
        def progress(kind, *args):
            self._q.put((kind, *args))
        try:
            result = run_scan(root_dir, min_size, recursive, progress, self._cancel)
            self._q.put(("done", result))
        except Exception as e:  # surface anything inside the thread
            self._q.put(("error", f"{type(e).__name__}: {e}"))

    def _stop_scan(self):
        self._cancel.set()
        self._flash("Stopping…", busy=True)

    def _poll(self):
        try:
            while True:
                msg = self._q.get_nowait()
                kind = msg[0]
                if kind == "walk":
                    self._flash(f"Scanning… {msg[1]:,} files found "
                                f"({human(msg[2])})", busy=True)
                elif kind == "hash_total":
                    self._bar.stop()
                    self._bar.configure(mode="determinate", maximum=max(1, msg[1]))
                elif kind == "hash":
                    self._bar.configure(value=msg[1])
                    self._flash(f"Comparing {msg[1]:,} / {msg[2]:,} candidate files…",
                                busy=True)
                elif kind == "done":
                    self._finish_scan(msg[1])
                elif kind == "error":
                    self._scan_done_ui()
                    messagebox.showerror(APP_TITLE, f"Scan failed:\n{msg[1]}")
                elif kind == "cprog":
                    self._flash(f"Cleaner: {msg[1]}", busy=True)
                elif kind == "cprev":
                    self._clean_previewing = False
                    self._clean_preview_btn.state(["!disabled"])
                    self._clean_sizes = msg[1]
                    self._clean_sizes_time = time.time()
                    for cid, r in msg[1].items():
                        if self._clean_tree.exists(cid):
                            self._clean_tree.set(
                                cid, "size", human(r["bytes"]))
                    total = sum(r["bytes"] for r in msg[1].values())
                    n = len(msg[1])
                    self._flash(f"Cleaner preview: {n} item(s), "
                                f"{human(total)} recoverable.")
                elif kind == "clog":
                    self._clean_log_line(msg[1])
                elif kind == "cdone":
                    t = msg[1]
                    self._cleaner_done_ui()
                    self._clean_log_line(
                        f"— done: freed {human(t['freed'])}, removed "
                        f"{t['removed']:,} files, {t['skipped']} skipped.")
                    self._flash(f"Cleaner done: {human(t['freed'])} freed.")
                    self._refresh_clean_storage()
                    self._cleaner_preview(all_items=True)  # refresh sizes
                elif kind == "cerror":
                    self._cleaner_done_ui()
                    self._clean_previewing = False
                    self._clean_preview_btn.state(["!disabled"])
                    messagebox.showerror(APP_TITLE,
                                         f"Cleaner failed:\n{msg[1]}")
                elif kind == "seclog":
                    self._security_log_line(msg[1])
                elif kind == "secscan_progress":
                    scanned, total, detail = msg[1], msg[2], msg[3]
                    if total is None:
                        suffix = f" · {detail}" if detail else ""
                        self._security_progress_lbl.configure(
                            text=f"{self._security_scan_mode}: preparing scan{suffix}")
                        continue
                    if str(self._security_progress.cget("mode")) != "determinate":
                        self._security_progress.stop()
                        self._security_progress.configure(
                            mode="determinate", maximum=max(1, total), value=0)
                    displayed = min(scanned, total)
                    remaining = max(0, total - scanned)
                    self._security_progress.configure(value=displayed)
                    self._security_progress_lbl.configure(
                        text=(f"{self._security_scan_mode}: "
                              f"{scanned:,} files completed · "
                              f"{remaining:,} files remaining "
                              f"({total:,} total)"
                              + (f" · {detail}" if detail else "")))
                elif kind == "secengine_ready":
                    self._security_engine_warming = False
                    self._security_log_line(
                        f"✓ ClamAV is warm with {msg[1]} scan workers.")
                    if not self._security_busy:
                        self._security_refresh_status()
                elif kind == "secengine_cancelled":
                    self._security_engine_warming = False
                    if not self._security_busy:
                        self._security_refresh_status()
                elif kind == "secengine_error":
                    self._security_engine_warming = False
                    self._security_log_line(
                        f"✗ Background scanner startup failed: {msg[1]}")
                    if not self._security_busy:
                        self._security_refresh_status()
                elif kind == "secupdate_done":
                    scan_after_update = self._security_scan_after_update
                    self._security_scan_after_update = False
                    self._security_prewarm_cancel.clear()
                    self._security_engine_warming = False
                    self._security_finish_busy()
                    self._refresh_clean_storage()
                    self._security_log_line("✓ ClamAV signatures are current.")
                    self._flash("ClamAV definitions updated.")
                    if scan_after_update:
                        self._security_run_scan()
                    else:
                        self.after(400, self._security_prewarm_engine)
                elif kind == "secupdate_error":
                    scan_after_update = self._security_scan_after_update
                    self._security_scan_after_update = False
                    self._security_prewarm_cancel.clear()
                    self._security_engine_warming = False
                    self._security_finish_busy()
                    self._security_log_line(f"✗ Signature update failed: {msg[1]}")
                    if (scan_after_update and
                            signature_database_status()["ready"] and
                            not self._security_cancel.is_set()):
                        use_existing = messagebox.askyesno(
                            APP_TITLE,
                            "ClamAV could not check for newer definitions. "
                            "Scan with the definitions already installed?\n\n"
                            f"{msg[1]}", parent=self)
                        if use_existing:
                            self._security_run_scan()
                    else:
                        messagebox.showerror(
                            APP_TITLE,
                            f"ClamAV signature update failed:\n{msg[1]}")
                        if signature_database_status()["ready"]:
                            self.after(400, self._security_prewarm_engine)
                elif kind == "secscan_done":
                    findings, stats = msg[1], msg[2]
                    self._security_finish_busy()
                    if stats.get("cancelled"):
                        self._security_log_line("— ClamAV scan cancelled.")
                        scanned = stats.get("scanned") or 0
                        remaining = stats.get("remaining")
                        if stats.get("counting_cancelled"):
                            self._security_progress_lbl.configure(
                                text="Cancelled while counting files.")
                            self._flash("Scan cancelled while counting files.")
                        elif remaining is not None:
                            self._security_progress_lbl.configure(
                                text=(f"Cancelled: {scanned:,} files scanned · "
                                      f"{remaining:,} files remaining"))
                            self._flash(
                                f"ClamAV scan cancelled after {scanned:,} files.")
                        else:
                            self._flash(
                                f"ClamAV scan cancelled after {scanned:,} files.")
                    else:
                        self._security_display_findings(findings)
                        if stats.get("total") is not None:
                            self._security_progress_lbl.configure(
                                text=(f"Finished: {stats.get('scanned', 0):,} "
                                      f"files scanned · "
                                      f"{stats.get('inaccessible', 0):,} "
                                      f"inaccessible · "
                                      f"{stats.get('remaining', 0):,} "
                                      "unprocessed"))
                        if stats["scanned"] is None:
                            coverage = (f"checked {len(self._security_scan_targets):,} "
                                        "scan location(s)")
                        else:
                            coverage = f"scanned {stats['scanned']:,} file(s)"
                        summary = (f"{self._security_scan_mode}: ClamAV {coverage}, "
                                   f"found {stats.get('infected', len(findings)):,} "
                                   "detection(s), "
                                   f"{stats.get('trusted_low_confidence_suppressed', 0):,} "
                                   "lower-confidence matches suppressed by valid "
                                   "code-signing trust, "
                                   f"{stats.get('incomplete', 0):,} "
                                   "limit-incomplete file(s), "
                                   f"{stats.get('inaccessible', 0):,} "
                                   "inaccessible item(s), "
                                   f"{stats['errors']:,} other scan error(s).")
                        self._security_log_line(summary)
                        inaccessible_examples = stats.get(
                            "inaccessible_examples", [])
                        if inaccessible_examples:
                            self._security_log_line(
                                "Access denied; sample skipped paths: " +
                                " · ".join(inaccessible_examples))
                        error_examples = stats.get("error_examples", [])
                        if error_examples:
                            self._security_log_line(
                                "Other scan error samples: " +
                                " · ".join(error_examples))
                        if stats.get("remaining", 0):
                            self._security_log_line(
                                f"Scan did not process {stats['remaining']:,} "
                                "counted file(s).")
                        if findings:
                            self._security_log_line(
                                "Review detections in the list. No files were "
                                "changed; select items before choosing an action.")
                            self._flash(
                                f"{summary} Review the list; no files were changed.")
                        else:
                            self._flash(summary)
                elif kind == "secscan_error":
                    self._security_finish_busy()
                    self._security_progress_lbl.configure(text="Scan failed.")
                    self._security_log_line(f"✗ ClamAV scan failed: {msg[1]}")
                    messagebox.showerror(APP_TITLE,
                                         f"ClamAV scan failed:\n{msg[1]}")
                elif kind == "secaction_done":
                    _kind, action, paths, result, failures = msg
                    done_paths = ({e["original_path"] for e in result}
                                  if action == "quarantine" else set(result))
                    for i, finding in enumerate(self._security_findings):
                        if finding["path"] in done_paths:
                            iid = str(i)
                            finding["status"] = ("Quarantined" if action == "quarantine"
                                                 else "Deleted")
                            self._security_tree.set(iid, "status", finding["status"])
                            self._security_tree.item(iid, tags=("handled",))
                            self._security_checked.discard(iid)
                            self._security_tree.set(iid, "check", "")
                    self._security_finish_busy()
                    self._refresh_clean_storage()
                    action_label = "quarantined" if action == "quarantine" else "deleted"
                    self._security_log_line(
                        f"— {len(done_paths)} file(s) {action_label}; "
                        f"{len(failures)} failed or skipped.")
                    for path, error in failures:
                        self._security_log_line(f"Could not process {path}: {error}")
                    if action == "quarantine" and done_paths:
                        self._security_log_line(
                            "Quarantine folder: " + os.path.join(
                                security_data_dir(), "Quarantine"))
                    self._flash(f"Security: {len(done_paths)} file(s) {action_label}; "
                                f"{len(failures)} failed or skipped.")
                elif kind == "secaction_error":
                    self._security_finish_busy()
                    self._security_log_line(f"✗ Security action failed: {msg[1]}")
                    messagebox.showerror(APP_TITLE,
                                         f"Could not process detections:\n{msg[1]}")
                elif kind == "secrestore_done":
                    _kind, win, button, populate, restored, failures = msg
                    try:
                        if win.winfo_exists():
                            populate()
                            button.state(["!disabled"])
                    except tk.TclError:
                        pass
                    self._security_log_line(
                        f"— restored {len(restored)} quarantined file(s); "
                        f"{len(failures)} could not be restored.")
                    for path, error in failures:
                        self._security_log_line(f"Could not restore {path}: {error}")
                    self._flash(f"Quarantine: restored {len(restored)} file(s); "
                                f"{len(failures)} failed.")
                elif kind == "secrestore_error":
                    _kind, win, button, error = msg
                    try:
                        if win.winfo_exists():
                            button.state(["!disabled"])
                    except tk.TclError:
                        pass
                    messagebox.showerror(APP_TITLE,
                                         f"Could not restore quarantined files:\n{error}")
        except queue.Empty:
            pass
        self.after(80, self._poll)

    def _scan_done_ui(self):
        self._bar.stop()
        self._bar.pack_forget()
        self._scan_btn.state(["!disabled"])
        self._stop_btn.state(["disabled"])

    def _finish_scan(self, result: ScanResult | None):
        self._scan_done_ui()
        if result is None:
            self._flash("Scan cancelled.")
            return
        self._result = result
        self._show_result(result)
        wasted = sum(g.wasted for g in result.groups)
        if result.groups:
            self._flash(f"Done: {result.files_seen:,} files scanned · "
                        f"{len(result.groups)} duplicate groups · "
                        f"{human(wasted)} recoverable.")
        else:
            self._flash(f"Done: {result.files_seen:,} files scanned — "
                        f"no duplicates found.")

    def _row_tags(self, idx: int) -> tuple:
        return ("odd",) if self.settings.get("zebra") and idx % 2 else ()

    def _retag_rows(self):
        if not hasattr(self, "_tree"):
            return
        i = 0
        for gid in self._tree.get_children(""):
            self._tree.item(gid, tags=("group",))
            for p in self._tree.get_children(gid):
                self._tree.item(p, tags=self._row_tags(i))
                i += 1

    def _clear_results(self):
        self._tree.delete(*self._tree.get_children())
        self._checked.clear()
        self._group_of.clear()
        self._gid.clear()
        self._result = None
        for b in (self._keep_new_btn, self._keep_old_btn, self._clear_btn,
                  self._open_btn, self._csv_btn, self._delete_btn):
            b.state(["disabled"])
        self._delete_btn.configure(text="Move to Recycle Bin")

    def _show_result(self, result: ScanResult):
        self._clear_results()
        self._result = result
        for i, g in enumerate(result.groups):
            gid = f"g{i}"
            self._gid[g] = gid
            for p in g.paths:
                self._group_of[p] = g
            header = (f"{len(g.paths)} copies × {human(g.size)}"
                      f"  —  {human(g.wasted)} wasted")
            self._tree.insert("", "end", iid=gid, open=True, tags=("group",),
                              text=header, values=("", "", "", ""))
            for j, p in enumerate(sorted(g.paths)):
                mt = g.mtimes.get(p, 0)
                when = datetime.fromtimestamp(mt).strftime(
                    "%Y-%m-%d %H:%M") if mt else "?"
                folder = os.path.dirname(p)
                self._tree.insert(gid, "end", iid=p,
                                  text="  " + os.path.basename(p),
                                  tags=self._row_tags(j),
                                  values=("", human(g.size), when, folder))
        if result.groups:
            for b in (self._keep_new_btn, self._keep_old_btn, self._clear_btn,
                      self._open_btn, self._csv_btn, self._delete_btn):
                b.state(["!disabled"])

    def _on_click(self, event):
        row = self._tree.identify_row(event.y)
        if not row:
            return
        col = self._tree.identify_column(event.x)
        if row.startswith("g"):
            if self._tree.get_children(row):
                self._toggle_group(row)
        elif col in ("#0", "#1"):
            self._toggle_child(row)
        return "break"  # keep the built-in rubber selection out of the way

    def _on_space(self, _event):
        row = self._tree.focus()
        if row and not row.startswith("g"):
            self._toggle_child(row)

    def _toggle_child(self, path: str):
        g = self._group_of.get(path)
        if g is None:
            return
        if path in self._checked:
            self._checked.discard(path)
            mark = ""
        else:
            n_kept = sum(1 for p in g.paths if p in self._checked)
            if n_kept >= len(g.paths) - 1:
                self._flash("Keep at least one copy in each group.")
                return
            self._checked.add(path)
            mark = "✓"
        self._tree.set(path, "check", mark)
        self._update_delete_btn()

    def _toggle_group(self, gid: str):
        g = next((grp for grp, i in self._gid.items() if i == gid), None)
        if g is None:
            return
        if any(p in self._checked for p in g.paths):
            for p in g.paths:
                self._checked.discard(p)
                self._tree.set(p, "check", "")
        else:
            newest = max(g.paths, key=lambda p: (g.mtimes.get(p, 0), p))
            for p in g.paths:
                if p != newest:
                    self._checked.add(p)
                    self._tree.set(p, "check", "✓")
        self._update_delete_btn()

    def _auto_keep(self, newest: bool):
        if not self._result:
            return
        self._checked.clear()
        for g in self._result.groups:
            ordered = sorted(g.paths, key=lambda p: (g.mtimes.get(p, 0), p),
                             reverse=newest)
            for p in ordered[1:]:
                self._checked.add(p)
        for p in self._checked:
            if self._tree.exists(p):
                self._tree.set(p, "check", "✓")
        for gid in self._tree.get_children(""):
            for p in self._tree.get_children(gid):
                if p not in self._checked:
                    self._tree.set(p, "check", "")
        self._update_delete_btn()

    def _uncheck_all(self):
        self._checked.clear()
        for gid in self._tree.get_children(""):
            for p in self._tree.get_children(gid):
                self._tree.set(p, "check", "")
        self._update_delete_btn()

    def _selected_paths(self) -> list[str]:
        return sorted(p for p in self._checked if self._tree.exists(p))

    def _update_delete_btn(self):
        n = len(self._checked)
        size = 0
        for p in self._checked:
            g = self._group_of.get(p)
            if g:
                size += g.size
        if n:
            self._delete_btn.configure(
                text=f"Move {n} file{'s' if n != 1 else ''} ({human(size)}) to Recycle Bin")
        else:
            self._delete_btn.configure(text="Move to Recycle Bin")

    def _open_location(self):
        sel = self._tree.focus()
        if sel and not sel.startswith("g") and os.path.exists(sel):
            subprocess.Popen(["explorer", "/select,", os.path.normpath(sel)])

    def _delete_selected(self):
        paths = self._selected_paths()
        if not paths:
            self._flash("Nothing selected — tick the 'Delete?' box on the copies "
                        "you want to remove.")
            return
        bad = [g for g in self._gid if all(p in self._checked for p in g.paths)]
        if bad:
            messagebox.showwarning(
                APP_TITLE,
                "One or more groups have every copy selected.\n"
                "Each duplicate group must keep at least one file.")
            return
        size = sum(self._group_of[p].size for p in paths)
        sample = "\n".join("  " + p for p in paths[:8])
        more = f"\n  … and {len(paths) - 8} more" if len(paths) > 8 else ""
        if not messagebox.askyesno(
                APP_TITLE,
                f"Move {len(paths)} file(s), {human(size)}, to the Recycle Bin?\n\n"
                f"{sample}{more}\n\n"
                f"You can restore them from the Recycle Bin if needed."):
            return
        self._delete_btn.state(["disabled"])
        self.update_idletasks()
        try:
            survivors, aborted = recycle_paths(paths)
        except OSError as e:
            messagebox.showerror(APP_TITLE, f"Recycle Bin failed:\n{e}")
            self._delete_btn.state(["!disabled"])
            return
        moved = [p for p in paths if p not in survivors]
        if moved:
            for p in moved:
                self._checked.discard(p)
            self._prune_deleted(moved)
        if aborted:
            self._flash("Move aborted by you — nothing else was changed.")
        elif moved:
            freed = sum(self._group_of.get(p, DupGroup(0, [])).size for p in moved)
            self._flash(f"Moved {len(moved)} file(s) to the Recycle Bin "
                        f"({human(freed)} recoverable).")
        else:
            self._flash("Nothing was moved.")
        self._delete_btn.state(["!disabled"])
        self._update_delete_btn()

    def _prune_deleted(self, moved: list[str]):
        for g in list(self._gid):
            g.paths = [p for p in g.paths if p not in moved]
            for p in moved:
                g.mtimes.pop(p, None)
            gid = self._gid[g]
            for p in moved:
                self._group_of.pop(p, None)
                if self._tree.exists(p):
                    self._tree.delete(p)
            if len(g.paths) < 2:
                if self._tree.exists(gid):
                    self._tree.delete(gid)
                del self._gid[g]
            else:
                header = (f"{len(g.paths)} copies × {human(g.size)}"
                          f"  —  {human(g.wasted)} wasted")
                self._tree.item(gid, text=header)
        if not self._gid:
            self._flash("All duplicates removed. 🎉")
            for b in (self._keep_new_btn, self._keep_old_btn, self._clear_btn,
                      self._open_btn, self._csv_btn, self._delete_btn):
                b.state(["disabled"])

    def _save_report(self):
        if not self._result:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", initialfile="duplicates.csv",
            filetypes=[("CSV report", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["group", "marked_for_delete", "path", "size_bytes",
                        "size", "modified"])
            for gi, (g, gid) in enumerate(sorted(self._gid.items(),
                                                 key=lambda kv: -kv[0].wasted), 1):
                for p in sorted(g.paths):
                    mt = g.mtimes.get(p, 0)
                    when = (datetime.fromtimestamp(mt).isoformat(
                        timespec="seconds") if mt else "")
                    w.writerow([gi, "YES" if p in self._checked else "", p,
                                g.size, human(g.size), when])
        self._flash(f"Report saved: {path}")


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
