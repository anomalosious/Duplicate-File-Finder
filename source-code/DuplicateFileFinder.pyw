#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Duplicate File Finder & Cleaner for Windows — tabbed edition.

Tabs:
  🗂 Duplicates — find files with identical content and remove the extra
                 copies safely to the Recycle Bin.
  🎨 Themes     — 15 color themes, custom accent color, font sizes, zebra
                 stripes, colorful title bar, live preview. Settings persist.
  🕒 Clock      — a big theme-aware analog clock with a smooth second hand,
                 12-hour digital caption, date and always-on-top toggle.

Pure standard library — no dependencies.
Run: double-click this file (pythonw runs it without a console window).
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import csv
import hashlib
import json
import math
import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from tkinter import colorchooser, filedialog, messagebox, ttk

APP_TITLE = "Duplicate File Finder"
CHUNK = 1 << 20
PARTIAL_BYTES = 64 * 1024
SKIP_DIRS = {"$recycle.bin", "system volume information"}
SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "settings.json")


def human(n: float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024.0 or unit == "TB":
            return f"{int(n)} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024.0


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


def load_settings(path: str = SETTINGS_FILE) -> dict:
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


def save_settings(settings: dict, path: str = SETTINGS_FILE) -> None:
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
# GUI
# --------------------------------------------------------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1080x700")
        self.minsize(900, 540)

        self._q: queue.Queue = queue.Queue()
        self._cancel = threading.Event()
        self._scan_thread = None
        self._result: ScanResult | None = None
        self._checked: set[str] = set()
        self._group_of: dict[str, DupGroup] = {}
        self._gid: dict[DupGroup, str] = {}

        self.settings = load_settings()
        self._custom_accent: str | None = self.settings.get("accent")

        self._build_fonts()
        self._build_notebook()
        self._build_duplicates_tab()
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
        self._notebook.select(0)

        self.after(80, self._poll)
        self.after(100, self._tick_clock)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._flash("Pick a folder and press Scan.")

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
        self._notebook.add(self._tab_dup, text="🗂  Duplicates")
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
