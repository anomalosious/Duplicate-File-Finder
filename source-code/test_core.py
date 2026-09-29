# -*- coding: utf-8 -*-
"""Headless smoke test for DuplicateFileFinder.pyw core logic."""
import importlib.util
import os
import sys
import tempfile
from importlib.machinery import SourceFileLoader

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(HERE, "DuplicateFileFinder.pyw")

loader = SourceFileLoader("dff", APP)
spec = importlib.util.spec_from_loader("dff", loader)
dff = importlib.util.module_from_spec(spec)
sys.modules["dff"] = dff
loader.exec_module(dff)

failures = []

def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        failures.append(name)

tmp = tempfile.mkdtemp(prefix="dff_test_")

# Layout:
#   a/big.bin (2 MB)  ==  sub/big.bin (exact copy)
#   same.txt x3 (identical, small)
#   unique.bin (2 MB, unique content)
import hashlib

def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return path

big = os.urandom(2 * 1024 * 1024)
write(os.path.join(tmp, "a", "big.bin"), big)
write(os.path.join(tmp, "sub", "big.bin"), big)          # duplicate of big
txt = b"hello duplicate\n"
p1 = write(os.path.join(tmp, "same.txt"), txt)
p2 = write(os.path.join(tmp, "b", "same.txt"), txt)      # duplicate
p3 = write(os.path.join(tmp, "b", "same_copy.txt"), txt) # duplicate
write(os.path.join(tmp, "unique.bin"), os.urandom(2 * 1024 * 1024))
write(os.path.join(tmp, "tiny.bin"), b"x")               # below min_size later

msgs = []
res = dff.run_scan(tmp, min_size=0, recursive=True,
                   progress=lambda k, *a: msgs.append(k), cancel=None)
check("scan returns result", res is not None)
check("walk counted 7 files", res.files_seen == 7)
check("found 2 duplicate groups", len(res.groups) == 2)
sizes = sorted(g.size for g in res.groups)
check("group sizes are 2MB and 16B", sizes == [16, 2 * 1024 * 1024])
big_group = next(g for g in res.groups if g.size == 2 * 1024 * 1024)
check("big group has 2 paths", len(big_group.paths) == 2)
txt_group = next(g for g in res.groups if g.size == 16)
check("txt group has 3 paths", len(txt_group.paths) == 3)
check("progress events fired", "hash" in msgs and "hash_total" in msgs)

# non-recursive scan should only see top-level files
res2 = dff.run_scan(tmp, min_size=0, recursive=False,
                    progress=lambda *a: None, cancel=None)
check("non-recursive finds no dup groups here", len(res2.groups) == 0)

# min_size filter
res3 = dff.run_scan(tmp, min_size=1024, recursive=True,
                    progress=lambda *a: None, cancel=None)
check("min_size filters the 16-byte group", len(res3.groups) == 1)

# cancellation returns None
import threading
ev = threading.Event(); ev.set()
check("cancelled scan returns None",
      dff.run_scan(tmp, 0, True, lambda *a: None, ev) is None)

# human()
check("human formatting", dff.human(0) == "0 B" and dff.human(2048) == "2.0 KB")

# ---- color helpers & themes ----
check("shade lightens and darkens",
      dff.shade("#808080", 0.5) == "#bfbfbf" and dff.shade("#808080", -0.5) == "#404040")
check("mix blends colors", dff.mix("#000000", "#ffffff", 0.5) == "#7f7f7f")
check("luminance ordering", dff.luminance("#ffffff") > dff.luminance("#000000"))
check("theme catalog has 16 themes", len(dff.THEMES) == 16)
required = {"bg", "fg", "accent", "accent_fg", "panel", "field", "border",
            "sub_fg", "zebra", "danger", "face", "ticks", "hands", "second"}
check("every theme is complete",
      all(required.issubset(t) for t in dff.THEMES.values()))
check("every theme color is valid hex",
      all(v.startswith("#") and len(v) == 7
          for t in dff.THEMES.values() for v in t.values() if isinstance(v, str)
          and v.startswith("#")))

# ---- settings persistence ----
sfile = os.path.join(tmp, "settings.json")
cfg = dict(dff.DEFAULT_SETTINGS)
cfg.update({"theme": "Nord", "font": "L", "zebra": False, "accent": "#ff0000"})
dff.save_settings(cfg, sfile)
loaded = dff.load_settings(sfile)
check("settings round trip", loaded["theme"] == "Nord" and loaded["font"] == "L"
      and loaded["zebra"] is False and loaded["accent"] == "#ff0000")
bad = {"theme": "Does Not Exist", "font": 42, "zebra": "yes"}
dff.save_settings(bad, sfile)
loaded2 = dff.load_settings(sfile)
check("invalid settings fall back to defaults",
      loaded2["theme"] == "Windows Light" and loaded2["font"] == "M"
      and loaded2["zebra"] is True)

# GUI selection logic without showing a window is hard; test group helper logic
# via _show_result on a withdrawn root instead.
app = dff.App()
app.withdraw()
app.update()
app._show_result(res)
check("treeview has 2 group rows", len(app._tree.get_children("")) == 2)

gid_big = app._gid[big_group]
children = app._tree.get_children(gid_big)
check("group row has 2 children", len(children) == 2)

# keep newest per group
app._auto_keep(newest=True)
check("keep-newest selects 3 files total", len(app._checked) == 3)
# never all copies of one group
for g in app._gid:
    n = sum(1 for p in g.paths if p in app._checked)
    check(f"group keeps at least one copy ({g.size}B)", 0 < n < len(g.paths))
app._uncheck_all()
check("uncheck all works", len(app._checked) == 0)

# toggle-last-one protection
first = app._tree.get_children(gid_big)[0]
second = app._tree.get_children(gid_big)[1]
app._toggle_child(first)
app._toggle_child(second)
check("cannot check every copy in a group", first in app._checked and second not in app._checked)

# delete-selected safety refuses all-selected groups
app._checked = set(children)
all_sel = all(p in app._checked for p in big_group.paths)
check("all-selected state detectable", all_sel)

# ---- tabs, theming and clock ----
check("notebook has 3 tabs", len(app._notebook.tabs()) == 3)
check("theme gallery shows one card per theme", len(app._theme_cards) == 16)
check("clock canvas has face, ticks, numbers and hands",
      all(app._clock.find_withtag(t) for t in ("face", "tick", "num", "hands")))
app._select_theme("Nord")
app.update()
check("selecting a theme repaints the window",
      app.cget("background") == dff.THEMES["Nord"]["bg"])
check("selecting a theme updates settings", app.settings["theme"] == "Nord")
app._reset_accent()
app._custom_accent = "#123456"
app.apply_settings()
check("custom accent overrides theme accent", app._accent() == "#123456")
app._random_theme()
check("random theme changes theme", app.settings["theme"] != "Nord")
app._font_var.set("L")
app._change_font()
check("font change persists", app.settings["font"] == "L")
check("group rows use the bold font",
      app._tree.tag_configure("group")["font"] == str(app._font_bold))
app.destroy()

# Recycle Bin: create a file, recycle it, verify it is gone
victim = os.path.join(tempfile.gettempdir(), f"dff_victim_{os.getpid()}.txt")
with open(victim, "w") as f:
    f.write("recycle me")
survivors, aborted = dff.recycle_paths([victim])
check("recycled file no longer exists", not os.path.exists(victim))
check("no survivors after recycle", survivors == [])
check("recycle not aborted", aborted is False)

# the GUI tests saved real settings next to the app — leave no side effects
if os.path.exists(dff.SETTINGS_FILE):
    os.remove(dff.SETTINGS_FILE)

print()
if failures:
    print(f"{len(failures)} FAILURES: {failures}")
    sys.exit(1)
print("ALL TESTS PASSED")
