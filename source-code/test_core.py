# -*- coding: utf-8 -*-
"""Headless smoke test for DuplicateFileFinder.pyw core logic."""
import importlib.util
import os
import shutil
import sys
import subprocess
import tempfile
import zipfile
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

tmp = tempfile.mkdtemp(prefix="dff_test_", dir=HERE)
# Keep GUI settings isolated so the smoke test never reads or removes the
# user's real settings.json beside the application.
dff.SETTINGS_FILE = os.path.join(tmp, "test_app_settings.json")

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
check("notebook has 5 tabs", len(app._notebook.tabs()) == 5)
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

# ---- cleaner GUI wiring (checkbox logic only, never cleans) ----------------
check("cleaner tree lists every catalog item",
      sum(len(app._clean_tree.get_children(c))
          for c in app._clean_tree.get_children("")) == len(app._clean_catalog))
check("cleaner pre-checks exactly the safe items",
      app._clean_checked == dff.SAFE_DEFAULT_CLEANERS)
app._cleaner_select(False)
check("cleaner uncheck-all works", not app._clean_checked)
app._cleaner_select(True)
check("cleaner safe-only restores safe defaults",
      app._clean_checked == dff.SAFE_DEFAULT_CLEANERS)

check("security tab has ClamAV controls and a review table",
      hasattr(app, "_security_scan_btn") and
      len(app._security_tree["columns"]) == 5)
check("security tab offers quick, full, and custom scans",
      hasattr(app, "_security_quick_btn") and
      hasattr(app, "_security_custom_folder_btn") and
      hasattr(app, "_security_custom_file_btn"))
real_security_dir = dff.security_data_dir
dff.security_data_dir = lambda: os.path.join(tmp, "security-manager")
manager = app._security_manage_quarantine()
app.update()
check("quarantine manager opens from the Security tab",
      manager.winfo_exists() and len(manager.winfo_children()) > 0)
manager.destroy()
dff.security_data_dir = real_security_dir

security_candidate = write(os.path.join(tmp, "security-review", "sample.bin"),
                           b"harmless test file")
app._security_display_findings([{
    "path": security_candidate, "signature": "Test.Detection",
    "status": "Detected"}])
check("new security detections remain unselected",
      not app._security_checked and app._security_tree.set("0", "check") == "")
app._security_toggle("0")
original_askyesno = dff.messagebox.askyesno
try:
    dff.messagebox.askyesno = lambda *args, **kwargs: False
    app._security_action("delete")
finally:
    dff.messagebox.askyesno = original_askyesno
check("declining delete confirmation keeps selected detection in place",
      os.path.isfile(security_candidate) and "0" in app._security_checked)

app.destroy()

# The real Shell recycle-bin integration was verified manually. Keep ordinary
# test runs away from the user's Recycle Bin unless explicitly requested.
if os.environ.get("DFF_TEST_REAL_RECYCLE") == "1":
    victim = os.path.join(tmp, f"dff_victim_{os.getpid()}.txt")
    with open(victim, "w") as f:
        f.write("recycle me")
    survivors, aborted = dff.recycle_paths([victim])
    check("recycled file no longer exists", not os.path.exists(victim))
    check("no survivors after recycle", survivors == [])
    check("recycle not aborted", aborted is False)

# The GUI uses a settings path inside the test sandbox.
if os.path.exists(dff.SETTINGS_FILE):
    os.remove(dff.SETTINGS_FILE)

# ---- Cleaner: tested ONLY against a fake sandbox --------------------------
# The user's real browser history and cookies are NEVER touched by these
# tests: the catalog roots are redirected into a temp directory, so every
# glob in every item resolves inside the sandbox.
sb = {"TEMP": os.path.join(tmp, "sandbox", "Temp"),
      "WTEMP": os.path.join(tmp, "sandbox", "WinTemp"),
      "LOCAL": os.path.join(tmp, "sandbox", "LocalAppData"),
      "APPDATA": os.path.join(tmp, "sandbox", "Roaming")}
for d in sb.values():
    os.makedirs(d, exist_ok=True)
S_LOC, S_APP = sb["LOCAL"], sb["APPDATA"]

def w(path, size=100):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(b"x" * size)
    return path

chr_prof = os.path.join(S_LOC, "Google", "Chrome", "User Data", "Default")
junk = w(os.path.join(chr_prof, "Cache", "junk_1"), 500)
cookies = w(os.path.join(chr_prof, "Network", "Cookies"), 200)
history = w(os.path.join(chr_prof, "History"), 300)
bookmarks = w(os.path.join(chr_prof, "Bookmarks"), 50)     # must survive
ff_prof = os.path.join(S_APP, "Mozilla", "Firefox", "Profiles", "abc.default")
ff_cookies = w(os.path.join(ff_prof, "cookies.sqlite"), 400)
places = w(os.path.join(ff_prof, "places.sqlite"), 600)    # must survive
prefs = w(os.path.join(ff_prof, "prefs.js"), 70)           # must survive
leftover = w(os.path.join(sb["TEMP"], "leftover.tmp"), 1000)
temp_personal = w(os.path.join(sb["TEMP"], "my-important-folder", "keep.txt"), 123)
appdata_personal = w(os.path.join(S_APP, "My Custom App", "keep.dat"), 234)
w(os.path.join(S_LOC, "Microsoft", "Windows", "Explorer",
               "thumbcache_001.db"), 250)
w(os.path.join(S_LOC, "CrashDumps", "app.dmp"), 800)

cat = dff.build_catalog(roots=sb, only_installed=False)
check("cleaner catalog has all items", len(cat) == 39)
check("catalog covers Chrome, Edge, Brave, Opera, Firefox and Windows",
      {"🌐 Google Chrome", "🌐 Microsoft Edge", "🌐 Brave", "🌐 Opera",
       "🦊 Firefox", "🪟 Windows system"} ==
      {i.category for i in cat})

real_browser_check = dff.browser_is_installed
dff.browser_is_installed = lambda *_args: False
leftover_profiles_only = dff.build_catalog(roots=sb, only_installed=True)
dff.browser_is_installed = real_browser_check
check("browser profile leftovers alone do not create cleaner entries",
      not any(i.category.startswith(("🌐", "🦊"))
              for i in leftover_profiles_only))

installed_roots = dict(sb)
installed_roots["LOCAL"] = os.path.join(tmp, "installed-only", "LocalAppData")
installed_roots["APPDATA"] = os.path.join(tmp, "installed-only", "Roaming")
chrome_exe = w(os.path.join(installed_roots["LOCAL"], "Google", "Chrome",
                            "Application", "chrome.exe"), 1)
installed_without_profile = dff.build_catalog(
    roots=installed_roots, only_installed=True)
check("installed browser is listed before it has a profile",
      os.path.isfile(chrome_exe) and
      any(i.category == "🌐 Google Chrome" for i in installed_without_profile))

# SAFETY: every pattern of every item must live inside the sandbox
roots_n = [os.path.normcase(os.path.normpath(v)) for v in sb.values()]
def inside(p):
    np = os.path.normcase(os.path.normpath(p))
    return any(np == rv or np.startswith(rv + os.sep) for rv in roots_n)
escapes = [p for it in cat for group in (it.contents, it.dirs, it.file_globs)
           for p in group if not inside(p)]
check("no cleaner pattern points outside the sandbox", not escapes)
check("special items (recyclebin/dns/clipboard) declare no paths",
      all(not (it.contents or it.dirs or it.file_globs)
          for it in cat if it.special))
check("history/cookies/passwords are destructive and off by default",
      all(by_id_default.destructive for by_id_default in
          (next(i for i in cat if i.cid == "chrome.exe-history"),
           next(i for i in cat if i.cid == "chrome.exe-cookies"),
           next(i for i in cat if i.cid == "chrome.exe-passwords"),
           next(i for i in cat if i.cid == "firefox.exe-history")))
      and not ({"chrome.exe-history", "chrome.exe-cookies",
                "chrome.exe-passwords", "firefox.exe-history",
                "msedge.exe-history"} & dff.SAFE_DEFAULT_CLEANERS))

# preview must be read-only
sizes = dff.preview_items(cat)
check("preview finds cache file", sizes["chrome.exe-cache"]["count"] == 1
      and sizes["chrome.exe-cache"]["bytes"] == 500)
check("preview finds temp + thumbs + dump",
      sizes["temp"]["count"] == 1 and sizes["thumbs"]["count"] == 1
      and sizes["dumps"]["count"] == 1)
check("preview is read-only", os.path.exists(cookies))

# clean a chosen subset inside the sandbox
sel = [next(i for i in cat if i.cid == cid) for cid in
       ("temp", "chrome.exe-cache", "chrome.exe-cookies",
        "chrome.exe-history", "firefox.exe-cookies")]
logs = []
totals = dff.clean_items(sel, lambda m: logs.append(m))
check("clean logs every item", len(logs) == len(sel))
check("clean removed exactly the 5 junk files", totals["removed"] == 5)
check("clean freed real bytes", totals["freed"] == 500 + 200 + 300 + 400 + 1000)
check("selected data is gone",
      not any(os.path.exists(p) for p in (cookies, history, ff_cookies, junk)))
check("unselected data survives (Bookmarks, prefs.js, places.sqlite)",
      all(os.path.exists(p) for p in (bookmarks, prefs, places)))
check("browser profile folders are kept",
      os.path.isdir(chr_prof) and os.path.isdir(ff_prof))
check("contents-wipe keeps the folder itself",
      os.path.isdir(sb["TEMP"]) and not os.path.exists(leftover))
check("temp cleaner leaves user-created subfolders untouched",
      os.path.isfile(temp_personal))
check("unlisted AppData folders survive cleanup",
      os.path.isfile(appdata_personal))

check("blockers list is empty for non-running exes",
      dff.blockers_for([dff.CleanItem("x", "c", "n", "d",
                                      browser_exes=("not_running_42.exe",))])
      == [])

# Downloads are protected even if accidentally included in a cleaner item.
# Test with a fake Downloads folder, never the real one.
fake_downloads = os.path.join(tmp, "sandbox", "fake-user", "Downloads")
downloaded_file = w(os.path.join(fake_downloads, "keep.exe"), 88)
dff.PROTECTED.append(fake_downloads)
download_item = dff.CleanItem("fake-downloads", "test", "Downloads", "",
                              contents=(fake_downloads,))
download_preview = dff.preview_items([download_item])
download_clean = dff.clean_items([download_item], lambda _line: None)
dff.PROTECTED.pop()
check("Downloads preview is zero and protected files survive",
      download_preview["fake-downloads"]["bytes"] == 0 and
      download_clean["removed"] == 0 and os.path.isfile(downloaded_file))

usage = dff.current_disk_usage()
check("current disk usage returns real non-empty values",
      usage is not None and usage["total"] > 0 and usage["free"] >= 0)
findings, stats = dff.parse_clamav_output([
    r"C:\Users\Test User\Downloads\bad file.exe: Win.Test.Malware FOUND",
    r"C:\Users\Test User\Downloads\clean.txt: OK",
    "Scanned files: 25", "Infected files: 1", "Total errors: 2"])
check("ClamAV parser extracts detection and scan statistics",
      len(findings) == 1 and findings[0]["signature"] == "Win.Test.Malware" and
      stats == {"scanned": 25, "infected": 1, "errors": 2})
freshclam_cfg = os.path.join(tmp, "freshclam", "freshclam.conf")
dff.write_freshclam_config(
    os.path.dirname(freshclam_cfg), freshclam_cfg,
    os.path.join(tmp, "clamav-certs"))
with open(freshclam_cfg, encoding="utf-8") as f:
    freshclam_text = f.read()
check("FreshClam config writes timeout options before closing the file",
      "ConnectTimeout 30" in freshclam_text and
      "ReceiveTimeout 60" in freshclam_text and
      "CVDCertsDirectory" in freshclam_text)

# Verify the bundled ClamAV binary itself using a harmless, generated HDB
# signature that matches only a disposable test file (no malware sample or
# downloaded signatures needed).
engine_dir = dff.find_clamav_dir()
custom_db = os.path.join(tmp, "custom-clamav-db")
os.makedirs(custom_db)
sample_bytes = b"harmless ClamAV integration test sample"
sample_path = write(os.path.join(tmp, "clamav_sample.txt"), sample_bytes)
sample_hash = hashlib.md5(sample_bytes, usedforsecurity=False).hexdigest()
with open(os.path.join(custom_db, "test.hdb"), "w", encoding="ascii") as f:
    f.write(f"{sample_hash}:{len(sample_bytes)}:Codex.Test.Generic\n")
clam_test = subprocess.run(
    [os.path.join(engine_dir, "clamscan.exe"), f"--database={custom_db}",
     "--infected", sample_path], cwd=engine_dir, capture_output=True,
    text=True, errors="replace")
check("bundled ClamAV engine detects a harmless custom test signature",
      clam_test.returncode == 1 and "Codex.Test.Generic" in
      clam_test.stdout + clam_test.stderr and "FOUND" in
      clam_test.stdout + clam_test.stderr)

# Exercise the ZIP-only release layout and its on-demand safe extraction.
bundle_root = os.path.join(tmp, "bundle")
bundle_source = os.path.join(bundle_root, "source-code")
os.makedirs(bundle_source)
bundle_zip = os.path.join(bundle_root, "clamav", "clamav-9.9.win.x64.zip")
os.makedirs(os.path.dirname(bundle_zip))
with zipfile.ZipFile(bundle_zip, "w") as zf:
    zf.writestr("clamav-9.9.win.x64/clamscan.exe", b"scanner")
    zf.writestr("clamav-9.9.win.x64/freshclam.exe", b"updater")
    zf.writestr("clamav-9.9.win.x64/libclamav.dll", b"library")
    zf.writestr("clamav-9.9.win.x64/certs/clamav.crt", b"certificate")
    zf.writestr("clamav-9.9.win.x64/UserManual/ignored.html", b"ignored")
old_app_dir = dff.APP_DIR
old_localappdata = os.environ.get("LOCALAPPDATA")
dff.APP_DIR = bundle_source
os.environ["LOCALAPPDATA"] = os.path.join(tmp, "local-appdata")
try:
    extracted_engine = dff.find_clamav_dir(prepare=True)
finally:
    dff.APP_DIR = old_app_dir
    if old_localappdata is None:
        os.environ.pop("LOCALAPPDATA", None)
    else:
        os.environ["LOCALAPPDATA"] = old_localappdata
check("release ClamAV archive is safely extracted on demand",
      extracted_engine is not None and
      os.path.isfile(os.path.join(extracted_engine, "clamscan.exe")) and
      os.path.isfile(os.path.join(extracted_engine, "certs", "clamav.crt")) and
      not os.path.exists(os.path.join(extracted_engine, "UserManual")))

security_dir = os.path.join(tmp, "security")
flagged = w(os.path.join(tmp, "sandbox", "flagged_sample.bin"), 99)
moved, move_errors = dff.quarantine_files([flagged], security_dir)
manifest = os.path.join(security_dir, "quarantine-manifest.json")
check("quarantine moves selected files and records the original path",
      not os.path.exists(flagged) and len(moved) == 1 and not move_errors and
      os.path.isfile(moved[0]["quarantined_path"]) and os.path.isfile(manifest))
restored, restore_errors = dff.restore_quarantined_files(
    security_dir, [moved[0]["quarantined_path"]])
check("quarantined file can be restored to its original location",
      len(restored) == 1 and not restore_errors and os.path.isfile(flagged))
flagged2 = w(os.path.join(tmp, "sandbox", "delete_sample.bin"), 77)
expected_identity = dff.file_identity(flagged2)
with open(flagged2, "wb") as f:
    f.write(b"y" * 78)
replaced, replacement_errors = dff.delete_detected_files(
    [flagged2], expected={os.path.normcase(os.path.abspath(flagged2)):
                          expected_identity})
check("security actions refuse a file changed since the scan",
      not replaced and replacement_errors and os.path.isfile(flagged2))
deleted, delete_errors = dff.delete_detected_files(
    [flagged2])
check("permanent deletion only processes selected regular files",
      deleted == [flagged2] and not delete_errors and not os.path.exists(flagged2))

shutil.rmtree(tmp)

print()
if failures:
    print(f"{len(failures)} FAILURES: {failures}")
    sys.exit(1)
print("ALL TESTS PASSED")
