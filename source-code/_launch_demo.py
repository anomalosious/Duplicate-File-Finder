# -*- coding: utf-8 -*-
"""Launch the app with demo data, print window coords, self-close."""
import importlib.util
import json
import os
import sys
import time
from importlib.machinery import SourceFileLoader

HERE = os.path.dirname(os.path.abspath(__file__))
loader = SourceFileLoader("dff", os.path.join(HERE, "DuplicateFileFinder.pyw"))
spec = importlib.util.spec_from_loader("dff", loader)
dff = importlib.util.module_from_spec(spec)
sys.modules["dff"] = dff
loader.exec_module(dff)

def G(size, paths, ages):
    return dff.DupGroup(size=size, paths=paths,
                        mtimes={p: time.time() - a for p, a in zip(paths, ages)})

MB = 1024 * 1024
u = os.path.expanduser("~")
groups = [
    G(43 * MB, [
        rf"{u}\Downloads\Setup-Archive-v2.4.1.exe",
        rf"{u}\Downloads\Old\Setup-Archive-v2.4.1.exe",
    ], [86400 * 200, 86400 * 400]),
    G(3.8 * MB, [
        rf"{u}\Pictures\IMG_20240712_093015.jpg",
        rf"{u}\Pictures\Backup\IMG_20240712_093015.jpg",
        rf"{u}\Downloads\IMG_20240712_093015 (1).jpg",
        rf"{u}\OneDrive\Pictures\Camera Roll\IMG_20240712_093015.jpg",
    ], [86400 * 30, 86400 * 29, 86400 * 10, 86400 * 5]),
    G(1.2 * MB, [
        rf"{u}\Documents\Q3-report-final.pdf",
        rf"{u}\Documents\Archive\Q3-report-final.pdf",
        rf"{u}\Desktop\Q3-report-final.pdf",
    ], [86400 * 7, 86400 * 60, 86400 * 3]),
    G(900 * 1024, [
        rf"{u}\Music\summer_mix_2024.mp3",
        rf"{u}\Music\Playlists\summer_mix_2024.mp3",
    ], [86400 * 90, 86400 * 45]),
]
res = dff.ScanResult(root=os.path.join(u, "Downloads"), files_seen=1287, groups=groups)

app = dff.App()
app.geometry("1080x700+60+20")
app.attributes("-topmost", True)
app.lift()
app.focus_force()
if len(sys.argv) > 1 and sys.argv[1].isdigit():
    app._notebook.select(int(sys.argv[1]))
app._show_result(res)
app._toggle_child(groups[0].paths[1])
app._toggle_child(groups[1].paths[1])
app._toggle_child(groups[1].paths[2])
app._flash("Done: 1,287 files scanned · 4 duplicate groups · 52.6 MB recoverable.")
# show off the theming in screenshots (silently — no settings side effect)
app.settings["theme"] = "Nord"
app.apply_settings()

def snap():
    print(json.dumps({"x": app.winfo_rootx(), "y": app.winfo_rooty(),
                      "w": app.winfo_width(), "h": app.winfo_height()}), flush=True)

app.after(1500, snap)
app.after(12000, app.destroy)
app.mainloop()
