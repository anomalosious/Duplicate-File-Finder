# Duplicate File Finder & Cleaner

A free, no-install Windows desktop app that finds files with **identical
content** (photos saved twice, downloads repeated, backups copied around)
and lets you remove the extra copies safely to the **Recycle Bin** — plus a
fully themeable UI and a built-in analog clock.

Pure Python standard library — no dependencies, nothing to install, no
telemetry, all local.

## Screenshots

**Real scan of a Downloads folder — 83,851 files scanned, 146 duplicate
groups, 1.1 GB recoverable:**

![Real scan results](preview1.png)

**Fresh start** | **Theme gallery (16 themes + options)**

![Fresh start](preview.png) 

**Themes**

![Themes tab](preview2.png)

**Built-in analog clock (12-hour, smooth second hand)**

![Clock tab](preview3.png)

## Run it

Double-click **`Run Duplicate Finder.bat`** (or
`source-code\DuplicateFileFinder.pyw` directly if `.pyw` is associated with
Python).

## How to use

1. Pick a folder (defaults to your Downloads) and press **🔍 Scan**.
2. Groups are listed **biggest wasted space first**. Each row shows every
   copy with its size, modified date, and folder.
3. Tick **Delete?** on the copies you want to remove — or use
   **Keep newest / Keep oldest per group** to mark everything in one click.
   Clicking a group header marks all copies of that group except the newest.
4. Press **Move N files (X MB) to Recycle Bin**. Everything is recoverable
   from the Recycle Bin, and the app refuses to delete the last remaining
   copy of any group.

Extras: **Save report…** exports a CSV (Excel-friendly), **Open location**
opens Explorer with the file highlighted, and **Stop** cancels a scan.
"Ignore files smaller than" (default 1 MB) keeps scans fast — set it to 0
to check every file.

## Tabs

- **🗂 Duplicates** — the scanner described above.
- **🎨 Themes** — 16 built-in themes (Nord, Dracula, Solarized, Retro
  Terminal, High Contrast and more), custom accent color picker, four font
  sizes, zebra-striped rows, colorful title bar on Windows 11, random theme
  button, live preview, and a reset-to-defaults button. Your choices are
  saved to `settings.json` and restored on the next launch.
- **🕒 Clock** — a big theme-aware analog clock with a smooth sweeping
  second hand, a 12-hour digital caption (AM/PM, never military time) and
  the date, plus toggles for smooth/ticking seconds, date visibility and
  always-on-top.

## How it detects duplicates

Two files are duplicates only if their **content hashes match exactly**
(size check → 64 KB partial hash → full MD5). Renamed or moved copies are
still found; files that merely have the same name are not.

## Files

| File | Purpose |
|---|---|
| `Run Duplicate Finder.bat` | Double-click launcher |
| `source-code/` | All source code — see `source-code/README.md` |
| `preview*.png` | Screenshots of the app in action |
