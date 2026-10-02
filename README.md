# Duplicate File Finder & Cleaner

A free Windows desktop app that finds files with **identical content**,
cleans a narrow set of known temporary files, and offers on-demand malware
scanning through the bundled ClamAV engine.

The desktop interface uses Python's standard library. ClamAV is bundled for
on-demand local scans. Internet is needed to download missing definitions or
when you choose Update definitions. No telemetry; scans and cleanup run
locally.

## Screenshots

All **25 current** screenshots are below. Where an **older** screenshot of
the same screen still exists (from when the app only had Duplicates, Themes,
and Clock), it is shown **directly under** the current one.

### Duplicates — fresh start

Current (five tabs, including Cleaner and Security):

<img src="preview.png" alt="Duplicates tab — fresh start" width="880">

Earlier:

<img src="old%20previews/preview.png" alt="Older Duplicates tab — fresh start" width="880">

### Duplicates — real scan results

Current — 81,326 files scanned, 143 duplicate groups, 1.1 GB recoverable:

<img src="preview1.png" alt="Duplicates tab — scan results" width="880">

Earlier — 83,851 files scanned, 146 duplicate groups, 1.1 GB recoverable:

<img src="old%20previews/preview1.png" alt="Older Duplicates tab — scan results" width="880">

### Cleaner

Preview before cleanup (safe Windows junk pre-checked; personal browser
data stays off):

<img src="preview2.png" alt="Cleaner tab — preview" width="880">

After a cleanup run — log of what was removed, skipped, and freed:

<img src="preview3.png" alt="Cleaner tab — after cleanup" width="880">

### Security (ClamAV)

Ready to scan, engine warm:

<img src="preview4.png" alt="Security tab — ready to scan" width="880">

Custom file scan finished, no detections:

<img src="preview5.png" alt="Security tab — custom file scan, clean" width="880">

Custom folder scan finished, no detections:

<img src="preview6.png" alt="Security tab — custom folder scan, clean" width="880">

Detection listed for review (nothing is deleted until you select it):

<img src="preview7.png" alt="Security tab — detection listed for review" width="880">

### Themes (all 16)

Windows Light (current):

<img src="preview8.png" alt="Themes — Windows Light" width="880">

Earlier Themes tab (same gallery, before Cleaner and Security existed):

<img src="old%20previews/preview2.png" alt="Older Themes tab" width="880">

Windows Dark:

<img src="preview9.png" alt="Themes — Windows Dark" width="880">

Midnight:

<img src="preview10.png" alt="Themes — Midnight" width="880">

Carbon:

<img src="preview11.png" alt="Themes — Carbon" width="880">

Nord:

<img src="preview12.png" alt="Themes — Nord" width="880">

Dracula:

<img src="preview13.png" alt="Themes — Dracula" width="880">

Solarized Dark:

<img src="preview14.png" alt="Themes — Solarized Dark" width="880">

Solarized Light:

<img src="preview15.png" alt="Themes — Solarized Light" width="880">

Forest:

<img src="preview16.png" alt="Themes — Forest" width="880">

Sakura:

<img src="preview17.png" alt="Themes — Sakura" width="880">

Ocean Deep:

<img src="preview18.png" alt="Themes — Ocean Deep" width="880">

Mocha:

<img src="preview19.png" alt="Themes — Mocha" width="880">

Retro Terminal:

<img src="preview20.png" alt="Themes — Retro Terminal" width="880">

Sunset:

<img src="preview21.png" alt="Themes — Sunset" width="880">

Grape Soda:

<img src="preview22.png" alt="Themes — Grape Soda" width="880">

High Contrast:

<img src="preview23.png" alt="Themes — High Contrast" width="880">

### Clock

Current (five tabs):

<img src="preview24.png" alt="Clock tab" width="880">

Earlier:

<img src="old%20previews/preview3.png" alt="Older Clock tab" width="880">

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
- **🧹 Cleaner** — BleachBit-style cleanup for installed Chrome, Edge, Brave,
  Opera variants, Firefox, DuckDuckGo, Ecosia, Tor Browser, Pale Moon,
  Waterfox, Vivaldi and other known browsers plus
  Windows junk: browser **cache**, **cookies**,
  **browsing history**, **tab sessions**, **saved passwords**, **form
  autofill**, temp files, thumbnail cache, recent documents, crash
  dumps/ reports, DirectX shader cache, the Recycle Bin, DNS cache and the
  clipboard. Safety-first design:
  - **Preview** shows exactly what will be removed and how much space it
    frees — before anything is deleted.
  - Only exact, known cache and Windows cleanup paths are touched. Unknown
    AppData folders and Downloads are protected from cleaner operations.
  - Browser entries appear only when a known install path, running portable
    browser, Store package, or installed-app registration is found, including
    Microsoft Store Edge and DuckDuckGo. An installed browser with no profile
    data shows zero-sized items;
    browser files are not cleaned while that browser is running. The
    **Refresh / detect browsers** button rereads the installed-browser list
    and current free space.
  - Free space on the system drive is read from Windows and refreshed after
    cleanup. Recoverable sizes are previewed automatically.
  - Personal-data items (⚠ cookies / history / passwords) are **unchecked
    by default**; safe junk (temp, caches, reports) is pre-checked.
  - Deleting saved passwords requires typing **YES**.
  - If a browser is running, you're asked to close it first (its files are
    locked).
  - "Safe items only" restores the safe selection in one click.
- **🛡 Security** — ClamAV scans of common user/Windows locations without
  scanning all of AppData\Roaming, full scans of mounted local disks
  (optionally including USB/removable disks), and optional custom file/folder
  scans. Potentially unwanted applications (PUA)
  can be included. The bundled ClamAV engine is prepared from the included
  archive. Missing definitions download automatically; older installed
  definitions are used immediately so a scan does not wait on a network
  update. Scans only add detections to an
  initially unselected review list; they never move or delete files. You
  select detections and confirm before quarantining or permanently deleting
  them. The quarantine manager can restore files when their original paths
  are free, and files changed since the scan are skipped. This is an on-demand
  scanner, not real-time protection. The app runs ClamD with a multi-threaded
  scan pool (2–16 workers, based on CPU count), loads signatures in the
  background at startup, and keeps them loaded while the app is open. Files
  are submitted individually to a bounded worker queue, so the scanned /
  remaining counter updates as each file finishes. The progress label also
  shows the active file's name, size, and elapsed seconds. A single file uses
  one worker. Archive scanning remains enabled without app-imposed file-size
  or scan-time caps. ClamAV limit alerts appear as **Incomplete** (not a
  malware verdict) and cannot be selected for deletion or quarantine. Windows
  locations that deny access are reported in the scan error count; scans run
  with the current user's permissions. Scan speed still depends on disk and
  file sizes. ClamAV's signed-executable trust and revoked-certificate checks
  stay enabled and use its updated certificate rules, not an app-name allowlist.
  Lower-confidence PUA/heuristic matches on files Windows verifies as
  Authenticode-signed are suppressed; direct malware-signature matches remain
  visible. PUA scanning is opt-in.
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
| `clamav/` | ClamAV 1.5.4 engine files and compact runtime archive; keep beside `source-code/` |
| `preview.png` … `preview24.png` | Current screenshots (25) |
| `old previews/` | Older screenshots from before Cleaner and Security were added |
| `standalone-scanner/` | Isolated YARA prototype — not used by the desktop app |
