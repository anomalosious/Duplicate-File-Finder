# Source Code

This folder holds the full source of the Duplicate File Finder. The app is
one file — `DuplicateFileFinder.pyw` — organized top-to-bottom in
independent sections so you can read or modify any part without touching
the rest.

| File | Purpose |
|---|---|
| `DuplicateFileFinder.pyw` | The whole app (double-click to run) |
| `test_core.py` | Core and GUI smoke tests — `python test_core.py` |
| `_launch_demo.py` | Dev helper: `python _launch_demo.py [tab 0-4]` opens the app with sample data for screenshots |
| `settings.json` | Created automatically from your in-app choices |

## Map of `DuplicateFileFinder.pyw`

1. **Color helpers & theme catalog** — `shade`, `mix`, `luminance` and
   `_theme()`, which derives a full 14-color palette from just four base
   colors (background, foreground, accent, accent foreground). All 16
   themes live in the `THEMES` list.
2. **Settings** — `load_settings` / `save_settings`, a tiny validated JSON
   store (`settings.json` next to this file).
3. **Scanning core** — `run_scan()`: walks the tree (junction-loop safe),
   buckets files by size, prunes with a 64 KB partial hash, confirms with a
   full MD5, and returns groups sorted by wasted bytes. No tkinter here, so
   it is unit-testable.
4. **Recycle Bin** — `recycle_paths()` calls the Windows shell API
   (`SHFileOperationW` with `FOF_ALLOWUNDO`), so deletion is reversible.
5. **Cleaner core** — `build_catalog(roots)` returns a strict whitelist of
   cleanable targets and lists known installed browsers from specific
   executable paths, running portable browsers, Store registrations, and
   Windows install records, including Edge, DuckDuckGo, Ecosia, Tor Browser,
   Pale Moon, Waterfox, Opera Air/GX, and other common Chromium/Firefox-family
   browsers. DuckDuckGo and Tor Browser expose cache-only cleaner entries;
   Downloads remains protected. An installed browser with no profile data
   simply previews as zero bytes. `preview_items` is
   read-only; `clean_items` deletes only matched paths, protects Downloads,
   and leaves TEMP subfolders and unlisted AppData folders untouched.
6. **Security core** — the bundled ClamAV engine archive is safely unpacked
   and prewarmed in the background at startup when definitions are available;
   quick, full-disk, and custom file/folder scans are available.
   The engine warms in the background at startup when definitions are present.
   Missing definitions download automatically; older existing definitions are
   used immediately and can be refreshed with the Update definitions button.
   Scans only populate an initially unselected findings list. Quarantine and
   permanent deletion require manually selecting detections and confirming
   the action.
7. **GUI (`App`)** — one notebook, five tabs:
   - `_build_duplicates_tab` — scan controls, results tree with simulated
     checkboxes, selection rules (never delete the last copy of a group).
   - `_build_cleaner_tab` — grouped checklist with safe items pre-checked,
     Preview / Clean / browser-detection refresh buttons, running-browser
     guard, typed-YES confirmation for saved passwords, live free-space
     display, and a log.
   - `_build_security_tab` — ClamAV definition update, quick/full/custom
     scans, selectable detections, quarantine and permanent-delete actions.
     Quick scans check Windows system files, temporary folders, startup/task
     locations, and running program files, while skipping personal Documents
     and Downloads folders. Quick, full, and custom scans count and inspect
     only the configured security extension allowlist. Full scans cover all
     files with listed extensions on selected drives, except for the protected
     `System32/vmfirmwarehcl.dll`; Windows recycle-bin and restore-point trees
     are skipped. Access-denied paths are summarized with a few examples
     instead of generating one log entry per failure. ClamD keeps its signed-PE
     trusted/revoked certificate checks enabled and uses the current ClamAV
     certificate data rather than a hard-coded safe-app or publisher list.
     Lower-confidence PUA/heuristic alerts on files with valid Windows
     Authenticode signatures are suppressed; direct malware-signature matches
     remain reviewable. PUA scanning remains opt-in. ClamD uses a 2–16 worker scan
     pool, warms signatures at startup, and keeps them loaded while the app is
     open. Files are submitted individually to a bounded worker queue for
     parallel file scans and per-file progress. Progress distinguishes
     counting, engine loading, and scanning; it shows scanned / remaining
     counts, plus the active file's name, size, and elapsed seconds. ClamAV
     scans archive contents without an aggregate scan-size or embedded-file
     count limit. Progress totals are counted first. Per-file ClamAV and
     recursion limits still apply where the engine requires them.
   - `_build_themes_tab` + `apply_settings()` — the theming engine. It
     recolors every ttk widget style, the canvas clock, the theme cards and
     the title bar via `DwmSetWindowAttribute`.
   - `_build_clock_tab` + `_tick_clock()` — canvas-drawn analog clock,
     refreshed 10×/second; the second hand sweeps smoothly or ticks.

## How to add a theme

Add one line to the `THEMES` list — everything else (panels, fields,
borders, zebra stripes, clock face) is derived automatically:

```python
_theme("My Theme", "#202020",  # background
                    "#f0f0f0",  # text color
                    "#ff8c42",  # accent
                    "#331303")  # text color on accent
```

## Design notes

- `ttk` uses the `clam` base theme because it can be fully recolored; the
  native `vista` theme cannot.
- Fonts are shared `tkinter.font.Font` objects, so changing the size in the
  Themes tab updates every widget (including the clock) at once.
- The scan runs in a daemon thread and reports through a `queue.Queue`
  polled by the UI, so the window never freezes.
