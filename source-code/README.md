# Source Code

This folder holds the full source of the Duplicate File Finder. The app is
one file — `DuplicateFileFinder.pyw` — organized top-to-bottom in
independent sections so you can read or modify any part without touching
the rest.

| File | Purpose |
|---|---|
| `DuplicateFileFinder.pyw` | The whole app (double-click to run) |
| `test_core.py` | Headless test suite — `python test_core.py` (38 checks) |
| `_launch_demo.py` | Dev helper: `python _launch_demo.py [tab 0/1/2]` opens the app with sample data for screenshots |
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
5. **GUI (`App`)** — one notebook, three tabs:
   - `_build_duplicates_tab` — scan controls, results tree with simulated
     checkboxes, selection rules (never delete the last copy of a group).
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
