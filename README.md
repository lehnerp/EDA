# Sentinel — ESET detection dashboard (Flask)

Analyze ESET PROTECT detection exports (CSV) and keep investigating them over time. Every import is added to a local SQLite database, so detections, review status and notes persist between sessions. Everything runs on your machine: no cloud services or external APIs.

## Run

**Windows, quickest:** double-click `start.bat`. The first run creates `.venv` and installs the dependencies; later runs skip that unless `requirements.txt` changes. It then starts Sentinel on waitress and opens your browser. `start.bat setup` only prepares the environment, and `start.bat test` runs the test suites. Set `PORT`, `HOST` or `GEODB_PATH` beforehand to override the defaults.

Manually, with Python 3.10 or newer:

```bash
python -m venv .venv
# Linux / macOS
source .venv/bin/activate
# Windows instead: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. Set `HOST` / `PORT` to change the bind address. For a production WSGI server on localhost:

```bash
waitress-serve --listen=127.0.0.1:5000 app:app
```

To expose this on your internal network, put it behind a reverse proxy with HTTPS and your organization's authentication. Authentication is not bundled. Do not expose an unauthenticated deployment on the public internet. The page uses relative URLs, so it also works under a sub-path (e.g. `https://intranet/sentinel/`). `GET /healthz` reports server and GeoDB status for monitoring.

## Using it

1. **Import** — click *Import CSV* or drop the file anywhere on the page. Columns are matched by name (ESET PROTECT headers such as *Occurred, Computer name, Detection name, Action taken, Resolved, Object, Hash* are recognised); each field shows a sample value from your first rows so you can check the mapping. Mappings are remembered per header layout in this browser. Rows are saved to the local database; detections already stored are recognised and skipped, so you can import overlapping exports (e.g. a weekly "last 30 days" export) without duplicates.
2. **Explore** — four views: *Overview*, *Detections*, *IP & geography*, *Endpoints & users*. Almost everything is clickable: a threat, severity, action, user, computer, IP, country or process applies a filter; a bar in the activity chart zooms to that day. Active filters appear as chips you can remove one by one.
3. **Investigate** — click a table row for the event summary, related-event counts, quick filters, an interpretation of the ESET detection name (platform, family, category, referenced CVEs and a suggested next step) and links to AbuseIPDB, VirusTotal, NVD and ESET. Use ‹ › or the arrow keys to step through events.
4. **Review** — each detection has a review status (*New, Investigating, Closed, False positive*), free-text notes and a change history, all saved in the database. Filter by *Review* status, or mark every row in the current filter at once with *Mark filtered rows as…*.
5. **Manage** — the *Database* view lists imports (delete one to remove the rows only it contained), shows review totals, and offers backup download, GeoDB re-run, purge-older-than-N-days and delete-everything.
6. **Share** — *Export filtered CSV* downloads the current selection in the current sort order; *Report* prints the current view or saves it as PDF.

Keyboard: <kbd>/</kbd> focuses search, <kbd>Esc</kbd> closes dialogs, <kbd>←</kbd>/<kbd>→</kbd> move between events in the detail dialog.

## Dashboard contents

- KPIs: total occurrences, high & critical share, affected computers and users, rows not resolved (Resolved = No / action Retained).
- Detection activity stacked by severity; threat breakdown; severity distribution and action taken.
- Weekday × hour heatmap (your local time) with the busiest slot and the share inside office hours.
- World map with country shading and bubbles, top countries, IP activity.
- User and computer leaderboards; top processes and object types (file extensions / URLs).
- Sortable, paginated detection log (10–100 rows per page).

## Local database

Detections are stored in `data/sentinel.db` (SQLite). Set `SENTINEL_DB` to another path before starting to keep it elsewhere, e.g. on an encrypted drive. Copy or back it up like any file, or use *Download backup* in the Database view (a consistent snapshot, safe while Sentinel runs).

- **De-duplication:** a detection is identified by its time, detection name, type, computer, user, IP, object, hash and process. When a later export reports the same event with more occurrences or a changed action/resolution/severity, the stored row is updated and the change is recorded in its history; your review status and notes are kept.
- **What is stored:** the mapped fields, the original CSV columns of each row, GeoDB results, review status, notes, history and the list of imports. Nothing else.
- **Protect the file:** it contains user names, IP addresses and file paths. Keep `data/` out of shared folders and version control, and restrict access if Sentinel runs on a shared server.
- **Retention:** use *Purge* in the Database view to delete detections older than N days, or *Delete all data* to start over.
- **Fallback:** if the database cannot be opened, imports still work for the open tab only, and the page says so.

## Privacy

**No external APIs, API keys, scraping, or file uploads to intelligence providers.** External links open only when clicked and reveal the selected indicator to that provider. Reputation/verdicts are not fetched into this app. Investigation notes are a labeled, local interpretation of the detection name, not a reputation result.

The CSV is parsed in the browser; the normalized rows are sent only to your own Sentinel server, which stores them in the local SQLite file described above. State-changing API requests are accepted only as same-origin JSON, so other websites cannot write to your database through your browser. The theme and column mappings are kept in browser storage. Demo records are synthetic, generated in the browser, labeled, and never stored.

## Geography

Countries come from a CSV country column or a local GeoDB. Place your MaxMind GeoLite2-City or GeoLite2-Country `.mmdb` file at `data/GeoLite2-City.mmdb`, or set `GEODB_PATH` to its absolute path before starting Flask (`export GEODB_PATH=/path/to/GeoLite2-City.mmdb` on Linux/macOS, `$env:GEODB_PATH="C:\data\GeoLite2-City.mmdb"` in PowerShell). The database is not bundled; supply your licensed copy and keep it up to date. IPs are looked up when rows are stored, and the result is saved with them; *Locate with GeoDB* (or *Re-run GeoDB* in the Database view) refreshes every stored IP after you update the .mmdb file. The reader is opened once and reloaded when the file changes. Missing/invalid databases produce a clear message while keeping CSV countries. Internal/reserved addresses are never geolocated.

The map is country-level, not precise IP geolocation. Every country in the bundled basemap (D3 Graph Gallery world.geojson, Natural Earth boundaries) can be placed, plus common small states such as Singapore, Hong Kong and Malta. Two-letter ISO codes and common spellings (USA, Czech Republic, UK, Turkey…) are normalized. A source-IP column is preferred in automatic mapping; if your export only contains the endpoint IP, endpoint location is not an attacker's origin. Fonts load from Google Fonts, with system-font fallback.

## CSV support

UTF-8, comma/semicolon/tab-separated, quoted/multiline values, up to 25 MB. Dates: ISO 8601 (with or without `T`, `Z`, `UTC` or an offset), `YYYY/MM/DD` and `DD.MM.YYYY [HH:MM[:SS]]`; timestamps without a timezone are read as your local time and shown that way. Ambiguous slash dates such as `03/04/2026` fall back to browser parsing — normalize them to ISO first. Rows with missing/unparsed dates stay in *All time* and are excluded from time filters. Missing severity is Unknown; ESET's *Warning/Information* map to Medium/Low. Occurrence fields weight KPIs, charts and rankings; the table and related-event counts show CSV rows, and invalid/blank occurrences count as one. *Resolved* is displayed as exported. Numeric Status is preserved in raw fields and not interpreted. *Cause* is used as the detection name when *Detection name* is absent. A hash is required for a VirusTotal file link; object URLs are preserved and never resolved to IPs. Exported CSVs neutralize spreadsheet formulas.

## Empty content

Blank/unknown optional fields and raw export values are hidden; literal zero and false remain visible. Optional table columns, filters and KPIs are hidden only when the imported dataset has no usable values for them. Charts and rankings without usable filtered data are hidden; the detection log still shows a no-match result and keeps filtering usable. GeoDB and basemap errors stay visible, with an explanation on the map.

## Development

```
app.py               Flask routes: page, /summary, /geolocate, /healthz and the /api/* database endpoints
store.py             SQLite schema, de-duplication, review workflow, maintenance
static/core.js       DOM-free logic (parsing, normalization, filtering, aggregation, demo data)
static/app.js        Rendering and interaction
static/style.css     Dark/light theme, responsive and print styles
static/world.json    Bundled basemap
tests/               Python (unittest) and Node tests
```

```bash
python -m unittest discover -s tests   # backend + database API
node tests/empty-content.cjs           # frontend core (Node 18+)
```
