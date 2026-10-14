"""Local SQLite store for Sentinel: accumulated detections, imports, review status, notes and history.

Everything lives in one file (default: data/sentinel.db). Rows are de-duplicated by a fingerprint of their
identifying fields, so re-importing an overlapping ESET export only adds what is new.
"""
import hashlib
import json
import sqlite3
import time
from datetime import datetime, timezone

STATUSES = ('new', 'investigating', 'closed', 'false_positive')
SEVERITIES = ('Critical', 'High', 'Medium', 'Low', 'Unknown')
TEXT_FIELDS = {'threat': 512, 'type': 256, 'cause': 512, 'severity': 16, 'computer': 256, 'user': 256, 'ip': 128,
               'country': 128, 'action': 256, 'resolved': 64, 'file': 2048, 'hash': 128, 'process': 512}
FINGERPRINT_FIELDS = ('threat', 'type', 'computer', 'user', 'ip', 'file', 'hash', 'process')
LIST_COLUMNS = ('id', 't', 'threat', 'type', 'cause', 'severity', 'computer', 'user', 'ip', 'country', 'action', 'resolved',
                'occurrences', 'file', 'hash', 'process', 'geo_status', 'geo_code', 'geo_city', 'status', 'has_note', 'first_seen')
MAX_RAW_BYTES = 32 * 1024
NOTE_LIMIT = 8000

SCHEMA = """
CREATE TABLE IF NOT EXISTS imports (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    imported_at TEXT NOT NULL,
    rows_total INTEGER NOT NULL DEFAULT 0,
    rows_new INTEGER NOT NULL DEFAULT 0,
    rows_updated INTEGER NOT NULL DEFAULT 0,
    rows_duplicate INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY,
    fp TEXT NOT NULL UNIQUE,
    t INTEGER,
    date_raw TEXT,
    threat TEXT, type TEXT, cause TEXT, severity TEXT, computer TEXT, user TEXT, ip TEXT, country TEXT,
    action TEXT, resolved TEXT, occurrences INTEGER NOT NULL DEFAULT 1, file TEXT, hash TEXT, process TEXT,
    raw TEXT, geo TEXT,
    first_seen TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    note TEXT NOT NULL DEFAULT '',
    updated_at TEXT
);
CREATE INDEX IF NOT EXISTS detections_t ON detections(t);
CREATE INDEX IF NOT EXISTS detections_ip ON detections(ip);
CREATE INDEX IF NOT EXISTS detections_status ON detections(status);
CREATE TABLE IF NOT EXISTS seen (
    import_id INTEGER NOT NULL REFERENCES imports(id) ON DELETE CASCADE,
    detection_id INTEGER NOT NULL REFERENCES detections(id) ON DELETE CASCADE,
    PRIMARY KEY (import_id, detection_id)
);
CREATE INDEX IF NOT EXISTS seen_detection ON seen(detection_id);
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY,
    detection_id INTEGER NOT NULL REFERENCES detections(id) ON DELETE CASCADE,
    at TEXT NOT NULL,
    field TEXT NOT NULL,
    old TEXT,
    new TEXT
);
CREATE INDEX IF NOT EXISTS history_detection ON history(detection_id);
"""


def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def connect(path):
    conn = sqlite3.connect(path, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA journal_mode = WAL')
    conn.execute('PRAGMA synchronous = NORMAL')
    conn.executescript(SCHEMA)
    conn.execute('PRAGMA user_version = 1')
    return conn


# ---------------------------------------------------------------------------
# Normalisation of rows sent by the browser
# ---------------------------------------------------------------------------
def clean_row(row):
    """Validate one normalised record from the browser. Returns a dict or raises ValueError."""
    if not isinstance(row, dict):
        raise ValueError('Each row must be an object.')
    out = {}
    for field, limit in TEXT_FIELDS.items():
        value = row.get(field, '')
        out[field] = ('' if value is None else str(value)).strip()[:limit]
    if out['severity'] not in SEVERITIES:
        out['severity'] = 'Unknown'
    t = row.get('t')
    out['t'] = int(t) if isinstance(t, (int, float)) and not isinstance(t, bool) and -2208988800000 < t < 32503680000000 else None
    out['date_raw'] = str(row.get('date_raw', '') or '')[:64]
    occ = row.get('occurrences', 1)
    out['occurrences'] = int(occ) if isinstance(occ, (int, float)) and not isinstance(occ, bool) and 0 < occ < 10 ** 9 else 1
    raw = row.get('raw')
    raw_json = json.dumps(raw, ensure_ascii=False) if isinstance(raw, dict) else '{}'
    out['raw'] = raw_json if len(raw_json.encode('utf-8')) <= MAX_RAW_BYTES else '{}'
    return out


def fingerprint(row):
    when = str(row['t']) if row['t'] is not None else 'raw:' + row['date_raw']
    key = '\x1f'.join([when] + [row[f].lower() for f in FINGERPRINT_FIELDS])
    return hashlib.sha256(key.encode('utf-8')).hexdigest()


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------
def create_import(conn, name):
    cur = conn.execute('INSERT INTO imports (name, imported_at) VALUES (?, ?)', (str(name or 'CSV import')[:255], now_iso()))
    conn.commit()
    return cur.lastrowid


def add_rows(conn, import_id, rows, geo_lookup=None):
    """Insert cleaned rows; returns counts. geo_lookup(list_of_ips) -> {ip: geo_dict} or None."""
    if conn.execute('SELECT 1 FROM imports WHERE id = ?', (import_id,)).fetchone() is None:
        raise LookupError('Import not found.')
    cleaned = [clean_row(r) for r in rows]
    geo = geo_lookup(sorted({r['ip'] for r in cleaned if r['ip']})) if geo_lookup else {}
    stamp = now_iso()
    new = updated = duplicate = 0
    for r in cleaned:
        fp = fingerprint(r)
        existing = conn.execute('SELECT id, occurrences, action, resolved, severity FROM detections WHERE fp = ?', (fp,)).fetchone()
        g = geo.get(r['ip']) if geo else None
        if existing is None:
            cur = conn.execute(
                'INSERT INTO detections (fp, t, date_raw, threat, type, cause, severity, computer, user, ip, country, action, resolved, '
                'occurrences, file, hash, process, raw, geo, first_seen, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (fp, r['t'], r['date_raw'], r['threat'], r['type'], r['cause'], r['severity'], r['computer'], r['user'], r['ip'],
                 r['country'], r['action'], r['resolved'], r['occurrences'], r['file'], r['hash'], r['process'], r['raw'],
                 json.dumps(g) if g else None, stamp, stamp))
            det_id = cur.lastrowid
            new += 1
        else:
            det_id = existing['id']
            # A later export can report more occurrences or a changed resolution for the same event.
            changes = {}
            if r['occurrences'] > existing['occurrences']:
                changes['occurrences'] = r['occurrences']
            for f in ('action', 'resolved', 'severity'):
                if r[f] and r[f] != existing[f] and not (f == 'severity' and r[f] == 'Unknown'):
                    changes[f] = r[f]
            if changes:
                sets = ', '.join(f'{k} = ?' for k in changes)
                conn.execute(f'UPDATE detections SET {sets}, updated_at = ? WHERE id = ?', (*changes.values(), stamp, det_id))
                for k, v in changes.items():
                    if k != 'occurrences':
                        log(conn, det_id, k, existing[k], v, stamp)
                updated += 1
            else:
                duplicate += 1
        conn.execute('INSERT OR IGNORE INTO seen (import_id, detection_id) VALUES (?, ?)', (import_id, det_id))
    conn.execute('UPDATE imports SET rows_total = rows_total + ?, rows_new = rows_new + ?, rows_updated = rows_updated + ?, '
                 'rows_duplicate = rows_duplicate + ? WHERE id = ?', (len(cleaned), new, updated, duplicate, import_id))
    conn.commit()
    return {'received': len(cleaned), 'new': new, 'updated': updated, 'duplicate': duplicate}


def list_imports(conn):
    rows = conn.execute('SELECT i.*, (SELECT COUNT(*) FROM seen s WHERE s.import_id = i.id) AS rows_present FROM imports i ORDER BY i.id DESC').fetchall()
    return [dict(r) for r in rows]


def delete_import(conn, import_id):
    """Remove an import. Detections that no other import contains are deleted with it."""
    if conn.execute('SELECT 1 FROM imports WHERE id = ?', (import_id,)).fetchone() is None:
        raise LookupError('Import not found.')
    cur = conn.execute('DELETE FROM detections WHERE id IN (SELECT detection_id FROM seen WHERE import_id = ?) '
                       'AND id NOT IN (SELECT detection_id FROM seen WHERE import_id != ?)', (import_id, import_id))
    removed = cur.rowcount
    conn.execute('DELETE FROM imports WHERE id = ?', (import_id,))
    conn.commit()
    return removed


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------
def list_detections(conn):
    rows = conn.execute('SELECT id, t, threat, type, cause, severity, computer, user, ip, country, action, resolved, occurrences, '
                        'file, hash, process, geo, status, note != \'\' AS has_note, first_seen FROM detections ORDER BY t DESC').fetchall()
    out = []
    for r in rows:
        g = json.loads(r['geo']) if r['geo'] else {}
        out.append([r['id'], r['t'], r['threat'], r['type'], r['cause'], r['severity'], r['computer'], r['user'], r['ip'], r['country'],
                    r['action'], r['resolved'], r['occurrences'], r['file'], r['hash'], r['process'], g.get('status'),
                    g.get('country_code'), g.get('city'), r['status'], bool(r['has_note']), r['first_seen']])
    return out


def get_detection(conn, det_id):
    r = conn.execute('SELECT * FROM detections WHERE id = ?', (det_id,)).fetchone()
    if r is None:
        return None
    hist = conn.execute('SELECT at, field, old, new FROM history WHERE detection_id = ? ORDER BY id DESC LIMIT 200', (det_id,)).fetchall()
    imports = conn.execute('SELECT i.id, i.name, i.imported_at FROM seen s JOIN imports i ON i.id = s.import_id WHERE s.detection_id = ? '
                           'ORDER BY i.id', (det_id,)).fetchall()
    return {'id': r['id'], 'status': r['status'], 'note': r['note'], 'first_seen': r['first_seen'], 'updated_at': r['updated_at'],
            'raw': json.loads(r['raw'] or '{}'), 'geo': json.loads(r['geo']) if r['geo'] else None,
            'history': [dict(h) for h in hist], 'imports': [dict(i) for i in imports]}


def stats(conn):
    s = conn.execute('SELECT COUNT(*) AS n, MIN(t) AS oldest, MAX(t) AS newest FROM detections').fetchone()
    by_status = {k: 0 for k in STATUSES}
    for r in conn.execute('SELECT status, COUNT(*) AS n FROM detections GROUP BY status'):
        by_status[r['status']] = r['n']
    return {'detections': s['n'], 'oldest': s['oldest'], 'newest': s['newest'], 'by_status': by_status,
            'imports': conn.execute('SELECT COUNT(*) FROM imports').fetchone()[0]}


# ---------------------------------------------------------------------------
# Review workflow
# ---------------------------------------------------------------------------
def log(conn, det_id, field, old, new, stamp=None):
    conn.execute('INSERT INTO history (detection_id, at, field, old, new) VALUES (?, ?, ?, ?, ?)',
                 (det_id, stamp or now_iso(), field, None if old is None else str(old)[:500], None if new is None else str(new)[:500]))


def update_detection(conn, det_id, status=None, note=None):
    r = conn.execute('SELECT status, note FROM detections WHERE id = ?', (det_id,)).fetchone()
    if r is None:
        raise LookupError('Detection not found.')
    stamp = now_iso()
    if status is not None:
        if status not in STATUSES:
            raise ValueError('Unknown status.')
        if status != r['status']:
            conn.execute('UPDATE detections SET status = ?, updated_at = ? WHERE id = ?', (status, stamp, det_id))
            log(conn, det_id, 'status', r['status'], status, stamp)
    if note is not None:
        note = str(note)[:NOTE_LIMIT]
        if note != r['note']:
            conn.execute('UPDATE detections SET note = ?, updated_at = ? WHERE id = ?', (note, stamp, det_id))
            log(conn, det_id, 'note', None, note, stamp)
    conn.commit()
    return get_detection(conn, det_id)


def bulk_status(conn, ids, status):
    if status not in STATUSES:
        raise ValueError('Unknown status.')
    stamp = now_iso()
    changed = 0
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        marks = ','.join('?' * len(chunk))
        rows = conn.execute(f'SELECT id, status FROM detections WHERE id IN ({marks}) AND status != ?', (*chunk, status)).fetchall()
        for r in rows:
            log(conn, r['id'], 'status', r['status'], status, stamp)
        conn.execute(f'UPDATE detections SET status = ?, updated_at = ? WHERE id IN ({marks}) AND status != ?', (status, stamp, *chunk, status))
        changed += len(rows)
    conn.commit()
    return changed


# ---------------------------------------------------------------------------
# Maintenance
# ---------------------------------------------------------------------------
def purge(conn, older_than_days=None, everything=False):
    if everything:
        n = conn.execute('SELECT COUNT(*) FROM detections').fetchone()[0]
        conn.execute('DELETE FROM detections')
        conn.execute('DELETE FROM imports')
    else:
        cutoff = int(time.time() * 1000) - int(older_than_days) * 86400000
        n = conn.execute('DELETE FROM detections WHERE t IS NOT NULL AND t < ?', (cutoff,)).rowcount
        conn.execute('DELETE FROM imports WHERE id NOT IN (SELECT DISTINCT import_id FROM seen)')
    conn.commit()
    conn.execute('VACUUM')
    return n


def public_ips(conn):
    return [r[0] for r in conn.execute("SELECT DISTINCT ip FROM detections WHERE ip != ''")]


def apply_geo(conn, results):
    for ip, g in results.items():
        conn.execute('UPDATE detections SET geo = ? WHERE ip = ?', (json.dumps(g) if g else None, ip))
    conn.commit()


def backup_bytes(conn, tmp_path):
    dest = sqlite3.connect(tmp_path)
    try:
        conn.backup(dest)
    finally:
        dest.close()
    with open(tmp_path, 'rb') as fh:
        return fh.read()
