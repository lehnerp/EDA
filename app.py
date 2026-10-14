"""Sentinel: Flask-hosted ESET detection analysis with a local SQLite case database.

The browser parses the CSV, then stores normalised rows in a local SQLite file (data/sentinel.db by default)
so investigations continue across sessions. Detection-name interpretation and IP geolocation run locally.
No external APIs are called.
"""
import io
import ipaddress
import os
import re
import tempfile
import threading
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlsplit

from flask import Flask, g, jsonify, render_template, request, send_file

import store

BASE = Path(__file__).parent
SMALL_LIMIT = 64 * 1024
IMPORT_LIMIT = 16 * 1024 * 1024

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = IMPORT_LIMIT
app.config['GEODB_PATH'] = os.environ.get('GEODB_PATH', str(BASE / 'data' / 'GeoLite2-City.mmdb'))
app.config['DB_PATH'] = os.environ.get('SENTINEL_DB', str(BASE / 'data' / 'sentinel.db'))

# ---------------------------------------------------------------------------
# Detection-name interpretation (local, heuristic; never a reputation verdict)
# ---------------------------------------------------------------------------
PLATFORMS = {
    'win32': '32-bit Windows program', 'win64': '64-bit Windows program', 'msil': '.NET (MSIL) program', 'js': 'JavaScript',
    'html': 'HTML page or attachment', 'vba': 'Office document macro (VBA)', 'vbs': 'VBScript', 'powershell': 'PowerShell script',
    'bat': 'Windows batch script', 'lnk': 'Windows shortcut (.lnk)', 'pdf': 'PDF document', 'doc': 'Word document', 'rtf': 'RTF document',
    'android': 'Android app', 'linux': 'Linux program', 'osx': 'macOS program', 'macos': 'macOS program', 'java': 'Java program',
    'python': 'Python script', 'php': 'PHP script', 'asp': 'ASP web script', 'swf': 'Flash file', 'nsis': 'NSIS installer',
    'autoit': 'AutoIt script', 'hta': 'HTML application (HTA)', 'iso': 'Disk image', 'zip': 'ZIP archive', 'ms word': 'Word document',
}
# (keyword regex, category, explanation, suggested next step) — first match wins, so specific entries come first.
CATEGORIES = [
    (r'filecoder|ransom', 'Ransomware',
     'The detection name suggests ransomware, which can encrypt data or disrupt access.',
     'Isolate the endpoint, check whether files were encrypted, and confirm backups are intact.'),
    (r'phish', 'Phishing',
     'The detection name suggests phishing: a page or message designed to capture credentials or mislead the user.',
     'Ask whether the user entered credentials; if so, reset the password and review sign-in activity.'),
    (r'brute', 'Brute-force attack',
     'The detection name suggests a brute-force attempt: repeated logins trying to guess credentials, often against RDP or SMB.',
     'Check whether the targeted service needs to be reachable and enforce account lockout and MFA.'),
    (r'botnet|cnc|c&c', 'Botnet communication',
     'The detection name suggests communication with a botnet command-and-control server.',
     'Treat the endpoint as possibly compromised: scan it fully and review which process opened the connection.'),
    (r'exploit|cve-\d|eternalblue', 'Exploit',
     'The detection name suggests an exploit: an attempt to take advantage of a software vulnerability.',
     'Confirm the affected software is patched for the referenced vulnerability.'),
    (r'coinminer|miner', 'Cryptocurrency miner',
     'The detection name suggests a cryptocurrency miner, which uses the computer\'s resources without benefit to the organisation.',
     'Find how the miner was installed; miners often arrive bundled with other unwanted software.'),
    (r'spy|psw|keylog|stealer|agenttesla|formbook|lokibot|redline', 'Spyware / information stealer',
     'The detection name suggests spyware or an information stealer that may collect passwords, keystrokes or files.',
     'Assume credentials on the endpoint may be exposed and rotate them if the threat ran.'),
    (r'downloader|dropper', 'Downloader / dropper',
     'The detection name suggests a downloader or dropper, which fetches or unpacks further malware.',
     'Check for follow-up detections on the same computer around the same time.'),
    (r'backdoor|\brat\b|remoteadmin', 'Backdoor / remote access',
     'The detection name suggests a backdoor or remote-access tool that may let someone control the computer.',
     'Review network connections from the endpoint and consider reimaging if the threat ran.'),
    (r'rootkit|bootkit', 'Rootkit', 'The detection name suggests a rootkit that hides itself or other software from the system.',
     'Run an offline scan; rootkits can survive normal clean-up.'),
    (r'worm', 'Worm', 'The detection name suggests a worm that can spread to other computers on its own.',
     'Check other endpoints on the same network segment for the same detection.'),
    (r'adware', 'Adware', 'The detection name suggests adware that displays unwanted advertising.',
     'Remove the bundled software and review how it was installed.'),
    (r'potentially unwanted|\bpua\b', 'Potentially unwanted application',
     'The detection name suggests a potentially unwanted application. Review its purpose and installation context.',
     'Decide whether the application is allowed by policy; ESET can exclude approved PUAs.'),
    (r'potentially unsafe', 'Potentially unsafe application',
     'The detection name suggests a potentially unsafe application: legitimate software that can be misused, such as a remote-admin or password tool.',
     'Confirm whether an administrator installed it intentionally.'),
    (r'attack|incoming|network|scan', 'Network attack',
     'The detection name suggests a network-related event. Review the source/destination context before attributing activity to this IP.',
     'Check whether the targeted port or service should be exposed, and whether the source repeats across endpoints.'),
    (r'trojan|agent|kryptik|generik|generic', 'Trojan',
     'The detection name suggests a trojan: software that may perform unwanted actions while appearing legitimate.',
     'Check whether the file was executed and where it came from (download, e-mail, removable media).'),
]
CATEGORY_WORDS = {'phishing', 'exploit', 'trojandownloader', 'trojandropper', 'spy', 'psw', 'filecoder', 'ransom', 'kryptik', 'coinminer',
                  'adware', 'backdoor', 'rootkit', 'pua', 'trojanclicker', 'trojanproxy', 'packed', 'riskware', 'hacktool'}
CVE_RE = re.compile(r'CVE-(\d{4})-(\d{4,7})', re.IGNORECASE)
HASH_RE = re.compile(r'(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})')


def interpret_detection(name):
    """Split an ESET-style name (Platform/Family.Variant suffix) and attach a plain-language category."""
    result = {'platform': None, 'family': None, 'variant': None, 'category': None,
              'explanation': 'Review the ESET detection name, action and endpoint context to understand this event.', 'next_step': None,
              'cves': sorted({f'CVE-{y}-{n}' for y, n in CVE_RE.findall(name)})}
    lowered = name.lower()
    for pattern, category, explanation, step in CATEGORIES:
        if re.search(pattern, lowered):
            result.update(category=category, explanation=explanation, next_step=step)
            break
    match = re.match(r'^([A-Za-z0-9 ]{1,20})/([^\s]+)', name.strip())
    if match:
        result['platform'] = PLATFORMS.get(match.group(1).lower(), match.group(1))
        parts = [p for p in CVE_RE.sub('', match.group(2)).split('.') if p]
        if len(parts) > 1 and re.fullmatch(r'[A-Z]{1,4}|\d+|Gen|Generic', parts[-1]):
            result['variant'] = parts.pop()
        if parts:
            family = parts[1] if parts[0].lower() in CATEGORY_WORDS and len(parts) > 1 else parts[0]
            if family.lower() not in CATEGORY_WORDS | {'agent', 'generic', 'generik'}:
                result['family'] = family
    return result


@app.get('/')
def index():
    return render_template('index.html')


@app.get('/healthz')
def healthz():
    path = Path(app.config['GEODB_PATH'])
    geodb = {'configured': path.is_file()}
    if geodb['configured']:
        try:
            meta = _geodb_reader().metadata()
            geodb.update(type=meta.database_type, build_epoch=meta.build_epoch)
        except Exception:  # noqa: BLE001 - report, don't crash a health check
            geodb.update(error='Database could not be opened.')
    try:
        database = {'ok': True, **store.stats(db())}
    except Exception:  # noqa: BLE001
        database = {'ok': False, 'error': 'Database could not be opened.'}
    return jsonify(status='ok', geodb=geodb, database=database)


@app.post('/summary')
def summary():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error='Expected a JSON object.'), 400
    detection = str(payload.get('threat', '') or 'Unknown detection').strip()[:512]
    ip = str(payload.get('ip', '')).strip()[:128]
    file_hash = str(payload.get('hash', '')).strip().lower()[:128]
    name = str(payload.get('file', '')).strip()[:1024]
    links = []
    scope = 'Missing or invalid IP address'
    try:
        address = ipaddress.ip_address(ip)
        scope = 'Public IP' if address.is_global else 'Internal / reserved IP'
        if address.is_global:
            links += [dict(label='Check IP on AbuseIPDB', url='https://www.abuseipdb.com/check/' + quote(str(address), safe='')),
                      dict(label='View IP on VirusTotal', url='https://www.virustotal.com/gui/ip-address/' + quote(str(address), safe=''))]
    except ValueError:
        pass
    valid_hash = bool(HASH_RE.fullmatch(file_hash))
    if valid_hash:
        links.append(dict(label='View file hash on VirusTotal', url='https://www.virustotal.com/gui/file/' + file_hash))
    known = detection.lower() != 'unknown detection'
    info = interpret_detection(detection) if known else interpret_detection('')
    if known:
        links.append(dict(label='Search ESET for this detection', url='https://www.google.com/search?q=' + quote('site:eset.com ' + detection, safe='')))
        for cve in info['cves'][:3]:
            links.append(dict(label=f'View {cve} on NVD', url='https://nvd.nist.gov/vuln/detail/' + quote(cve, safe='-')))
    explanation = info['explanation'] + (' ' + info['next_step'] if info['next_step'] else '')
    return jsonify(scope=scope, explanation=explanation, category=info['category'], platform=info['platform'],
                   family=info['family'], variant=info['variant'], cves=info['cves'],
                   provenance='Interpretation of the CSV detection name; external reputation has not been retrieved.',
                   hash_valid=valid_hash, file=name, links=links)


# ---------------------------------------------------------------------------
# Local GeoDB
# ---------------------------------------------------------------------------
_reader_lock = threading.Lock()
_reader_cache = {'key': None, 'reader': None}


def _geodb_reader():
    """Open the MMDB once and reuse it until the path or file changes."""
    import geoip2.database
    path = app.config['GEODB_PATH']
    try:
        stat = os.stat(path)
        key = (path, stat.st_mtime_ns, stat.st_size, geoip2.database.Reader)
    except OSError:
        key = (path, None, None, geoip2.database.Reader)
    with _reader_lock:
        if _reader_cache['key'] != key:
            if _reader_cache['reader'] is not None:
                try:
                    _reader_cache['reader'].close()
                except Exception:  # noqa: BLE001
                    pass
            _reader_cache.update(key=key, reader=geoip2.database.Reader(path))
        return _reader_cache['reader']


def lookup_ips(ips):
    """Classify and geolocate IPs with the local MMDB. Returns (results, error_or_None)."""
    results, public = {}, []
    for value in dict.fromkeys(ips):
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError:
            results[value] = {'status': 'invalid', 'country': None}
            continue
        if not address.is_global:
            results[value] = {'status': 'internal', 'country': 'Internal network'}
        else:
            public.append((value, str(address)))
    if not public:
        return results, None
    if not Path(app.config['GEODB_PATH']).is_file():
        return results, 'GeoDB not configured. Set GEODB_PATH to your local GeoLite2-City or Country .mmdb file.'
    try:
        import geoip2.errors
        reader = _geodb_reader()
        db_type = reader.metadata().database_type
        if 'City' not in db_type and 'Country' not in db_type:
            return results, 'Use a City or Country MMDB database.'
        for original, address in public:
            try:
                record = reader.city(address) if 'City' in db_type else reader.country(address)
                result = {'status': 'located' if record.country.iso_code else 'not_found',
                          'country': record.country.name, 'country_code': record.country.iso_code, 'source': 'Local GeoDB'}
                if 'City' in db_type:
                    result.update(city=record.city.name, latitude=record.location.latitude,
                                  longitude=record.location.longitude, accuracy_radius_km=record.location.accuracy_radius)
                results[original] = result
            except geoip2.errors.AddressNotFoundError:
                results[original] = {'status': 'not_found', 'country': None}
    except (ImportError, OSError, ValueError):
        return results, 'Could not read GeoDB. Check the file and installed requirements.'
    except Exception:  # noqa: BLE001
        app.logger.warning('GeoDB lookup failed; database unavailable or invalid.')
        return results, 'GeoDB lookup failed. Check that the database is a valid City or Country MMDB.'
    return results, None


@app.post('/geolocate')
def geolocate():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get('ips'), list):
        return jsonify(error='Expected an ips array.'), 400
    ips = payload['ips']
    if len(ips) > 500 or any(not isinstance(ip, str) or len(ip) > 128 for ip in ips):
        return jsonify(error='Send up to 500 IP address strings per request.'), 400
    results, error = lookup_ips(ips)
    if error:
        return jsonify(error=error, results=results), 503
    return jsonify(results=results, source='Local GeoDB; approximate IP locations')


# ---------------------------------------------------------------------------
# Local detection database (SQLite)
# ---------------------------------------------------------------------------
def db():
    if 'db' not in g:
        path = app.config['DB_PATH']
        if path != ':memory:':
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        g.db = store.connect(path)
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop('db', None)
    if conn is not None:
        conn.close()


@app.before_request
def protect_api():
    """Reject cross-site writes: same-origin only, JSON bodies only."""
    if request.path.startswith('/api/') and request.method in ('POST', 'PATCH', 'DELETE'):
        origin = request.headers.get('Origin')
        if origin and urlsplit(origin).netloc != request.host:
            return jsonify(error='Cross-origin request refused.'), 403
        if request.method != 'DELETE' and not request.is_json:
            return jsonify(error='Expected application/json.'), 415
        if request.content_length and request.content_length > IMPORT_LIMIT:
            return jsonify(error='Request too large; send rows in smaller chunks.'), 413
    elif request.content_length and request.content_length > SMALL_LIMIT:
        return jsonify(error='Request too large.'), 413
    return None


def _geo_for_store(ips):
    results, _error = lookup_ips([ip for ip in ips if len(ip) <= 128])
    return {ip: {k: r.get(k) for k in ('status', 'country', 'country_code', 'city')} for ip, r in results.items()
            if r.get('status') in ('located', 'not_found')}


@app.get('/api/detections')
def api_detections():
    conn = db()
    return jsonify(columns=store.LIST_COLUMNS, rows=store.list_detections(conn), stats=store.stats(conn))


@app.get('/api/detections/<int:det_id>')
def api_detection(det_id):
    item = store.get_detection(db(), det_id)
    return (jsonify(item), 200) if item else (jsonify(error='Detection not found.'), 404)


@app.patch('/api/detections/<int:det_id>')
def api_update_detection(det_id):
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error='Expected a JSON object.'), 400
    status, note = payload.get('status'), payload.get('note')
    if note is not None and not isinstance(note, str):
        return jsonify(error='Note must be text.'), 400
    try:
        return jsonify(store.update_detection(db(), det_id, status=status, note=note))
    except LookupError as exc:
        return jsonify(error=str(exc)), 404
    except ValueError as exc:
        return jsonify(error=str(exc)), 400


@app.post('/api/detections/status')
def api_bulk_status():
    payload = request.get_json(silent=True)
    ids = payload.get('ids') if isinstance(payload, dict) else None
    if not isinstance(ids, list) or len(ids) > 200000 or not all(isinstance(i, int) and not isinstance(i, bool) for i in ids):
        return jsonify(error='Expected ids as a list of integers.'), 400
    try:
        return jsonify(changed=store.bulk_status(db(), ids, payload.get('status')))
    except ValueError as exc:
        return jsonify(error=str(exc)), 400


@app.get('/api/imports')
def api_imports():
    conn = db()
    path = app.config['DB_PATH']
    size = sum(os.path.getsize(p) for p in (path, path + '-wal') if path != ':memory:' and os.path.exists(p))
    return jsonify(imports=store.list_imports(conn), stats=store.stats(conn), path=str(Path(path).resolve()) if path != ':memory:' else path,
                   size_bytes=size)


@app.post('/api/imports')
def api_create_import():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error='Expected a JSON object.'), 400
    return jsonify(id=store.create_import(db(), payload.get('name'))), 201


@app.post('/api/imports/<int:import_id>/rows')
def api_import_rows(import_id):
    payload = request.get_json(silent=True)
    rows = payload.get('rows') if isinstance(payload, dict) else None
    if not isinstance(rows, list) or not 0 < len(rows) <= 5000:
        return jsonify(error='Send between 1 and 5000 rows per request.'), 400
    try:
        return jsonify(store.add_rows(db(), import_id, rows, geo_lookup=_geo_for_store))
    except LookupError as exc:
        return jsonify(error=str(exc)), 404
    except ValueError as exc:
        return jsonify(error=str(exc)), 400


@app.delete('/api/imports/<int:import_id>')
def api_delete_import(import_id):
    try:
        return jsonify(removed=store.delete_import(db(), import_id))
    except LookupError as exc:
        return jsonify(error=str(exc)), 404


@app.post('/api/purge')
def api_purge():
    payload = request.get_json(silent=True) or {}
    if payload.get('everything') is True:
        return jsonify(removed=store.purge(db(), everything=True))
    days = payload.get('older_than_days')
    if not isinstance(days, int) or isinstance(days, bool) or days < 1:
        return jsonify(error='older_than_days must be a whole number of days (1 or more).'), 400
    return jsonify(removed=store.purge(db(), older_than_days=days))


@app.post('/api/relocate')
def api_relocate():
    conn = db()
    ips = store.public_ips(conn)
    results, error = lookup_ips([ip for ip in ips if len(ip) <= 128])
    if error:
        return jsonify(error=error), 503
    stored = {ip: {k: r.get(k) for k in ('status', 'country', 'country_code', 'city')} for ip, r in results.items()
              if r.get('status') in ('located', 'not_found')}
    store.apply_geo(conn, stored)
    return jsonify(located=sum(1 for r in stored.values() if r['status'] == 'located'), checked=len(stored))


@app.get('/api/backup')
def api_backup():
    with tempfile.TemporaryDirectory() as tmp:
        data = store.backup_bytes(db(), os.path.join(tmp, 'backup.db'))
    stamp = datetime.now().strftime('%Y%m%d-%H%M')
    return send_file(io.BytesIO(data), mimetype='application/vnd.sqlite3', as_attachment=True, download_name=f'sentinel-backup-{stamp}.db')


@app.after_request
def headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'self'")
    return response


if __name__ == '__main__':
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', '5000'))
    print(f' * Sentinel running on http://{host}:{port}')
    print(f' * Database: {app.config["DB_PATH"]}')
    print(f' * GeoDB:    {app.config["GEODB_PATH"]}')
    app.run(host=host, port=port, debug=False)
