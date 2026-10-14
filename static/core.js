/* Sentinel core: pure, DOM-free logic shared by the dashboard and the Node tests.
 * Nothing in this file touches the network or the page. */
var SentinelCore = (function () {
  'use strict';

  const DAY = 86400000;
  const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];
  const SEVERITY_COLORS = { Critical: '#ff5d73', High: '#f5946b', Medium: '#edbd6c', Low: '#53dfc2', Unknown: '#6b7a8f' };
  const STATUSES = ['new', 'investigating', 'closed', 'false_positive'];
  const STATUS_LABELS = { new: 'New', investigating: 'Investigating', closed: 'Closed', false_positive: 'False positive' };

  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  /* ---------- empty-content rules ---------- */
  const EMPTY = ['', 'unknown', 'unknown detection', 'not included', 'not included in export', 'n/a', 'null', 'undefined', '-'];
  function hasValue(value) {
    if (value === null || value === undefined) return false;
    if (typeof value === 'boolean' || typeof value === 'number') return true;
    return !EMPTY.includes(String(value).trim().toLowerCase());
  }

  /* ---------- countries ---------- */
  let regionNames = null;
  try { regionNames = new Intl.DisplayNames(['en'], { type: 'region' }); } catch (e) { regionNames = null; }

  // Display-name normalisation: many spellings -> one canonical name.
  const COUNTRY_ALIASES = {
    'usa': 'United States', 'us': 'United States', 'u.s.': 'United States', 'united states of america': 'United States', 'america': 'United States',
    'uk': 'United Kingdom', 'great britain': 'United Kingdom', 'england': 'United Kingdom', 'britain': 'United Kingdom',
    'czech republic': 'Czechia', 'turkey': 'Türkiye', 'turkiye': 'Türkiye', 'russian federation': 'Russia',
    'korea, republic of': 'South Korea', 'republic of korea': 'South Korea', 'korea': 'South Korea',
    "korea, democratic people's republic of": 'North Korea', 'viet nam': 'Vietnam', 'iran, islamic republic of': 'Iran',
    'republic of serbia': 'Serbia', 'macedonia': 'North Macedonia', 'east timor': 'Timor-Leste', 'swaziland': 'Eswatini',
    'the bahamas': 'Bahamas', 'guinea bissau': 'Guinea-Bissau', 'ivory coast': "Côte d’Ivoire", "cote d'ivoire": "Côte d’Ivoire", "côte d'ivoire": "Côte d’Ivoire",
    'congo republic': 'Congo - Brazzaville', 'republic of the congo': 'Congo - Brazzaville', 'dr congo': 'Congo - Kinshasa',
    'democratic republic of the congo': 'Congo - Kinshasa', 'united republic of tanzania': 'Tanzania', 'hong kong sar china': 'Hong Kong',
    'palestine': 'Palestinian Territories', 'west bank': 'Palestinian Territories', 'myanmar (burma)': 'Myanmar', 'burma': 'Myanmar',
    'internal': 'Internal network', 'internal network': 'Internal network', 'local': 'Internal network'
  };
  // Canonical name -> name used in the bundled world.json.
  const WORLD_NAMES = {
    'United States': 'USA', 'United Kingdom': 'England', 'Czechia': 'Czech Republic', 'Türkiye': 'Turkey', 'Serbia': 'Republic of Serbia',
    'North Macedonia': 'Macedonia', 'Timor-Leste': 'East Timor', 'Eswatini': 'Swaziland', 'Bahamas': 'The Bahamas', 'Guinea-Bissau': 'Guinea Bissau',
    "Côte d’Ivoire": 'Ivory Coast', 'Congo - Brazzaville': 'Republic of the Congo', 'Congo - Kinshasa': 'Democratic Republic of the Congo',
    'Tanzania': 'United Republic of Tanzania', 'Palestinian Territories': 'West Bank'
  };
  // Hand-tuned centroids (lon, lat) for countries whose geometric centroid is misleading, plus small states missing from the basemap.
  const CENTROIDS = {
    'United States': [-98, 39], 'Russia': [90, 60], 'Canada': [-106, 57], 'France': [2, 47], 'Norway': [9, 62], 'United Kingdom': [-2, 54],
    'Chile': [-71, -33], 'Indonesia': [118, -3], 'New Zealand': [174, -41], 'Japan': [138, 37], 'Fiji': [178, -18],
    'Singapore': [103.8, 1.35], 'Hong Kong': [114.2, 22.3], 'Macao': [113.5, 22.2], 'Malta': [14.4, 35.9], 'Bahrain': [50.6, 26.1],
    'Monaco': [7.4, 43.7], 'Liechtenstein': [9.55, 47.15], 'Andorra': [1.5, 42.5], 'San Marino': [12.45, 43.94], 'Mauritius': [57.6, -20.3],
    'Maldives': [73.5, 3.2], 'Seychelles': [55.5, -4.6], 'Barbados': [-59.55, 13.15], 'Gibraltar': [-5.35, 36.14], 'Bermuda': [-64.75, 32.3],
    'Cayman Islands': [-81.25, 19.3], 'Isle of Man': [-4.5, 54.2], 'Jersey': [-2.1, 49.2], 'Guernsey': [-2.58, 49.45], 'Cabo Verde': [-23.6, 15.1],
    'Antigua & Barbuda': [-61.8, 17.1], 'Saint Lucia': [-60.98, 13.9], 'Grenada': [-61.68, 12.1], 'Comoros': [43.3, -11.7], 'Samoa': [-172.1, -13.75],
    'Tonga': [-175.2, -21.2], 'Brunei': [114.7, 4.5], 'Luxembourg': [6.1, 49.8], 'Curaçao': [-68.95, 12.17], 'Aruba': [-69.97, 12.52],
    'Réunion': [55.5, -21.1], 'Guadeloupe': [-61.55, 16.25], 'Martinique': [-61.0, 14.65], 'French Guiana': [-53, 4], 'Faroe Islands': [-6.9, 62]
  };

  function canonicalCountry(value) {
    if (!hasValue(value)) return 'Unknown';
    const v = String(value).trim();
    if (/^[A-Za-z]{2}$/.test(v) && regionNames) {
      const code = v.toUpperCase();
      if (code === 'UK') return 'United Kingdom';
      try { const name = regionNames.of(code); if (name && name !== code) return COUNTRY_ALIASES[name.toLowerCase()] || name; } catch (e) { /* not a region */ }
    }
    return COUNTRY_ALIASES[v.toLowerCase()] || v;
  }

  // Area-weighted centroid of the largest polygon of each GeoJSON feature.
  function computeCentroids(geojson) {
    const out = {};
    for (const f of (geojson && geojson.features) || []) {
      const g = f.geometry; if (!g) continue;
      const polys = g.type === 'Polygon' ? [g.coordinates] : g.type === 'MultiPolygon' ? g.coordinates : [];
      let best = null, bestArea = 0;
      for (const poly of polys) {
        const ring = poly[0]; let a = 0, cx = 0, cy = 0;
        for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
          const k = ring[j][0] * ring[i][1] - ring[i][0] * ring[j][1];
          a += k; cx += (ring[j][0] + ring[i][0]) * k; cy += (ring[j][1] + ring[i][1]) * k;
        }
        if (Math.abs(a) > bestArea && a !== 0) { bestArea = Math.abs(a); best = [cx / (3 * a), cy / (3 * a)]; }
      }
      if (best) out[f.properties.name] = best;
    }
    return out;
  }

  function worldName(country) { return WORLD_NAMES[country] || country; }
  function locate(country, centroids) {
    if (!hasValue(country) || country === 'Internal network') return null;
    return CENTROIDS[country] || (centroids && centroids[worldName(country)]) || null;
  }

  /* ---------- IP addresses ---------- */
  function isIPv4(s) { return /^(\d{1,3})(\.\d{1,3}){3}$/.test(s) && s.split('.').every(p => Number(p) <= 255); }
  function isIPv6(s) { return /^[0-9a-f:]+(%\w+)?$/i.test(s) && s.includes(':') && (s.match(/::/g) || []).length <= 1; }
  function isIP(s) { s = String(s || '').trim(); return isIPv4(s) || isIPv6(s); }
  function privateIP(ip) {
    if (!ip) return false;
    const s = String(ip).trim().toLowerCase();
    if (s.includes(':')) return /^(::$|::1$|f[cd]|fe[89ab]|2001:db8|::ffff:(10|127|192\.168)\.)/.test(s);
    const p = s.split('.').map(Number);
    return p.length === 4 && (p[0] === 10 || p[0] === 127 || p[0] === 0 || p[0] >= 224 || (p[0] === 192 && (p[1] === 168 || (p[1] === 0 && (p[2] === 0 || p[2] === 2)))) ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 169 && p[1] === 254) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127) ||
      (p[0] === 198 && (p[1] === 18 || p[1] === 19 || (p[1] === 51 && p[2] === 100))) || (p[0] === 203 && p[1] === 0 && p[2] === 113));
  }

  /* ---------- CSV ---------- */
  function detectDelimiter(text) {
    // Count delimiters in the first logical line, ignoring quoted sections.
    const counts = { ';': 0, ',': 0, '\t': 0 }; let quoted = false;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (c === '"') quoted = !quoted;
      else if (!quoted && (c === '\n' || c === '\r')) break;
      else if (!quoted && c in counts) counts[c]++;
    }
    return Object.keys(counts).sort((a, b) => counts[b] - counts[a])[0];
  }
  function parseCSV(text) {
    text = String(text).replace(/^\uFEFF/, '');
    const delim = detectDelimiter(text), rows = []; let row = [], cell = '', quoted = false;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (c === '"') { if (quoted && text[i + 1] === '"') { cell += '"'; i++; } else quoted = !quoted; }
      else if (c === delim && !quoted) { row.push(cell); cell = ''; }
      else if ((c === '\n' || c === '\r') && !quoted) {
        if (c === '\r' && text[i + 1] === '\n') i++;
        row.push(cell); if (row.some(x => x.trim())) rows.push(row); row = []; cell = '';
      } else cell += c;
    }
    if (quoted) throw Error('CSV has an unclosed quoted field. Check the export and try again.');
    if (cell || row.length) { row.push(cell); if (row.some(x => x.trim())) rows.push(row); }
    if (rows.length < 2) throw Error('The file must contain a header row and at least one detection.');
    return rows;
  }

  /* ---------- dates: returns epoch ms or NaN ---------- */
  function parseDate(v) {
    if (!hasValue(v)) return NaN;
    let d = String(v).trim();
    let m = d.match(/^(\d{1,2})\.\s?(\d{1,2})\.\s?(\d{4})(?:[ T,]+(\d{1,2}):(\d{2})(?::(\d{2}))?)?/);
    if (m) return new Date(+m[3], m[2] - 1, +m[1], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0)).getTime();
    m = d.match(/^(\d{4})[-/](\d{1,2})[-/](\d{1,2})(?:[ T]+(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,3}))?)?)?\s*(Z|UTC|GMT|[+-]\d{2}:?\d{2})?$/i);
    if (m) {
      const [, y, mo, da, h = 0, mi = 0, s = 0, ms = 0, tz] = m;
      if (!tz) return new Date(+y, mo - 1, +da, +h, +mi, +s, +String(ms).padEnd(3, '0')).getTime();
      let t = Date.UTC(+y, mo - 1, +da, +h, +mi, +s, +String(ms).padEnd(3, '0'));
      const off = /^[+-]/.test(tz) ? tz.replace(':', '') : '';
      if (off) t -= (off[0] === '-' ? -1 : 1) * (Number(off.slice(1, 3)) * 60 + Number(off.slice(3, 5))) * 60000;
      return t;
    }
    const t = Date.parse(d);
    return Number.isFinite(t) ? t : NaN;
  }
  const pad = n => String(n).padStart(2, '0');
  function localDay(t) { const d = new Date(t); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`; }
  function localTime(t) { const d = new Date(t); return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; }
  function startOfDay(t) { const d = new Date(t); d.setHours(0, 0, 0, 0); return d.getTime(); }

  function severity(v) {
    const s = String(v || '').toLowerCase();
    return /critical|fatal|severe/.test(s) ? 'Critical' : /high|error/.test(s) ? 'High' : /medium|warning|moderate/.test(s) ? 'Medium' : /low|info/.test(s) ? 'Low' : 'Unknown';
  }

  /* ---------- column mapping ---------- */
  const FIELDS = {
    date: ['occurred', 'occurred at', 'time occurred', 'time', 'date', 'detected at', 'detection time', 'timestamp', 'first seen', 'last occurrence', 'last occurred'],
    threat: ['detection name', 'threat name', 'cause', 'threat', 'detection', 'name'],
    type: ['detection type', 'type', 'scanner', 'category', 'detection engine'],
    cause: ['cause'],
    severity: ['severity', 'level', 'risk', 'risk level'],
    computer: ['computer name', 'computer', 'device', 'device name', 'hostname', 'host name'],
    user: ['user', 'username', 'user name', 'logged user', 'logged in user'],
    ip: ['source address', 'source ip', 'source ip address', 'remote ip', 'remote ip address', 'remote address', 'ip address', 'ip', 'ipv4', 'ipv4 address', 'computer ip address', 'target ip', 'target address'],
    country: ['country', 'country name', 'source country', 'country code'],
    action: ['action taken', 'action', 'status'],
    resolved: ['resolved', 'resolved occurrences'],
    occurrences: ['occurrences', 'occurrence', 'count', 'hit count'],
    file: ['object', 'object uri', 'file path', 'file', 'file name', 'filename', 'path'],
    hash: ['hash', 'sha1', 'sha-1', 'sha256', 'sha-256', 'md5', 'file hash', 'object hash'],
    process: ['process name', 'process', 'process path']
  };
  const FIELD_LABELS = { date: 'Date / time', threat: 'Detection name', type: 'Detection type', cause: 'Cause', severity: 'Severity', computer: 'Computer', user: 'User',
    ip: 'IP address', country: 'Country', action: 'Action', resolved: 'Resolved', occurrences: 'Occurrences', file: 'File / object', hash: 'Hash', process: 'Process' };

  function autoMap(headers, saved) {
    const norm = headers.map(h => String(h).trim().toLowerCase());
    const map = {};
    for (const [field, aliases] of Object.entries(FIELDS)) {
      map[field] = -1;
      for (const alias of aliases) { const n = norm.indexOf(alias); if (n >= 0) { map[field] = n; break; } }
    }
    if (saved) for (const [f, i] of Object.entries(saved)) if (f in map && Number.isInteger(i) && i < headers.length) map[f] = i;
    return map;
  }
  function headerSignature(headers) { return headers.map(h => String(h).trim().toLowerCase()).join('|'); }

  function buildRecord(o) {
    o.occurrences = /^\d+$/.test(String(o.occurrences ?? '').trim()) && Number(o.occurrences) > 0 ? Number(o.occurrences) : 1;
    o.t = typeof o.t === 'number' ? o.t : parseDate(o.date);
    o.date = Number.isFinite(o.t) ? new Date(o.t).toISOString() : '';
    o.severity = SEVERITIES.includes(o.severity) ? o.severity : severity(o.severity);
    o.threat = hasValue(o.threat) ? o.threat : (hasValue(o.cause) ? o.cause : 'Unknown detection');
    o.ip = String(o.ip || '').trim();
    o.country = privateIP(o.ip) ? 'Internal network' : canonicalCountry(o.country);
    for (const k of ['user', 'computer', 'action']) o[k] = hasValue(o[k]) ? String(o[k]).trim() : 'Unknown';
    o._q = [o.threat, o.user, o.ip, o.computer, o.file, o.hash, o.process, o.type, o.action].filter(Boolean).join('\n').toLowerCase();
    return o;
  }
  function buildRows(headers, rows, map) {
    return rows.map(r => {
      const o = { raw: Object.fromEntries(headers.map((h, i) => [`${h} [column ${i + 1}]`, r[i] || ''])) };
      for (const f of Object.keys(FIELDS)) o[f] = map[f] >= 0 ? String(r[map[f]] || '').trim() : '';
      o.date_raw = o.date;
      return buildRecord(o);
    });
  }

  // Short label for the kind of object detected: a URL, or a file extension.
  function objectKind(file) {
    if (!hasValue(file)) return '';
    const f = String(file).trim();
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(f)) return /^https?:/i.test(f) ? 'Web URL' : f.split(':')[0].toLowerCase() + ' URI';
    const m = f.split(/[\\/]/).pop().match(/\.([a-z0-9]{1,8})$/i);
    return m ? '.' + m[1].toLowerCase() : 'No extension';
  }

  /* ---------- aggregation ---------- */
  const weight = x => x.occurrences || 1;
  const total = rows => rows.reduce((n, x) => n + weight(x), 0);
  function group(rows, key) {
    const m = new Map();
    for (const x of rows) { const v = x[key] || 'Unknown'; m.set(v, (m.get(v) || 0) + weight(x)); }
    return [...m].sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])));
  }

  function periodRange(rows, period, from, to) {
    if (period === 'custom') {
      const f = from ? new Date(from + 'T00:00:00').getTime() : -Infinity;
      const t = to ? new Date(to + 'T00:00:00').getTime() + DAY - 1 : Infinity;
      return { from: f, to: t };
    }
    const days = Number(period); if (!days) return null;
    let latest = -Infinity; for (const x of rows) if (x.t > latest) latest = x.t;
    if (!Number.isFinite(latest)) return null;
    if (days === 1) return { from: latest - DAY + 1, to: Infinity };
    return { from: startOfDay(latest) - (days - 1) * DAY, to: Infinity };
  }

  function filterRows(rows, f) {
    const q = (f.q || '').trim().toLowerCase();
    const ip = (f.ip || '').trim().toLowerCase(), exactIP = isIP(ip);
    const range = f.range;
    return rows.filter(x =>
      (!q || x._q.includes(q)) &&
      (!ip || (exactIP ? x.ip.toLowerCase() === ip : x.ip.toLowerCase().includes(ip))) &&
      (!f.user || x.user === f.user) && (!f.computer || x.computer === f.computer) &&
      (!f.severity || x.severity === f.severity) && (!f.country || x.country === f.country) &&
      (!f.action || x.action === f.action) && (!f.threat || x.threat === f.threat) && (!f.status || x.status === f.status) &&
      (!range || (Number.isFinite(x.t) && x.t >= range.from && x.t <= range.to)));
  }

  function timeline(rows) {
    const dated = rows.filter(x => Number.isFinite(x.t));
    if (!dated.length) return null;
    let min = Infinity, max = -Infinity;
    for (const x of dated) { if (x.t < min) min = x.t; if (x.t > max) max = x.t; }
    const start = startOfDay(min), end = startOfDay(max);
    const span = Math.round((end - start) / DAY) + 1, step = Math.max(1, Math.ceil(span / 60));
    const bins = Array.from({ length: Math.ceil(span / step) }, (_, i) => {
      const d = new Date(start); d.setDate(d.getDate() + i * step);
      return { day: localDay(d.getTime()), t: d.getTime(), total: 0, sev: Object.fromEntries(SEVERITIES.map(s => [s, 0])) };
    });
    for (const x of dated) {
      const idx = Math.min(bins.length - 1, Math.floor(Math.round((startOfDay(x.t) - start) / DAY) / step));
      bins[idx].total += weight(x); bins[idx].sev[x.severity] += weight(x);
    }
    return { bins, step };
  }

  function heatmap(rows) {
    // 7 rows (Mon..Sun) x 24 hours, local time.
    const grid = Array.from({ length: 7 }, () => Array(24).fill(0)); let max = 0, n = 0;
    for (const x of rows) {
      if (!Number.isFinite(x.t)) continue;
      const d = new Date(x.t), wd = (d.getDay() + 6) % 7, h = d.getHours();
      grid[wd][h] += weight(x); if (grid[wd][h] > max) max = grid[wd][h]; n++;
    }
    return { grid, max, n };
  }

  /* ---------- what to show (pure; the page applies it) ---------- */
  function visibilityPlan(data, filtered, state) {
    state = state || {};
    const has = (rows, key) => rows.some(x => hasValue(x[key]));
    const located = filtered.some(x => locate(x.country, state.centroids));
    return {
      panels: {
        chart: filtered.some(x => Number.isFinite(x.t)),
        heatmap: filtered.some(x => Number.isFinite(x.t)),
        threats: has(filtered, 'threat'),
        severity: has(filtered, 'severity') || has(filtered, 'action'),
        users: has(filtered, 'user'),
        computers: has(filtered, 'computer'),
        ips: has(filtered, 'ip'),
        objects: has(filtered, 'file') || has(filtered, 'process'),
        countries: filtered.some(x => hasValue(x.country) && x.country !== 'Internal network'),
        map: located || state.geoState === 'loading' || state.geoState === 'error' || !!state.basemapError
      },
      filters: {
        userFilter: has(data, 'user'), computerFilter: has(data, 'computer'), ipFilter: has(data, 'ip'), severityFilter: has(data, 'severity'),
        countryFilter: has(data, 'country'), actionFilter: has(data, 'action'), threatFilter: has(data, 'threat'), statusFilter: has(data, 'status'),
        period: data.some(x => Number.isFinite(x.t))
      },
      columns: [data.some(x => Number.isFinite(x.t)), has(data, 'threat'), has(data, 'severity'), has(data, 'computer') || has(data, 'user'), has(data, 'ip'), has(data, 'country'), has(data, 'action'), has(data, 'status')],
      metrics: [true, has(data, 'severity'), has(data, 'computer'), has(data, 'user'), has(data, 'resolved') || has(data, 'action'), has(data, 'status')]
    };
  }

  /* ---------- rows from the local database ---------- */
  function fromDatabase(columns, rows) {
    return rows.map(values => {
      const o = {}; columns.forEach((c, i) => { o[c] = values[i]; });
      o.t = typeof o.t === 'number' ? o.t : NaN;
      if (o.geo_status === 'located' && o.geo_code) o.country = o.geo_code;
      o.geo = o.geo_city ? { city: o.geo_city } : null;
      o.occurrences = String(o.occurrences ?? 1); o.raw = null;
      return buildRecord(o);
    });
  }
  // Compact payload for the server; t is null when the date could not be parsed.
  function toUpload(x) {
    const out = { t: Number.isFinite(x.t) ? x.t : null, date_raw: x.date_raw || '', occurrences: x.occurrences, raw: x.raw || {} };
    for (const f of ['threat', 'type', 'cause', 'severity', 'computer', 'user', 'ip', 'country', 'action', 'resolved', 'file', 'hash', 'process']) out[f] = hasValue(x[f]) ? x[f] : '';
    if (out.country === 'Internal network') out.country = '';
    return out;
  }

  /* ---------- CSV export (formula-injection safe) ---------- */
  function toCSV(rows, cols, labels) {
    const cell = v => '"' + String(v ?? '').replace(/^[=+@\-\t\r]/, "'$&").replace(/"/g, '""') + '"';
    return [labels || cols, ...rows.map(x => cols.map(k => typeof k === 'function' ? k(x) : x[k]))].map(r => r.map(cell).join(',')).join('\r\n');
  }

  /* ---------- synthetic demo data ---------- */
  function demoData(now) {
    let seed = 20261014;
    const rnd = () => { seed |= 0; seed = seed + 0x6D2B79F5 | 0; let t = Math.imul(seed ^ seed >>> 15, 1 | seed); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; };
    const pick = (arr, w) => { if (!w) return arr[Math.floor(rnd() * arr.length)]; let r = rnd() * w.reduce((a, b) => a + b, 0); for (let i = 0; i < arr.length; i++) { r -= w[i]; if (r < 0) return arr[i]; } return arr.at(-1); };
    const hex = n => Array.from({ length: n }, () => '0123456789abcdef'[Math.floor(rnd() * 16)]).join('');
    const people = [['j.novak', 'PRG-WS-014'], ['a.smith', 'PRG-LT-038'], ['m.kral', 'BRN-WS-007'], ['s.weber', 'BER-LT-009'], ['l.chen', 'PRG-WS-026'],
      ['p.dvorak', 'BRN-LT-021'], ['e.martin', 'VIE-WS-003'], ['k.horak', 'PRG-WS-031'], ['t.svoboda', 'PRG-LT-044'], ['h.mueller', 'BER-WS-012']];
    const servers = ['FIN-SRV-02', 'PRG-DC-01', 'PRG-WEB-03', 'BER-FS-01'];
    // name, type, severity weights [C,H,M,L], weight, kind
    const threats = [
      ['HTML/Phishing.Agent.EOP trojan', 'Trojan', [0, 2, 6, 1], 14, 'web'], ['JS/Agent.QQV trojan', 'Trojan', [0, 3, 5, 1], 10, 'web'],
      ['Win32/InstallCore.D potentially unwanted application', 'Potentially unwanted application', [0, 0, 2, 8], 9, 'file'],
      ['Win64/CoinMiner.KV potentially unwanted application', 'Potentially unwanted application', [0, 1, 6, 2], 4, 'file'],
      ['MSIL/Spy.AgentTesla.F trojan', 'Trojan', [1, 6, 2, 0], 5, 'file'], ['VBA/TrojanDownloader.Agent.ZXK trojan', 'Trojan', [1, 5, 3, 0], 6, 'mail'],
      ['LNK/Agent.ACN trojan', 'Trojan', [0, 3, 4, 0], 3, 'file'], ['Win32/Exploit.CVE-2017-11882.A trojan', 'Exploit', [2, 5, 1, 0], 3, 'mail'],
      ['Incoming.Attack.Generic', 'Network attack', [0, 2, 6, 3], 16, 'net'], ['RDP.Attack.Bruteforce', 'Network attack', [3, 6, 1, 0], 10, 'net'],
      ['Botnet.CnC.Generic', 'Botnet', [3, 5, 1, 0], 3, 'cnc'], ['SMB.Attack.Exploit.EternalBlue', 'Exploit', [4, 4, 0, 0], 2, 'net']
    ];
    const sources = [['RU', 9], ['CN', 8], ['US', 6], ['NL', 5], ['BR', 4], ['VN', 4], ['IN', 3], ['IR', 2], ['KR', 2], ['RO', 2], ['UA', 2], ['DE', 3], ['SG', 2], ['TR', 2], ['HK', 2], ['ZA', 1], ['ID', 2], ['FR', 2]];
    const ipPool = sources.flatMap(([cc, w]) => Array.from({ length: Math.ceil(w / 2) }, () => [`${pick([45, 77, 91, 103, 109, 141, 176, 185, 193, 194, 212])}.${Math.floor(rnd() * 254) + 1}.${Math.floor(rnd() * 254) + 1}.${Math.floor(rnd() * 253) + 2}`, cc, w]));
    const end = now, start = startOfDay(now) - 29 * DAY, rows = [];
    const ransomDay = startOfDay(now) - 9 * DAY, phishDay = startOfDay(now) - 18 * DAY;
    const add = (t, th, extra) => {
      const [name, type, sw, , kind] = th; const net = kind === 'net' || kind === 'cnc';
      const [user, host] = pick(people); const server = net && rnd() < .6 ? pick(servers) : null;
      const src = net ? pick(ipPool, ipPool.map(x => x[2])) : null;
      const sev = pick(['Critical', 'High', 'Medium', 'Low'], sw);
      const action = kind === 'net' ? 'Blocked' : kind === 'cnc' ? pick(['Blocked', 'Connection terminated'], [8, 2]) : pick(['Cleaned', 'Deleted', 'Quarantined', 'Blocked', 'Retained'], [5, 3, 3, 4, 1]);
      const file = kind === 'web' ? `https://${pick(['secure-login', 'docs-share', 'invoice-portal', 'm365-verify'])}.${pick(['example', 'test', 'invalid'])}/${hex(6)}`
        : kind === 'mail' ? `C:\\Users\\${user}\\AppData\\Local\\Microsoft\\Outlook\\${pick(['Invoice_', 'Order_', 'Scan_'])}${Math.floor(rnd() * 9000 + 1000)}.${pick(['docm', 'xlsm', 'rtf'])}`
        : kind === 'file' ? `C:\\Users\\${user}\\Downloads\\${pick(['setup', 'driver_update', 'crack', 'invoice', 'photo'])}_${hex(4)}.${pick(['exe', 'zip', 'lnk', 'msi'])}` : '';
      rows.push(buildRecord(Object.assign({
        t, date: '', threat: name, type, severity: sev, user: server ? 'SYSTEM' : `DOMAIN\\${user}`, computer: server || host,
        ip: net ? src[0] : `10.0.${Math.floor(rnd() * 4) + 1}.${Math.floor(rnd() * 200) + 20}`, country: net ? src[1] : '',
        action, resolved: action === 'Retained' ? 'No' : 'Yes', occurrences: net ? String(1 + Math.floor(rnd() ** 4 * 24)) : '1',
        file, hash: kind === 'file' || kind === 'mail' ? hex(40) : '', process: kind === 'web' ? pick(['chrome.exe', 'msedge.exe', 'firefox.exe']) : kind === 'mail' ? pick(['OUTLOOK.EXE', 'WINWORD.EXE', 'EXCEL.EXE']) : kind === 'file' ? 'explorer.exe' : kind === 'cnc' ? pick(['svchost.exe', 'rundll32.exe']) : '',
        cause: '', raw: {}, synthetic: true
      }, extra)));
    };
    for (let i = 0; i < 470; i++) {
      const th = pick(threats, threats.map(x => x[3]));
      let day = start + Math.floor(rnd() * 30) * DAY; const wd = new Date(day).getDay();
      if ((wd === 0 || wd === 6) && th[4] !== 'net' && rnd() < .7) day += (wd === 6 ? 2 : 1) * DAY;
      const hour = th[4] === 'net' ? Math.floor(rnd() * 24) : Math.min(23, Math.max(6, Math.round(8 + rnd() * 9 + (rnd() - .5) * 3)));
      const t = Math.min(end, day + hour * 3600000 + Math.floor(rnd() * 3600000));
      add(t, th);
    }
    // A short ransomware incident and a phishing wave make the timeline worth reading.
    for (let i = 0; i < 9; i++) add(ransomDay + (13 + i * .2) * 3600000, ['Win32/Filecoder.Phobos.C trojan', 'Trojan', [1, 0, 0, 0], 0, 'file'], { action: i < 7 ? 'Cleaned' : 'Retained', resolved: i < 7 ? 'Yes' : 'No' });
    for (let i = 0; i < 26; i++) add(phishDay + (9 + rnd() * 6) * 3600000, threats[0]);
    return rows.filter(x => x.t <= end).sort((a, b) => b.t - a.t);
  }

  return {
    DAY, SEVERITIES, SEVERITY_COLORS, STATUSES, STATUS_LABELS, fromDatabase, toUpload, FIELDS, FIELD_LABELS, esc, hasValue, canonicalCountry, computeCentroids, worldName, locate,
    isIP, privateIP, parseCSV, parseDate, localDay, localTime, startOfDay, severity, autoMap, headerSignature, objectKind, buildRows, buildRecord,
    weight, total, group, periodRange, filterRows, timeline, heatmap, visibilityPlan, toCSV, demoData
  };
})();
if (typeof module !== 'undefined' && module.exports) module.exports = SentinelCore;
