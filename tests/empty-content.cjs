// Frontend logic tests. Run with: node tests/empty-content.cjs
const assert = require('assert');
const path = require('path');
const fs = require('fs');
const C = require(path.join(__dirname, '../static/core.js'));

let passed = 0;
const test = (name, fn) => { fn(); passed++; };

test('blank vs. meaningful values', () => {
  for (const v of ['', null, undefined, '  ', 'Unknown', 'N/A', '-']) assert.equal(C.hasValue(v), false, JSON.stringify(v));
  for (const v of [0, '0', false, 'false', 'Blocked']) assert.equal(C.hasValue(v), true, JSON.stringify(v));
});

test('visibility plan hides empty panels, filters and columns but keeps errors visible', () => {
  const row = C.buildRecord({ date: '', user: '', severity: '', country: '', ip: '10.16.8.3', threat: 'Trojan', computer: 'PC', action: 'Blocked' });
  let plan = C.visibilityPlan([row], [row], { geoState: 'ready' });
  assert.equal(row.country, 'Internal network');
  assert.equal(plan.panels.map, false); assert.equal(plan.panels.users, false); assert.equal(plan.panels.ips, true); assert.equal(plan.panels.chart, false);
  assert.equal(plan.filters.severityFilter, false); assert.equal(plan.filters.period, false);
  assert.deepEqual(plan.columns, [false, true, false, true, true, true, true, false]);
  assert.deepEqual(plan.metrics, [true, false, true, false, true, false]);
  assert.equal(plan.filters.statusFilter, false);
  plan = C.visibilityPlan([row], [row], { geoState: 'error' }); assert.equal(plan.panels.map, true);
  plan = C.visibilityPlan([row], [row], { basemapError: true }); assert.equal(plan.panels.map, true);
});

test('CSV parsing: delimiters, quotes, multiline, BOM', () => {
  assert.deepEqual(C.parseCSV('\uFEFFa;"b;c";d\r\n1;"x\n""y""";3\n'), [['a', 'b;c', 'd'], ['1', 'x\n"y"', '3']]);
  assert.deepEqual(C.parseCSV('"Name, full",Count\nA,1'), [['Name, full', 'Count'], ['A', '1']]);
  assert.deepEqual(C.parseCSV('a\tb\n1\t2'), [['a', 'b'], ['1', '2']]);
  assert.throws(() => C.parseCSV('a,b\n"1,2'), /unclosed/);
  assert.throws(() => C.parseCSV('a,b\n'), /header row/);
});

test('date parsing', () => {
  const local = (y, m, d, h = 0, mi = 0, s = 0) => new Date(y, m - 1, d, h, mi, s).getTime();
  assert.equal(C.parseDate('14.10.2026 10:22:33'), local(2026, 10, 14, 10, 22, 33));
  assert.equal(C.parseDate('2026-10-14 10:22'), local(2026, 10, 14, 10, 22));
  assert.equal(C.parseDate('2026/10/14'), local(2026, 10, 14));
  assert.equal(C.parseDate('2026-10-14 10:22:33 UTC'), Date.UTC(2026, 9, 14, 10, 22, 33));
  assert.equal(C.parseDate('2026-10-14T10:22:33+02:00'), Date.UTC(2026, 9, 14, 8, 22, 33));
  assert.ok(Number.isNaN(C.parseDate('not a date'))); assert.ok(Number.isNaN(C.parseDate('')));
});

test('countries: ISO codes, aliases and map locations', () => {
  assert.deepEqual(['SG', 'cz', 'Czech Republic', 'USA', 'England', 'Turkey'].map(C.canonicalCountry), ['Singapore', 'Czechia', 'Czechia', 'United States', 'United Kingdom', 'Türkiye']);
  const centroids = C.computeCentroids(JSON.parse(fs.readFileSync(path.join(__dirname, '../static/world.json'), 'utf8')));
  for (const name of ['Czechia', 'United States', 'Türkiye', 'Singapore', 'Hong Kong', 'Serbia', 'Kenya']) assert.ok(C.locate(name, centroids), name);
  assert.equal(C.locate('Internal network', centroids), null);
  const [lon, lat] = C.locate('Czechia', centroids); assert.ok(lon > 12 && lon < 19 && lat > 48 && lat < 51);
});

test('IP classification', () => {
  for (const ip of ['10.1.2.3', '192.168.0.1', '172.20.0.1', '127.0.0.1', '::1', 'fd00::1', '100.64.0.1']) assert.ok(C.privateIP(ip), ip);
  for (const ip of ['8.8.8.8', '172.32.0.1', '2a00:1450::1']) assert.ok(!C.privateIP(ip), ip);
  assert.ok(C.isIP('1.2.3.4') && C.isIP('2a00::1') && !C.isIP('1.2.3') && !C.isIP('300.1.1.1'));
});

test('column mapping and record building', () => {
  const headers = ['Occurred', 'Computer name', 'Detection name', 'Severity', 'Action taken', 'IP address', 'Occurrences', 'Object', 'Hash', 'Resolved'];
  const map = C.autoMap(headers);
  assert.equal(map.date, 0); assert.equal(map.computer, 1); assert.equal(map.threat, 2); assert.equal(map.action, 4); assert.equal(map.resolved, 9); assert.equal(map.country, -1);
  const [r] = C.buildRows(headers, [['14.10.2026 09:00', 'PC-1', 'JS/Agent', 'Warning', 'Blocked', '8.8.8.8', 'abc', 'C:\\a.exe', 'ff', '0']], map);
  assert.equal(r.severity, 'Medium'); assert.equal(r.occurrences, 1); assert.equal(r.resolved, '0'); assert.equal(r.user, 'Unknown'); assert.ok(r._q.includes('c:\\a.exe'));
  assert.equal(C.autoMap(headers, { country: 5 }).country, 5);
});

test('filters, weighting and time ranges', () => {
  const now = Date.UTC(2026, 9, 14, 12);
  const rows = [
    C.buildRecord({ t: now, threat: 'A', ip: '8.8.8.8', user: 'u1', computer: 'c1', severity: 'High', occurrences: '5' }),
    C.buildRecord({ t: now - 10 * C.DAY, threat: 'B', ip: '8.8.8.80', user: 'u2', computer: 'c2', severity: 'Low' }),
    C.buildRecord({ threat: 'C', ip: '10.0.0.1', user: 'u1', computer: 'c1', severity: 'Low' })
  ];
  assert.equal(C.total(rows), 7);
  assert.deepEqual(C.group(rows, 'user')[0], ['u1', 6]);
  assert.equal(C.filterRows(rows, { ip: '8.8.8.8' }).length, 1, 'full IP matches exactly');
  assert.equal(C.filterRows(rows, { ip: '8.8.8' }).length, 2, 'partial IP matches as substring');
  assert.equal(C.filterRows(rows, { range: C.periodRange(rows, '7') }).length, 1, 'undated rows are excluded from time filters');
  assert.equal(C.filterRows(rows, { range: C.periodRange(rows, 'all') }).length, 3);
  assert.equal(C.filterRows(rows, { q: 'b' }).length, 1);
});

test('timeline and heatmap', () => {
  const t0 = new Date(2026, 9, 1, 9).getTime();
  const rows = [C.buildRecord({ t: t0, severity: 'High', occurrences: '2' }), C.buildRecord({ t: t0 + 3 * C.DAY, severity: 'Low' })];
  const tl = C.timeline(rows);
  assert.equal(tl.bins.length, 4); assert.equal(tl.bins[0].sev.High, 2); assert.equal(tl.bins[3].total, 1);
  const hm = C.heatmap(rows); assert.equal(hm.grid[3][9], 2); assert.equal(hm.max, 2); // 1 Oct 2026 is a Thursday
});

test('CSV export guards against formula injection', () => {
  const csv = C.toCSV([{ a: '=1+1', b: 'x"y' }], ['a', 'b']);
  assert.equal(csv.split('\r\n')[1], `"'=1+1","x""y"`);
});

test('demo data is deterministic, synthetic and well-formed', () => {
  const now = Date.UTC(2026, 9, 14, 12), a = C.demoData(now), b = C.demoData(now);
  assert.equal(a.length, b.length); assert.equal(a[0].ip, b[0].ip);
  assert.ok(a.length > 300 && a.every(x => x.synthetic && Number.isFinite(x.t) && x.t <= now));
  assert.ok(!a.some(x => x.ip === '8.8.8.8'));
  assert.ok(C.group(a, 'severity').length >= 4);
});

test('database rows: GeoDB country wins, status survives, upload payload is clean', () => {
  const cols = ['id', 't', 'threat', 'ip', 'country', 'geo_status', 'geo_code', 'geo_city', 'status', 'occurrences', 'severity', 'user'];
  const [a, b] = C.fromDatabase(cols, [[1, 1760000000000, 'X', '8.8.8.8', 'Germany', 'located', 'SG', 'Singapore', 'investigating', 3, 'High', ''],
    [2, null, 'Y', '10.0.0.1', '', null, null, null, 'new', 1, 'Low', 'bob']]);
  assert.equal(a.country, 'Singapore'); assert.equal(a.status, 'investigating'); assert.equal(a.occurrences, 3); assert.equal(a.geo.city, 'Singapore');
  assert.ok(Number.isNaN(b.t)); assert.equal(b.country, 'Internal network');
  const up = C.toUpload(a); assert.equal(up.t, 1760000000000); assert.equal(up.user, ''); assert.equal(C.toUpload(b).t, null); assert.equal(C.toUpload(b).country, '');
  const plan = C.visibilityPlan([a, b], [a, b], {}); assert.equal(plan.columns[7], true); assert.equal(plan.filters.statusFilter, true);
  assert.equal(C.filterRows([a, b], { status: 'new' }).length, 1);
});

console.log(`Frontend core: ${passed} test groups passed.`);
