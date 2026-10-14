/* Sentinel dashboard: DOM rendering and interaction. Pure logic lives in core.js. */
(function () {
  'use strict';
  const C = SentinelCore, { esc, hasValue, weight, total } = C;
  const $ = id => document.getElementById(id);
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* storage unavailable */ } }
  };

  const state = {
    data: C.demoData(Date.now()), demo: true, mode: 'demo', db: null, sourceName: '', filtered: [], sorted: [],
    page: 0, pageSize: 25, sort: { key: 't', dir: -1 }, view: 'overview',
    geoState: 'idle', basemapError: false, world: null, centroids: null, pending: null, detailIndex: -1
  };
  const FILTER_IDS = ['search', 'threatFilter', 'severityFilter', 'userFilter', 'computerFilter', 'ipFilter', 'countryFilter', 'actionFilter', 'statusFilter'];
  const FILTER_LABELS = { search: 'Search', threatFilter: 'Detection', severityFilter: 'Severity', userFilter: 'User', computerFilter: 'Computer', ipFilter: 'IP', countryFilter: 'Country', actionFilter: 'Action', statusFilter: 'Review' };
  const api = async (url, opts = {}) => {
    const res = await fetch(url, Object.assign({ headers: opts.body ? { 'Content-Type': 'application/json' } : {} }, opts));
    let body = null; try { body = await res.json(); } catch (e) { body = null; }
    if (!res.ok) throw Error((body && body.error) || `Server error ${res.status}`);
    return body;
  };
  const fmtWhen = iso => { const d = new Date(iso); return Number.isFinite(d.getTime()) ? `${C.localDay(d.getTime())} ${C.localTime(d.getTime()).slice(0, 5)}` : ''; };
  const VIEWS = {
    overview: ['Security overview', 'A clear picture of what’s happening across your environment.', 'Overview'],
    detections: ['Detection log', 'Inspect, filter and export the events in your dataset.', 'Detections'],
    geography: ['IP & geography', 'Explore source addresses and approximate country locations.', 'IP & geography'],
    users: ['Endpoints & users', 'See which accounts, computers and processes have the most detections.', 'Endpoints & users'],
    database: ['Local database', 'Everything you have imported, kept between sessions on this server.', 'Database']
  };
  const SEV_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3, Unknown: 4 };

  /* ---------- messages ---------- */
  function message(text) { $('messageText').textContent = text || ''; $('message').hidden = !text; }
  $('messageClose').onclick = () => message('');

  /* ---------- filters ---------- */
  function setupFilters() {
    const opts = (id, key, label) => {
      const sel = $(id), cur = sel.value;
      const values = C.group(state.data, key).map(([v]) => v).filter(hasValue);
      if (key !== 'threat') values.sort((a, b) => a.localeCompare(b));
      sel.innerHTML = `<option value="">All ${label}</option>` + values.map(v => `<option>${esc(v)}</option>`).join('');
      sel.value = values.includes(cur) ? cur : '';
    };
    opts('threatFilter', 'threat', 'detections'); opts('userFilter', 'user', 'users'); opts('computerFilter', 'computer', 'computers');
    opts('countryFilter', 'country', 'countries'); opts('actionFilter', 'action', 'actions');
  }
  function currentFilters() {
    const period = $('period').value;
    return {
      q: $('search').value, threat: $('threatFilter').value, severity: $('severityFilter').value, user: $('userFilter').value,
      computer: $('computerFilter').value, ip: $('ipFilter').value, country: $('countryFilter').value, action: $('actionFilter').value, status: $('statusFilter').value,
      range: C.periodRange(state.data, period, $('dateFrom').value, $('dateTo').value)
    };
  }
  function setFilter(id, value) {
    const el = $(id);
    if (el.tagName === 'SELECT' && ![...el.options].some(o => o.value === value)) el.add(new Option(value, value));
    el.value = value; state.page = 0; render();
  }
  function reset() {
    FILTER_IDS.forEach(k => $(k).value = ''); $('period').value = 'all'; $('dateFrom').value = ''; $('dateTo').value = '';
    $('customRange').hidden = true; state.page = 0; render();
  }
  $('reset').onclick = reset;
  let debounce;
  FILTER_IDS.concat(['period', 'dateFrom', 'dateTo']).forEach(id => $(id).addEventListener('input', () => {
    if (id === 'period') $('customRange').hidden = $('period').value !== 'custom';
    clearTimeout(debounce); debounce = setTimeout(() => { state.page = 0; render(); }, id === 'search' || id === 'ipFilter' ? 160 : 0);
  }));

  function renderChips(f) {
    const chips = FILTER_IDS.filter(id => $(id).value.trim()).map(id => `<button class="chip" data-clear="${id}">${FILTER_LABELS[id]}: <b>${esc(id === 'statusFilter' ? C.STATUS_LABELS[$(id).value] : $(id).value)}</b> <span aria-hidden="true">×</span></button>`);
    const p = $('period').value;
    if (p !== 'all') {
      const label = p === 'custom' ? `${$('dateFrom').value || '…'} → ${$('dateTo').value || '…'}` : $('period').selectedOptions[0].textContent;
      chips.push(`<button class="chip" data-clear="period">Time: <b>${esc(label)}</b> <span aria-hidden="true">×</span></button>`);
    }
    if (chips.length > 1) chips.push('<button class="chip clear-all" data-clear="all">Clear all</button>');
    $('chips').innerHTML = chips.join('');
    $('chips').querySelectorAll('[data-clear]').forEach(b => b.onclick = () => {
      const id = b.dataset.clear;
      if (id === 'all') return reset();
      if (id === 'period') { $('period').value = 'all'; $('customRange').hidden = true; } else $(id).value = '';
      state.page = 0; render();
    });
  }

  /* ---------- main render ---------- */
  function render() {
    const f = currentFilters();
    state.filtered = C.filterRows(state.data, f);
    renderChips(f); renderMetrics(); renderChart(); renderThreats(); renderSeverity(); renderHeatmap(); renderRanks(); renderMap(); renderTable();
    $('navCount').textContent = state.data.length.toLocaleString();
    updateVisibility();
  }

  function renderMetrics() {
    const rows = state.filtered, all = total(rows) || 0;
    const high = total(rows.filter(x => x.severity === 'Critical' || x.severity === 'High'));
    const devices = new Set(rows.map(x => x.computer).filter(hasValue)).size, people = new Set(rows.map(x => x.user).filter(hasValue)).size;
    const unresolved = rows.filter(x => /^(no|false|0|not resolved|unresolved)$/i.test(String(x.resolved).trim()) || /retain|not resolved|no action/i.test(x.action)).length;
    const stats = [
      ['Total occurrences', all, `${rows.length.toLocaleString()} exported rows`, '◈', ''],
      ['High & critical', high, `${all ? Math.round(high / all * 100) : 0}% of filtered occurrences`, '!', 'danger'],
      ['Affected computers', devices, 'Unique endpoints with detections', '▣', ''],
      ['Affected users', people, 'Unique identified user accounts', '♙', ''],
      ['Not resolved', unresolved, unresolved ? 'Rows marked unresolved or retained' : 'Every row was resolved or handled', '◷', unresolved ? 'warn' : ''],
      ['Awaiting review', rows.filter(x => x.status === 'new').length, `${rows.filter(x => x.status === 'investigating').length.toLocaleString()} under investigation`, '✎', '']
    ];
    $('metrics').innerHTML = stats.map(([label, value, sub, icon, cls]) => `<div class="metric ${cls}"><div class="metric-label">${label}<span>${icon}</span></div><strong>${value.toLocaleString()}</strong><small>${esc(sub)}</small></div>`).join('');
  }

  function renderChart() {
    const tl = C.timeline(state.filtered);
    const present = C.SEVERITIES.filter(s => state.filtered.some(x => x.severity === s && Number.isFinite(x.t)));
    $('chartLegend').innerHTML = present.map(s => `<span><i style="background:${C.SEVERITY_COLORS[s]}"></i>${s}</span>`).join('');
    if (!tl) { $('chart').innerHTML = '<div class="empty">No dated detections in this selection.</div>'; return; }
    const { bins, step } = tl, W = 700, H = 190, top = 12, bottom = 24, left = 40, plotH = H - top - bottom;
    const max = Math.max(...bins.map(b => b.total), 1), nice = niceMax(max), bw = (W - left - 4) / bins.length;
    let svg = [0, .25, .5, .75, 1].map(v => { const y = top + plotH - v * plotH; return `<line x1="${left}" y1="${y}" x2="${W}" y2="${y}" class="gridline"/><text x="${left - 8}" y="${y + 3.5}" text-anchor="end" class="axis">${Math.round(nice * v).toLocaleString()}</text>`; }).join('');
    bins.forEach((b, i) => {
      let y = top + plotH; const x = left + 2 + i * bw, w = Math.max(1.5, bw * .78);
      const tip = `${b.day}${step > 1 ? ` (+${step - 1} days)` : ''}: ${b.total.toLocaleString()} occurrences` + C.SEVERITIES.filter(s => b.sev[s]).map(s => `\n${s}: ${b.sev[s]}`).join('');
      svg += `<g class="bar-group" data-day="${b.day}" data-step="${step}"><rect x="${x - (bw - w) / 2}" y="${top}" width="${bw}" height="${plotH}" fill="transparent"/>`;
      for (const s of C.SEVERITIES) {
        if (!b.sev[s]) continue; const h = b.sev[s] / nice * plotH; y -= h;
        svg += `<rect x="${x}" y="${y}" width="${w}" height="${Math.max(h, .5)}" fill="${C.SEVERITY_COLORS[s]}" fill-opacity=".9"/>`;
      }
      svg += `<title>${esc(tip)}</title></g>`;
    });
    const every = Math.max(1, Math.ceil(bins.length / 7));
    bins.forEach((b, i) => { if (i % every === 0) svg += `<text x="${left + 2 + i * bw + bw * .39}" y="${H - 6}" text-anchor="middle" class="axis">${b.day.slice(5)}</text>`; });
    $('chart').innerHTML = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Detections per day">${svg}</svg>`;
    $('chart').querySelectorAll('.bar-group').forEach(g => g.onclick = () => {
      const from = g.dataset.day, d = new Date(from + 'T00:00:00'); d.setDate(d.getDate() + Number(g.dataset.step) - 1);
      $('period').value = 'custom'; $('customRange').hidden = false; $('dateFrom').value = from; $('dateTo').value = C.localDay(d.getTime()); state.page = 0; render();
    });
  }
  function niceMax(v) { const p = Math.pow(10, Math.floor(Math.log10(v))); for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p; return v; }

  function renderThreats() {
    const items = C.group(state.filtered, 'threat').filter(([n]) => hasValue(n)), top = items[0]?.[1] || 1, all = total(state.filtered) || 1;
    const palette = ['#53dfc2', '#7e93e9', '#d6a873', '#d0799e', '#63a9d9', '#9bd17a'];
    $('threats').innerHTML = items.slice(0, 6).map(([n, c], i) => `<button class="threat-item" data-filter="threatFilter" data-value="${esc(n)}" title="Filter: ${esc(n)}"><div><span>${esc(n)}</span><b>${c.toLocaleString()} <small>${Math.round(c / all * 100)}%</small></b></div><div class="bar"><i style="width:${c / top * 100}%;background:${palette[i]}"></i></div></button>`).join('') || '<div class="empty">No matching detections.</div>';
    bindFilterButtons($('threats'));
  }

  function renderSeverity() {
    const rows = state.filtered, all = total(rows) || 1, sev = new Map(C.group(rows, 'severity'));
    const present = C.SEVERITIES.filter(s => sev.get(s));
    const stack = present.map(s => `<button class="stack-seg" style="flex:${sev.get(s)};background:${C.SEVERITY_COLORS[s]}" data-filter="severityFilter" data-value="${s}" title="${s}: ${sev.get(s).toLocaleString()} (${Math.round(sev.get(s) / all * 100)}%)"></button>`).join('');
    const legend = present.map(s => `<button class="sev-row" data-filter="severityFilter" data-value="${s}"><i style="background:${C.SEVERITY_COLORS[s]}"></i><span>${s}</span><b>${sev.get(s).toLocaleString()}</b><small>${Math.round(sev.get(s) / all * 100)}%</small></button>`).join('');
    const actions = C.group(rows, 'action').filter(([a]) => hasValue(a)), atop = actions[0]?.[1] || 1;
    const outcome = actions.slice(0, 5).map(([a, n]) => `<button class="outcome" data-filter="actionFilter" data-value="${esc(a)}"><span>${esc(a)}</span><span class="bar"><i style="width:${n / atop * 100}%"></i></span><b>${n.toLocaleString()}</b></button>`).join('');
    $('severity').innerHTML = (present.length ? `<div class="stack">${stack}</div><div class="sev-grid">${legend}</div>` : '') +
      (outcome ? `<h3 class="sub-h">Action taken</h3><div class="outcomes">${outcome}</div>` : '');
    bindFilterButtons($('severity'));
  }

  function renderHeatmap() {
    const { grid, max } = C.heatmap(state.filtered);
    if (!max) { $('heatmap').innerHTML = '<div class="empty">No dated detections in this selection.</div>'; return; }
    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'], cw = 26, ch = 24, left = 36, top = 18;
    let svg = '';
    for (let h = 0; h < 24; h += 3) svg += `<text x="${left + h * cw + cw / 2}" y="11" text-anchor="middle" class="axis">${String(h).padStart(2, '0')}</text>`;
    grid.forEach((row, d) => {
      svg += `<text x="${left - 8}" y="${top + d * ch + ch / 2 + 4}" text-anchor="end" class="axis">${days[d]}</text>`;
      row.forEach((v, h) => {
        const o = v ? .14 + .86 * Math.sqrt(v / max) : 0;
        svg += `<rect x="${left + h * cw + 1}" y="${top + d * ch + 1}" width="${cw - 2}" height="${ch - 2}" rx="3" class="${v ? 'hm' : 'hm-empty'}" ${v ? `fill-opacity="${o.toFixed(2)}"` : ''}><title>${days[d]} ${String(h).padStart(2, '0')}:00–${String(h).padStart(2, '0')}:59 · ${v.toLocaleString()} occurrences</title></rect>`;
      });
    });
    const busiest = grid.flatMap((r, d) => r.map((v, h) => [v, d, h])).sort((a, b) => b[0] - a[0])[0];
    const work = grid.slice(0, 5).reduce((n, r) => n + r.slice(8, 18).reduce((a, b) => a + b, 0), 0), sum = grid.flat().reduce((a, b) => a + b, 0);
    $('heatmap').innerHTML = `<svg viewBox="0 0 ${left + 24 * cw + 4} ${top + 7 * ch + 4}" role="img" aria-label="Detections by weekday and hour">${svg}</svg>
      <div class="hm-foot"><span>Busiest: <b>${days[busiest[1]]} ${String(busiest[2]).padStart(2, '0')}:00</b></span><span><b>${Math.round(work / (sum || 1) * 100)}%</b> during office hours (Mon–Fri 08–18)</span></div>`;
  }

  function rankHTML(items, kind, sub) {
    const top = items[0]?.[1] || 1, filter = { user: 'userFilter', ip: 'ipFilter', country: 'countryFilter', computer: 'computerFilter' }[kind];
    return items.slice(0, 8).map(([name, n], i) => {
      const avatar = kind === 'country' ? '◎' : kind === 'ip' ? '⌘' : kind === 'computer' ? '▣' : esc(String(name).split('\\').at(-1).slice(0, 2).toUpperCase());
      return `<button class="rank" ${filter ? `data-filter="${filter}"` : ''} data-value="${esc(name)}"><span class="rank-number">${String(i + 1).padStart(2, '0')}</span><span class="avatar">${avatar}</span><span class="rank-main"><span class="rank-label">${esc(name)}</span><span class="rank-sub">${sub(name, n)}</span><span class="bar"><i style="width:${n / top * 100}%"></i></span></span><span class="rank-count">${n.toLocaleString()}</span></button>`;
    }).join('') || '<div class="empty">No matching detections.</div>';
  }
  function renderRanks() {
    const rows = state.filtered, all = total(rows) || 1;
    const index = (key, val) => { const m = new Map(); for (const x of rows) { if (!m.has(x[key])) m.set(x[key], new Set()); m.get(x[key]).add(x[val]); } return m; };
    const userPCs = index('user', 'computer'), pcUsers = index('computer', 'user'), ipCountry = new Map(rows.map(x => [x.ip, x.country]));
    $('users').innerHTML = rankHTML(C.group(rows, 'user').filter(([n]) => hasValue(n)), 'user', n => { const k = userPCs.get(n)?.size || 0; return `${k} computer${k === 1 ? '' : 's'}`; });
    $('computers').innerHTML = rankHTML(C.group(rows, 'computer').filter(([n]) => hasValue(n)), 'computer', n => { const u = [...(pcUsers.get(n) || [])].filter(hasValue); return u.length ? esc(u.slice(0, 2).join(', ') + (u.length > 2 ? ` +${u.length - 2}` : '')) : 'No user recorded'; });
    $('ips').innerHTML = rankHTML(C.group(rows, 'ip').filter(([n]) => hasValue(n)), 'ip', n => C.privateIP(n) ? 'Internal / reserved address' : esc(hasValue(ipCountry.get(n)) ? ipCountry.get(n) : 'Country unknown'));
    $('countries').innerHTML = rankHTML(C.group(rows, 'country').filter(([n]) => hasValue(n) && n !== 'Internal network'), 'country', (name, n) => `${Math.round(n / all * 100)}% of filtered occurrences`);
    const procs = C.group(rows, 'process').filter(([n]) => hasValue(n)).slice(0, 6);
    const kinds = new Map();
    for (const x of rows) { const k = C.objectKind(x.file); if (k) kinds.set(k, (kinds.get(k) || 0) + weight(x)); }
    const types = [...kinds].sort((a, b) => b[1] - a[1]).slice(0, 6);
    const list = (items, title, q) => items.length ? `<div><h3 class="sub-h">${title}</h3>` + items.map(([n, c]) => `<button class="obj" data-filter="search" data-value="${esc(q(n))}" title="Search for ${esc(q(n))}"><span>${esc(n)}</span><b>${c.toLocaleString()}</b></button>`).join('') + '</div>' : '';
    const body = list(procs, 'Processes', n => n) + list(types, 'Object types', n => n === 'Web URL' ? 'http' : n);
    $('objects').innerHTML = body ? `<div class="obj-cols">${body}</div>` : '<div class="empty">No process or object fields in this selection.</div>';
    ['users', 'computers', 'ips', 'countries', 'objects'].forEach(id => bindFilterButtons($(id)));
  }
  function bindFilterButtons(root) { root.querySelectorAll('[data-filter]').forEach(b => b.onclick = () => setFilter(b.dataset.filter, b.dataset.value)); }

  /* ---------- map ---------- */
  const project = ([lon, lat]) => [(lon + 180) / 360 * 900, (85 - lat) / 170 * 370];
  let landCache = null;
  function renderMap() {
    const counts = new Map(C.group(state.filtered, 'country')), byWorld = new Map();
    for (const [name, n] of counts) if (C.locate(name, state.centroids)) byWorld.set(C.worldName(name), [name, n]);
    const max = Math.max(1, ...[...byWorld.values()].map(v => v[1]));
    let grid = '';
    for (let x = 0; x <= 900; x += 75) grid += `<line x1="${x}" y1="0" x2="${x}" y2="370" class="gridline faint"/>`;
    for (let y = 0; y <= 370; y += 62) grid += `<line x1="0" y1="${y}" x2="900" y2="${y}" class="gridline faint"/>`;
    if (state.world && !landCache) landCache = state.world.features.filter(f => f.properties.name !== 'Antarctica').map(f => {
      const polys = f.geometry.type === 'Polygon' ? [f.geometry.coordinates] : f.geometry.coordinates;
      return [f.properties.name, polys.map(p => p.map(r => r.map((c, i) => `${i ? 'L' : 'M'}${project(c).map(v => v.toFixed(1)).join(',')}`).join('') + 'Z').join('')).join('')];
    });
    const land = (landCache || []).map(([wn, d]) => {
      const hit = byWorld.get(wn);
      return hit ? `<path d="${d}" class="land hit" style="fill-opacity:${(.18 + .6 * Math.log1p(hit[1]) / Math.log1p(max)).toFixed(2)}" data-country="${esc(hit[0])}"><title>${esc(hit[0])}: ${hit[1].toLocaleString()} occurrences</title></path>` : `<path d="${d}" class="land"/>`;
    }).join('');
    let located = 0;
    const points = [...counts].filter(([name]) => C.locate(name, state.centroids)).map(([name, n]) => {
      located += n; const [x, y] = project(C.locate(name, state.centroids)), r = 3.5 + Math.sqrt(n / max) * 14;
      return `<g class="map-point" data-country="${esc(name)}" tabindex="0" role="button" aria-label="Filter ${esc(name)}, ${n} occurrences"><circle cx="${x}" cy="${y}" r="${r}" class="bubble"/><circle cx="${x}" cy="${y}" r="1.8" class="bubble-core"/><title>${esc(name)}: ${n.toLocaleString()} occurrences</title></g>`;
    }).join('');
    let note = !state.world ? `<text x="880" y="355" text-anchor="end" class="axis">${state.basemapError ? 'Basemap unavailable · country coordinate view' : 'Loading basemap…'}</text>` : '';
    if (!points && state.world) {
      const why = state.geoState === 'loading' ? 'Looking up IP addresses in the local GeoDB…' : state.geoState === 'error' ? 'No country data: the CSV has no country column and the GeoDB lookup is unavailable.' : 'No located countries in this selection.';
      note += `<text x="450" y="190" text-anchor="middle" class="map-empty">${esc(why)}</text>`;
    }
    $('world').innerHTML = grid + land + points + note;
    const internal = total(state.filtered.filter(x => x.country === 'Internal network'));
    $('mappedCount').textContent = located.toLocaleString();
    $('unlocated').textContent = `${internal.toLocaleString()} internal · ${(total(state.filtered) - located - internal).toLocaleString()} unlocated`;
    $('world').querySelectorAll('[data-country]').forEach(el => { el.onclick = () => setFilter('countryFilter', el.dataset.country); el.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); el.onclick(); } }; });
  }

  /* ---------- table ---------- */
  function sortRows(rows) {
    const { key, dir } = state.sort;
    const val = x => key === 'status' ? C.STATUSES.indexOf(x.status) : key === 't' ? (Number.isFinite(x.t) ? x.t : -Infinity) : key === 'severity' ? -SEV_RANK[x.severity] : key === 'ip' ? ipKey(x.ip) : String(x[key] || '').toLowerCase();
    return rows.map(x => [val(x), x]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0) * dir || (b[1].t || 0) - (a[1].t || 0)).map(p => p[1]);
  }
  function ipKey(ip) { return C.isIP(ip) && ip.includes('.') ? ip.split('.').map(n => n.padStart(3, '0')).join('.') : String(ip || '~').toLowerCase(); }
  function renderTable() {
    state.sorted = sortRows(state.filtered);
    const n = state.sorted.length, size = state.pageSize;
    state.page = Math.min(state.page, Math.max(0, Math.ceil(n / size) - 1));
    const slice = state.sorted.slice(state.page * size, state.page * size + size);
    $('rows').innerHTML = slice.map((x, i) => `<tr tabindex="0" data-row="${state.page * size + i}">
      <td>${Number.isFinite(x.t) ? esc(C.localDay(x.t)) + `<small>${C.localTime(x.t)}</small>` : '<span class="muted">Unknown date</span>'}</td>
      <td class="threat-cell">${esc(x.threat)}${x.occurrences > 1 ? ` <span class="occ" title="${x.occurrences} occurrences">×${x.occurrences.toLocaleString()}</span>` : ''}${hasValue(x.type) ? `<small>${esc(x.type)}</small>` : ''}</td>
      <td><span class="badge ${x.severity}">${x.severity}</span></td>
      <td>${esc(x.computer)}<small>${esc(x.user)}</small></td>
      <td class="mono">${esc(hasValue(x.ip) ? x.ip : '—')}</td><td>${esc(hasValue(x.country) ? x.country : '—')}</td><td class="action">${esc(x.action)}</td>
      <td>${x.status ? `<span class="status ${x.status}">${C.STATUS_LABELS[x.status]}</span>${x.has_note ? '<span class="note-dot" title="Has notes">✎</span>' : ''}` : '—'}</td></tr>`).join('') ||
      '<tr><td colspan="8" class="empty">No detections match these filters. Clear filters to see all events.</td></tr>';
    $('resultCount').textContent = n.toLocaleString();
    $('pageInfo').textContent = `${n ? state.page * size + 1 : 0}–${Math.min((state.page + 1) * size, n)} of ${n.toLocaleString()} rows`;
    $('prev').disabled = state.page === 0; $('next').disabled = (state.page + 1) * size >= n;
    document.querySelectorAll('[data-sort]').forEach(b => { const on = b.dataset.sort === state.sort.key; b.classList.toggle('sorted', on); b.dataset.dir = on ? (state.sort.dir > 0 ? '↑' : '↓') : ''; b.closest('th').setAttribute('aria-sort', on ? (state.sort.dir > 0 ? 'ascending' : 'descending') : 'none'); });
    $('rows').querySelectorAll('[data-row]').forEach(tr => { tr.onclick = () => openDetail(Number(tr.dataset.row)); tr.onkeydown = e => { if (e.key === 'Enter') tr.click(); }; });
  }
  document.querySelectorAll('[data-sort]').forEach(b => b.onclick = () => {
    const k = b.dataset.sort; state.sort = { key: k, dir: state.sort.key === k ? -state.sort.dir : (k === 't' || k === 'severity' ? -1 : 1) }; state.page = 0; renderTable(); updateVisibility();
  });
  $('prev').onclick = () => { state.page--; renderTable(); updateVisibility(); };
  $('next').onclick = () => { state.page++; renderTable(); updateVisibility(); };
  $('pageSize').onchange = () => { state.pageSize = Number($('pageSize').value); state.page = 0; renderTable(); updateVisibility(); };

  /* ---------- visibility (empty-content rules from core) ---------- */
  function updateVisibility() {
    const plan = C.visibilityPlan(state.data, state.filtered, { geoState: state.geoState, basemapError: state.basemapError, centroids: state.centroids });
    const inView = el => (el.dataset.views || '').split(' ').includes(state.view);
    document.querySelectorAll('[data-panel]').forEach(a => a.hidden = !inView(a) || !plan.panels[a.dataset.panel]);
    document.querySelectorAll('.middle').forEach(s => { const shown = [...s.children].filter(c => !c.hidden).length; s.hidden = !shown; s.classList.toggle('single', shown === 1); });
    $('tableSection').hidden = !inView($('tableSection'));
    for (const [id, show] of Object.entries(plan.filters)) $(id).hidden = !show;
    $('customRange').hidden = !plan.filters.period || $('period').value !== 'custom';
    document.querySelectorAll('thead tr, #rows tr').forEach(tr => {
      if (tr.children.length === 8) [...tr.children].forEach((cell, i) => cell.hidden = !plan.columns[i]);
      else if (tr.children.length === 1) tr.children[0].colSpan = Math.max(1, plan.columns.filter(Boolean).length);
    });
    [...$('metrics').children].forEach((m, i) => m.hidden = !plan.metrics[i]);
    $('dbSection').hidden = state.view !== 'database';
    $('bulkTools').hidden = state.mode !== 'db';
  }

  /* ---------- detail dialog ---------- */
  function openDetail(index) {
    state.detailIndex = index; showDetails(state.sorted[index]);
    if (!$('detailDialog').open) $('detailDialog').showModal();
  }
  $('detailPrev').onclick = () => state.detailIndex > 0 && openDetail(state.detailIndex - 1);
  $('detailNext').onclick = () => state.detailIndex < state.sorted.length - 1 && openDetail(state.detailIndex + 1);
  $('detailDialog').addEventListener('keydown', e => { if (e.key === 'ArrowLeft') $('detailPrev').click(); if (e.key === 'ArrowRight') $('detailNext').click(); });

  let detailToken = 0;
  async function showDetails(x) {
    const token = ++detailToken;
    $('detailPos').textContent = `${(state.detailIndex + 1).toLocaleString()} / ${state.sorted.length.toLocaleString()}`;
    $('detailPrev').disabled = state.detailIndex <= 0; $('detailNext').disabled = state.detailIndex >= state.sorted.length - 1;
    const line = (label, value, cls) => hasValue(value) ? `<dt>${esc(label)}</dt><dd class="${cls || ''}">${esc(value)}</dd>` : '';
    const count = (key) => hasValue(x[key]) ? state.data.filter(r => r[key] === x[key]).length : 0;
    const counts = [['detection', count('threat')], ['IP', count('ip')], ['user', count('user')], ['computer', count('computer')]].filter(([, n]) => n);
    const details = Object.keys(x.raw || {}).length ? x.raw : null;
    const raw = details ? Object.entries(details).filter(([, v]) => hasValue(v)) : [];
    const quick = [['threatFilter', x.threat, 'detection'], ['ipFilter', x.ip, 'IP'], ['userFilter', x.user, 'user'], ['computerFilter', x.computer, 'computer']]
      .filter(([, v]) => hasValue(v)).map(([id, v, l]) => `<button type="button" class="subtle" data-quick="${id}" data-value="${esc(v)}">Filter this ${l}</button>`).join('');
    const caseHTML = x.id ? `<div class="case" id="case"><h3>Review</h3>
        <div class="seg" role="group" aria-label="Review status">${C.STATUSES.map(st => `<button type="button" data-status="${st}" aria-pressed="${x.status === st}">${C.STATUS_LABELS[st]}</button>`).join('')}</div>
        <textarea id="caseNote" placeholder="Notes for this detection — what you checked, who you contacted, the outcome…" maxlength="8000"></textarea>
        <div class="case-foot"><span id="caseInfo">Loading…</span><button type="button" id="caseSave" class="primary" disabled>Save note</button></div>
        <ul class="history" id="caseHistory"></ul></div>`
      : x.synthetic ? '<p class="note">Import your own CSV to track review status and notes — they are saved in the local database.</p>' : '';
    $('detail').innerHTML = caseHTML + `<div class="summary-card">
        ${hasValue(x.threat) ? `<h3>${esc(x.threat)} <span class="badge ${x.severity}">${x.severity}</span></h3>` : ''}
        <dl class="facts">${line('Detected at', Number.isFinite(x.t) ? `${C.localDay(x.t)} ${C.localTime(x.t)} (your local time)` : '')}${line('Action', x.action)}${line('Resolved', x.resolved)}
        ${line('Computer', x.computer)}${line('User', x.user)}${line('Type', x.type)}${line('Cause', x.cause !== x.threat ? x.cause : '')}${line('Occurrences', weight(x))}
        ${line('Process', x.process)}${line('IP address', x.ip, 'mono')}${line('Country', x.country)}${line('City (GeoDB)', x.geo?.city)}${line('File / object', x.file, 'mono')}${line('Hash', x.hash, 'mono')}</dl>
        ${counts.length ? `<div class="summary-counts">${counts.map(([l, n]) => `<span><b>${n.toLocaleString()}</b> rows with same ${l}</span>`).join('')}</div><p class="note">Counts use all imported rows, including rows outside the active filters.</p>` : ''}
        ${quick ? `<div class="quick">${quick}</div>` : ''}
      </div>
      ${hasValue(x.threat) || hasValue(x.ip) || hasValue(x.hash) ? '<div id="intel"><p class="note">Preparing investigation notes…</p></div>' : ''}
      <div id="rawWrap">${raw.length ? `<details class="raw"><summary>Exported fields (${raw.length})</summary><dl>${raw.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl></details>` : ''}</div>
      ${x.synthetic ? '<p class="note">Synthetic demo record — indicators are invented and do not describe real activity.</p>' : ''}`;
    $('detail').querySelectorAll('[data-quick]').forEach(b => b.onclick = () => { $('detailDialog').close(); if (state.view !== 'detections' && state.view !== 'overview') setView('detections'); setFilter(b.dataset.quick, b.dataset.value); });
    if (x.id) loadCase(x, token);
    if (!$('intel')) return;
    try {
      const res = await fetch('summary', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ threat: hasValue(x.threat) ? x.threat : '', ip: x.ip || '', hash: x.hash || '', file: x.file || '' }) });
      if (!res.ok) throw Error('Summary unavailable');
      const info = await res.json(); if (token !== detailToken) return;
      const facts = [['Platform', info.platform], ['Family', info.family], ['Category', info.category], ['Vulnerability', (info.cves || []).join(', ')]].filter(([, v]) => v);
      $('intel').innerHTML = `<h3>Investigation notes</h3>
        ${hasValue(x.threat) ? `<p>${esc(info.explanation)}</p>${facts.length ? `<dl class="facts">${facts.map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join('')}</dl>` : ''}<p class="provenance">${esc(info.provenance)}</p>` : ''}
        ${hasValue(x.ip) ? `<p><b>${esc(info.scope)}</b> · <span class="mono">${esc(x.ip)}</span></p>` : ''}
        ${hasValue(x.hash) && !info.hash_valid ? '<p class="note">The exported hash is not a valid MD5, SHA-1 or SHA-256 value, so no file lookup is offered.</p>' : ''}
        ${!hasValue(x.hash) && hasValue(x.file) ? '<p class="note">No hash in this row — a file name alone does not reliably identify a file.</p>' : ''}
        ${info.links.length ? `<div class="intel-links">${info.links.map(l => `<a href="${esc(l.url)}" target="_blank" rel="noopener noreferrer">${esc(l.label)} ↗</a>`).join('')}</div><p class="note">Links open the indicator on the provider’s website only when clicked. Nothing has been fetched from them.</p>` : ''}`;
    } catch (e) { if (token === detailToken) $('intel').innerHTML = '<p class="note">Could not prepare investigation notes. Check that the Flask server is running.</p>'; }
  }

  /* ---------- review workflow (database mode) ---------- */
  const FIELD_NAMES = { status: 'Status', note: 'Note', action: 'Action (from export)', resolved: 'Resolved (from export)', severity: 'Severity (from export)' };
  async function loadCase(x, token) {
    try {
      const d = await api(`api/detections/${x.id}`); if (token !== detailToken) return;
      renderCase(x, d);
      const raw = Object.entries(d.raw || {}).filter(([, v]) => hasValue(v));
      if (raw.length) $('rawWrap').innerHTML = `<details class="raw"><summary>Exported fields (${raw.length})</summary><dl>${raw.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl></details>`;
    } catch (e) { if (token === detailToken && $('caseInfo')) $('caseInfo').textContent = 'Could not load review data: ' + e.message; }
  }
  function renderCase(x, d) {
    if (!$('case')) return;
    $('caseNote').value = d.note || ''; $('caseSave').disabled = true;
    const seen = d.imports.map(i => esc(i.name)).join(', ');
    $('caseInfo').innerHTML = `First stored ${esc(fmtWhen(d.first_seen))}${seen ? ` · in ${seen}` : ''}`;
    $('caseHistory').innerHTML = d.history.map(h => `<li>${esc(fmtWhen(h.at))} · <b>${esc(FIELD_NAMES[h.field] || h.field)}</b> ${h.field === 'note' ? (h.new ? 'updated' : 'cleared') : `${esc(C.STATUS_LABELS[h.old] || h.old || '—')} → ${esc(C.STATUS_LABELS[h.new] || h.new || '—')}`}</li>`).join('');
    $('case').querySelectorAll('[data-status]').forEach(b => b.onclick = () => saveCase(x, { status: b.dataset.status }));
    $('caseNote').oninput = () => { $('caseSave').disabled = $('caseNote').value === (d.note || ''); };
    $('caseNote').onkeydown = e => { e.stopPropagation(); if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) $('caseSave').click(); };
    $('caseSave').onclick = () => saveCase(x, { note: $('caseNote').value });
  }
  async function saveCase(x, patch) {
    try {
      const d = await api(`api/detections/${x.id}`, { method: 'PATCH', body: JSON.stringify(patch) });
      x.status = d.status; x.has_note = !!d.note;
      $('case').querySelectorAll('[data-status]').forEach(b => b.setAttribute('aria-pressed', b.dataset.status === d.status));
      renderCase(x, d); $('caseInfo').textContent = patch.note !== undefined ? 'Note saved.' : `Marked as ${C.STATUS_LABELS[d.status]}.`;
      renderMetrics(); renderTable(); updateVisibility();
    } catch (e) { $('caseInfo').textContent = 'Could not save: ' + e.message; }
  }
  $('bulkStatus').onchange = () => {
    const st = $('bulkStatus').value, n = state.filtered.filter(x => x.id && x.status !== st).length;
    $('bulkApply').disabled = !st || !n; $('bulkApply').textContent = st ? `Apply to ${n.toLocaleString()}` : 'Apply';
  };
  $('bulkApply').onclick = () => armed($('bulkApply'), async () => {
    const st = $('bulkStatus').value, ids = state.filtered.filter(x => x.id && x.status !== st).map(x => x.id);
    try {
      const r = await api('api/detections/status', { method: 'POST', body: JSON.stringify({ ids, status: st }) });
      for (const x of state.filtered) if (x.id) x.status = st;
      $('bulkStatus').value = ''; $('bulkStatus').onchange(); render();
      message(`${r.changed.toLocaleString()} detection${r.changed === 1 ? '' : 's'} marked as ${C.STATUS_LABELS[st]}.`);
    } catch (e) { message('Could not update review status: ' + e.message); }
  });
  // Two-step confirmation without browser dialogs.
  function armed(btn, action) {
    if (btn.classList.contains('armed')) { btn.classList.remove('armed'); btn.textContent = btn.dataset.label; clearTimeout(btn._t); action(); return; }
    btn.dataset.label = btn.textContent; btn.classList.add('armed'); btn.textContent = 'Click again to confirm';
    btn._t = setTimeout(() => { btn.classList.remove('armed'); btn.textContent = btn.dataset.label; }, 4000);
  }

  /* ---------- local database ---------- */
  async function loadFromDB(quiet) {
    try {
      const d = await api('api/detections');
      state.db = d.stats; state.dbAvailable = true;
      $('dbBadge').hidden = !d.stats.detections; $('dbBadge').textContent = d.stats.detections.toLocaleString();
      if (!d.rows.length) { if (state.mode === 'db') { state.mode = 'demo'; state.demo = true; state.data = C.demoData(Date.now()); } return false; }
      state.data = C.fromDatabase(d.columns, d.rows); state.mode = 'db'; state.demo = false; state.geoState = 'ready';
      return true;
    } catch (e) {
      state.dbAvailable = false;
      if (!quiet) message('The local database is unavailable (' + e.message + '). Imported data will only be kept in this tab.');
      if (state.mode === 'db') state.mode = 'memory';
      return false;
    }
  }
  function refreshAll() { setupFilters(); updateSource(); render(); if (state.view === 'database') renderDatabase(); }

  async function renderDatabase() {
    let info, health = null;
    try { [info, health] = await Promise.all([api('api/imports'), api('healthz').catch(() => null)]); }
    catch (e) { $('dbStats').innerHTML = `<div class="empty">The local database is unavailable: ${esc(e.message)}</div>`; $('dbImports').innerHTML = ''; return; }
    const st = info.stats, by = st.by_status, mb = (info.size_bytes / 1048576).toFixed(info.size_bytes > 10485760 ? 0 : 1);
    const range = st.oldest ? `${C.localDay(st.oldest)} → ${C.localDay(st.newest)}` : 'No dated detections';
    $('dbStats').innerHTML = [['Stored detections', st.detections.toLocaleString(), range], ['Imports', st.imports.toLocaleString(), `${mb} MB on disk`],
      ['Awaiting review', by.new.toLocaleString(), `${by.investigating.toLocaleString()} investigating`], ['Closed', (by.closed + by.false_positive).toLocaleString(), `${by.false_positive.toLocaleString()} false positives`]]
      .map(([l, v, sub]) => `<div class="metric"><div class="metric-label">${l}</div><strong>${v}</strong><small>${esc(sub)}</small></div>`).join('');
    $('dbPath').textContent = `Stored in ${info.path}`;
    $('dbImports').innerHTML = info.imports.length ? `<div class="table-scroll"><table class="db-imports"><thead><tr><th><button disabled>File</button></th><th><button disabled>Rows</button></th><th><button disabled>New</button></th><th></th></tr></thead><tbody>${info.imports.map(i => `<tr>
        <td>${esc(i.name)}<small>${esc(fmtWhen(i.imported_at))}</small></td><td>${i.rows_total.toLocaleString()}</td>
        <td>${i.rows_new.toLocaleString()}<small>${i.rows_updated ? `${i.rows_updated.toLocaleString()} updated · ` : ''}${i.rows_duplicate.toLocaleString()} already stored</small></td>
        <td><button class="mini-del danger" data-del="${i.id}">Delete</button></td></tr>`).join('')}</tbody></table></div>`
      : '<div class="empty">Nothing imported yet. Use Import CSV to start your database.</div>';
    $('dbImports').querySelectorAll('[data-del]').forEach(b => b.onclick = () => armed(b, async () => {
      try { const r = await api(`api/imports/${b.dataset.del}`, { method: 'DELETE' }); message(`Import deleted; ${r.removed.toLocaleString()} detections removed.`); await loadFromDB(); refreshAll(); }
      catch (e) { message('Could not delete the import: ' + e.message); }
    }));
    const geo = health && health.geodb;
    $('geoStatus').textContent = geo && geo.configured ? `GeoDB: ${geo.type || 'MMDB'}${geo.build_epoch ? `, built ${C.localDay(geo.build_epoch * 1000)}` : ''}. Re-run after updating the .mmdb file.` : 'No GeoDB found. Put GeoLite2-City.mmdb in the data folder (or set GEODB_PATH) to locate IPs.';
    $('dbRelocate').disabled = !(geo && geo.configured) || !st.detections;
    $('dbBackup').disabled = !st.detections; $('dbPurge').disabled = !st.detections; $('dbWipe').disabled = !st.detections;
  }
  $('manageDb').onclick = () => setView('database');
  $('dbBackup').onclick = () => { const a = document.createElement('a'); a.href = 'api/backup'; a.download = ''; document.body.append(a); a.click(); a.remove(); };
  $('dbRelocate').onclick = async () => {
    $('dbRelocate').disabled = true; $('dbRelocate').textContent = 'Locating…';
    try { const r = await api('api/relocate', { method: 'POST', body: '{}' }); message(`GeoDB located ${r.located.toLocaleString()} of ${r.checked.toLocaleString()} public IP addresses.`); await loadFromDB(); refreshAll(); }
    catch (e) { message('GeoDB lookup failed: ' + e.message); }
    finally { $('dbRelocate').textContent = 'Locate all IPs'; $('dbRelocate').disabled = false; }
  };
  $('dbPurge').onclick = () => {
    const days = Math.floor(Number($('purgeDays').value));
    if (!(days >= 1)) { message('Enter a number of days (1 or more).'); return; }
    armed($('dbPurge'), async () => {
      try { const r = await api('api/purge', { method: 'POST', body: JSON.stringify({ older_than_days: days }) }); message(`${r.removed.toLocaleString()} detections older than ${days} days deleted.`); await loadFromDB(); refreshAll(); }
      catch (e) { message('Purge failed: ' + e.message); }
    });
  };
  $('dbWipe').onclick = () => armed($('dbWipe'), async () => {
    try { const r = await api('api/purge', { method: 'POST', body: JSON.stringify({ everything: true }) }); message(`Database cleared (${r.removed.toLocaleString()} detections deleted).`); await loadFromDB(); if (state.mode !== 'db') { state.data = C.demoData(Date.now()); state.demo = true; state.mode = 'demo'; } reset(); refreshAll(); }
    catch (e) { message('Could not clear the database: ' + e.message); }
  });

  /* ---------- import ---------- */
  $('upload').onclick = () => $('file').click();
  $('file').onchange = e => { const f = e.target.files[0]; e.target.value = ''; if (f) readFile(f); };
  async function readFile(file) {
    try {
      if (file.size > 25 * 1024 * 1024) throw Error('Please use a CSV smaller than 25 MB.');
      const text = await file.text();
      if (text.includes('\u0000')) throw Error('This file looks binary or UTF-16. Please export or save the CSV with UTF-8 encoding.');
      const rows = C.parseCSV(text), headers = rows[0].map(h => h.trim() || '(blank header)');
      let saved = null; try { saved = JSON.parse(store.get('sentinel-mapping:' + C.headerSignature(headers)) || 'null'); } catch (e) { saved = null; }
      const map = C.autoMap(headers, saved), sample = rows.slice(1, 4);
      state.pending = { headers, rows: rows.slice(1), name: file.name };
      const dupes = headers.filter((h, i) => headers.indexOf(h) !== i);
      $('mapping').innerHTML = Object.keys(C.FIELDS).map(f => `<label><span>${C.FIELD_LABELS[f]}</span><select data-field="${f}"><option value="-1">Not in export</option>${headers.map((h, i) => `<option value="${i}" ${i === map[f] ? 'selected' : ''}>${esc(h)} · col ${i + 1}</option>`).join('')}</select><small class="sample" data-sample="${f}"></small></label>`).join('');
      const showSample = sel => { const i = Number(sel.value), v = i >= 0 ? sample.map(r => (r[i] || '').trim()).find(Boolean) : ''; sel.nextElementSibling.textContent = i < 0 ? '' : v ? `e.g. ${v.length > 60 ? v.slice(0, 57) + '…' : v}` : 'empty in first rows'; };
      $('mapping').querySelectorAll('select').forEach(s => { showSample(s); s.onchange = () => showSample(s); });
      $('importInfo').innerHTML = `<b>${esc(file.name)}</b> · ${(rows.length - 1).toLocaleString()} rows · ${headers.length} columns${saved ? ' · using your saved mapping' : ''}${dupes.length ? `<br><span class="error">Duplicate headers: ${esc([...new Set(dupes)].join(', '))} — check the mapping.</span>` : ''}`;
      $('dbNote').hidden = state.dbAvailable === false; $('appendWrap').hidden = state.dbAvailable !== false || state.mode !== 'memory';
      $('appendImport').checked = false; $('importError').textContent = ''; $('applyImport').disabled = false;
      $('importDialog').showModal();
    } catch (err) { message(err.message); }
  }
  $('applyImport').onclick = () => {
    const p = state.pending; if (!p) return;
    const map = {}; document.querySelectorAll('[data-field]').forEach(s => map[s.dataset.field] = Number(s.value));
    if (map.threat < 0 && map.ip < 0 && map.computer < 0 && map.cause < 0) { $('importError').textContent = 'Map at least Detection name, IP address or Computer.'; return; }
    if ($('rememberMap').checked) store.set('sentinel-mapping:' + C.headerSignature(p.headers), JSON.stringify(map));
    const rows = C.buildRows(p.headers, p.rows, map);
    if (state.dbAvailable !== false) return uploadToDB(p, rows);
    const append = state.mode === 'memory' && $('appendImport').checked;
    state.data = append ? state.data.concat(rows) : rows;
    state.demo = false; state.mode = 'memory'; state.sourceName = append ? `${state.sourceName} + ${p.name}` : p.name; state.pending = null; state.geoState = 'idle';
    $('importDialog').close(); updateSource();
    const undated = rows.filter(x => !Number.isFinite(x.t)).length;
    message(undated ? `${undated.toLocaleString()} row${undated === 1 ? ' has' : 's have'} a missing or unrecognized date. They appear under All time; time filters exclude them.` : '');
    setupFilters(); reset(); enrichGeo(true);
  };
  async function uploadToDB(p, rows) {
    $('applyImport').disabled = true;
    const status = t => { $('importError').innerHTML = t; };
    let totals = { new: 0, updated: 0, duplicate: 0 };
    try {
      const { id } = await api('api/imports', { method: 'POST', body: JSON.stringify({ name: p.name }) });
      const CHUNK = 1000;
      for (let i = 0; i < rows.length; i += CHUNK) {
        status(`<span class="progress"><i style="width:${Math.round(i / rows.length * 100)}%"></i></span> Saving ${Math.min(i + CHUNK, rows.length).toLocaleString()} / ${rows.length.toLocaleString()} rows…`);
        const r = await api(`api/imports/${id}/rows`, { method: 'POST', body: JSON.stringify({ rows: rows.slice(i, i + CHUNK).map(C.toUpload) }) });
        totals = { new: totals.new + r.new, updated: totals.updated + r.updated, duplicate: totals.duplicate + r.duplicate };
      }
    } catch (e) {
      $('applyImport').disabled = false;
      status(`<span class="error">Could not save to the local database: ${esc(e.message)}. Check that Sentinel is running and try again.</span>`);
      return;
    }
    state.pending = null; $('importDialog').close();
    await loadFromDB(); reset(); refreshAll();
    const undated = rows.filter(x => !Number.isFinite(x.t)).length;
    message(`${p.name}: ${totals.new.toLocaleString()} new detection${totals.new === 1 ? '' : 's'} stored` +
      (totals.updated ? `, ${totals.updated.toLocaleString()} updated with newer export values` : '') +
      (totals.duplicate ? `, ${totals.duplicate.toLocaleString()} already in the database` : '') + '.' +
      (undated ? ` ${undated.toLocaleString()} row${undated === 1 ? ' has no recognizable date and appears' : 's have no recognizable date and appear'} only under All time.` : ''));
  }
  function updateSource() {
    $('dataset').textContent = state.mode === 'db' ? 'LOCAL DATABASE' : state.demo ? 'DEMO DATA' : 'IMPORTED CSV'; $('dataset').classList.toggle('imported', !state.demo);
    const st = state.db;
    $('sourceText').textContent = state.mode === 'db' ? `${state.data.length.toLocaleString()} detections from ${st.imports.toLocaleString()} import${st.imports === 1 ? '' : 's'} · ${st.by_status.new.toLocaleString()} awaiting review · saved in the local database`
      : state.demo ? 'You’re exploring synthetic sample detections. Import an ESET CSV — or drop it anywhere on this page — to start your local database.'
      : `${state.sourceName} · ${state.data.length.toLocaleString()} detection rows · held only in this browser tab (database unavailable)`;
    $('loadDemo').hidden = state.mode !== 'memory'; $('sample').hidden = !state.demo; $('manageDb').hidden = state.mode !== 'db';
    $('footerNote').textContent = state.mode === 'memory' ? 'The database is unavailable: imported data is held in this tab only and is cleared on reload.' : 'Imported detections are stored in a local SQLite database on this server. Nothing is sent to external services.';
  }
  $('loadDemo').onclick = () => { state.data = C.demoData(Date.now()); state.demo = true; state.mode = 'demo'; state.geoState = 'idle'; updateSource(); message(''); setupFilters(); reset(); };

  // Drag & drop anywhere on the page.
  let dragDepth = 0;
  const isFileDrag = e => [...(e.dataTransfer?.types || [])].includes('Files');
  window.addEventListener('dragenter', e => { if (!isFileDrag(e)) return; e.preventDefault(); dragDepth++; $('dropZone').hidden = false; });
  window.addEventListener('dragover', e => { if (isFileDrag(e)) e.preventDefault(); });
  window.addEventListener('dragleave', e => { if (!isFileDrag(e)) return; if (--dragDepth <= 0) { dragDepth = 0; $('dropZone').hidden = true; } });
  window.addEventListener('drop', e => { if (!isFileDrag(e)) return; e.preventDefault(); dragDepth = 0; $('dropZone').hidden = true; const f = e.dataTransfer.files[0]; if (f) readFile(f); });

  /* ---------- export ---------- */
  const EXPORT_COLS = [['Occurred', x => x.date], ['Detection name', 'threat'], ['Detection type', 'type'], ['Severity', 'severity'], ['Computer name', 'computer'], ['User', 'user'],
    ['IP address', 'ip'], ['Country', 'country'], ['Action taken', 'action'], ['Resolved', 'resolved'], ['Occurrences', 'occurrences'], ['Object', 'file'], ['Hash', 'hash'], ['Process name', 'process'], ['Cause', 'cause']];
  function download(rows, name) {
    const csv = C.toCSV(rows, EXPORT_COLS.map(c => c[1]), EXPORT_COLS.map(c => c[0]));
    const url = URL.createObjectURL(new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8' })), a = document.createElement('a');
    a.href = url; a.download = name; document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  $('export').onclick = () => download(state.sorted, `sentinel-detections-${C.localDay(Date.now())}.csv`);
  $('sample').onclick = () => download(C.demoData(Date.now()), 'eset-sample-detections.csv');
  $('print').onclick = () => window.print();

  /* ---------- geo enrichment through the local Flask server ---------- */
  let geoVersion = 0;
  async function enrichGeo(auto) {
    const current = ++geoVersion, snapshot = state.data;
    const ips = [...new Set(state.data.map(x => x.ip).filter(ip => C.isIP(ip) && !C.privateIP(ip)))];
    if (!ips.length) { if (!auto) message('No public IP addresses to locate. Internal and reserved addresses are never geolocated.'); return; }
    state.geoState = 'loading'; $('locate').disabled = true; updateVisibility();
    let error = '', located = 0;
    try {
      for (let offset = 0; offset < ips.length; offset += 500) {
        $('locate').textContent = `Locating ${Math.min(offset + 500, ips.length).toLocaleString()} / ${ips.length.toLocaleString()}`;
        const response = await fetch('geolocate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ips: ips.slice(offset, offset + 500) }) });
        const payload = await response.json(); if (current !== geoVersion || state.data !== snapshot) return;
        const results = payload.results || {};
        for (const row of state.data) {
          const r = results[row.ip]; if (!r) continue; row.geo = r;
          if (r.status === 'internal') row.country = 'Internal network';
          else if (r.status === 'located') { row.country = C.canonicalCountry(r.country_code || r.country); located++; }
        }
        if (!response.ok) { error = payload.error || 'Local GeoDB lookup unavailable.'; break; }
      }
      state.geoState = error ? 'error' : 'ready'; setupFilters(); render();
      const prior = auto ? $('messageText').textContent : '';
      message((prior ? prior + ' ' : '') + (error ? (auto ? `Country data comes from the CSV only — ${error}` : error) : `GeoDB located ${located.toLocaleString()} rows. Internal and unknown IPs stay labeled. Locations are approximate and country-level.`));
    } catch (e) {
      if (current === geoVersion) { state.geoState = 'error'; message('Could not reach the local GeoDB lookup. Check that Flask is running.'); updateVisibility(); }
    } finally {
      if (current === geoVersion) { $('locate').disabled = false; $('locate').textContent = 'Locate with GeoDB'; }
    }
  }
  $('locate').onclick = () => state.mode === 'db' ? $('dbRelocate').onclick() : enrichGeo(false);

  /* ---------- views, theme, keyboard ---------- */
  function setView(view, push) {
    if (!VIEWS[view]) view = 'overview';
    state.view = view; document.body.dataset.view = view;
    document.querySelectorAll('.nav').forEach(n => { n.classList.toggle('active', n.dataset.view === view); n.setAttribute('aria-current', n.dataset.view === view ? 'page' : 'false'); });
    const [h, s, crumb] = VIEWS[view]; $('heading').textContent = h; $('subtitle').textContent = s; $('viewCrumb').textContent = crumb;
    if (push !== false && location.hash !== '#' + view) history.replaceState(null, '', '#' + view);
    updateVisibility();
    if (view === 'database') renderDatabase();
  }
  document.querySelectorAll('.nav').forEach(b => b.onclick = () => setView(b.dataset.view));
  window.addEventListener('hashchange', () => setView(location.hash.slice(1), false));

  function applyTheme(light) {
    document.body.classList.toggle('light', light);
    $('theme').textContent = light ? '☾ Switch to dark mode' : '☼ Switch to light mode';
  }
  $('theme').onclick = () => { const light = !document.body.classList.contains('light'); applyTheme(light); store.set('sentinel-theme', light ? 'light' : 'dark'); };
  applyTheme(store.get('sentinel-theme') === 'light');

  document.addEventListener('keydown', e => {
    if (e.key === '/' && !/INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName) && !document.querySelector('dialog[open]')) { e.preventDefault(); $('search').focus(); }
  });

  /* ---------- boot ---------- */
  setupFilters(); updateSource(); render(); setView(location.hash.slice(1) || 'overview', false);
  loadFromDB().then(found => { if (found) { reset(); refreshAll(); } else updateSource(); });
  fetch('static/world.json').then(r => { if (!r.ok) throw Error(); return r.json(); }).then(j => {
    state.world = j; state.centroids = C.computeCentroids(j); renderMap(); updateVisibility();
  }).catch(() => { state.basemapError = true; renderMap(); message('The local map basemap could not load. The country coordinate view remains available.'); updateVisibility(); });
})();
