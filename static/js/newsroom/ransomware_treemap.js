// ══════════════════════════════════════════════════════════════
// RANSOMWARE GROUP ACTIVITY TREEMAP (Exec dashboard)
// ══════════════════════════════════════════════════════════════

let _rwTmDays = 7;
let _rwTmData = null;

// Diverging color scale matching darkfeed Ransom View legend: green (drop) → gray (flat) → red (surge)
const _RWTM_STOPS = [
  [-100, [22, 163, 74]],
  [-50,  [41, 140, 84]],
  [-17,  [59, 118, 93]],
  [0,    [82, 90, 105]],
  [17,   [136, 72, 83]],
  [50,   [180, 57, 65]],
  [100,  [225, 42, 46]],
];

function _rwTmColorForPct(pct) {
  if (pct === null || pct === undefined) return 'rgb(140,20,24)'; // NEW
  const p = Math.max(-100, Math.min(100, pct));
  for (let i = 0; i < _RWTM_STOPS.length - 1; i++) {
    const [p0, c0] = _RWTM_STOPS[i], [p1, c1] = _RWTM_STOPS[i + 1];
    if (p >= p0 && p <= p1) {
      const t = (p - p0) / (p1 - p0);
      const c = c0.map((v, idx) => Math.round(v + (c1[idx] - v) * t));
      return `rgb(${c[0]},${c[1]},${c[2]})`;
    }
  }
  return 'rgb(82,90,105)';
}

function _rwTmFmtPct(pct) {
  if (pct === null || pct === undefined) return 'NEW';
  return (pct > 0 ? '+' : '') + pct + '%';
}

// Classic squarified treemap layout (Bruls et al.) — returns items augmented with x/y/w/h.
function _rwTmSquarify(items, x, y, w, h) {
  const result = [];
  const data = items.filter(d => d.value > 0).sort((a, b) => b.value - a.value);
  const total = data.reduce((s, d) => s + d.value, 0);
  if (!total || w <= 0 || h <= 0) return result;
  const scale = (w * h) / total;

  function worstAspect(row, rowTotal, sideLen) {
    const rowArea = rowTotal * scale;
    let maxA = 0;
    for (const d of row) {
      const a = d.value * scale;
      const ratio = Math.max((a * sideLen * sideLen) / (rowArea * rowArea), (rowArea * rowArea) / (a * sideLen * sideLen));
      if (ratio > maxA) maxA = ratio;
    }
    return maxA;
  }

  let rect = { x, y, w, h };
  let remaining = data;

  while (remaining.length) {
    const sideLen = Math.min(rect.w, rect.h);
    let row = [remaining[0]];
    let rowTotal = remaining[0].value;
    let best = worstAspect(row, rowTotal, sideLen);
    let i = 1;
    while (i < remaining.length) {
      const testRow = row.concat([remaining[i]]);
      const testTotal = rowTotal + remaining[i].value;
      const testAspect = worstAspect(testRow, testTotal, sideLen);
      if (testAspect <= best) {
        row = testRow; rowTotal = testTotal; best = testAspect; i++;
      } else break;
    }

    const rowArea = rowTotal * scale;
    if (rect.w >= rect.h) {
      const colW = rowArea / rect.h;
      let cy = rect.y;
      for (const d of row) {
        const itemH = (d.value / rowTotal) * rect.h;
        result.push({ ...d, x: rect.x, y: cy, w: colW, h: itemH });
        cy += itemH;
      }
      rect = { x: rect.x + colW, y: rect.y, w: rect.w - colW, h: rect.h };
    } else {
      const rowH = rowArea / rect.w;
      let cx = rect.x;
      for (const d of row) {
        const itemW = (d.value / rowTotal) * rect.w;
        result.push({ ...d, x: cx, y: rect.y, w: itemW, h: rowH });
        cx += itemW;
      }
      rect = { x: rect.x, y: rect.y + rowH, w: rect.w, h: rect.h - rowH };
    }
    remaining = remaining.slice(row.length);
  }
  return result;
}

function _rwTmRenderLegend() {
  const el = document.getElementById('rwtm-legend');
  if (!el) return;
  const labels = [-100, -50, -17, 0, 17, 50, 100];
  el.innerHTML = '<span>Activity change</span>' + labels.map(p =>
    `<span class="rw-tm-legend-cell" style="background:${_rwTmColorForPct(p)}">${p > 0 ? '+' : ''}${p}%</span>`
  ).join('');
}

function renderRwTreemap(data) {
  const el = document.getElementById('rwtm-map');
  if (!el) return;
  el.innerHTML = '';
  const groups = data?.groups || [];
  if (!groups.length) {
    el.innerHTML = '<div class="rw-tm-empty">No ransomware activity in the selected period</div>';
    return;
  }

  const w = el.clientWidth || 800;
  const h = el.clientHeight || 560;
  const tiles = _rwTmSquarify(groups.map(g => ({ ...g, value: g.cur })), 0, 0, w, h);

  tiles.forEach(t => {
    const bg = _rwTmColorForPct(t.pct);
    const div = document.createElement('div');
    div.className = 'rw-tile';
    div.style.cssText = `left:${t.x}px;top:${t.y}px;width:${t.w}px;height:${t.h}px;background:${bg}`;
    div.title = `${t.group} — ${t.cur} victim(s) — ${_rwTmFmtPct(t.pct)}`;
    const showText = t.w > 46 && t.h > 30;
    if (showText) {
      const fs = Math.max(9, Math.min(15, t.w / 8, t.h / 4));
      div.innerHTML = `
        <div class="rw-tile-ticker" style="font-size:${fs}px">${esc(t.group)}</div>
        ${t.h > 46 ? `<div class="rw-tile-pct" style="font-size:${fs * 0.72}px">${_rwTmFmtPct(t.pct)}</div>` : ''}
        ${t.h > 60 ? `<div class="rw-tile-count" style="font-size:${fs * 0.58}px">${t.cur} victims</div>` : ''}
      `;
    }
    div.onclick = () => openRwTreemapModal(t.group);
    el.appendChild(div);
  });
}

async function loadRwTreemap(days) {
  if (days) _rwTmDays = days;
  document.querySelectorAll('#rwtm-ranges button').forEach(b => {
    b.classList.toggle('active', Number(b.dataset.days) === _rwTmDays);
  });
  _rwTmRenderLegend();
  try {
    const resp = await fetch(`/api/ransomware/treemap?days=${_rwTmDays}`, { headers: _authAndClientHeaders() });
    const data = await resp.json();
    _rwTmData = data;
    renderRwTreemap(data);
  } catch (e) {
    const el = document.getElementById('rwtm-map');
    if (el) el.innerHTML = '<div class="rw-tm-empty">Failed to load ransomware activity</div>';
  }
}

function _rwTmInitials(name) {
  const parts = (name || '?').trim().split(/\s+/);
  return (parts.length > 1 ? parts[0][0] + parts[1][0] : (name || '?').slice(0, 2)).toUpperCase();
}

function _rwTmAvatarColor(name) {
  let h = 0;
  for (let i = 0; i < (name || '').length; i++) h = (h * 31 + name.charCodeAt(i)) % 360;
  return `hsl(${h},58%,42%)`;
}

const _RWTM_MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
function _rwTmMonthLabel(ym) {
  const [, m] = (ym || '').split('-');
  return _RWTM_MONTHS[Number(m) - 1] || ym;
}

function _rwTmStat(label, value, colorVar) {
  return `<div class="rw-modal-stat">
    <div class="rw-modal-stat-label">${esc(label)}</div>
    <div class="rw-modal-stat-value" style="${colorVar ? `color:${colorVar}` : ''}">${value}</div>
  </div>`;
}

function _rwTmRankRows(items) {
  if (!items || !items.length) return '<div class="rw-tm-empty" style="height:auto;padding:14px 0">No data</div>';
  const max = Math.max(...items.map(i => i.count));
  return items.map(i => `
    <div class="rw-rank-row">
      <div class="rw-rank-label" title="${esc(i.name)}">${esc(i.name)}</div>
      <div class="rw-rank-track"><div class="rw-rank-fill" style="width:${max ? Math.round((i.count / max) * 100) : 0}%"></div></div>
      <div class="rw-rank-value">${i.count}</div>
    </div>
  `).join('');
}

function _rwTmMonthChart(trend) {
  if (!trend || !trend.length) return '<div class="rw-tm-empty" style="height:190px">No historical data</div>';
  const W = 800, H = 190, padL = 30, padR = 10, padT = 16, padB = 24;
  const innerW = W - padL - padR, innerH = H - padT - padB;
  const max = Math.max(1, ...trend.map(t => t.count));
  const slot = innerW / trend.length;
  const barW = Math.min(30, slot * 0.55);
  let svg = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet">`;
  for (let g = 0; g <= 4; g++) {
    const gy = padT + innerH - (g / 4) * innerH;
    svg += `<line x1="${padL}" y1="${gy}" x2="${W - padR}" y2="${gy}" stroke="rgba(139,148,158,0.15)" stroke-width="1"/>`;
  }
  trend.forEach((t, i) => {
    const bh = Math.max(2, (t.count / max) * innerH);
    const bx = padL + slot * i + (slot - barW) / 2;
    const by = padT + innerH - bh;
    svg += `<rect x="${bx}" y="${by}" width="${barW}" height="${bh}" rx="3" fill="#DA3633"><title>${_rwTmMonthLabel(t.month)} — ${t.count} victim(s)</title></rect>`;
    svg += `<text x="${bx + barW / 2}" y="${by - 5}" text-anchor="middle" font-size="10" font-weight="700" fill="#e6edf3">${t.count}</text>`;
    svg += `<text x="${bx + barW / 2}" y="${H - 6}" text-anchor="middle" font-size="9" fill="#8b949e">${_rwTmMonthLabel(t.month)}</text>`;
  });
  svg += '</svg>';
  return svg;
}

function _rwTmVictimsTable(victims, group) {
  if (!victims || !victims.length) return '<div class="rw-tm-empty" style="height:auto;padding:14px 0">No victim records</div>';
  const rows = victims.map(v => `
    <tr>
      <td>${esc(v.published || '—')}</td>
      <td title="${esc(v.victim || '')}">${esc(v.victim || '—')}</td>
      <td>${esc(v.country || '—')}</td>
      <td>${esc(v.industry || '—')}</td>
      <td style="white-space:nowrap">
        <button class="rw-victim-edit-btn" data-id="${esc(v.id||'')}" data-country="${esc(v.country||'')}" data-industry="${esc(v.industry||'')}"
                onclick="openRwVictimEdit(this.dataset.id, this.dataset.country, this.dataset.industry, () => openRwTreemapModal('${esc(group)}'))"
                style="background:none;border:none;color:var(--text-dim);cursor:pointer;font-size:11px;padding:0" title="Edit country / industry">${ic("edit", 11)}</button>
        ${v.post_url && v.post_url !== 'Unknown' ? `<a href="${esc(v.post_url)}" target="_blank" rel="noopener" style="margin-left:6px">${ic("external-link", 11)}</a>` : ''}
      </td>
    </tr>
  `).join('');
  return `<table class="rw-victims-table">
    <thead><tr><th>Date</th><th>Company</th><th>Country</th><th>Industry</th><th></th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

async function _rwTmIsWatched(group) {
  try {
    const resp = await fetch('/api/ta/watchlist-names', { headers: _clientHeader() });
    if (!resp.ok) return false;
    const d = await resp.json();
    return (d.names || []).some(n => n.toLowerCase() === group.toLowerCase());
  } catch (e) { return false; }
}

function _rwTmWatchBtnHTML(group, watched) {
  return watched
    ? `<button class="ta-watch-btn watched" data-name="${esc(group)}" onclick="rwTmToggleWatch(this.dataset.name, true)" title="Remove from watchlist">${ic("circle-dot", 11)} UNWATCH</button>`
    : `<button class="ta-watch-btn" data-name="${esc(group)}" onclick="rwTmToggleWatch(this.dataset.name, false)" title="Add to threat actor watchlist">${ic("plus-circle", 11)} WATCH</button>`;
}

async function rwTmToggleWatch(group, watched) {
  if (watched) {
    showConfirmModal({
      title: 'Remove from Watchlist',
      okLabel: `${ic('x', 12)} Remove`,
      okColor: 'var(--red)',
      body: `<p style="font-size:13px;color:var(--text);line-height:1.7">Remove <strong style="color:var(--accent)">${esc(group)}</strong> from the threat actor watchlist?</p>`,
      onConfirm: async () => {
        requireTAAuth(async (password) => {
          try {
            const resp = await fetch(`/api/ta/watchlist/${encodeURIComponent(group)}`, {
              method: 'DELETE',
              headers: { 'Authorization': 'Bearer ' + password, ..._clientHeader() },
            });
            if (resp.status === 401) { _authFailed(); return; }
            const d = await resp.json();
            if (d.success) {
              _cveToast(`"${group}" removed from watchlist`, true);
              _rwTmRefreshWatchBtn(group, false);
            }
          } catch (e) { _cveToast('Failed to remove from watchlist', false); }
        });
      },
    });
  } else {
    requireTAAuth(async (password) => {
      try {
        const resp = await fetch('/api/ta/watchlist', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + password, ..._clientHeader() },
          body: JSON.stringify({ name: group }),
        });
        if (resp.status === 401) { _authFailed(); return; }
        const d = await resp.json();
        if (d.success) {
          _cveToast(`"${group}" added to watchlist`, true);
          _rwTmRefreshWatchBtn(group, true);
        } else {
          _cveToast(`"${group}" already in watchlist`, false);
        }
      } catch (e) { _cveToast('Failed to add to watchlist', false); }
    });
  }
}

function _rwTmRefreshWatchBtn(group, watched) {
  const btn = document.querySelector(`#rwtm-modal-body .ta-watch-btn[data-name="${CSS.escape(group)}"]`);
  if (btn) btn.outerHTML = _rwTmWatchBtnHTML(group, watched);
}

// ── LEAK SITES (dls-monitor): hosts shown defanged + non-clickable; copy only ──
function _rwTmDlsSection(dls) {
  if (!dls) return '<div class="rw-tm-empty" style="height:60px">No leak-site data for this group</div>';
  const flag = (on, label) => on ? `<span style="font-size:10px;padding:1px 6px;border:1px solid var(--border);border-radius:8px;margin-right:4px">${label}</span>` : '';
  const upColor = dls.hosts_up > 0 ? 'var(--green)' : 'var(--red)';
  const hosts = (dls.hosts || []).map(h => `
    <div style="display:flex;align-items:center;gap:8px;padding:4px 0;font-size:11px">
      <span title="${h.available ? 'Up' : 'Down'}" >${statusDot(h.available ? "online" : "danger")}</span>
      <code style="word-break:break-all;flex:1">${esc(h.host)}</code>
      <span style="color:var(--text-dim)">v${esc(h.version ?? '?')}</span>
      <button class="rw-victim-edit-btn" data-host="${esc(h.host)}" onclick="navigator.clipboard?.writeText(this.dataset.host)" style="background:none;border:none;color:var(--text-dim);cursor:pointer;font-size:11px" title="Copy defanged host">${ic("copy", 11)}</button>
    </div>`).join('');
  const refs = (dls.profile_urls || []).slice(0, 8).map(u =>
    `<div style="font-size:11px;word-break:break-all"><a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u)}</a></div>`).join('');
  return `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;font-size:11px">
      <span style="color:${upColor};font-weight:600">${dls.hosts_up}/${dls.hosts_total} hosts up</span>
      <span style="color:var(--text-dim)">Last scrape: ${esc((dls.last_scrape || '—').toString().slice(0, 16))}</span>
    </div>
    <div style="margin-bottom:6px">${flag(dls.flags?.captcha, 'CAPTCHA')}${flag(dls.flags?.javascript_render, 'JS render')}${flag(dls.flags?.parser, 'Parsed')}</div>
    ${dls.meta ? `<div style="font-size:11px;color:var(--text-dim);margin-bottom:6px">${esc(dls.meta)}</div>` : ''}
    ${hosts}
    ${refs ? `<div style="margin-top:8px;border-top:1px solid var(--border);padding-top:6px"><div style="font-size:10px;color:var(--text-dim);margin-bottom:2px">References</div>${refs}</div>` : ''}`;
}

async function openRwTreemapModal(group) {
  const overlay = document.getElementById('rwtm-modal-overlay');
  const body = document.getElementById('rwtm-modal-body');
  if (!overlay || !body) return;
  body.innerHTML = '<div class="loading-state"><div class="loading-spinner"></div><div class="loading-text">Loading...</div></div>';
  overlay.classList.add('open');
  document.body.style.overflow = 'hidden';
  try {
    const [resp, watched] = await Promise.all([
      fetch(`/api/ransomware/group-detail?group=${encodeURIComponent(group)}`, { headers: _authAndClientHeaders() }),
      _rwTmIsWatched(group),
    ]);
    const d = await resp.json();
    const tile = (_rwTmData?.groups || []).find(g => g.group === group);

    body.innerHTML = `
      <div class="rw-modal-header">
        <div class="rw-modal-avatar" style="background:${_rwTmAvatarColor(group)}">${esc(_rwTmInitials(group))}</div>
        <div class="rw-modal-title">
          <h2>${esc(group)}</h2>
          <p>Ransomware group · full profile</p>
        </div>
        ${_rwTmWatchBtnHTML(group, watched)}
        <button class="modal-close" onclick="closeRwTreemapModal()" style="position:static">${ic("x", 14)}</button>
      </div>

      <div class="rw-modal-stats">
        ${_rwTmStat('Total victims (all-time)', d.total_volume ?? 0)}
        ${tile ? _rwTmStat(`Victims (${_rwTmDays}d)`, tile.cur) : ''}
        ${tile ? _rwTmStat('Change', _rwTmFmtPct(tile.pct), tile.pct === null || tile.pct >= 0 ? 'var(--red)' : 'var(--green)') : ''}
        ${_rwTmStat('Top industry', esc(d.top_industry || '—'))}
        ${_rwTmStat('Top country', esc(d.top_country || '—'))}
      </div>

      <div class="rw-modal-section">
        <div class="rw-modal-section-title">Attacks — last 12 months</div>
        <div class="rw-modal-card rw-tm-chart-wrap">${_rwTmMonthChart(d.monthly_trend)}</div>
      </div>

      <div class="rw-modal-grid">
        <div class="rw-modal-section">
          <div class="rw-modal-section-title">Most targeted industries</div>
          <div class="rw-modal-card">${_rwTmRankRows(d.top_industries)}</div>
        </div>
        <div class="rw-modal-section">
          <div class="rw-modal-section-title">Most targeted countries</div>
          <div class="rw-modal-card">${_rwTmRankRows(d.top_countries)}</div>
        </div>
      </div>

      <div class="rw-modal-section">
        <div class="rw-modal-section-title">Leak sites (source: dls-monitor)</div>
        <div class="rw-modal-card">${_rwTmDlsSection(d.dls)}</div>
      </div>

      <div class="rw-modal-section" style="margin-bottom:0">
        <div class="rw-modal-section-title">Latest victims</div>
        <div class="rw-modal-card" style="padding:0;overflow:hidden">${_rwTmVictimsTable(d.recent_victims, group)}</div>
      </div>
    `;
  } catch (e) {
    body.innerHTML = '<div class="rw-tm-empty">Failed to load group detail</div>';
  }
}

function closeRwTreemapModal() {
  document.getElementById('rwtm-modal-overlay')?.classList.remove('open');
  document.body.style.overflow = '';
}

document.querySelectorAll('#rwtm-ranges button').forEach(btn => {
  btn.addEventListener('click', () => loadRwTreemap(Number(btn.dataset.days)));
});

window.addEventListener('resize', () => { if (_rwTmData) renderRwTreemap(_rwTmData); });

// ── RANSOMWARE VICTIMS — FULL LIST MODAL ──
// Compact panel table is too small to read comfortably; this modal gives room
// to browse + edit the full victim list without cramming edit controls into the panel.
let _rwFullPage = 1;
const RW_FULL_PAGE_SIZE = 50;

function openRwVictimsFullModal() {
  document.getElementById('rw-full-modal-overlay')?.classList.add('open');
  document.body.style.overflow = 'hidden';
  loadRwVictimsFull(1);
}

function closeRwVictimsFullModal() {
  document.getElementById('rw-full-modal-overlay')?.classList.remove('open');
  document.body.style.overflow = '';
}

function _rwFullVictimsTable(victims) {
  if (!victims || !victims.length) return '<div class="rw-tm-empty" style="height:120px">No victim records</div>';
  const rows = victims.map(v => `
    <tr>
      <td style="color:#DA3633;font-weight:600" title="${esc(v.group_name||'')}">${esc(v.group_name||'—')}</td>
      <td title="${esc(v.victim||'')}">${esc(v.victim||'—')}</td>
      <td>${esc(v.country||'—')}</td>
      <td>${esc(v.industry||'—')}</td>
      <td>${esc((v.published||'').slice(0,10))||'—'}</td>
      <td style="white-space:nowrap">
        <button class="rw-victim-edit-btn" data-id="${esc(v.id||'')}" data-country="${esc(v.country||'')}" data-industry="${esc(v.industry||'')}"
                onclick="openRwVictimEdit(this.dataset.id, this.dataset.country, this.dataset.industry, () => loadRwVictimsFull(_rwFullPage))"
                style="background:none;border:none;color:var(--text-dim);cursor:pointer;font-size:11px;padding:0" title="Edit country / industry">${ic("edit", 11)}</button>
        ${v.post_url && v.post_url !== 'Unknown' ? `<a href="${esc(v.post_url)}" target="_blank" rel="noopener" style="margin-left:6px">${ic("external-link", 11)}</a>` : ''}
      </td>
    </tr>
  `).join('');
  return `<table class="rw-victims-table">
    <thead><tr><th>Group</th><th>Company</th><th>Country</th><th>Industry</th><th>Published</th><th></th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

async function loadRwVictimsFull(page) {
  _rwFullPage = page || 1;
  const body = document.getElementById('rw-full-modal-body');
  if (!body) return;
  body.innerHTML = '<div class="loading-state"><div class="loading-spinner"></div><div class="loading-text">Loading...</div></div>';

  const group    = document.getElementById('rwf-f-group')?.value.trim() || '';
  const country  = document.getElementById('rwf-f-country')?.value.trim() || '';
  const industry = document.getElementById('rwf-f-industry')?.value.trim() || '';
  const params = new URLSearchParams({ page: _rwFullPage, page_size: RW_FULL_PAGE_SIZE });
  if (group) params.set('group', group);
  if (country) params.set('country', country);
  if (industry) params.set('industry', industry);

  try {
    const resp = await fetch(`/api/ransomware/victims?${params}`, { headers: _authAndClientHeaders() });
    const d = await resp.json();
    body.innerHTML = _rwFullVictimsTable(d.victims);

    const countEl = document.getElementById('rwf-count');
    if (countEl) countEl.textContent = `${d.total} victim(s)`;

    const totalPages = Math.ceil(d.total / RW_FULL_PAGE_SIZE);
    const pagerEl = document.getElementById('rwf-pager');
    if (pagerEl) {
      pagerEl.innerHTML = totalPages > 1
        ? `Page ${_rwFullPage} / ${totalPages} &nbsp;`
          + (_rwFullPage > 1 ? `<button class="btn-apply" style="font-size:10px;padding:2px 8px;margin:0 2px" onclick="loadRwVictimsFull(${_rwFullPage-1})">${ic("chevron-left", 11)} Prev</button>` : '')
          + (_rwFullPage < totalPages ? `<button class="btn-apply" style="font-size:10px;padding:2px 8px;margin:0 2px" onclick="loadRwVictimsFull(${_rwFullPage+1})">Next ${ic("chevron-right", 11)}</button>` : '')
        : '';
    }
  } catch (e) {
    body.innerHTML = '<div class="rw-tm-empty">Failed to load victims</div>';
  }
}

// ── MANUAL VICTIM ENRICHMENT (country/industry) — analyst edit, shared by
//    the Ransomware Activity panel table and this treemap's group-detail modal ──
let _rwEditState = null;

function _rwPlaceholderVal(v) {
  return (v && v !== '-' && v.toLowerCase() !== 'not found') ? v : '';
}

function openRwVictimEdit(id, country, industry, onSaved) {
  if (!id) { _cveToast('Missing record id — cannot edit', false); return; }
  _rwEditState = { id, onSaved };
  document.getElementById('rw-edit-country').value = _rwPlaceholderVal(country);
  document.getElementById('rw-edit-industry').value = _rwPlaceholderVal(industry);
  document.getElementById('rw-edit-modal-overlay').classList.add('open');
  document.body.style.overflow = 'hidden';
}

function closeRwVictimEdit() {
  document.getElementById('rw-edit-modal-overlay')?.classList.remove('open');
  document.body.style.overflow = '';
  _rwEditState = null;
}

function saveRwVictimEdit() {
  if (!_rwEditState) return;
  const { id, onSaved } = _rwEditState;
  const country = document.getElementById('rw-edit-country').value.trim();
  const industry = document.getElementById('rw-edit-industry').value.trim();

  requireTAAuth(async (password) => {
    try {
      const resp = await fetch(`/api/ransomware/victims/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + password },
        body: JSON.stringify({ country: country || null, industry: industry || null }),
      });
      if (resp.status === 401) { _authFailed(); return; }
      if (!resp.ok) { _cveToast('Failed to save changes', false); return; }
      _cveToast('Victim record updated', true);
      closeRwVictimEdit();
      if (onSaved) onSaved();
    } catch (e) { _cveToast('Failed to save changes', false); }
  });
}
