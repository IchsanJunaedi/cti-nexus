// ── BRAND WATCH (favicon hash + Shodan search, scanned by ScraperNewsRevamp) ──
const _bwState = { page: 1, pageSize: 50, total: 0 };
let   _bwMap   = {};  // _id → brand doc

function _bwStatus(msg, ok) {
  const el = document.getElementById('bw-status');
  if (!el) return;
  el.textContent = msg;
  el.className = `ta-status show ${ok ? 'ok' : 'err'}`;
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('show'), 4000);
}

function _bwCountBadge(n, color) {
  if (!n) return `<span style="font-size:11px;color:var(--text-dim)">0</span>`;
  return `<span style="font-family:var(--font-ui);font-size:11px;font-weight:600;color:${color}">${n}</span>`;
}

// ── Stats ─────────────────────────────────────────────────────

async function bwLoadStats() {
  try {
    const resp = await fetch('/api/brandwatch/stats', { headers: _authAndClientHeaders() });
    if (resp.status === 401) { _authFailed(); return; }
    if (!resp.ok) return;
    const d = await resp.json();
    document.getElementById('bw-stat-brands').textContent    = d.brands ?? '—';
    document.getElementById('bw-stat-matches').textContent   = d.total_matches ?? '—';
    document.getElementById('bw-stat-new').textContent       = d.new_matches ?? '—';
    document.getElementById('bw-stat-suspicious').textContent = d.suspicious ?? '—';
    document.getElementById('bw-stat-unacked').textContent   = d.unacknowledged ?? '—';
  } catch(e) { console.error('bw stats error:', e); }
}

// ── Watchlist ────────────────────────────────────────────────

async function loadBrandWatchPanel() {
  bwLoadStats();
  bwLoadDomains();
}

async function bwLoadDomains() {
  const tbody = document.getElementById('bw-tbody');
  tbody.innerHTML = `<tr><td colspan="9" class="ta-td">${loadingHTML()}</td></tr>`;

  try {
    const params = new URLSearchParams({ page: _bwState.page, page_size: _bwState.pageSize });
    const resp = await fetch(`/api/brandwatch/domains?${params}`, { headers: _authAndClientHeaders() });
    if (resp.status === 401) { _authFailed(); return; }
    if (!resp.ok) throw new Error(resp.statusText);
    const d = await resp.json();

    _bwState.total = d.total;
    _bwMap = {};

    if (!d.items.length) {
      tbody.innerHTML = `<tr><td colspan="9" class="ta-td">${emptyHTML('No brands watched — add a domain above')}</td></tr>`;
    } else {
      const offset = (_bwState.page - 1) * _bwState.pageSize;
      tbody.innerHTML = d.items.map((b, i) => {
        _bwMap[b._id] = b;
        const lastScan = b.last_scan ? b.last_scan.slice(0, 16).replace('T', ' ') : 'pending…';
        return `<tr>
          <td class="ta-td ta-num">${offset + i + 1}</td>
          <td class="ta-td ta-name" style="font-weight:600" onclick="bwShowResults('${esc(b._id)}')" title="View favicon matches">${esc(b.name)}</td>
          <td class="ta-td" style="font-size:11px;color:var(--text-dim)">${esc(b.added_date || '—')}</td>
          <td class="ta-td" style="font-size:11px;color:var(--text-dim)">${esc(lastScan)}</td>
          <td class="ta-td" style="font-size:10px;font-family:var(--font-ui);color:var(--text-dim)">${esc(b.favicon_hash || '—')}</td>
          <td class="ta-td">${_bwCountBadge(b.match_count, 'var(--accent)')}</td>
          <td class="ta-td">${_bwCountBadge(b.new_match_count, 'var(--orange)')}</td>
          <td class="ta-td">${_bwCountBadge(b.suspicious_count, 'var(--red, #DA3633)')}</td>
          <td class="ta-td">
            <button class="btn-reset" style="font-size:10px;padding:3px 8px" onclick="bwShowResults('${esc(b._id)}')">View</button>
            <button class="btn-reset" style="font-size:10px;padding:3px 8px;border-color:rgba(218,54,51,0.4);color:var(--red,#DA3633)" onclick="bwDeleteDomain('${esc(b._id)}')">${ic("x", 11)}</button>
          </td>
        </tr>`;
      }).join('');
    }
    _bwRenderPager();
  } catch(e) {
    tbody.innerHTML = `<tr><td colspan="9" class="ta-td" style="color:var(--red)">Failed to load</td></tr>`;
    console.error('[bwLoadDomains]', e);
  }
}

function _bwRenderPager() {
  const totalPages = Math.max(1, Math.ceil(_bwState.total / _bwState.pageSize));
  const el = document.getElementById('bw-pager');
  if (totalPages <= 1) { el.innerHTML = ''; return; }
  el.innerHTML = `<div class="pager">
    <button class="pager-btn" onclick="bwGoPage(-1)" ${_bwState.page <= 1 ? 'disabled' : ''}>${ic("chevron-left", 12)} Prev</button>
    <span class="pager-info">PAGE <strong>${_bwState.page}</strong> / ${totalPages}</span>
    <button class="pager-btn" onclick="bwGoPage(1)" ${_bwState.page >= totalPages ? 'disabled' : ''}>Next ${ic("chevron-right", 12)}</button>
  </div>`;
}

async function bwGoPage(delta) {
  const totalPages = Math.ceil(_bwState.total / _bwState.pageSize);
  _bwState.page = Math.min(Math.max(1, _bwState.page + delta), totalPages);
  await bwLoadDomains();
}

async function bwAddDomain() {
  const nameEl = document.getElementById('bw-name-input');
  const name = nameEl.value.trim();
  if (!name) { _bwStatus('Enter a domain', false); return; }
  try {
    _bwStatus('Adding…', true);
    const resp = await fetch('/api/brandwatch/domains', {
      method: 'POST',
      headers: _authAndClientHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ name }),
    });
    if (resp.status === 401) { _authFailed(); return; }
    const d = await resp.json();
    if (resp.ok && d.success) {
      nameEl.value = '';
      _bwStatus(`"${d.name}" watched — first scan runs on the next scan cycle`, true);
      _bwState.page = 1;
      bwLoadDomains();
      bwLoadStats();
    } else {
      _bwStatus(d.detail || 'Cannot add: already watched', false);
    }
  } catch(e) {
    _bwStatus(`Error: ${e.message}`, false);
    console.error('[bwAddDomain]', e);
  }
}

function bwDeleteDomain(domainId) {
  const b = _bwMap[domainId];
  if (!b) return;
  showConfirmModal({
    title:   'Stop Watching Brand',
    okLabel: `${ic('x', 12)} Remove`,
    body: `<p style="font-size:13px;color:var(--text);line-height:1.7;margin-bottom:10px">
      Stop watching <strong style="color:var(--red)">${esc(b.name)}</strong>?
    </p>
    <p style="font-size:12px;color:var(--text-dim);font-family:var(--font-ui);line-height:1.7">
      All favicon match results for this domain will be deleted.
    </p>`,
    onConfirm: async () => {
      try {
        const resp = await fetch(`/api/brandwatch/domains/${encodeURIComponent(domainId)}`, {
          method: 'DELETE', headers: _authAndClientHeaders(),
        });
        if (resp.status === 401) { _authFailed(); return; }
        const d = await resp.json();
        if (d.success) {
          _bwStatus(`"${b.name}" removed`, true);
          bwLoadDomains();
          bwLoadStats();
        }
      } catch(e) {
        _bwStatus('Failed to remove brand', false);
      }
    },
  });
}

// ── Results modal ────────────────────────────────────────────

let _bwCurrentDomainId = null;
let _bwResultMap = {};  // _id → result doc, for the currently open modal

function bwShowResults(domainId) {
  _bwCurrentDomainId = domainId;
  document.getElementById('bw-unacked-filter').checked = false;
  document.getElementById('bw-suspicious-filter').checked = false;
  document.getElementById('bw-results-modal').classList.add('open');
  bwReloadResults();
}

function bwReloadResults() {
  if (_bwCurrentDomainId) _bwLoadResultsInto(_bwCurrentDomainId);
}

async function _bwLoadResultsInto(domainId) {
  const b = _bwMap[domainId];
  if (!b) return;
  const body = document.getElementById('bw-results-modal-body');
  body.innerHTML = loadingHTML();

  try {
    const unackedOnly    = document.getElementById('bw-unacked-filter')?.checked;
    const suspiciousOnly = document.getElementById('bw-suspicious-filter')?.checked;
    const params = new URLSearchParams({ page_size: 500 });
    if (unackedOnly)    params.set('acknowledged', 'false');
    if (suspiciousOnly) params.set('suspicious_only', 'true');
    const resp = await fetch(`/api/brandwatch/domains/${encodeURIComponent(domainId)}/results?${params}`, {
      headers: _authAndClientHeaders(),
    });
    if (resp.status === 401) { _authFailed(); return; }
    const d = await resp.json();
    const hits = d.items || [];

    _bwResultMap = {};
    hits.forEach(r => { _bwResultMap[r._id] = r; });

    if (!hits.length) {
      body.innerHTML = `<h3 style="margin-bottom:10px">${esc(b.name)} — Favicon Matches</h3>${emptyHTML(unackedOnly ? 'No unacknowledged findings' : 'No Shodan matches found yet')}`;
      return;
    }

    hits.sort((a, c) => (c.newly_seen - a.newly_seen) || ((!a.is_own_domain) - (!c.is_own_domain)));

    const rows = hits.map(r => {
      const flags = [];
      if (r.newly_seen) flags.push(`<span style="color:var(--orange)">NEW</span>`);
      if (!r.is_own_domain) flags.push(`<span style="color:var(--red,#DA3633)">SUSPICIOUS</span>`);
      else flags.push(`<span style="color:var(--green,#3fb950)">OWN</span>`);
      const ackCell = r.acknowledged
        ? `<span style="font-size:10px;color:var(--text-dim)" title="${esc(r.ack_by || '')} · ${esc((r.ack_date||'').slice(0,16).replace('T',' '))}">${ic("check", 11)} ${esc(r.ack_by || '')}</span>
           <button class="btn-reset" style="font-size:10px;padding:2px 6px;margin-left:4px" onclick="bwAckResult('${esc(r._id)}')">Undo</button>`
        : `<button class="btn-reset" style="font-size:10px;padding:2px 6px;border-color:rgba(63,185,80,0.4);color:var(--green,#3fb950)" onclick="bwAckResult('${esc(r._id)}')">${ic("check", 11)} Ack</button>`;
      return `<tr style="${r.acknowledged ? 'opacity:0.55' : ''}">
        <td class="ta-td" style="font-size:11px">${esc(r.ip_str)}${r.port ? ':' + r.port : ''}</td>
        <td class="ta-td" style="font-size:11px">${esc((r.hostnames || []).join(', ') || '—')}</td>
        <td class="ta-td" style="font-size:11px">${esc(r.org || '—')}</td>
        <td class="ta-td" style="font-size:11px">${esc([r.city, r.country].filter(Boolean).join(', ') || '—')}</td>
        <td class="ta-td" style="font-size:11px;color:var(--text-dim)">${esc((r.first_seen || '—').slice(0,16).replace('T',' '))}</td>
        <td class="ta-td" style="font-size:10px">${flags.join(' ') || '—'}</td>
        <td class="ta-td">${ackCell}</td>
      </tr>`;
    }).join('');

    body.innerHTML = `
      <h3 style="margin-bottom:4px">${esc(b.name)} — Favicon Matches</h3>
      <p style="font-size:11px;color:var(--text-dim);margin-bottom:12px">
        ${hits.length} matches · favicon hash <code>${esc(b.favicon_hash || '—')}</code> · last scan ${esc((b.last_scan || '—').slice(0,16).replace('T',' '))}
      </p>
      <div class="cve-table-wrapper">
        <table class="cve-table">
          <thead><tr>
            <th class="cve-table th">IP:Port</th>
            <th class="cve-table th">Hostnames</th>
            <th class="cve-table th">Org</th>
            <th class="cve-table th">Location</th>
            <th class="cve-table th">First Seen</th>
            <th class="cve-table th">Flags</th>
            <th class="cve-table th">Ack</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  } catch(e) {
    body.innerHTML = `<div style="color:var(--red)">Failed to load results</div>`;
    console.error('[bwShowResults]', e);
  }
}

async function bwAckResult(resultId) {
  try {
    const resp = await fetch(`/api/brandwatch/results/${encodeURIComponent(resultId)}/ack`, {
      method: 'POST', headers: _authAndClientHeaders(),
    });
    if (resp.status === 401) { _authFailed(); return; }
    if (!resp.ok) throw new Error(resp.statusText);
    bwReloadResults();
    bwLoadStats();
  } catch(e) {
    console.error('[bwAckResult]', e);
  }
}

function bwCloseResultsModal() {
  document.getElementById('bw-results-modal').classList.remove('open');
  _bwCurrentDomainId = null;
}
