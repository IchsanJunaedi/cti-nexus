// ── DOMAIN WATCH (TLD sweep via tldsweep, scanned by ScraperNewsRevamp) ──
const _dwState = { page: 1, pageSize: 50, total: 0 };
let   _dwMap   = {};  // _id → domain doc

function _dwStatus(msg, ok) {
  const el = document.getElementById('dw-status');
  if (!el) return;
  el.textContent = msg;
  el.className = `ta-status show ${ok ? 'ok' : 'err'}`;
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('show'), 4000);
}

function _dwCertExpiryCell(r) {
  const notAfter = r.tls && r.tls.not_after;
  if (!notAfter) return '<span style="color:var(--text-dim)">—</span>';
  const expDate = new Date(notAfter);
  if (isNaN(expDate)) return esc(notAfter);
  const daysLeft = Math.ceil((expDate - Date.now()) / 86400000);
  let color = 'var(--text-dim)';
  if (daysLeft < 0)       color = 'var(--red, #DA3633)';
  else if (daysLeft <= 14) color = 'var(--red, #DA3633)';
  else if (daysLeft <= 30) color = 'var(--orange)';
  const label = daysLeft < 0 ? `expired ${Math.abs(daysLeft)}d ago` : `${daysLeft}d left`;
  const dateStr = expDate.toISOString().slice(0, 10);
  return `<span style="color:${color}">${esc(dateStr)} <span style="font-size:10px">(${label})</span></span>`;
}

function _dwCountBadge(n, color) {
  if (!n) return `<span style="font-size:11px;color:var(--text-dim)">0</span>`;
  return `<span style="font-family:var(--font-ui);font-size:11px;font-weight:600;color:${color}">${n}</span>`;
}

// ── Stats ─────────────────────────────────────────────────────

async function dwLoadStats() {
  try {
    const resp = await fetch('/api/domainwatch/stats', { headers: _authAndClientHeaders() });
    if (resp.status === 401) { _authFailed(); return; }
    if (!resp.ok) return;
    const d = await resp.json();
    document.getElementById('dw-stat-domains').textContent   = d.domains ?? '—';
    document.getElementById('dw-stat-registered').textContent = d.registered ?? '—';
    document.getElementById('dw-stat-alive').textContent      = d.alive ?? '—';
    document.getElementById('dw-stat-newly').textContent      = d.newly_registered ?? '—';
    document.getElementById('dw-stat-risk').textContent       = d.at_risk ?? '—';
    document.getElementById('dw-stat-unacked').textContent    = d.unacknowledged ?? '—';
    document.getElementById('dw-stat-parked').textContent     = d.parked ?? '—';
  } catch(e) { console.error('dw stats error:', e); }
}

// ── Watchlist ────────────────────────────────────────────────

async function loadDomainWatchPanel() {
  dwLoadStats();
  dwLoadDomains();
}

async function dwLoadDomains() {
  const tbody = document.getElementById('dw-tbody');
  tbody.innerHTML = `<tr><td colspan="11" class="ta-td">${loadingHTML()}</td></tr>`;

  try {
    const params = new URLSearchParams({ page: _dwState.page, page_size: _dwState.pageSize });
    const resp = await fetch(`/api/domainwatch/domains?${params}`, { headers: _authAndClientHeaders() });
    if (resp.status === 401) { _authFailed(); return; }
    if (!resp.ok) throw new Error(resp.statusText);
    const d = await resp.json();

    _dwState.total = d.total;
    _dwMap = {};

    if (!d.items.length) {
      tbody.innerHTML = `<tr><td colspan="11" class="ta-td">${emptyHTML('No domains watched — add a base domain above')}</td></tr>`;
    } else {
      const offset = (_dwState.page - 1) * _dwState.pageSize;
      tbody.innerHTML = d.items.map((dom, i) => {
        _dwMap[dom._id] = dom;
        const lastScan = dom.last_scan ? dom.last_scan.slice(0, 16).replace('T', ' ') : 'pending…';
        return `<tr>
          <td class="ta-td ta-num">${offset + i + 1}</td>
          <td class="ta-td ta-name" style="font-weight:600" onclick="dwShowResults('${esc(dom._id)}')" title="View TLD sweep results">${esc(dom.name)}</td>
          <td class="ta-td" style="font-size:11px;color:var(--text-dim)">${esc(dom.added_date || '—')}</td>
          <td class="ta-td" style="font-size:11px;color:var(--text-dim)">${esc(lastScan)}</td>
          <td class="ta-td">${_dwCountBadge(dom.tld_count, 'var(--text-dim)')}</td>
          <td class="ta-td">${_dwCountBadge(dom.registered_count, 'var(--accent)')}</td>
          <td class="ta-td">${_dwCountBadge(dom.alive_count, 'var(--green, #3fb950)')}</td>
          <td class="ta-td">${_dwCountBadge(dom.parked_count, 'var(--text-dim)')}</td>
          <td class="ta-td">${_dwCountBadge(dom.newly_registered_count, 'var(--orange)')}</td>
          <td class="ta-td">${_dwCountBadge(dom.risk_count, 'var(--red, #DA3633)')}</td>
          <td class="ta-td">
            <button class="btn-reset" style="font-size:10px;padding:3px 8px" onclick="dwShowResults('${esc(dom._id)}')">View</button>
            <button class="btn-reset" style="font-size:10px;padding:3px 8px;border-color:rgba(218,54,51,0.4);color:var(--red,#DA3633)" onclick="dwDeleteDomain('${esc(dom._id)}')">${ic("x", 11)}</button>
          </td>
        </tr>`;
      }).join('');
    }
    _dwRenderPager();
  } catch(e) {
    tbody.innerHTML = `<tr><td colspan="11" class="ta-td" style="color:var(--red)">Failed to load</td></tr>`;
    console.error('[dwLoadDomains]', e);
  }
}

function _dwRenderPager() {
  const totalPages = Math.max(1, Math.ceil(_dwState.total / _dwState.pageSize));
  const el = document.getElementById('dw-pager');
  if (totalPages <= 1) { el.innerHTML = ''; return; }
  el.innerHTML = `<div class="pager">
    <button class="pager-btn" onclick="dwGoPage(-1)" ${_dwState.page <= 1 ? 'disabled' : ''}>${ic("chevron-left", 12)} Prev</button>
    <span class="pager-info">PAGE <strong>${_dwState.page}</strong> / ${totalPages}</span>
    <button class="pager-btn" onclick="dwGoPage(1)" ${_dwState.page >= totalPages ? 'disabled' : ''}>Next ${ic("chevron-right", 12)}</button>
  </div>`;
}

async function dwGoPage(delta) {
  const totalPages = Math.ceil(_dwState.total / _dwState.pageSize);
  _dwState.page = Math.min(Math.max(1, _dwState.page + delta), totalPages);
  await dwLoadDomains();
}

async function dwAddDomain() {
  const nameEl = document.getElementById('dw-name-input');
  const name = nameEl.value.trim();
  if (!name) { _dwStatus('Enter a base domain', false); return; }
  try {
    _dwStatus('Adding…', true);
    const resp = await fetch('/api/domainwatch/domains', {
      method: 'POST',
      headers: _authAndClientHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ name }),
    });
    if (resp.status === 401) { _authFailed(); return; }
    const d = await resp.json();
    if (resp.ok && d.success) {
      nameEl.value = '';
      _dwStatus(`"${d.name}" watched — first sweep runs on the next scan cycle`, true);
      _dwState.page = 1;
      dwLoadDomains();
      dwLoadStats();
    } else {
      _dwStatus(d.detail || 'Cannot add: already watched', false);
    }
  } catch(e) {
    _dwStatus(`Error: ${e.message}`, false);
    console.error('[dwAddDomain]', e);
  }
}

function dwDeleteDomain(domainId) {
  const dom = _dwMap[domainId];
  if (!dom) return;
  showConfirmModal({
    title:   'Stop Watching Domain',
    okLabel: `${ic('x', 12)} Remove`,
    body: `<p style="font-size:13px;color:var(--text);line-height:1.7;margin-bottom:10px">
      Stop watching <strong style="color:var(--red)">${esc(dom.name)}</strong>?
    </p>
    <p style="font-size:12px;color:var(--text-dim);font-family:var(--font-ui);line-height:1.7">
      All TLD sweep results for this domain will be deleted.
    </p>`,
    onConfirm: async () => {
      try {
        const resp = await fetch(`/api/domainwatch/domains/${encodeURIComponent(domainId)}`, {
          method: 'DELETE', headers: _authAndClientHeaders(),
        });
        if (resp.status === 401) { _authFailed(); return; }
        const d = await resp.json();
        if (d.success) {
          _dwStatus(`"${dom.name}" removed`, true);
          dwLoadDomains();
          dwLoadStats();
        }
      } catch(e) {
        _dwStatus('Failed to remove domain', false);
      }
    },
  });
}

// ── Results modal ────────────────────────────────────────────

let _dwCurrentDomainId = null;
let _dwResultMap = {};  // _id → result doc, for the currently open modal

function dwShowResults(domainId) {
  _dwCurrentDomainId = domainId;
  document.getElementById('dw-unacked-filter').checked = false;
  document.getElementById('dw-hide-parked-filter').checked = false;
  document.getElementById('dw-results-modal').classList.add('open');
  dwReloadResults();
}

function dwReloadResults() {
  if (_dwCurrentDomainId) _dwLoadResultsInto(_dwCurrentDomainId);
}

async function _dwLoadResultsInto(domainId) {
  const dom = _dwMap[domainId];
  if (!dom) return;
  const body = document.getElementById('dw-results-modal-body');
  body.innerHTML = loadingHTML();

  try {
    const unackedOnly = document.getElementById('dw-unacked-filter')?.checked;
    const hideParked  = document.getElementById('dw-hide-parked-filter')?.checked;
    const params = new URLSearchParams({ page_size: 500 });
    if (unackedOnly) params.set('acknowledged', 'false');
    if (hideParked)  params.set('exclude_parked', 'true');
    const resp = await fetch(`/api/domainwatch/domains/${encodeURIComponent(domainId)}/results?${params}`, {
      headers: _authAndClientHeaders(),
    });
    if (resp.status === 401) { _authFailed(); return; }
    const d = await resp.json();
    const hits = (d.items || []).filter(r => r.registered || r.alive);

    _dwResultMap = {};
    hits.forEach(r => { _dwResultMap[r._id] = r; });

    if (!hits.length) {
      body.innerHTML = `<h3 style="margin-bottom:10px">${esc(dom.name)} — TLD Sweep</h3>${emptyHTML(unackedOnly ? 'No unacknowledged findings' : 'No registered/live TLD variants found yet')}`;
      return;
    }

    hits.sort((a, b) => (b.newly_registered - a.newly_registered) || ((b.alive && !b.parked) - (a.alive && !a.parked)) || (b.registered - a.registered));

    const rows = hits.map(r => {
      const flags = [];
      if (r.newly_registered) flags.push(`<span style="color:var(--orange)">NEW</span>`);
      if (r.parked) flags.push(`<span style="color:var(--text-dim)" title="${esc(r.parked_provider || 'unknown provider')}">PARKED${r.parked_provider ? ` (${esc(r.parked_provider)})` : ''}</span>`);
      else if (r.alive) flags.push(`<span style="color:var(--green,#3fb950)">LIVE</span>`);
      else if (r.registered) flags.push(`<span style="color:var(--text-dim)">NO SITE</span>`);
      if ((r.risk_indicators || []).length) flags.push(`<span style="color:var(--red,#DA3633)">${esc(r.risk_indicators.join(', '))}</span>`);
      const ip = (r.dns && r.dns.a && r.dns.a[0]) || '—';
      const ackCell = r.acknowledged
        ? `<span style="font-size:10px;color:var(--text-dim)" title="${esc(r.ack_by || '')} · ${esc((r.ack_date||'').slice(0,16).replace('T',' '))}">${ic("check", 11)} ${esc(r.ack_by || '')}</span>
           <button class="btn-reset" style="font-size:10px;padding:2px 6px;margin-left:4px" onclick="dwAckResult('${esc(r._id)}')">Undo</button>`
        : `<button class="btn-reset" style="font-size:10px;padding:2px 6px;border-color:rgba(63,185,80,0.4);color:var(--green,#3fb950)" onclick="dwAckResult('${esc(r._id)}')">${ic("check", 11)} Ack</button>`;
      return `<tr style="${r.acknowledged ? 'opacity:0.55' : ''}">
        <td class="ta-td ta-name">${r.url ? `<a href="${esc(r.url)}" target="_blank" rel="noopener" style="color:var(--text-bright,#fff);text-decoration:none">${esc(r.domain)}</a>` : esc(r.domain)}</td>
        <td class="ta-td" style="font-size:11px">${esc(ip)}</td>
        <td class="ta-td" style="font-size:11px">${esc((r.whois && r.whois.registrar) || '—')}</td>
        <td class="ta-td" style="font-size:11px">${esc((r.whois && r.whois.creation_date) || '—')}</td>
        <td class="ta-td" style="font-size:11px">${_dwCertExpiryCell(r)}</td>
        <td class="ta-td" style="font-size:10px">${flags.join(' ') || '—'}</td>
        <td class="ta-td">${ackCell}</td>
      </tr>`;
    }).join('');

    body.innerHTML = `
      <h3 style="margin-bottom:4px">${esc(dom.name)} — TLD Sweep</h3>
      <p style="font-size:11px;color:var(--text-dim);margin-bottom:12px">
        ${hits.length} registered/live of ${d.total} TLDs checked · last scan ${esc((dom.last_scan || '—').slice(0,16).replace('T',' '))}
      </p>
      <div class="cve-table-wrapper">
        <table class="cve-table">
          <thead><tr>
            <th class="cve-table th">Domain</th>
            <th class="cve-table th">IP</th>
            <th class="cve-table th">Registrar</th>
            <th class="cve-table th">Created</th>
            <th class="cve-table th">Cert Expires</th>
            <th class="cve-table th">Flags</th>
            <th class="cve-table th">Ack</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  } catch(e) {
    body.innerHTML = `<div style="color:var(--red)">Failed to load results</div>`;
    console.error('[dwShowResults]', e);
  }
}

async function dwAckResult(resultId) {
  try {
    const resp = await fetch(`/api/domainwatch/results/${encodeURIComponent(resultId)}/ack`, {
      method: 'POST', headers: _authAndClientHeaders(),
    });
    if (resp.status === 401) { _authFailed(); return; }
    if (!resp.ok) throw new Error(resp.statusText);
    dwReloadResults();
    dwLoadStats();
  } catch(e) {
    console.error('[dwAckResult]', e);
  }
}

function dwCloseResultsModal() {
  document.getElementById('dw-results-modal').classList.remove('open');
  _dwCurrentDomainId = null;
}
