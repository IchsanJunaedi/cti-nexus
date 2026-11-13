// ── CISA KEV CATALOG ─────────────────────────────────────────
let _kevPage     = 1;
let _kevPageSize = 50;
let _kevTotal    = 0;
let _kevSortBy   = 'date_added';
let _kevSortDir  = 'desc';
let _kevMap      = {};  // _id → entry doc

function kevSortBy(col) {
  if (_kevSortBy === col) {
    _kevSortDir = _kevSortDir === 'asc' ? 'desc' : 'asc';
  } else {
    _kevSortBy  = col;
    _kevSortDir = (col === 'date_added' || col === 'due_date') ? 'desc' : 'asc';
  }
  _updateKevSortUI();
  _kevPage = 1;
  kevLoadEntries();
}

function _updateKevSortUI() {
  ['cve_id', 'vendor_project', 'date_added', 'due_date'].forEach(col => {
    const th = document.getElementById('kev-th-' + col);
    const si = document.getElementById('kev-si-' + col);
    if (!th || !si) return;
    const active = _kevSortBy === col;
    th.classList.toggle('sort-active', active);
    si.innerHTML = active ? (_kevSortDir === 'asc' ? ic('arrow-up', 11) : ic('arrow-down', 11)) : ic('chevrons-up-down', 11);
  });
}

async function kevLoadStats() {
  try {
    const resp = await fetch('/api/cisa-kev-catalog/stats', { headers: _authAndClientHeaders() });
    if (!resp.ok) return;
    const d = await resp.json();
    document.getElementById('kev-stat-total').textContent      = d.total            ?? '—';
    document.getElementById('kev-stat-matched').textContent    = d.matched          ?? '—';
    document.getElementById('kev-stat-unmatched').textContent  = d.unmatched        ?? '—';
    document.getElementById('kev-stat-ransomware').textContent = d.ransomware_known ?? '—';
    document.getElementById('kev-stat-duesoon').textContent    = d.due_soon         ?? '—';
    const badge = document.getElementById('kev-submenu-count');
    if (badge) badge.textContent = d.total ?? '—';
  } catch (e) { console.error('kev stats error:', e); }
}

async function kevLoadEntries() {
  const tbody = document.getElementById('kev-tbody');
  tbody.innerHTML = `<tr><td colspan="8">${loadingHTML()}</td></tr>`;

  try {
    const params = new URLSearchParams({
      page: _kevPage, page_size: _kevPageSize,
      sort_by: _kevSortBy, sort_dir: _kevSortDir,
    });
    const search    = document.getElementById('kev-search').value.trim();
    const matched   = document.getElementById('kev-matched-filter').value;
    const ransomOnly = document.getElementById('kev-ransomware-filter')?.checked;
    if (search)      params.set('search', search);
    if (matched)     params.set('matched', matched);
    if (ransomOnly)  params.set('ransomware_only', 'true');

    const resp = await fetch(`/api/cisa-kev-catalog?${params}`, { headers: _authAndClientHeaders() });
    if (resp.status === 401) { _authFailed(); return; }
    if (!resp.ok) throw new Error(resp.statusText);
    const d = await resp.json();

    _kevTotal = d.total;
    _kevMap = {};

    if (!d.items.length) {
      tbody.innerHTML = `<tr><td colspan="8">${emptyHTML('No KEV entries found. Run cisaKevIngestion.py to populate.')}</td></tr>`;
    } else {
      const offset = (_kevPage - 1) * _kevPageSize;
      tbody.innerHTML = d.items.map((k, i) => {
        _kevMap[k._id] = k;
        const ransomBadge = k.known_ransomware_use === 'Known'
          ? `<span style="font-family:var(--font-ui);font-size:9px;padding:1px 6px;border-radius:2px;background:rgba(218,54,51,0.2);color:#DA3633;border:1px solid rgba(218,54,51,0.4)">KNOWN</span>`
          : `<span style="font-family:var(--font-ui);font-size:10px;color:var(--text-dim)">—</span>`;
        const trackerBadge = k.matched_tracker
          ? `<span style="font-family:var(--font-ui);font-size:9px;padding:1px 6px;border-radius:2px;background:rgba(61,201,175,0.15);color:var(--green);border:1px solid rgba(61,201,175,0.4)">${ic("check", 10)} Tracked</span>`
          : `<span style="font-family:var(--font-ui);font-size:9px;padding:1px 6px;border-radius:2px;background:rgba(227,179,65,0.15);color:var(--orange);border:1px solid rgba(227,179,65,0.4)">Untracked</span>`;

        return `<tr style="cursor:pointer" onclick="kevShowDetail('${esc(k._id)}')">
          <td class="ta-td ta-num">${offset + i + 1}</td>
          <td class="ta-td" style="font-family:var(--font-ui);font-size:11px;color:var(--text-bright)">${esc(k.cve_id)}</td>
          <td class="ta-td" style="font-size:12px">
            <div>${esc(k.vendor_project || '—')}</div>
            <div style="font-size:10px;color:var(--text-dim)">${esc(k.product || '')}</div>
          </td>
          <td class="ta-td" style="font-size:12px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(k.vulnerability_name)}">${esc(k.vulnerability_name || '—')}</td>
          <td class="ta-td" style="font-family:var(--font-ui);font-size:10px;color:var(--text-dim)">${esc(k.date_added || '—')}</td>
          <td class="ta-td" style="font-family:var(--font-ui);font-size:10px;color:var(--text-dim)">${esc(k.due_date || '—')}</td>
          <td class="ta-td">${ransomBadge}</td>
          <td class="ta-td">${trackerBadge}</td>
        </tr>`;
      }).join('');
    }
    _renderKevPager();
  } catch (e) {
    console.error('kev load entries error:', e);
    tbody.innerHTML = `<tr><td colspan="8">${emptyHTML('Failed to load CISA KEV catalog')}</td></tr>`;
  }
}

function _renderKevPager() {
  const totalPages = Math.max(1, Math.ceil(_kevTotal / _kevPageSize));
  document.getElementById('kev-page-info').textContent = `Page ${_kevPage} / ${totalPages} — ${_kevTotal} entries`;
  document.getElementById('kev-page-prev').disabled = _kevPage <= 1;
  document.getElementById('kev-page-next').disabled = _kevPage >= totalPages;
}

function kevChangePage(page) {
  const totalPages = Math.max(1, Math.ceil(_kevTotal / _kevPageSize));
  if (page < 1 || page > totalPages) return;
  _kevPage = page;
  kevLoadEntries();
}

function kevResetFilters() {
  document.getElementById('kev-search').value = '';
  document.getElementById('kev-matched-filter').value = '';
  const ransom = document.getElementById('kev-ransomware-filter');
  if (ransom) ransom.checked = false;
  _kevPage = 1;
  kevLoadEntries();
}

function kevShowDetail(id) {
  const k = _kevMap[id];
  if (!k) return;

  // If matched to a tracked CVE, prefer opening the richer CVE Tracker modal.
  if (k.matched_tracker && typeof openCveModal === 'function') {
    openCveModal(k.cve_id);
    return;
  }

  const modal = document.getElementById('kev-modal');
  const body  = document.getElementById('kev-modal-body');
  const cwes  = (k.cwes || []).join(', ') || '—';

  body.innerHTML = `
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:12px;flex-wrap:wrap">
      <div>
        <div style="font-family:var(--font-ui);font-size:15px;color:var(--text-bright)">${esc(k.cve_id)}</div>
        <div style="font-size:11px;color:var(--text-dim);font-family:var(--font-ui);margin-top:3px">
          ${esc(k.vendor_project)} · ${esc(k.product)}
        </div>
      </div>
      ${k.known_ransomware_use === 'Known' ? `<span style="font-family:var(--font-ui);font-size:10px;padding:2px 6px;border-radius:3px;background:rgba(218,54,51,0.2);color:#DA3633;border:1px solid rgba(218,54,51,0.4)">Known Ransomware Use</span>` : ''}
    </div>
    <div class="cve-detail-section">
      <div class="cve-detail-label">Vulnerability Name</div>
      <div class="cve-detail-value" style="font-size:11px">${esc(k.vulnerability_name || '—')}</div>
    </div>
    <div class="cve-detail-section">
      <div class="cve-detail-label">Description</div>
      <div class="cve-detail-value" style="font-size:11px">${esc(k.short_description || '—')}</div>
    </div>
    <div class="cve-detail-section">
      <div class="cve-detail-label">Required Action</div>
      <div class="cve-detail-value" style="font-size:11px">${esc(k.required_action || '—')}</div>
    </div>
    <div class="cve-detail-section" style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
      <div>
        <div class="cve-detail-label">Date Added</div>
        <div class="cve-detail-value" style="font-size:11px">${esc(k.date_added || '—')}</div>
      </div>
      <div>
        <div class="cve-detail-label">Due Date</div>
        <div class="cve-detail-value" style="font-size:11px">${esc(k.due_date || '—')}</div>
      </div>
    </div>
    <div class="cve-detail-section">
      <div class="cve-detail-label">CWEs</div>
      <div class="cve-detail-value" style="font-family:var(--font-ui);font-size:10px">${esc(cwes)}</div>
    </div>
    <div class="cve-detail-section" style="border-bottom:none">
      <div class="cve-detail-label">Notes</div>
      <div class="cve-detail-value" style="font-size:11px">${esc(k.notes || '—')}</div>
    </div>
  `;
  modal.classList.add('open');
}

function kevCloseModal() {
  document.getElementById('kev-modal').classList.remove('open');
}

async function loadCisaKevPanel() {
  await kevLoadStats();
  await kevLoadEntries();
}
