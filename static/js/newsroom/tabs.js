// ── LOAD ALL ──────────────────────────────────────────────
async function loadAllPanels() {
  Object.values(state).forEach(s => s.page = 1);

  await loadTpCveSet();

  const [apacTotal, globalTotal, rwTotal, indoTotal] = await Promise.all([
    loadPanel('apac'),
    loadPanel('global'),
    loadRwArticles(1),
    loadPanel('indo'),
    loadWatchlistPanel(),
    loadTechStackPanel(),
    loadIndustryNewsPanel(),
    loadCvePanel(),
    loadRwVictims(1),
  ]);

  const total = apacTotal + globalTotal + rwTotal + indoTotal;
  const setTxt = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  setTxt('newsroom-count', total);
  setTxt('newsroom-count-cyber', total);
  setTxt('stat-total', total);
  setTxt('stat-apac', apacTotal);
  setTxt('stat-global', globalTotal);
  setTxt('stat-indo', indoTotal);
  setTxt('last-update', new Date().toLocaleString('en-GB', {
    day:'2-digit', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit',
  }) + ' WIB');
}

function refreshPanel(panelId) {
  if (panelId === 'rw')         { loadRwArticles(1);      return; }
  if (panelId === 'watchlist')  { loadWatchlistPanel();   return; }
  if (panelId === 'techstack')  { loadTechStackPanel();   return; }
  if (panelId === 'industry')   { loadIndustryNewsPanel(); return; }
  loadPanel(panelId);
}

// ── NEWSROOM SUB-VIEWS ────────────────────────────────────
let _newsroomView = 'cyber';

function newsroomSwitchView(view) {
  // Non-admin cannot access filtered view
  if (view === 'filtered' && !['admin','superadmin'].includes(_jwtRole())) {
    view = 'cyber';
  }
  _newsroomView = view;
  document.getElementById('newsroom-view-cyber').style.display    = view === 'cyber'    ? '' : 'none';
  document.getElementById('newsroom-view-filtered').style.display = view === 'filtered' ? '' : 'none';
  document.getElementById('newsroom-cyber-btn').classList.toggle('active',    view === 'cyber');
  document.getElementById('newsroom-filtered-btn').classList.toggle('active', view === 'filtered');
  if (view === 'filtered') loadFilteredArticles(1);
}

const _filteredState = { page: 1, total: 0 };
const _FILTERED_PAGE_SIZE = 20;

async function loadFilteredArticles(page) {
  _filteredState.page = page || 1;
  const listEl  = document.getElementById('filtered-list');
  const pagerEl = document.getElementById('filtered-pager');
  listEl.innerHTML = '<div class="loading-state"><div class="loading-spinner"></div><div class="loading-text">Loading...</div></div>';

  const params = new URLSearchParams({ page: _filteredState.page, page_size: _FILTERED_PAGE_SIZE });
  const search = document.getElementById('filtered-search')?.value.trim();
  if (search) params.set('search', search);

  try {
    const d = await fetch('/api/filtered-articles?' + params).then(r => r.json());
    _filteredState.total = d.total;
    document.getElementById('filtered-count').textContent = d.total + ' items';
    document.getElementById('newsroom-count-filtered').textContent = d.total;

    if (!d.items.length) {
      listEl.innerHTML = '<div class="empty-state">No filtered articles</div>';
      pagerEl.innerHTML = '';
      return;
    }

    listEl.innerHTML = d.items.map(a => renderFilteredItem(a)).join('');
    renderFilteredPager(pagerEl, d.total, _filteredState.page);
  } catch(e) {
    listEl.innerHTML = '<div class="empty-state" style="color:var(--red)">Failed to load</div>';
  }
}

function renderFilteredItem(a) {
  const src = (a.script_name || '').toUpperCase().includes('FROM')
    ? a.script_name.split(/FROM/i)[1].trim()
    : a.script_name;
  const dateStr = (a.completed_at || a.created_at || '').slice(0, 10);
  return `<div class="news-item" style="display:flex;align-items:flex-start;gap:10px">
    <div style="flex:1;min-width:0">
      <div class="news-headline">
        <a href="${esc(a.url)}" target="_blank" rel="noopener" style="color:inherit;text-decoration:none">${esc(a.title)}</a>
      </div>
      <div class="news-meta">
        <span class="news-time">${esc(dateStr)}</span>
        <span class="news-source">${esc(src)}</span>
        ${a.posted_on ? `<span class="news-tag">posted ${esc(a.posted_on)}</span>` : ''}
      </div>
    </div>
    <button onclick="restoreFilteredArticle('${esc(a.id)}',this)" style="flex-shrink:0;padding:4px 10px;font-size:10px;background:rgba(47,129,247,0.08);border:1px solid rgba(47,129,247,0.3);color:var(--accent);border-radius:3px;cursor:pointer;white-space:nowrap" title="Manually restore to News Room">
      ${ic("undo", 11)} Restore
    </button>
  </div>`;
}

function renderFilteredPager(el, total, page) {
  const pages = Math.ceil(total / _FILTERED_PAGE_SIZE);
  if (pages <= 1) { el.innerHTML = ''; return; }
  el.innerHTML = `<div class="pager">
    <button class="pager-btn" onclick="loadFilteredArticles(${page - 1})" ${page <= 1 ? 'disabled' : ''}>${ic("chevron-left", 12)} Prev</button>
    <span class="pager-info">PAGE <strong>${page}</strong> / ${pages}</span>
    <button class="pager-btn" onclick="loadFilteredArticles(${page + 1})" ${page >= pages ? 'disabled' : ''}>Next ${ic("chevron-right", 12)}</button>
  </div>`;
}

async function restoreFilteredArticle(id, btn) {
  btn.disabled = true;
  btn.textContent = '…';
  try {
    const resp = await fetch(`/api/filtered-articles/${id}/restore`, {
      method: 'POST',
      headers: _jwtToken ? { 'Authorization': 'Bearer ' + _jwtToken } : {},
    });
    if (resp.ok) {
      btn.closest('.news-item').style.opacity = '0.4';
      btn.innerHTML = `${ic('check', 11)} Restored`;
      setTimeout(() => loadFilteredArticles(_filteredState.page), 1200);
    } else {
      btn.innerHTML = `${ic('x', 11)} Error`;
      btn.disabled = false;
    }
  } catch(e) {
    btn.innerHTML = `${ic('x', 11)} Error`;
    btn.disabled = false;
  }
}

// ── FILTERS ───────────────────────────────────────────────
function applyFilters() {
  loadAllPanels();
  if (document.querySelector('.tab-panel.active')?.id === 'tab-dashboard') {
    loadDashboard();
  }
}

function resetFilters() {
  document.getElementById('filter-search').value   = '';
  document.getElementById('filter-country').value  = '';
  document.getElementById('filter-industry').value = '';
  document.getElementById('filter-actor').value    = '';
  document.getElementById('filter-date-start').value = window._defaultDateStart || '';
  document.getElementById('filter-date-end').value   = window._defaultDateEnd   || '';
  loadAllPanels();
  if (document.querySelector('.tab-panel.active')?.id === 'tab-dashboard') {
    loadDashboard();
  }
}

// ── TABS ──────────────────────────────────────────────────
const _charts = {};

// Watch sub-tabs (Domain Watch / Brand Watch nested under one "Watch" tab)
let _watchActiveSubTab = 'domain';

function watchSwitchSubTab(tab) {
  _watchActiveSubTab = tab;
  const tabs = ['domain', 'brand'];
  tabs.forEach(t => {
    const panel = document.getElementById(`watch-subtab-${t}`);
    const btn   = document.getElementById(`watch-subtab-btn-${t}`);
    if (!panel || !btn) return;
    const active = t === tab;
    panel.style.display = active ? '' : 'none';
    btn.style.background = active ? 'rgba(47,129,247,0.12)' : 'transparent';
    btn.style.borderColor = active ? 'var(--border-bright)' : 'var(--border)';
    btn.style.color = active ? 'var(--accent)' : 'var(--text-dim)';
  });
  if (tab === 'domain') loadDomainWatchPanel();
  if (tab === 'brand')  loadBrandWatchPanel();
}

const _TAB_HEADINGS = {
  dashboard:    ['Dashboard',           'Global Threat & Intelligence Overview'],
  newsroom:     ['News Room',           'Real-Time Cyber Threat Feeds & Advisories'],
  cvetracker:   ['CVE Tracker',         'Vulnerability Intelligence & NVD Triage'],
  intelligence: ['Intelligence',        'Threat Actor Room, PIR, IOCs & Source Reliability'],
  exec:         ['Executive Dashboard', 'Strategic Risk Posture & Sector Telemetry'],
  xintel:       ['X Intel',             'OSINT & Social Threat Monitoring'],
  watch:        ['Watch',               'Domain & Brand Impersonation Monitoring'],
  recap:        ['Daily Recap',         'Automated Daily Intelligence Briefing'],
  usermgmt:     ['User Management',     'Access Control, Client Tenants & Audit Logs'],
  apidocs:      ['API Documentation',   'Platform REST Endpoints & Integration Reference'],
};

function switchTab(tabId, el) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-' + tabId).classList.add('active');
  if (el && el.classList.contains('tab')) el.classList.add('active');
  const meta = _TAB_HEADINGS[tabId];
  if (meta) {
    const tEl = document.getElementById('workspace-page-title');
    const sEl = document.getElementById('workspace-page-subtitle');
    if (tEl) tEl.textContent = meta[0];
    if (sEl) sEl.textContent = meta[1];
  }
  const hideBar = tabId === 'cvetracker' || tabId === 'intelligence' || tabId === 'exec' || tabId === 'usermgmt' || tabId === 'xintel' || tabId === 'recap' || tabId === 'apidocs' || tabId === 'watch';
  document.querySelector('.filter-bar').style.display = hideBar ? 'none' : '';
  if (tabId === 'dashboard')    { loadDashboard(); loadScraperHealth(); }
  if (tabId === 'cvetracker')   loadCvePanel();
  if (tabId === 'intelligence') loadIntelligence();
  if (tabId === 'exec')         { restoreExecWatchlist(); loadExecDashboard(); loadRwTreemap(_rwTmDays); }
  if (tabId === 'xintel')       { loadXIntel(1); xiLoadBalance(); }
  if (tabId === 'recap')        loadRecap();
  if (tabId === 'watch')        watchSwitchSubTab(_watchActiveSubTab);
  if (tabId === 'usermgmt')     { loadUMUsers(); loadUMClients(); loadUMRoles(); loadAuditLog(1); loadPolicy(); _applyPolicyToUI(); _populateRoleSelect('um-new-role'); }
}

