const PAGE_SIZE = 15;

// ── ARTICLE CACHE (counter-based, avoids _id vs id alias issue) ──
let   _cacheIdx = 0;
const _cache    = {};

function storeArticle(a) {
  const key = ++_cacheIdx;
  _cache[key] = a;
  return key;
}

// ── COUNTRY GROUPS ────────────────────────────────────────
// Populated at init from /api/country-groups (single source of truth)
let variantToCanonical = {};
let canonicalToVariants = {};

function normalizeCountryList(rawList) {
  const seen = new Set();
  const result = [];
  rawList.forEach(raw => {
    const c = variantToCanonical[raw] || raw;
    if (!seen.has(c)) { seen.add(c); result.push(c); }
  });
  return result.sort();
}

function expandCountry(canonical) {
  // Return all DB-side variant strings for this canonical name
  return canonicalToVariants[canonical] || [canonical];
}

// ── STATE ─────────────────────────────────────────────────
const state = {
  apac:       { page: 1, total: 0 },
  global:     { page: 1, total: 0 },
  rw:         { page: 1, total: 0 },
  indo:       { page: 1, total: 0 },
  watchlist:  { page: 1, total: 0 },
  techstack:  { page: 1, total: 0 },
  industry:   { page: 1, total: 0 },
};

function getClientCountries() {
  try {
    return JSON.parse(localStorage.getItem('cti_client_countries') || '[]');
  } catch { return []; }
}

function localPanelTitle(countries) {
  if (!countries || countries.length === 0) return 'Global';
  if (countries.length === 1) return countries[0];
  return 'Local';
}

// ── CLIENT TENANT ALIASING (Competition & Presentation Masking) ──
const CLIENT_ALIAS_MAP = {
  'cynnexis': { name: 'Client Alpha (Tech)',   code: 'client-alpha', label: 'Client Alpha (Tech) (client-alpha)' },
  'jtrust':   { name: 'Client Beta (BFSI)',    code: 'client-beta',  label: 'Client Beta (BFSI) (client-beta)' },
  'pgncom':   { name: 'Client Gamma (Energy)', code: 'client-gamma', label: 'Client Gamma (Energy) (client-gamma)' },
  'default':  { name: 'Default Tenant',        code: 'default',      label: 'Default Tenant (default)' }
};

const CLIENT_CODE_TO_REAL = {
  'client-alpha': 'cynnexis',
  'client-a':     'cynnexis',
  'client-beta':  'jtrust',
  'client-b':     'jtrust',
  'client-gamma': 'pgncom',
  'client-c':     'pgncom',
  'default':      'default'
};

function formatClientLabel(clientId, origName) {
  const m = CLIENT_ALIAS_MAP[clientId];
  if (m) return m.label;
  return `${origName || clientId} (${clientId})`;
}

function formatClientName(clientId, origName) {
  const m = CLIENT_ALIAS_MAP[clientId];
  if (m) return m.name;
  return origName || clientId;
}

function formatClientCode(clientId) {
  const m = CLIENT_ALIAS_MAP[clientId];
  if (m) return m.code;
  return clientId;
}

window.CLIENT_ALIAS_MAP    = CLIENT_ALIAS_MAP;
window.CLIENT_CODE_TO_REAL = CLIENT_CODE_TO_REAL;
window.formatClientLabel   = formatClientLabel;
window.formatClientName    = formatClientName;
window.formatClientCode    = formatClientCode;

// ── UTILS ─────────────────────────────────────────────────
function esc(str) {
  return String(str ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function timeAgo(dateStr) {
  if (!dateStr) return '—';
  const d = new Date(dateStr);
  if (isNaN(d)) return dateStr;
  const days = Math.floor((Date.now() - d) / 86400000);
  if (days === 0) return 'Today';
  if (days === 1) return '1d ago';
  return `${days}d ago`;
}

function loadingHTML(span) {
  const style = span ? `style="grid-column:1/-1"` : '';
  return `<div class="loading-state" ${style}><div class="loading-spinner"></div><div class="loading-text">Loading...</div></div>`;
}

function emptyHTML(msg, span) {
  const style = span ? `style="grid-column:1/-1"` : '';
  return `<div class="empty-state" ${style}><div class="empty-icon">${ic("inbox", 20)}</div><div class="empty-text">${esc(msg)}</div></div>`;
}

// ── SIDEBAR CONTROL (Expanded, Collapsed, Expand on Hover) ──
const _SIDEBAR_MODE_KEY = 'cti_sidebar_mode';

function getSidebarMode() {
  return localStorage.getItem(_SIDEBAR_MODE_KEY) || 'expanded';
}

function setSidebarMode(mode) {
  const sidebar = document.querySelector('.tabs, .sidebar');
  if (sidebar) {
    sidebar.classList.remove('sidebar-mode-expanded', 'sidebar-mode-collapsed', 'sidebar-mode-expand-on-hover');
    sidebar.classList.add(`sidebar-mode-${mode}`);
  }

  if (document.body) {
    document.body.classList.remove('sidebar-mode-expanded', 'sidebar-mode-collapsed', 'sidebar-mode-expand-on-hover');
    document.body.classList.add(`sidebar-mode-${mode}`);
  }

  localStorage.setItem(_SIDEBAR_MODE_KEY, mode);

  document.querySelectorAll('.sidebar-control-item').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-mode') === mode);
  });

  closeSidebarMenu();
}

function toggleSidebarMenu(event) {
  if (event) {
    event.stopPropagation();
    event.preventDefault();
  }
  const menu = document.getElementById('sidebar-control-menu');
  const btn = document.getElementById('sidebar-control-btn');
  if (!menu) return;
  const isShown = menu.classList.contains('show');
  if (isShown) {
    closeSidebarMenu();
  } else {
    menu.classList.add('show');
    if (btn) btn.classList.add('active');
  }
}

function closeSidebarMenu() {
  const menu = document.getElementById('sidebar-control-menu');
  const btn = document.getElementById('sidebar-control-btn');
  if (menu) menu.classList.remove('show');
  if (btn) btn.classList.remove('active');
}

document.addEventListener('click', (e) => {
  const menu = document.getElementById('sidebar-control-menu');
  const btn = document.getElementById('sidebar-control-btn');
  if (menu && menu.classList.contains('show')) {
    if (!menu.contains(e.target) && (!btn || !btn.contains(e.target))) {
      closeSidebarMenu();
    }
  }
});

function _initSidebarMode() {
  const mode = getSidebarMode();
  setSidebarMode(mode);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', _initSidebarMode);
} else {
  _initSidebarMode();
}


