// ── AUTO-REFRESH ──────────────────────────────────────────
let _refreshTimer    = null;
let _refreshCountdown = 0;
let _refreshInterval  = 0;

function setAutoRefresh() {
  clearInterval(_refreshTimer);
  _refreshTimer = null;
  const val = parseInt(document.getElementById('refresh-interval').value, 10);
  _refreshInterval  = val;
  _refreshCountdown = val;
  _updateCountdown();
  if (val > 0) {
    _refreshTimer = setInterval(() => {
      _refreshCountdown--;
      if (_refreshCountdown <= 0) {
        _refreshCountdown = _refreshInterval;
        const modalOpen = document.getElementById('modal-overlay').classList.contains('open');
        if (!modalOpen) {
          const activeTab = document.querySelector('.tab-panel.active')?.id;
          if (activeTab === 'tab-dashboard') {
            loadDashboard();
          } else {
            loadAllPanels();
          }
        }
      }
      _updateCountdown();
    }, 1000);
  }
}

function _updateCountdown() {
  const el = document.getElementById('refresh-countdown');
  if (_refreshInterval > 0 && _refreshCountdown > 0) {
    const m = Math.floor(_refreshCountdown / 60);
    const s = _refreshCountdown % 60;
    el.textContent = `${m}:${s.toString().padStart(2, '0')}`;
  } else {
    el.textContent = '';
  }
}

// ── INIT ──────────────────────────────────────────────────
document.getElementById('footer-year').textContent = new Date().getFullYear();

// Set default 7-day date range immediately so Dashboard & News Room never query unbounded dates
(() => {
  const _todayD = new Date();
  const _d7 = new Date(_todayD);
  _d7.setDate(_todayD.getDate() - 7);
  const _ds = _d7.toISOString().split('T')[0];
  const _de = _todayD.toISOString().split('T')[0];
  window._defaultDateStart = _ds;
  window._defaultDateEnd   = _de;
  const startEl = document.getElementById('filter-date-start');
  const endEl   = document.getElementById('filter-date-end');
  if (startEl && !startEl.value) startEl.value = _ds;
  if (endEl   && !endEl.value)   endEl.value   = _de;
})();

(async () => {
  // Yield one microtask so trailing <script> tags (e.g. scraper.js) finish registering functions
  await Promise.resolve();

  // Start Dashboard, SR scores, and Scraper health immediately without waiting for /api/filters
  const dashPromise = Promise.allSettled([
    loadDashboard(),
    typeof loadSRScoreMap === 'function' ? loadSRScoreMap() : Promise.resolve(),
    typeof loadScraperHealth === 'function' ? loadScraperHealth() : Promise.resolve(),
  ]);

  try {
    // Fetch country groups, current user's client countries, and filters in parallel
    const authHeaders = _jwtToken ? { 'Authorization': 'Bearer ' + _jwtToken } : {};

    const cgTask = fetch('/api/country-groups').then(async (cgResp) => {
      if (cgResp.ok) {
        const groups = await cgResp.json();
        groups.forEach(({ canonical, variants }) => {
          canonicalToVariants[canonical] = variants;
          variants.forEach(v => { variantToCanonical[v] = canonical; });
        });
      }
    }).catch(e => console.error('country-groups error:', e));

    const meTask = (_jwtToken ? fetch('/api/auth/me', { headers: authHeaders }) : Promise.resolve(null))
      .then(async (meResp) => {
        if (meResp && meResp.ok) {
          const me = await meResp.json();
          if (me.clients_map && typeof me.clients_map === 'object') {
            window._clientsCountriesMap = me.clients_map;
          }
          if (me.clients_sectors_map && typeof me.clients_sectors_map === 'object') {
            window._clientsSectorsMap = me.clients_sectors_map;
          }
          const activeId = typeof getActiveClientId === 'function' ? getActiveClientId() : null;
          const countries = (activeId && window._clientsCountriesMap?.[activeId])
            || me.client_countries || [];
          localStorage.setItem('cti_client_countries', JSON.stringify(countries));
        }
      }).catch(e => console.error('auth/me error:', e));

    // Only wait for country-groups & me before loading News Room panels
    await Promise.allSettled([cgTask, meTask]);
    loadAllPanels();

    // Populate filter dropdowns in background as soon as /api/filters responds
    fetch('/api/filters').then(async (filtersResp) => {
      if (!filtersResp.ok) return;
      const fd = await filtersResp.json();

      const cSel = document.getElementById('filter-country');
      const iSel = document.getElementById('filter-industry');
      const aSel = document.getElementById('filter-actor');

      if (cSel) {
        const frag = document.createDocumentFragment();
        normalizeCountryList(fd.countries || []).forEach(c => {
          const o = document.createElement('option');
          o.value = o.textContent = c;
          frag.appendChild(o);
        });
        cSel.appendChild(frag);
        cSel._ctiSelect?.sync();
      }

      if (iSel) {
        const frag = document.createDocumentFragment();
        (fd.industries || []).forEach(i => {
          const o = document.createElement('option');
          o.value = o.textContent = i;
          frag.appendChild(o);
        });
        iSel.appendChild(frag);
        iSel._ctiSelect?.sync();
      }

      if (aSel) {
        const frag = document.createDocumentFragment();
        (fd.threat_actors || []).forEach(t => {
          const o = document.createElement('option');
          o.value = o.textContent = t;
          frag.appendChild(o);
        });
        aSel.appendChild(frag);
        aSel._ctiSelect?.sync();
      }
    }).catch(e => console.error('filters load error:', e));

  } catch (e) { console.error('Init load error:', e); }

  await dashPromise;
})();

