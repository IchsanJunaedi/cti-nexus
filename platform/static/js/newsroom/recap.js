// Daily Recap tab
'use strict';

function _recapClientId() {
  const sel = document.getElementById('recap-client');
  return (sel && sel.value) || 'default';
}

async function recapLoadClients() {
  const sel = document.getElementById('recap-client');
  if (!sel) return;
  try {
    const r = await fetch('/api/clients', { headers: { ..._authHeader() } });
    if (!r.ok) return; // likely 403 for non-admins — stay on org-wide only, silently
    const clients = await r.json();
    if (!Array.isArray(clients) || clients.length <= 1) return;
    sel.innerHTML = clients.map(c =>
      `<option value="${_recapEsc(c.client_id)}">${_recapEsc(c.name || c.client_id)}${c.client_id === 'default' ? ' (org-wide)' : ''}</option>`
    ).join('');
    sel.style.display = '';
  } catch (_e) { /* no client picker for this user — fine */ }
}

function _recapStatus(msg, kind) {
  const el = document.getElementById('recap-status');
  if (!el) return;
  const colors = { info: 'var(--text-dim)', ok: 'var(--accent)', err: 'var(--red)', warn: 'var(--orange)' };
  el.textContent = msg || '';
  el.style.color = colors[kind] || colors.info;
}

function _recapSafeUrl(u) {
  const s = (u == null ? '' : String(u)).trim();
  return /^https?:\/\//i.test(s) ? s : '';
}

function _recapLinkTitle(title, url) {
  const t = _recapEsc(title);
  const href = _recapSafeUrl(url);
  return href ? `<a href="${_recapEsc(href)}" target="_blank" rel="noopener" style="color:inherit;text-decoration:underline">${t}</a>` : t;
}

function _recapBadge(label, kind) {
  const colors = {
    critical: ['#e5534b', 'rgba(229,83,75,0.12)'],
    high:     ['#f39c12', 'rgba(243,156,18,0.12)'],
    default:  ['#8b949e', 'rgba(139,148,158,0.12)'],
  };
  const [fg, bg] = colors[kind] || colors.default;
  return `<span style="font-family:var(--font-ui);font-size:9px;background:${bg};color:${fg};border:1px solid ${fg}55;padding:1px 6px;border-radius:2px;margin-left:4px">${_recapEsc(label)}</span>`;
}

function _recapEsc(s) {
  return (s == null ? '' : String(s))
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function _recapConfBadge(c) {
  const t = (c || '').toLowerCase();
  const map = {
    high: ['#2ecc71', 'rgba(46,204,113,0.12)'],
    med:  ['#f39c12', 'rgba(243,156,18,0.12)'],
    low:  ['#95a5a6', 'rgba(149,165,166,0.12)'],
  };
  const [fg, bg] = map[t] || map.low;
  return `<span style="font-family:var(--font-ui);font-size:9px;background:${bg};color:${fg};border:1px solid ${fg}55;padding:1px 6px;border-radius:2px;text-transform:uppercase;letter-spacing:.08em">${_recapEsc(c || 'low')}</span>`;
}

function _recapSection(title) {
  return `<div style="font-family:var(--font-ui);font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.12em;margin:18px 0 8px;padding-bottom:5px;border-bottom:1px solid var(--border)">${_recapEsc(title)}</div>`;
}

function _recapList(items, mapFn) {
  if (!items || !items.length) {
    return `<div style="color:var(--text-dim);font-size:11px;font-style:italic">(none)</div>`;
  }
  return `<ul style="margin:0;padding:0 0 0 18px;font-size:13px;line-height:1.55">${
    items.map(mapFn).join('')
  }</ul>`;
}

function _recapChips(items) {
  if (!items || !items.length) return '<span style="color:var(--text-dim);font-size:11px;font-style:italic">(none)</span>';
  return items.map(v => `<span style="display:inline-block;background:rgba(47,129,247,0.10);border:1px solid var(--border-bright);color:var(--accent);padding:2px 8px;font-size:11px;font-family:var(--font-ui);border-radius:2px;margin:2px 4px 2px 0">${_recapEsc(v)}</span>`).join('');
}

function _recapRenderEmpty(date, isLatest) {
  const body = document.getElementById('recap-body');
  if (!body) return;
  body.innerHTML = `
    <div style="padding:30px;text-align:center;border:1px dashed var(--border);border-radius:3px">
      <div style="font-family:var(--font-ui);font-size:12px;color:var(--text-dim);margin-bottom:10px">
        No recap stored for <b>${_recapEsc(date)}</b>${isLatest ? ' (yesterday)' : ''}.
      </div>
      <button onclick="recapGenerate(false)" class="btn-apply" style="font-size:11px;padding:6px 16px">${ic("refresh", 12)} GENERATE NOW</button>
    </div>`;
}

function _recapRender(doc) {
  const body = document.getElementById('recap-body');
  if (!body) return;
  if (!doc) { _recapRenderEmpty('—', false); return; }

  const recap = doc.yesterday || {};
  const fcast = doc.forecast || {};
  const counts = doc.counts || {};
  const deltas = doc.counts_delta || {};
  const cveDetails = doc.cve_details || {};
  const gen = doc.generated_at ? new Date(doc.generated_at).toLocaleString() : '—';
  const tu = doc.token_usage || {};
  const tuStr = tu.total_tokens ? ` · ${tu.total_tokens} tokens` : '';

  const _d = (key) => {
    if (!(key in deltas)) return '';
    const v = deltas[key];
    const sign = v >= 0 ? '+' : '';
    const color = v > 0 ? '#2ecc71' : (v < 0 ? '#e5534b' : 'var(--text-dim)');
    return ` <span style="color:${color}">(${sign}${v})</span>`;
  };

  let html = '';

  if (doc.parse_error || !doc.headline) {
    html += `<div style="margin-bottom:10px;padding:10px 14px;border:1px solid rgba(243,156,18,0.4);background:rgba(243,156,18,0.08);color:var(--orange);border-radius:3px;font-size:12px">${ic("alert-triangle", 13)} LLM response for this recap could not be parsed (or returned no headline). Sections below may be empty or incomplete.</div>`;
  }

  const health = doc.scraper_health || {};
  let healthLine = '';
  if (health.accept_rate != null) {
    const degraded = health.accept_rate < 70;
    healthLine = `<div style="margin-top:4px;color:${degraded ? '#e5534b' : '#2ecc71'};font-weight:${degraded ? '600' : '400'}">Scraper health: ${degraded ? ic('alert-triangle', 11) + ' DEGRADED' : 'OK'} — ${health.accept_rate}% accept (${health.total_accepted||0}/${health.total_rejected||0})</div>`;
  }

  html += `
    <div style="display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;padding:14px 16px;border:1px solid var(--border);border-radius:3px;background:linear-gradient(135deg,rgba(47,129,247,0.05),rgba(88,166,255,0.04));margin-bottom:8px">
      <div>
        <div style="font-family:var(--font-ui);font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.12em;margin-bottom:4px">Daily Recap · ${_recapEsc(doc.date)}</div>
        <div style="font-size:14px;line-height:1.5">${_recapEsc(doc.headline || '(no headline)')}</div>
      </div>
      <div style="font-family:var(--font-ui);font-size:10px;color:var(--text-dim);text-align:right">
        <div>${counts.articles||0} articles${_d('articles')} · ${counts.tweets||0} tweets${_d('tweets')}</div>
        <div>${counts.cves||0} CVEs${_d('cves')} · ${counts.iocs||0} IOCs${_d('iocs')} · ${counts.campaigns||0} campaigns${_d('campaigns')}</div>
        <div>${counts.ransomware_victims||0} ransomware${_d('ransomware_victims')} · ${counts.kev_additions||0} KEV${_d('kev_additions')} · ${counts.domain_watch_hits||0} domains${_d('domain_watch_hits')} · ${counts.package_vulns||0} pkg vulns${_d('package_vulns')}</div>
        <div style="margin-top:4px">gen: ${_recapEsc(gen)}${_recapEsc(tuStr)}</div>
        ${healthLine}
      </div>
    </div>`;

  html += _recapSection('Summary');
  html += `<div style="font-size:13px;line-height:1.6">${_recapEsc(recap.summary || '(no summary)')}</div>`;

  html += _recapSection(`Top Stories (${(recap.top_stories||[]).length})`);
  html += _recapList(recap.top_stories, s => `
    <li style="margin-bottom:6px"><b>${_recapLinkTitle(s.title, s.url)}</b>
      <span style="color:var(--text-dim);font-family:var(--font-ui);font-size:10px"> [${_recapEsc(s.source||'?')}]</span>
      <div style="color:var(--text-dim);font-size:12px;margin-top:2px">${_recapEsc(s.why_it_matters||'')}</div>
    </li>`);

  html += _recapSection(`Top Tweets (${(recap.top_tweets||[]).length})`);
  html += _recapList(recap.top_tweets, t => `
    <li style="margin-bottom:6px"><b>${_recapLinkTitle('@' + (t.author||'?'), t.url)}</b>
      <span style="font-family:var(--font-ui);font-size:9px;background:rgba(88,166,255,0.12);color:#58A6FF;border:1px solid rgba(88,166,255,0.3);padding:1px 5px;border-radius:2px;margin-left:4px">${_recapEsc(t.signal||'other')}</span>
      <div style="font-size:12px;margin-top:2px">${_recapEsc(t.summary||'')}</div>
    </li>`);

  html += _recapSection('Active Threat Actors');
  html += `<div>${_recapChips(recap.active_threat_actors)}</div>`;

  html += _recapSection('Notable CVEs');
  if ((recap.notable_cves || []).length) {
    html += `<div>` + recap.notable_cves.map(id => {
      const d = cveDetails[id] || {};
      let badges = '';
      if (d.cve_score != null) badges += _recapBadge(`CVSS ${d.cve_score}`, d.cve_score >= 9 ? 'critical' : (d.cve_score >= 7 ? 'high' : 'default'));
      if (d.cisa_kev) badges += _recapBadge('KEV', 'critical');
      if (d.poc_available) badges += _recapBadge('PoC', 'high');
      if (d.epss_score != null) badges += _recapBadge(`EPSS ${d.epss_score}`, 'default');
      return `<span style="display:inline-block;margin:2px 8px 4px 0;font-family:var(--font-ui);font-size:11px">${_recapEsc(id)}${badges}</span>`;
    }).join('') + `</div>`;
  } else {
    html += `<div>${_recapChips([])}</div>`;
  }

  html += _recapSection(`Ransomware Victims (${((recap.ransomware||{}).victims||[]).length})`);
  html += _recapList((recap.ransomware||{}).victims, v => `
    <li style="margin-bottom:4px"><b>${_recapEsc(v.group||'?')}</b> — ${_recapEsc(v.victim||'?')}
      <span style="color:var(--text-dim);font-size:11px"> (${_recapEsc(v.country||'?')}, ${_recapEsc(v.industry||'?')})</span>
    </li>`);
  if ((recap.ransomware||{}).most_active_note) {
    html += `<div style="color:var(--text-dim);font-size:12px;font-style:italic;margin-top:4px">${_recapEsc(recap.ransomware.most_active_note)}</div>`;
  }

  html += _recapSection(`CISA KEV Additions (${(recap.kev_additions||[]).length})`);
  html += _recapList(recap.kev_additions, k => `
    <li style="margin-bottom:4px">${_recapBadge(k.cve_id||'?', 'critical')} ${_recapEsc(k.vendor_product||'')}
      <span style="color:var(--text-dim);font-size:11px"> — due <b>${_recapEsc(k.due_date||'?')}</b></span>
    </li>`);

  html += _recapSection(`MITRE TTPs (${(recap.mitre_ttps||[]).length})`);
  html += _recapList(recap.mitre_ttps, t => `<li>${_recapEsc(t.id||'?')} — ${_recapEsc(t.name||'')} <span style="color:var(--text-dim)">(x${t.count||0})</span></li>`);

  html += _recapSection(`Domain Watch — Newly Registered (${(recap.domain_watch||[]).length})`);
  html += _recapList(recap.domain_watch, d => `<li>${_recapEsc(d.domain||'?')}${d.note ? ` <span style="color:var(--text-dim);font-size:11px">— ${_recapEsc(d.note)}</span>` : ''}</li>`);

  html += _recapSection(`Package Vulnerabilities (${(recap.package_vulns||[]).length})`);
  html += _recapList(recap.package_vulns, p => `
    <li style="margin-bottom:4px">${_recapEsc(p.advisory_id||'?')} — ${_recapEsc(p.package||'?')}
      <span style="color:var(--text-dim);font-size:11px"> (${_recapEsc(p.ecosystem||'?')})</span>
      ${_recapBadge(p.severity||'?', (String(p.severity||'').toUpperCase()==='CRITICAL'?'critical':(String(p.severity||'').toUpperCase()==='HIGH'?'high':'default')))}
      <span style="color:var(--text-dim);font-size:11px"> fixed in: ${_recapEsc(p.fixed_version||'none')}</span>
    </li>`);

  const iocDetail = doc.ioc_detail || [];
  html += _recapSection(`Top IOCs (${iocDetail.length})`);
  if (iocDetail.length) {
    html += `<pre style="background:var(--surface);border:1px solid var(--border);border-radius:3px;padding:10px 12px;font-size:11px;overflow-x:auto;white-space:pre">${
      iocDetail.map(i => `[${_recapEsc(i.type)}] ${_recapEsc(i.value)} (confidence: ${_recapEsc(i.confidence_score)})`).join('\n')
    }</pre>`;
  } else {
    html += `<div style="color:var(--text-dim);font-size:11px;font-style:italic">(none)</div>`;
  }

  html += _recapSection(`Active Campaigns (${(recap.active_campaigns||[]).length})`);
  html += _recapList(recap.active_campaigns, c => `
    <li style="margin-bottom:6px"><b>${_recapEsc(c.theme||'(unlabeled)')}</b>
      <span style="color:var(--text-dim);font-family:var(--font-ui);font-size:10px"> · ${c.article_count||0} articles</span>
      <div style="color:var(--text-dim);font-size:12px;margin-top:2px">${_recapEsc(c.why_it_matters||'')}</div>
    </li>`);

  if ((recap.apac_signals || []).length) {
    html += _recapSection((doc.client_id || 'default') === 'default' ? 'APAC Signals' : 'Regional Signals');
    html += _recapList(recap.apac_signals, s => `<li>${_recapEsc(s)}</li>`);
  }

  // ── Forecast ──
  html += `<div style="margin-top:24px;padding:14px 16px;border:1px solid var(--border-bright);border-radius:3px;background:rgba(243,156,18,0.04)">
    <div style="font-family:var(--font-ui);font-size:11px;color:var(--orange);text-transform:uppercase;letter-spacing:.12em;margin-bottom:8px">${ic("chevron-up", 11)} Forecast · Next 1-3 Days</div>
    <div style="font-size:13px;line-height:1.6;margin-bottom:8px">${_recapEsc(fcast.summary || '(no forecast)')}</div>`;

  html += _recapSection(`Likely Events (${(fcast.likely_events||[]).length})`);
  html += _recapList(fcast.likely_events, e => `
    <li style="margin-bottom:8px"><b>${_recapEsc(e.event||'')}</b> ${_recapConfBadge(e.confidence)}
      <div style="color:var(--text-dim);font-size:12px;margin-top:2px"><span style="font-family:var(--font-ui);font-size:10px;text-transform:uppercase;letter-spacing:.08em">Basis:</span> ${_recapEsc(e.basis||'')}</div>
    </li>`);

  if ((fcast.watch_items || []).length) {
    html += _recapSection('Watch Items');
    html += _recapList(fcast.watch_items, w => `<li>${_recapEsc(w)}</li>`);
  }
  html += `</div>`;

  const review = doc.forecast_review || [];
  html += _recapSection(`Forecast Review — Previous Day (${review.length})`);
  if (review.length) {
    const vKind = { hit: 'high', miss: 'default', unclear: 'default' };
    html += _recapList(review, r => `
      <li style="margin-bottom:6px">${_recapBadge(r.verdict||'?', vKind[r.verdict] || 'default')} <b>${_recapEsc(r.event||'')}</b>
        <div style="color:var(--text-dim);font-size:12px;margin-top:2px">${_recapEsc(r.justification||'')}</div>
      </li>`);
  } else {
    html += `<div style="color:var(--text-dim);font-size:11px;font-style:italic">(no prior-day forecast to score)</div>`;
  }

  if (doc.raw_llm) {
    html += `<details style="margin-top:18px"><summary style="cursor:pointer;font-family:var(--font-ui);font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.1em">Raw LLM output (parse fallback)</summary><pre style="font-size:11px;color:var(--text-dim);white-space:pre-wrap;padding:10px;border:1px solid var(--border);border-radius:3px;margin-top:6px">${_recapEsc(doc.raw_llm)}</pre></details>`;
  }

  body.innerHTML = html;
}

async function recapLoadHistory() {
  const list = document.getElementById('recap-history-list');
  if (!list) return;
  try {
    const r = await fetch(`/api/recap/list?limit=60&client_id=${encodeURIComponent(_recapClientId())}`, { headers: { ..._authHeader() } });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();
    const items = j.recaps || [];
    if (!items.length) {
      list.innerHTML = '<div style="color:var(--text-dim);padding:6px;font-size:11px">No recaps yet.</div>';
      return;
    }
    list.innerHTML = items.map(it => {
      const c = it.counts || {};
      return `<button onclick="recapLoad('${_recapEsc(it.date)}')"
        style="text-align:left;background:transparent;border:1px solid var(--border);color:var(--text);padding:6px 8px;font-family:var(--font-ui);font-size:11px;border-radius:2px;cursor:pointer">
        <div style="color:var(--accent)">${_recapEsc(it.date)}</div>
        <div style="color:var(--text-dim);font-size:10px;margin-top:2px">${c.articles||0}a · ${c.tweets||0}t · ${c.cves||0}c</div>
      </button>`;
    }).join('');
  } catch (e) {
    list.innerHTML = `<div style="color:var(--red);font-size:11px;padding:6px">${_recapEsc(e.message)}</div>`;
  }
}

async function recapLoad(date) {
  const input = document.getElementById('recap-date');
  if (date && input) input.value = date;
  const d = date || (input ? input.value : '');
  _recapStatus('Loading…', 'info');
  try {
    const cq = `client_id=${encodeURIComponent(_recapClientId())}`;
    const url = d ? `/api/recap/${encodeURIComponent(d)}?${cq}` : `/api/recap/latest?${cq}`;
    const r = await fetch(url, { headers: { ..._authHeader() } });
    if (r.status === 404) {
      _recapRenderEmpty(d || 'yesterday', !d);
      _recapStatus('No recap stored for that date', 'warn');
      return;
    }
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();
    _recapRender(j.recap);
    _recapStatus('Loaded', 'ok');
  } catch (e) {
    _recapStatus(e.message, 'err');
  }
}

function recapConfirmClose() {
  const ov = document.getElementById('recap-confirm-overlay');
  if (ov) ov.classList.remove('open');
}

function recapGenerate(force) {
  const input = document.getElementById('recap-date');
  const d = (input ? input.value : '') || '';
  const dateLabel = d || 'yesterday';
  const clientId = _recapClientId();
  const clientLabel = clientId !== 'default' ? ` for client "${clientId}"` : '';
  const ov = document.getElementById('recap-confirm-overlay');
  const msg = document.getElementById('recap-confirm-msg');
  const warn = document.getElementById('recap-confirm-warn');
  const ok = document.getElementById('recap-confirm-ok');
  if (!ov || !msg || !ok) {
    _recapRunGenerate(d, force, clientId);
    return;
  }
  msg.textContent = `Generate recap for ${dateLabel}${clientLabel}?`;
  if (warn) warn.style.display = force ? 'block' : 'none';
  ok.textContent = force ? 'FORCE REGEN' : 'GENERATE';
  ok.onclick = () => {
    recapConfirmClose();
    _recapRunGenerate(d, force, clientId);
  };
  ov.classList.add('open');
}

function _recapProgressShow() {
  const wrap = document.getElementById('recap-progress-wrap');
  if (wrap) wrap.style.display = 'block';
  _recapProgressSet(0, 'starting');
}

function _recapProgressSet(pct, label) {
  const bar = document.getElementById('recap-progress-bar');
  const lbl = document.getElementById('recap-progress-label');
  if (bar) bar.style.width = Math.max(0, Math.min(100, pct)) + '%';
  if (lbl) lbl.textContent = label || '';
}

function _recapProgressHide() {
  const wrap = document.getElementById('recap-progress-wrap');
  if (wrap) wrap.style.display = 'none';
}

async function _recapRunGenerate(d, force, clientId) {
  clientId = clientId || 'default';
  _recapStatus('Generating…', 'info');
  _recapProgressShow();

  const pollDate = d || '';
  const pollQs = new URLSearchParams();
  if (pollDate) pollQs.set('date', pollDate);
  pollQs.set('client_id', clientId);
  let polling = true;
  const poll = async () => {
    while (polling) {
      try {
        const pr = await fetch(`/api/recap/progress/status?${pollQs.toString()}`, { headers: { ..._authHeader() } });
        if (pr.ok) {
          const p = await pr.json();
          _recapProgressSet(p.pct || 0, p.stage || '');
          if (p.done) break;
        }
      } catch (_e) { /* keep polling — a transient failure here shouldn't kill the request */ }
      await new Promise(res => setTimeout(res, 1000));
    }
  };
  const pollPromise = poll();

  try {
    const qs = new URLSearchParams();
    if (d) qs.set('date', d);
    if (force) qs.set('force', 'true');
    qs.set('client_id', clientId);
    const r = await fetch(`/api/recap/generate?${qs.toString()}`, {
      method: 'POST',
      headers: { ..._authHeader() },
    });
    if (!r.ok) {
      const txt = await r.text();
      throw new Error('HTTP ' + r.status + ': ' + txt.slice(0, 200));
    }
    const j = await r.json();
    _recapRender(j.recap);
    _recapStatus('Generated · saved', 'ok');
    recapLoadHistory();
  } catch (e) {
    _recapStatus(e.message, 'err');
  } finally {
    polling = false;
    await pollPromise;
    _recapProgressHide();
  }
}

async function loadRecap() {
  const input = document.getElementById('recap-date');
  if (input && !input.value) {
    const y = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
    input.value = y;
  }
  await recapLoadClients();
  recapLoadHistory();
  recapLoad(input ? input.value : '');
}
