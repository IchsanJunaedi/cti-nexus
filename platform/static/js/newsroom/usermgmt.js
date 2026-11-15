// ── COUNTRY LIST ─────────────────────────────────────────────
const _COUNTRIES = [
  'Afghanistan','Albania','Algeria','Andorra','Angola','Antigua and Barbuda','Argentina','Armenia',
  'Australia','Austria','Azerbaijan','Bahamas','Bahrain','Bangladesh','Barbados','Belarus','Belgium',
  'Belize','Benin','Bhutan','Bolivia','Bosnia and Herzegovina','Botswana','Brazil','Brunei',
  'Bulgaria','Burkina Faso','Burundi','Cabo Verde','Cambodia','Cameroon','Canada','Central African Republic',
  'Chad','Chile','China','Colombia','Comoros','Congo (Brazzaville)','Congo (Kinshasa)','Costa Rica',
  'Croatia','Cuba','Cyprus','Czechia','Denmark','Djibouti','Dominica','Dominican Republic','Ecuador',
  'Egypt','El Salvador','Equatorial Guinea','Eritrea','Estonia','Eswatini','Ethiopia','Fiji','Finland',
  'France','Gabon','Gambia','Georgia','Germany','Ghana','Greece','Grenada','Guatemala','Guinea',
  'Guinea-Bissau','Guyana','Haiti','Honduras','Hungary','Iceland','India','Indonesia','Iran','Iraq',
  'Ireland','Israel','Italy','Jamaica','Japan','Jordan','Kazakhstan','Kenya','Kiribati','Kosovo',
  'Kuwait','Kyrgyzstan','Laos','Latvia','Lebanon','Lesotho','Liberia','Libya','Liechtenstein',
  'Lithuania','Luxembourg','Madagascar','Malawi','Malaysia','Maldives','Mali','Malta','Marshall Islands',
  'Mauritania','Mauritius','Mexico','Micronesia','Moldova','Monaco','Mongolia','Montenegro','Morocco',
  'Mozambique','Myanmar','Namibia','Nauru','Nepal','Netherlands','New Zealand','Nicaragua','Niger',
  'Nigeria','North Korea','North Macedonia','Norway','Oman','Pakistan','Palau','Palestine','Panama',
  'Papua New Guinea','Paraguay','Peru','Philippines','Poland','Portugal','Qatar','Romania','Russia',
  'Rwanda','Saint Kitts and Nevis','Saint Lucia','Saint Vincent and the Grenadines','Samoa',
  'San Marino','Sao Tome and Principe','Saudi Arabia','Senegal','Serbia','Seychelles','Sierra Leone',
  'Singapore','Slovakia','Slovenia','Solomon Islands','Somalia','South Africa','South Korea',
  'South Sudan','Spain','Sri Lanka','Sudan','Suriname','Sweden','Switzerland','Syria','Taiwan',
  'Tajikistan','Tanzania','Thailand','Timor-Leste','Togo','Tonga','Trinidad and Tobago','Tunisia',
  'Turkey','Turkmenistan','Tuvalu','Uganda','Ukraine','United Arab Emirates','United Kingdom',
  'United States','Uruguay','Uzbekistan','Vanuatu','Vatican City','Venezuela','Vietnam',
  'Yemen','Zambia','Zimbabwe'
];

function _buildCountryPicker(containerId, selected = []) {
  const sel  = new Set(selected.map(s => s.trim()).filter(Boolean));
  const wrap = document.getElementById(containerId);
  if (!wrap) return;
  wrap.innerHTML = `
    <input type="text" class="filter-input" placeholder="Search countries…"
           style="width:100%;margin-bottom:6px;font-size:11px;padding:5px 8px;box-sizing:border-box;font-family:var(--font-ui)"
           oninput="_filterCountryPicker(this,'${containerId}-list')">
    <div id="${containerId}-list" style="max-height:160px;overflow-y:auto;display:flex;flex-direction:column;gap:2px">
      ${_COUNTRIES.map(c => `<label style="display:flex;align-items:center;gap:6px;cursor:pointer;padding:2px 4px;border-radius:2px">
        <input type="checkbox" value="${esc(c)}" ${sel.has(c) ? 'checked' : ''} style="accent-color:var(--accent);cursor:pointer;flex-shrink:0">
        <span style="font-family:var(--font-ui);font-size:11px;color:var(--text-bright)">${esc(c)}</span>
      </label>`).join('')}
    </div>`;
}

function _filterCountryPicker(input, listId) {
  const q = input.value.toLowerCase();
  document.getElementById(listId).querySelectorAll('label').forEach(lbl => {
    lbl.style.display = lbl.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}

function _getCheckedCountries(containerId) {
  const wrap = document.getElementById(containerId);
  if (!wrap) return [];
  return Array.from(wrap.querySelectorAll('input[type=checkbox]:checked')).map(cb => cb.value);
}

// ── SECTOR LIST ──────────────────────────────────────────────
const _SECTORS = ['gov','bfsi','healthcare','energy','telco','manufacturing','retail','education','defense','technology'];
const _SECTOR_LABELS = {
  gov: 'Government', bfsi: 'BFSI', healthcare: 'Healthcare', energy: 'Energy', telco: 'Telecom',
  manufacturing: 'Manufacturing', retail: 'Retail', education: 'Education', defense: 'Defense', technology: 'Technology',
};

function _buildSectorPicker(containerId, selected = []) {
  const sel  = new Set(selected.map(s => s.trim().toLowerCase()).filter(Boolean));
  const wrap = document.getElementById(containerId);
  if (!wrap) return;
  wrap.innerHTML = `<div style="display:flex;flex-wrap:wrap;gap:4px 14px">
    ${_SECTORS.map(s => `<label style="display:flex;align-items:center;gap:6px;cursor:pointer;padding:2px 4px;border-radius:2px">
      <input type="checkbox" value="${esc(s)}" ${sel.has(s) ? 'checked' : ''} style="accent-color:var(--accent);cursor:pointer;flex-shrink:0">
      <span style="font-family:var(--font-ui);font-size:11px;color:var(--text-bright)">${esc(_SECTOR_LABELS[s] || s)}</span>
    </label>`).join('')}
  </div>`;
}

function _getCheckedSectors(containerId) {
  const wrap = document.getElementById(containerId);
  if (!wrap) return [];
  return Array.from(wrap.querySelectorAll('input[type=checkbox]:checked')).map(cb => cb.value);
}

// ── ROLES ────────────────────────────────────────────────────

let _umRolesCache = null;
let _umPermissionsCache = null;

async function _fetchRoles() {
  if (_umRolesCache) return _umRolesCache;
  try {
    const res = await fetch('/api/roles', { headers: { 'Authorization': 'Bearer ' + _jwtToken } });
    if (!res.ok) return [];
    _umRolesCache = await res.json();
    return _umRolesCache;
  } catch(_) { return []; }
}

async function _fetchPermissions() {
  if (_umPermissionsCache) return _umPermissionsCache;
  try {
    const res = await fetch('/api/roles/permissions', { headers: { 'Authorization': 'Bearer ' + _jwtToken } });
    if (!res.ok) return [];
    _umPermissionsCache = await res.json();
    return _umPermissionsCache;
  } catch(_) { return []; }
}

async function _populateRoleSelect(selectId, currentValue) {
  const sel = document.getElementById(selectId);
  if (!sel) return;
  const roles = await _fetchRoles();
  const isSuperadmin = _jwtRole() === 'superadmin';
  sel.innerHTML = roles
    .filter(r => isSuperadmin || r.name !== 'superadmin')
    .map(r => `<option value="${esc(r.name)}"${r.name === currentValue ? ' selected' : ''}>${esc(r.name)}${r.display_name !== r.name ? ' — ' + esc(r.display_name) : ''}</option>`)
    .join('');
}

async function loadUMRoles() {
  const tbody  = document.getElementById('um-roles-tbody');
  const addBtn = document.getElementById('um-add-role-btn');
  if (!tbody) return;
  if (!_jwtValid()) {
    tbody.innerHTML = '<tr><td colspan="4" style="padding:12px 8px;color:var(--text-dim);font-family:var(--font-ui);font-size:10px">Sign in as admin to view roles.</td></tr>';
    return;
  }
  _umRolesCache = null;
  const roles = await _fetchRoles();
  const isSuperadmin = _jwtRole() === 'superadmin';
  if (addBtn) addBtn.style.display = isSuperadmin ? '' : 'none';

  if (!roles.length) {
    tbody.innerHTML = '<tr><td colspan="4" style="padding:12px 8px;color:var(--text-dim);font-size:11px">No roles found.</td></tr>';
    return;
  }

  tbody.innerHTML = roles.map(r => {
    const systemBadge = r.is_system
      ? '<span style="font-family:var(--font-ui);font-size:8px;padding:1px 5px;border-radius:2px;background:rgba(88,166,255,0.1);border:1px solid rgba(88,166,255,0.3);color:var(--accent3);margin-left:6px">system</span>'
      : '';
    const perms = (r.permissions || []).map(p =>
      `<span style="font-family:var(--font-ui);font-size:8px;padding:1px 5px;border-radius:2px;background:rgba(47,129,247,0.06);border:1px solid rgba(47,129,247,0.2);color:var(--text-dim);margin:1px 2px 1px 0;display:inline-block">${esc(p)}</span>`
    ).join('');
    const canDelete = isSuperadmin && !r.is_system;
    const canEdit   = ['admin','superadmin'].includes(_jwtRole()) && r.name !== 'superadmin';
    return `<tr>
      <td style="padding:6px 8px;font-family:var(--font-ui);font-size:11px;color:var(--accent)">
        ${esc(r.name)}${systemBadge}
      </td>
      <td style="padding:6px 8px;font-size:12px;color:var(--text)">${esc(r.display_name || r.name)}</td>
      <td style="padding:6px 8px;max-width:500px">${perms || '<span style="color:var(--text-dim);font-size:10px">no permissions</span>'}</td>
      <td style="padding:6px 8px;white-space:nowrap">
        ${canEdit ? `<button class="pir-btn" onclick="umOpenAddRoleModal('${esc(r.name)}')" style="font-size:9px;margin-right:4px">Edit</button>` : ''}
        ${canDelete ? `<button class="pir-btn" onclick="umDeleteRole('${esc(r.name)}')" style="font-size:9px;color:var(--red);border-color:rgba(218,54,51,0.4)">Delete</button>` : ''}
      </td>
    </tr>`;
  }).join('');
}

let _umEditingRole = null;

async function umOpenAddRoleModal(editName) {
  const roles = editName ? await _fetchRoles() : [];
  const existing = editName ? roles.find(r => r.name === editName) : null;
  _umEditingRole = existing ? existing.name : null;
  document.getElementById('ar-title').textContent = existing ? 'Edit Role' : 'Add Custom Role';
  document.getElementById('ar-save-btn').textContent = existing ? 'Save Changes' : 'Create Role';
  document.getElementById('ar-name').value = existing ? existing.name : '';
  document.getElementById('ar-name').disabled = !!existing;
  document.getElementById('ar-display-name').value = existing ? (existing.display_name || '') : '';
  document.getElementById('ar-err').style.display = 'none';
  const grid = document.getElementById('ar-permissions-grid');
  grid.innerHTML = '<div style="color:var(--text-dim);font-family:var(--font-ui);font-size:10px">Loading…</div>';
  document.getElementById('ar-overlay').classList.add('open');
  document.body.style.overflow = 'hidden';

  const perms = await _fetchPermissions();
  const have = new Set(existing ? (existing.permissions || []) : []);
  grid.innerHTML = perms.map(p =>
    `<label style="display:flex;align-items:flex-start;gap:6px;cursor:pointer;font-family:var(--font-ui);font-size:11px;line-height:1.4">
      <input type="checkbox" class="ar-perm-cb" value="${esc(p.key)}"${have.has(p.key) ? ' checked' : ''} style="margin-top:2px;flex-shrink:0">
      <span><span style="color:var(--text-bright)">${esc(p.key)}</span><br><span style="color:var(--text-dim);font-size:9px">${esc(p.description)}</span></span>
    </label>`
  ).join('');
  setTimeout(() => document.getElementById(existing ? 'ar-display-name' : 'ar-name').focus(), 100);
}

function umCloseAddRoleModal() {
  document.getElementById('ar-overlay').classList.remove('open');
  document.body.style.overflow = '';
}

async function umSaveRole() {
  const name        = document.getElementById('ar-name').value.trim();
  const displayName = document.getElementById('ar-display-name').value.trim();
  const errEl       = document.getElementById('ar-err');
  errEl.style.display = 'none';
  if (!name)        { errEl.textContent = 'Role ID required.'; errEl.style.display = ''; return; }
  if (!displayName) { errEl.textContent = 'Display name required.'; errEl.style.display = ''; return; }
  if (!/^[a-z0-9_-]+$/.test(name)) { errEl.textContent = 'Role ID: lowercase a-z, 0-9, _ or - only.'; errEl.style.display = ''; return; }

  const permissions = Array.from(document.querySelectorAll('.ar-perm-cb:checked')).map(cb => cb.value);

  const editing = _umEditingRole;
  try {
    const res = await fetch(editing ? `/api/roles/${encodeURIComponent(editing)}` : '/api/roles', {
      method: editing ? 'PUT' : 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + _jwtToken },
      body: JSON.stringify(editing ? { display_name: displayName, permissions } : { name, display_name: displayName, permissions }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { errEl.textContent = data.detail || `Error ${res.status}`; errEl.style.display = ''; return; }
    umCloseAddRoleModal();
    _cveToast(`Role "${name}" ${editing ? 'updated' : 'created'}.`, true);
    _umRolesCache = null;
    loadUMRoles();
    _populateRoleSelect('um-new-role');
    _populateRoleSelect('er-role-select');
  } catch(e) { errEl.textContent = e.message; errEl.style.display = ''; }
}

async function umDeleteRole(name) {
  if (!confirm(`Delete role "${name}"? Users assigned this role will keep it until manually changed.`)) return;
  try {
    const res = await fetch(`/api/roles/${encodeURIComponent(name)}`, {
      method: 'DELETE',
      headers: { 'Authorization': 'Bearer ' + _jwtToken },
    });
    if (!res.ok) { const d = await res.json().catch(()=>({})); alert(d.detail || `Error ${res.status}`); return; }
    _cveToast(`Role "${name}" deleted.`, true);
    _umRolesCache = null;
    loadUMRoles();
    _populateRoleSelect('um-new-role');
    _populateRoleSelect('er-role-select');
  } catch(e) { alert(e.message); }
}

// ── USER MANAGEMENT ──────────────────────────────────────────
let _umAuditPage = 1;
let _umAuditTimer = null;

// _validatePasswordClient and _pwPolicy defined in policy section above

async function loadUMUsers() {
  if (!_jwtValid()) { document.getElementById('um-user-tbody').innerHTML = '<tr><td colspan="7" style="padding:12px 8px;color:var(--text-dim);font-family:var(--font-ui);font-size:10px">Sign in as admin to view users.</td></tr>'; return; }
  try {
    const res  = await fetch('/api/auth/users', { headers: { 'Authorization': 'Bearer ' + _jwtToken } });
    if (!res.ok) { document.getElementById('um-user-tbody').innerHTML = `<tr><td colspan="7" style="padding:12px 8px;color:var(--red);font-size:11px">${res.status === 403 ? 'Admin access required.' : 'Error ' + res.status}</td></tr>`; return; }
    const users = await res.json();
    document.getElementById('um-user-tbody').innerHTML = users.length
      ? users.map(u => {
          const clientIds  = u.client_ids || [u.client_id || 'default'];
          const clientsCsv = esc(clientIds.join(','));
          const un         = esc(u.username);
          const isAdmin    = ['admin','superadmin'].includes(_jwtRole());
          const roleBadge  = u.role==='superadmin'
            ? 'background:rgba(245,158,11,0.15);color:#FBBF24;border:1px solid rgba(245,158,11,0.4);border-radius:4px;padding:2px 8px;font-weight:600;'
            : u.role==='admin'
              ? 'background:rgba(56,189,248,0.15);color:#38BDF8;border:1px solid rgba(56,189,248,0.4);border-radius:4px;padding:2px 8px;font-weight:600;'
              : 'background:rgba(167,139,250,0.15);color:#C4B5FD;border:1px solid rgba(167,139,250,0.4);border-radius:4px;padding:2px 8px;font-weight:600;';
          return `<tr>
            <td style="padding:10px 14px;font-family:var(--font-ui);font-size:11.5px;color:var(--text-bright);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${un}">${un}</td>
            <td style="padding:10px 14px;font-size:11px;white-space:nowrap"><span style="font-family:var(--font-ui);font-size:9.5px;${roleBadge}">${esc(u.role)}</span></td>
            <td style="padding:10px 14px;font-family:var(--font-ui);font-size:10.5px;color:var(--text-dim)">
              ${clientIds.map(c=>`<span style="font-family:var(--font-ui);font-size:9.5px;padding:2px 7px;border-radius:4px;background:rgba(15,34,64,0.65);border:1px solid rgba(90,185,193,0.28);color:#93B1C8;margin-right:4px;display:inline-block">${esc(typeof formatClientCode === 'function' ? formatClientCode(c) : c)}</span>`).join('')}
            </td>
            <td style="padding:10px 14px;font-family:var(--font-ui);font-size:10.5px;color:var(--text-dim);white-space:nowrap">${(u.created_at||'').split('T')[0]}</td>
            <td style="padding:10px 14px;font-family:var(--font-ui);font-size:10.5px;color:var(--text-dim);white-space:nowrap">${u.last_sign_in ? u.last_sign_in.replace('T',' ').split('.')[0] : '—'}</td>
            <td style="padding:10px 14px;font-family:var(--font-ui);font-size:10.5px;color:var(--text-dim);white-space:nowrap">${esc(u.created_by||'')}</td>
            <td style="padding:10px 14px;white-space:nowrap;position:relative;text-align:right">
              <button class="pir-btn" onclick="umToggleActionMenu(event,'${un}','${esc(u.role)}','${clientsCsv}')"
                      style="font-size:11px;padding:4px 8px;letter-spacing:.05em">${ic("more-vertical", 13)}</button>
            </td>
          </tr>`;
        }).join('')
      : '<tr><td colspan="7" style="padding:12px 8px;color:var(--text-dim);font-size:11px">No users found.</td></tr>';
  } catch(e) {
    document.getElementById('um-user-tbody').innerHTML = `<tr><td colspan="7" style="color:var(--red);padding:8px">${e.message}</td></tr>`;
  }
}

// Reset password modal
let _resetPwTarget = null;
function openResetPwModal(username) {
  _resetPwTarget = username;
  document.getElementById('um-reset-username').textContent = username;
  document.getElementById('um-reset-pw-input').value = '';
  document.getElementById('um-reset-pw-err').style.display = 'none';
  document.getElementById('um-reset-overlay').classList.add('open');
  document.body.style.overflow = 'hidden';
  setTimeout(() => document.getElementById('um-reset-pw-input').focus(), 150);
}
function closeResetPwModal() {
  document.getElementById('um-reset-overlay').classList.remove('open');
  document.body.style.overflow = '';
  _resetPwTarget = null;
}
async function doResetPassword() {
  const pw    = document.getElementById('um-reset-pw-input').value;
  const errEl = document.getElementById('um-reset-pw-err');
  errEl.style.display = 'none';
  const pwErr = _validatePasswordClient(pw);
  if (pwErr) { errEl.textContent = pwErr; errEl.style.display = ''; return; }
  if (!_jwtValid()) { errEl.textContent = 'Not signed in.'; errEl.style.display = ''; return; }
  try {
    const res = await fetch(`/api/auth/users/${encodeURIComponent(_resetPwTarget)}/reset-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + _jwtToken },
      body: JSON.stringify({ new_password: pw }),
    });
    const data = await res.json();
    if (!res.ok) { errEl.textContent = data.detail || `Error ${res.status}`; errEl.style.display = ''; return; }
    closeResetPwModal();
    _taStatus(`Password reset for ${_resetPwTarget || ''}`, true);
  } catch(e) { errEl.textContent = e.message; errEl.style.display = ''; }
}

async function umAddUser() {
  const username = document.getElementById('um-new-username').value.trim();
  const password = document.getElementById('um-new-password').value;
  const role     = document.getElementById('um-new-role').value;
  const errEl    = document.getElementById('um-add-err');
  errEl.style.display = 'none';

  if (!username) { errEl.textContent = 'Username required.'; errEl.style.display = ''; return; }
  if (!password) { errEl.textContent = 'Password required.'; errEl.style.display = ''; return; }

  try {
    const pwErr = _validatePasswordClient(password);
    if (pwErr) { errEl.textContent = pwErr; errEl.style.display = ''; return; }
  } catch (_) {}

  if (!_jwtValid()) { errEl.textContent = 'Not signed in — use Sign In button.'; errEl.style.display = ''; return; }

  const btn = document.querySelector('#tab-users .btn-apply');
  if (btn) { btn.textContent = 'Adding…'; btn.disabled = true; }
  try {
    const clientRaw = document.getElementById('um-new-client-id-user')?.value.trim() || 'default';
    const clientIds = clientRaw.split(',').map(s => {
      const t = s.trim().toLowerCase();
      return (window.CLIENT_CODE_TO_REAL && window.CLIENT_CODE_TO_REAL[t]) || t;
    }).filter(Boolean);
    const res = await fetch('/api/auth/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + _jwtToken },
      body: JSON.stringify({ username, password, role, client_ids: clientIds.length ? clientIds : ['default'] }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const msg = Array.isArray(data.detail)
        ? data.detail.map(e => e.msg || JSON.stringify(e)).join('; ')
        : (data.detail || `Server error ${res.status}`);
      errEl.textContent = msg;
      errEl.style.display = '';
      return;
    }
    document.getElementById('um-new-username').value = '';
    document.getElementById('um-new-password').value = '';
    _cveToast(`User "${username}" created as ${role}.`, true);
    loadUMUsers();
  } catch(e) {
    errEl.textContent = e.message;
    errEl.style.display = '';
  } finally {
    if (btn) { btn.textContent = 'Add User'; btn.disabled = false; }
  }
}

// ── Password Policy ──────────────────────────────────────────
let _pwPolicy = { min_length:8, require_upper:true, require_lower:true, require_number:true, require_symbol:true };

async function loadPolicy() {
  try {
    const res = await fetch('/api/auth/policy');
    if (!res.ok) return;
    _pwPolicy = await res.json();
    _applyPolicyToUI();
  } catch(_) {}
}

function _renderPwTooltip(el, p) {
  if (!el) return;
  const policy = p || _pwPolicy || {};
  const minLen = policy.min_length || 8;
  const items = [
    `Min ${minLen} characters`
  ];
  if (policy.require_upper !== false)  items.push('Uppercase letter (A–Z)');
  if (policy.require_lower !== false)  items.push('Lowercase letter (a–z)');
  if (policy.require_number !== false) items.push('Number (0–9)');
  if (policy.require_symbol !== false) items.push('Special symbol (!@#$...)');

  const checkSvg = (window.ic ? window.ic('check', 10, 'pw-rule-check') : '<i data-ic="check" data-size="10" class="pw-rule-check"></i>');
  const shieldSvg = (window.ic ? window.ic('shield', 11) : '<i data-ic="shield" data-size="11"></i>');

  el.innerHTML = `
    <div class="pw-tooltip-head">
      ${shieldSvg}
      <span>Password Policy</span>
    </div>
    <ul class="pw-tooltip-list">
      ${items.map(it => `
        <li class="pw-tooltip-item">
          ${checkSvg}
          <span>${esc(it)}</span>
        </li>
      `).join('')}
    </ul>
  `;
}

function _applyPolicyToUI() {
  // Update all tooltip spans with structured policy card
  ['pw-tooltip-dyn','pw-tooltip-dyn2','pw-tooltip-force','pw-tooltip-self'].forEach(id => {
    _renderPwTooltip(document.getElementById(id), _pwPolicy);
  });
  // Populate policy form if visible
  const ml = document.getElementById('pol-min-length');
  if (ml) {
    ml.value = _pwPolicy.min_length ?? 8;
    document.getElementById('pol-upper').checked  = !!_pwPolicy.require_upper;
    document.getElementById('pol-lower').checked  = !!_pwPolicy.require_lower;
    document.getElementById('pol-number').checked = !!_pwPolicy.require_number;
    document.getElementById('pol-symbol').checked = !!_pwPolicy.require_symbol;
  }
}

function _buildHint(p) {
  const parts = [`Min ${p.min_length||8} chars`];
  if (p.require_upper)  parts.push('uppercase');
  if (p.require_lower)  parts.push('lowercase');
  if (p.require_number) parts.push('number');
  if (p.require_symbol) parts.push('symbol');
  return parts.join(' · ');
}

function _validatePasswordClient(pw) {
  const p = _pwPolicy;
  if (pw.length < (p.min_length||8))          return `Min ${p.min_length||8} characters`;
  if (p.require_upper  && !/[A-Z]/.test(pw))  return 'Need uppercase letter';
  if (p.require_lower  && !/[a-z]/.test(pw))  return 'Need lowercase letter';
  if (p.require_number && !/[0-9]/.test(pw))  return 'Need number';
  if (p.require_symbol && !/[^A-Za-z0-9]/.test(pw)) return 'Need symbol (e.g. !@#$)';
  return null;
}

async function savePolicy() {
  const errEl = document.getElementById('pol-err');
  const stat  = document.getElementById('pol-status');
  errEl.style.display = 'none';
  if (!_jwtValid()) { errEl.textContent = 'Not signed in.'; errEl.style.display = ''; return; }
  const body = {
    min_length:       parseInt(document.getElementById('pol-min-length').value) || 8,
    require_upper:    document.getElementById('pol-upper').checked,
    require_lower:    document.getElementById('pol-lower').checked,
    require_number:   document.getElementById('pol-number').checked,
    require_symbol:   document.getElementById('pol-symbol').checked,
    force_all_change: document.getElementById('pol-force-all').checked,
  };
  try {
    const res = await fetch('/api/auth/policy', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + _jwtToken },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) { errEl.textContent = data.detail || `Error ${res.status}`; errEl.style.display = ''; return; }
    document.getElementById('pol-force-all').checked = false;
    await loadPolicy();
    stat.textContent = `Saved${data.flagged_users ? ` · ${data.flagged_users} users flagged` : ''}`;
    setTimeout(() => { if (stat) stat.textContent = ''; }, 3500);
  } catch(e) { errEl.textContent = e.message; errEl.style.display = ''; }
}

// ── Header user dropdown ──────────────────────────────────────
function _refreshQueueCount() {
  try {
    const q = nlQueueGet();
    document.getElementById('header-queue-count').textContent = q.length;
  } catch(e) {}
}

function toggleUserDropdown(ev) {
  ev.stopPropagation();
  _refreshQueueCount();
  const dd = document.getElementById('user-dropdown');
  dd.style.display = dd.style.display === 'none' ? '' : 'none';
}

function closeUserDropdown() {
  document.getElementById('user-dropdown').style.display = 'none';
}

function openNewsletterQueue() {
  closeUserDropdown();
  // Navigate to newsletter page (same tab) — queue banner will show on load
  window.location.href = '/newsletter';
}

document.addEventListener('click', function(e) {
  const wrap = document.getElementById('header-user-wrap');
  if (wrap && !wrap.contains(e.target)) closeUserDropdown();
});

// ── Self change password (header username click) ─────────────
function openSelfPwModal() {
  if (!_jwtValid()) { _cveToast('Sign in first.', false); return; }
  document.getElementById('self-pw-username').textContent = _jwtUsername() || '—';
  document.getElementById('self-pw-input').value = '';
  document.getElementById('self-pw-err').style.display = 'none';
  const tipEl = document.getElementById('pw-tooltip-self');
  if (tipEl) _renderPwTooltip(tipEl, _pwPolicy);
  document.getElementById('self-pw-overlay').classList.add('open');
  document.body.style.overflow = 'hidden';
  setTimeout(() => document.getElementById('self-pw-input').focus(), 150);
}

function closeSelfPwModal() {
  document.getElementById('self-pw-overlay').classList.remove('open');
  document.body.style.overflow = '';
}

async function doSelfPwChange() {
  const pw    = document.getElementById('self-pw-input').value;
  const errEl = document.getElementById('self-pw-err');
  errEl.style.display = 'none';
  if (!pw) { errEl.textContent = 'Password required.'; errEl.style.display = ''; return; }
  try {
    const pwErr = _validatePasswordClient(pw);
    if (pwErr) { errEl.textContent = pwErr; errEl.style.display = ''; return; }
  } catch (_) {}
  try {
    const res = await fetch('/api/auth/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + _jwtToken },
      body: JSON.stringify({ new_password: pw }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const msg = Array.isArray(data.detail)
        ? data.detail.map(e => e.msg || JSON.stringify(e)).join('; ')
        : (data.detail || `Error ${res.status}`);
      errEl.textContent = msg; errEl.style.display = ''; return;
    }
    closeSelfPwModal();
    _cveToast('Password updated successfully.', true);
  } catch(e) { errEl.textContent = e.message; errEl.style.display = ''; }
}

// ── Force password change flow ───────────────────────────────
async function doForcePwChange() {
  const pw    = document.getElementById('force-pw-input').value;
  const errEl = document.getElementById('force-pw-err');
  errEl.style.display = 'none';
  const pwErr = _validatePasswordClient(pw);
  if (pwErr) { errEl.textContent = pwErr; errEl.style.display = ''; return; }
  try {
    const res = await fetch('/api/auth/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + _jwtToken },
      body: JSON.stringify({ new_password: pw }),
    });
    const data = await res.json();
    if (!res.ok) { errEl.textContent = data.detail || `Error ${res.status}`; errEl.style.display = ''; return; }
    document.getElementById('force-pw-overlay').classList.remove('open');
    document.body.style.overflow = '';
    _taStatus('Password updated.', true);
  } catch(e) { errEl.textContent = e.message; errEl.style.display = ''; }
}

function _umAuditDebounce() {
  clearTimeout(_umAuditTimer);
  _umAuditTimer = setTimeout(() => loadAuditLog(1), 400);
}

async function loadAuditLog(page) {
  _umAuditPage = page;
  const userF    = (document.getElementById('um-audit-user')?.value   || '').trim();
  const actionF  = (document.getElementById('um-audit-action')?.value || '').trim();
  const pageSize = parseInt(document.getElementById('um-audit-page-size')?.value || '25', 10);
  const tbody    = document.getElementById('um-audit-tbody');
  const pager    = document.getElementById('um-audit-pager');
  if (!_jwtValid()) { tbody.innerHTML = '<tr><td colspan="6" style="padding:12px 8px;color:var(--text-dim);font-size:10px;font-family:var(--font-ui)">Sign in as admin to view audit log.</td></tr>'; return; }
  tbody.innerHTML = '<tr><td colspan="6" style="padding:12px 8px;color:var(--text-dim);font-size:10px;font-family:var(--font-ui)">Loading…</td></tr>';
  try {
    const params = new URLSearchParams({ page, page_size: pageSize });
    if (userF)   params.set('user',   userF);
    if (actionF) params.set('action', actionF);
    const res  = await fetch(`/api/auth/audit-log?${params}`, { headers: { 'Authorization': 'Bearer ' + _jwtToken } });
    if (!res.ok) { tbody.innerHTML = `<tr><td colspan="6" style="color:var(--red);padding:8px;font-size:11px">${res.status === 403 ? 'Admin access required.' : 'Error ' + res.status}</td></tr>`; return; }
    const data = await res.json();
    document.getElementById('um-audit-total').textContent = `${data.total} entries`;
    tbody.innerHTML = (data.logs || []).length
      ? data.logs.map(l => `<tr>
          <td style="padding:5px 8px;font-family:var(--font-ui);font-size:10px;color:var(--text-dim);white-space:nowrap">${(l.timestamp||'').replace('T',' ').split('.')[0]}</td>
          <td style="padding:5px 8px;font-family:var(--font-ui);font-size:11px;color:var(--accent)">${esc(l.user||'')}</td>
          <td style="padding:5px 8px;font-family:var(--font-ui);font-size:11px;color:var(--text-bright)">${esc(l.action||'')}</td>
          <td style="padding:5px 8px;font-size:11px;color:var(--text-dim);max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(l.target_id||'')}</td>
          <td style="padding:5px 8px;font-size:10px;color:var(--text-dim);font-family:var(--font-ui);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${l.detail && Object.keys(l.detail).length ? JSON.stringify(l.detail) : '—'}</td>
          <td style="padding:5px 8px;font-family:var(--font-ui);font-size:10px;color:var(--text-dim)">${esc(l.ip||'')}</td>
        </tr>`).join('')
      : '<tr><td colspan="6" style="padding:12px 8px;color:var(--text-dim);font-size:11px">No entries found.</td></tr>';

    // Pager
    const totalPages = Math.ceil(data.total / pageSize);
    pager.innerHTML = '';
    if (totalPages > 1) {
      if (page > 1) pager.innerHTML += `<button class="pir-btn" onclick="loadAuditLog(${page-1})">${ic("chevron-left", 12)} Prev</button>`;
      pager.innerHTML += `<span>Page ${page} / ${totalPages}</span>`;
      if (page < totalPages) pager.innerHTML += `<button class="pir-btn" onclick="loadAuditLog(${page+1})">Next ${ic("chevron-right", 12)}</button>`;
    }
  } catch(e) {
    tbody.innerHTML = `<tr><td colspan="6" style="color:var(--red);padding:8px">${e.message}</td></tr>`;
  }
}

// ── USER ACTION DROPDOWN ──────────────────────────────────────

let _umActionMenu = null;

function umCloseActionMenu() {
  if (_umActionMenu) { _umActionMenu.remove(); _umActionMenu = null; }
}

document.addEventListener('click', (e) => {
  if (_umActionMenu && !_umActionMenu.contains(e.target)) umCloseActionMenu();
});

function umToggleActionMenu(evt, username, role, clientsCsv) {
  evt.stopPropagation();
  umCloseActionMenu();

  const btn  = evt.currentTarget;
  const rect = btn.getBoundingClientRect();
  const isAdmin = ['admin','superadmin'].includes(_jwtRole());

  const menu = document.createElement('div');
  menu.className = 'um-action-popup';
  menu.style.cssText = `
    position:fixed;right:${document.documentElement.clientWidth - rect.right}px;
    top:${rect.bottom + 4}px;z-index:9999;
  `;

  const item = (icon, label, fn) => {
    const b = document.createElement('button');
    b.innerHTML = `${icon} <span>${label}</span>`;
    b.onclick = (e) => { e.stopPropagation(); umCloseActionMenu(); fn(); };
    return b;
  };

  menu.appendChild(item(ic('key', 12), 'Reset Password',  () => openResetPwModal(username)));
  if (isAdmin) {
    menu.appendChild(item(ic('building', 12), 'Edit Clients',  () => openEditClientsModal(username, clientsCsv)));
    menu.appendChild(item(ic('user', 12), 'Change Role',   () => openEditRoleModal(username, role)));
    const myRole = _jwtRole();
    const canDelete = (myRole === 'superadmin' && username !== _jwtUsername()) ||
                      (myRole === 'admin' && role !== 'superadmin');
    if (canDelete) {
      const delBtn = item(ic('trash', 12), 'Delete User', () => umDeleteUser(username, role));
      delBtn.style.color = 'var(--red)';
      menu.appendChild(delBtn);
    }
  }

  // remove border from last item
  const last = menu.lastElementChild;
  if (last) last.style.borderBottom = 'none';

  document.body.appendChild(menu);
  _umActionMenu = menu;
}

// ── CHANGE ROLE MODAL ─────────────────────────────────────────

let _editRoleTarget = null;

async function openEditRoleModal(username, currentRole) {
  _editRoleTarget = username;
  document.getElementById('er-username').textContent = username;
  document.getElementById('er-err').style.display = 'none';
  document.getElementById('er-overlay').classList.add('open');
  document.body.style.overflow = 'hidden';
  await _populateRoleSelect('er-role-select', currentRole);
}

function closeEditRoleModal() {
  document.getElementById('er-overlay').classList.remove('open');
  document.body.style.overflow = '';
  _editRoleTarget = null;
}

async function saveEditRole() {
  const role  = document.getElementById('er-role-select').value;
  const errEl = document.getElementById('er-err');
  errEl.style.display = 'none';
  try {
    const res = await fetch(`/api/auth/users/${encodeURIComponent(_editRoleTarget)}/role`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + _jwtToken },
      body: JSON.stringify({ role }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { errEl.textContent = data.detail || `Error ${res.status}`; errEl.style.display = ''; return; }
    _cveToast(`Role updated for "${_editRoleTarget}".`, true);
    closeEditRoleModal();
    loadUMUsers();
  } catch(e) { errEl.textContent = e.message; errEl.style.display = ''; }
}

// ── EDIT USER CLIENTS (superadmin only) ──────────────────────

let _editClientsTarget = null;

async function openEditClientsModal(username, currentIdsCsv) {
  _editClientsTarget = username;
  document.getElementById('ec-username').textContent = username;
  document.getElementById('ec-err').style.display = 'none';
  document.getElementById('ec-overlay').classList.add('open');
  document.body.style.overflow = 'hidden';

  const currentIds = new Set((currentIdsCsv || 'default').split(',').map(s => s.trim()).filter(Boolean));
  const listEl = document.getElementById('ec-clients-list');
  listEl.innerHTML = '<span style="font-family:var(--font-ui);font-size:10px;color:var(--text-dim)">Loading…</span>';
  try {
    const res = await fetch('/api/clients', { headers: { 'Authorization': 'Bearer ' + _jwtToken } });
    const clients = res.ok ? await res.json() : [];
    listEl.innerHTML = clients.map(c => `
      <label style="display:flex;align-items:center;gap:8px;cursor:pointer;padding:3px 0">
        <input type="checkbox" value="${esc(c.client_id)}" ${currentIds.has(c.client_id) ? 'checked' : ''}
               style="accent-color:var(--accent);width:13px;height:13px;cursor:pointer">
        <span style="font-family:var(--font-ui);font-size:11px;color:var(--text-bright)">${esc(typeof formatClientName === 'function' ? formatClientName(c.client_id, c.name) : c.name)}</span>
        <span style="font-family:var(--font-ui);font-size:9px;color:var(--text-dim)">(${esc(typeof formatClientCode === 'function' ? formatClientCode(c.client_id) : c.client_id)})</span>
      </label>`).join('') || '<span style="font-family:var(--font-ui);font-size:10px;color:var(--text-dim)">No clients found.</span>';
  } catch(e) {
    listEl.innerHTML = `<span style="font-family:var(--font-ui);font-size:10px;color:var(--red)">${e.message}</span>`;
  }
}

function closeEditClientsModal() {
  document.getElementById('ec-overlay').classList.remove('open');
  document.body.style.overflow = '';
  _editClientsTarget = null;
}

async function saveEditClients() {
  const checked = document.querySelectorAll('#ec-clients-list input[type=checkbox]:checked');
  const ids     = Array.from(checked).map(cb => cb.value);
  const errEl   = document.getElementById('ec-err');
  errEl.style.display = 'none';
  if (!ids.length) { errEl.textContent = 'At least one client required.'; errEl.style.display = ''; return; }
  try {
    const res = await fetch(`/api/auth/users/${encodeURIComponent(_editClientsTarget)}/clients`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + _jwtToken },
      body: JSON.stringify({ client_ids: ids }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { errEl.textContent = data.detail || `Error ${res.status}`; errEl.style.display = ''; return; }
    _cveToast(`Updated clients for "${_editClientsTarget}".`, true);
    closeEditClientsModal();
    loadUMUsers();
    if (typeof _loadClientSwitcher === 'function') _loadClientSwitcher();
  } catch(e) { errEl.textContent = e.message; errEl.style.display = ''; }
}

async function umDeleteUser(username, role) {
  if (!confirm(`Delete user "${username}"? This cannot be undone.`)) return;
  try {
    const res = await fetch(`/api/auth/users/${encodeURIComponent(username)}`, {
      method: 'DELETE',
      headers: { 'Authorization': 'Bearer ' + _jwtToken },
    });
    if (!res.ok) { const d = await res.json().catch(()=>({})); alert(d.detail || `Error ${res.status}`); return; }
    _cveToast(`User "${username}" deleted.`, true);
    loadUMUsers();
  } catch(e) { alert(e.message); }
}

// ── CLIENT MANAGEMENT (superadmin only) ───────────────────────

async function loadUMClients() {
  const section = document.getElementById('um-clients-section');
  if (!section) return;
  const isPriv = ['admin','superadmin'].includes(_jwtRole());
  section.style.display = isPriv ? '' : 'none';
  if (!isPriv) return;

  const tbody = document.getElementById('um-clients-tbody');
  tbody.innerHTML = '<tr><td colspan="6" style="padding:12px 8px;color:var(--text-dim);font-family:var(--font-ui);font-size:10px">Loading…</td></tr>';
  try {
    const res = await fetch('/api/clients', { headers: { 'Authorization': 'Bearer ' + _jwtToken } });
    if (!res.ok) { tbody.innerHTML = `<tr><td colspan="6" style="color:var(--red);padding:8px">${res.status}</td></tr>`; return; }
    const clients = await res.json();
    window._umClientsCache = clients;
    const canManage = _jwtRole() === 'superadmin';
    // show/hide add button
    const addBtn = document.querySelector('#um-clients-section > div > button.btn-apply');
    if (addBtn) addBtn.style.display = canManage ? '' : 'none';
    tbody.innerHTML = clients.map(c => {
      const countriesDisplay = (c.countries && c.countries.length)
        ? c.countries.map(co => `<span style="display:inline-block;background:rgba(255,255,255,0.06);border:1px solid var(--border);border-radius:2px;padding:1px 5px;font-size:9px;margin:1px">${esc(co)}</span>`).join(' ')
        : `<span style="color:var(--text-dim);font-size:10px">—</span>`;
      const sectorsDisplay = (c.sectors && c.sectors.length)
        ? c.sectors.map(se => `<span style="display:inline-block;background:rgba(255,255,255,0.06);border:1px solid var(--border);border-radius:2px;padding:1px 5px;font-size:9px;margin:1px">${esc(_SECTOR_LABELS[se] || se)}</span>`).join(' ')
        : `<span style="color:var(--text-dim);font-size:10px">—</span>`;
      const recipients = c.recipients || [];
      const recipientsDisplay = recipients.length
        ? `<span style="font-family:var(--font-ui);font-size:10px;color:var(--text-dim)" title="${esc(recipients.join(', '))}">${recipients.length} recipient${recipients.length === 1 ? '' : 's'}</span>`
        : `<span style="color:var(--text-dim);font-size:10px">—</span>`;
      const editBtn = canManage
        ? `<button class="pir-btn" onclick="umOpenEditClient('${esc(c.client_id)}')" style="font-size:9px;margin-right:4px">Edit</button>`
        : '';
      const delBtn = canManage && c.client_id !== 'default'
        ? `<button class="pir-btn" onclick="umDeleteClient('${esc(c.client_id)}')" style="font-size:9px;color:var(--red);border-color:rgba(218,54,51,0.4)">Delete</button>`
        : '';
      return `<tr>
        <td style="padding:10px 14px;font-family:var(--font-ui);font-size:11px;color:var(--accent)">${esc(typeof formatClientCode === 'function' ? formatClientCode(c.client_id) : c.client_id)}</td>
        <td style="padding:10px 14px;font-size:12px;color:var(--text);font-weight:500">${esc(typeof formatClientName === 'function' ? formatClientName(c.client_id, c.name) : c.name)}</td>
        <td style="padding:6px 8px">${countriesDisplay}</td>
        <td style="padding:6px 8px">${sectorsDisplay}</td>
        <td style="padding:6px 8px">${recipientsDisplay}</td>
        <td style="padding:6px 8px;font-family:var(--font-ui);font-size:10px;color:var(--text-dim)">${(c.created_at||'').split('T')[0]}</td>
        <td style="padding:6px 8px;white-space:nowrap">${editBtn}${delBtn}</td>
      </tr>`;
    }).join('') || '<tr><td colspan="7" style="padding:12px 8px;color:var(--text-dim);font-size:11px">No clients.</td></tr>';
  } catch(e) {
    tbody.innerHTML = `<tr><td colspan="7" style="color:var(--red);padding:8px">${e.message}</td></tr>`;
  }
}

function umOpenAddClient() {
  const form = document.getElementById('um-add-client-form');
  if (!form) return;
  form.style.display = 'flex';
  _buildCountryPicker('um-new-client-countries-picker', []);
  _buildSectorPicker('um-new-client-sectors-picker', []);
  document.getElementById('um-new-client-id').focus();
}

function umCloseAddClient() {
  const form = document.getElementById('um-add-client-form');
  if (form) form.style.display = 'none';
  document.getElementById('um-client-err').style.display = 'none';
}

async function umSaveClient() {
  const clientId  = document.getElementById('um-new-client-id').value.trim();
  const name      = document.getElementById('um-new-client-name').value.trim();
  const countries = _getCheckedCountries('um-new-client-countries-picker');
  const sectors   = _getCheckedSectors('um-new-client-sectors-picker');
  const recipients = document.getElementById('um-new-client-recipients').value.split(',').map(s => s.trim()).filter(Boolean);
  const newsletter_css    = document.getElementById('um-new-client-css').value;
  const newsletter_intro  = document.getElementById('um-new-client-intro').value;
  const newsletter_footer = document.getElementById('um-new-client-footer').value;
  const errEl     = document.getElementById('um-client-err');
  errEl.style.display = 'none';
  if (!clientId || !name) { errEl.textContent = 'Both fields required.'; errEl.style.display = ''; return; }
  if (!/^[a-z0-9_-]+$/.test(clientId)) { errEl.textContent = 'Client ID: lowercase a-z, 0-9, _ or - only.'; errEl.style.display = ''; return; }
  try {
    const res = await fetch('/api/clients', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + _jwtToken },
      body: JSON.stringify({ client_id: clientId, name, countries, sectors, recipients, newsletter_css, newsletter_intro, newsletter_footer }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { errEl.textContent = data.detail || `Error ${res.status}`; errEl.style.display = ''; return; }
    umCloseAddClient();
    document.getElementById('um-new-client-id').value   = '';
    document.getElementById('um-new-client-name').value = '';
    document.getElementById('um-new-client-recipients').value = '';
    document.getElementById('um-new-client-css').value = '';
    document.getElementById('um-new-client-intro').value = '';
    document.getElementById('um-new-client-footer').value = '';
    _cveToast(`Client "${name}" created.`, true);
    loadUMClients();
    if (typeof _loadClientSwitcher === 'function') _loadClientSwitcher();
  } catch(e) { errEl.textContent = e.message; errEl.style.display = ''; }
}

async function umDeleteClient(clientId) {
  if (!confirm(`Delete client "${clientId}"? This does NOT delete their data — only the tenant record.`)) return;
  try {
    const res = await fetch(`/api/clients/${encodeURIComponent(clientId)}`, {
      method: 'DELETE',
      headers: { 'Authorization': 'Bearer ' + _jwtToken },
    });
    if (!res.ok) { const d = await res.json().catch(()=>({})); alert(d.detail || `Error ${res.status}`); return; }
    _cveToast(`Client "${clientId}" deleted.`, true);
    loadUMClients();
    if (typeof _loadClientSwitcher === 'function') _loadClientSwitcher();
  } catch(e) { alert(e.message); }
}

// ── EDIT CLIENT TENANT (superadmin only) ──────────────────────

let _editClientTarget = null;

function umOpenEditClient(clientId) {
  const c = (window._umClientsCache || []).find(x => x.client_id === clientId) || {};
  _editClientTarget = clientId;
  document.getElementById('ect-client-id').textContent = typeof formatClientCode === 'function' ? formatClientCode(clientId) : clientId;
  document.getElementById('ect-name').value = c.name || '';
  document.getElementById('ect-recipients').value = (c.recipients || []).join(', ');
  document.getElementById('ect-css').value = c.newsletter_css || '';
  document.getElementById('ect-intro').value = c.newsletter_intro || '';
  document.getElementById('ect-footer').value = c.newsletter_footer || '';
  document.getElementById('ect-err').style.display = 'none';
  _buildCountryPicker('ect-countries-picker', c.countries || []);
  _buildSectorPicker('ect-sectors-picker', c.sectors || []);
  document.getElementById('ect-overlay').classList.add('open');
  document.body.style.overflow = 'hidden';
  setTimeout(() => document.getElementById('ect-name').focus(), 100);
}

function umCloseEditClient() {
  document.getElementById('ect-overlay').classList.remove('open');
  document.body.style.overflow = '';
  _editClientTarget = null;
}

async function umSaveEditClient() {
  const name       = document.getElementById('ect-name').value.trim();
  const countries  = _getCheckedCountries('ect-countries-picker');
  const sectors    = _getCheckedSectors('ect-sectors-picker');
  const recipients = document.getElementById('ect-recipients').value.split(',').map(s => s.trim()).filter(Boolean);
  const newsletter_css    = document.getElementById('ect-css').value;
  const newsletter_intro  = document.getElementById('ect-intro').value;
  const newsletter_footer = document.getElementById('ect-footer').value;
  const errEl       = document.getElementById('ect-err');
  errEl.style.display = 'none';
  if (!name) { errEl.textContent = 'Name is required.'; errEl.style.display = ''; return; }
  try {
    const res = await fetch(`/api/clients/${encodeURIComponent(_editClientTarget)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + _jwtToken },
      body: JSON.stringify({ name, countries, sectors, recipients, newsletter_css, newsletter_intro, newsletter_footer }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { errEl.textContent = data.detail || `Error ${res.status}`; errEl.style.display = ''; return; }
    _cveToast(`Client "${_editClientTarget}" updated.`, true);
    if (window._clientsCountriesMap) window._clientsCountriesMap[_editClientTarget] = countries;
    if (typeof getActiveClientId === 'function' && getActiveClientId() === _editClientTarget) {
      localStorage.setItem('cti_client_countries', JSON.stringify(countries));
    }
    umCloseEditClient();
    loadUMClients();
    if (typeof _loadClientSwitcher === 'function') _loadClientSwitcher();
  } catch(e) { errEl.textContent = e.message; errEl.style.display = ''; }
}

