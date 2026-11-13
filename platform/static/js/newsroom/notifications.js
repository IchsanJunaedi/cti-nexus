// In-app notifications: post-login modal + header bell.
// Backend: /api/notifications (see app/services/notification_service.py)

let _notifItems = [];
const _NOTIF_SEV_COLOR = { info: 'var(--accent)', warning: 'var(--yellow, #d29922)', critical: 'var(--red)' };

async function _notifFetch() {
  const res = await fetch('/api/notifications', { headers: _authHeader() });
  if (!res.ok) return [];
  return res.json();
}

function _notifUpdateBell() {
  const bell = document.getElementById('notif-bell');
  if (!bell) return;
  const unread = _notifItems.filter(n => !n.read).length;
  const badge = document.getElementById('notif-badge');
  badge.textContent = unread > 99 ? '99+' : unread;
  badge.style.display = unread ? '' : 'none';
  bell.style.display = _jwtValid() ? '' : 'none';
}

// popup=true: open the modal if there are unread popup-worthy items.
async function loadNotifications(popup = false) {
  if (!_jwtValid()) return;
  try {
    _notifItems = await _notifFetch();
  } catch (e) {
    return;
  }
  _notifUpdateBell();
  if (popup && _notifItems.some(n => !n.read && n.popup)) openNotifModal(true);
}

function _notifRender(unreadOnly) {
  const list = document.getElementById('notif-list');
  const items = _notifItems.filter(n => !unreadOnly || !n.read);
  if (!items.length) {
    list.innerHTML = '<div class="empty-state"><div class="empty-text">No notifications.</div></div>';
    return;
  }
  list.innerHTML = items.map(n => {
    const color = _NOTIF_SEV_COLOR[n.severity] || _NOTIF_SEV_COLOR.info;
    const when = new Date(n.created_at).toLocaleString();
    const act = n.action && n.action.tab
      ? `<button class="btn-apply" style="margin-top:8px" onclick="notifAction('${esc(n.id)}')">${esc(n.action.label || 'Open')}</button>`
      : '';
    return `<div style="padding:12px 18px;border-bottom:1px solid var(--border);border-left:3px solid ${color};opacity:${n.read ? .55 : 1}">
      <div style="font-weight:600;font-size:13px">${esc(n.title)}</div>
      <div style="font-size:12px;color:var(--text-dim);margin-top:4px">${esc(n.body)}</div>
      <div style="font-family:var(--font-ui);font-size:10px;color:var(--text-dim);margin-top:6px">${esc(when)}</div>
      ${act}
    </div>`;
  }).join('');
}

function openNotifModal(unreadOnly = false) {
  _notifRender(unreadOnly);
  document.getElementById('notif-overlay').classList.add('open');
}

function closeNotifModal() {
  document.getElementById('notif-overlay').classList.remove('open');
}

async function notifMarkAllRead() {
  await fetch('/api/notifications/read-all', { method: 'POST', headers: _authHeader() });
  _notifItems.forEach(n => { n.read = true; });
  _notifUpdateBell();
  closeNotifModal();
}

async function notifAction(id) {
  const n = _notifItems.find(x => x.id === id);
  if (!n || !n.action) return;
  fetch(`/api/notifications/${encodeURIComponent(id)}/read`, { method: 'POST', headers: _authHeader() });
  n.read = true;
  _notifUpdateBell();
  closeNotifModal();
  const tabBtn = [...document.querySelectorAll('.tab')]
    .find(b => (b.getAttribute('onclick') || '').includes(`'${n.action.tab}'`));
  if (tabBtn) switchTab(n.action.tab, tabBtn);
}

// Once per browser session on page load; login calls loadNotifications(true) directly.
if (_jwtValid()) {
  let seen = false;
  try { seen = sessionStorage.getItem('cti_notif_shown') === '1'; } catch (e) {}
  loadNotifications(!seen);
  try { sessionStorage.setItem('cti_notif_shown', '1'); } catch (e) {}
}
