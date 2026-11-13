// Newsletter queue + builder state are stored per user, so analysts sharing a
// browser never see each other's picks. Key is derived from the JWT "sub".
function _nlUser() {
  try {
    const t = localStorage.getItem('cti_jwt');
    if (!t) return 'anon';
    const b64 = t.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(b64)).sub || 'anon';
  } catch (e) { return 'anon'; }
}

function nlQueueKey() { return `newsletter_queue:${_nlUser()}`; }
function nlStateKey() { return `newsletter_builder_state:${_nlUser()}`; }

// Legacy un-namespaced keys were shared by every user of the browser; drop them.
localStorage.removeItem('newsletter_queue');
localStorage.removeItem('newsletter_builder_state');

function nlQueueGet() {
  try { return JSON.parse(localStorage.getItem(nlQueueKey()) || '[]'); } catch (e) { return []; }
}
function nlQueueSet(queue) { localStorage.setItem(nlQueueKey(), JSON.stringify(queue)); }
function nlQueueClear() { localStorage.removeItem(nlQueueKey()); }
