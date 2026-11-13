/* CTI Nexus — Custom Glassmorphic Dropdown (CtiSelect)
 * Replaces native OS <select> menus with a unified macOS/Linear-grade custom dropdown
 * while keeping 100% compatibility with native .value, .selectedIndex, onchange, and dynamic options.
 */
(function () {
  'use strict';

  const NATIVE_VALUE_DESC = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value');
  const NATIVE_INDEX_DESC = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'selectedIndex');

  let activeInstance = null;
  let portalMenu = null;

  function ensurePortal() {
    if (portalMenu && document.body.contains(portalMenu)) return portalMenu;
    portalMenu = document.createElement('div');
    portalMenu.className = 'cti-select-portal';
    portalMenu.setAttribute('role', 'listbox');
    portalMenu.style.display = 'none';
    document.body.appendChild(portalMenu);
    return portalMenu;
  }

  function stripLeadingSymbols(text) {
    return String(text || '').replace(/^[\s\p{Emoji_Presentation}\p{Extended_Pictographic}\u2190-\u27BF]+/u, '').trim();
  }

  function formatOptionLabel(opt) {
    if (!opt) return '';
    const raw = (opt.textContent || '').trim();
    return stripLeadingSymbols(raw) || raw;
  }

  function closeActiveMenu() {
    if (!activeInstance) return;
    const inst = activeInstance;
    activeInstance = null;
    inst.wrap.classList.remove('is-open');
    inst.trigger.setAttribute('aria-expanded', 'false');
    if (portalMenu) {
      portalMenu.classList.remove('is-visible');
      portalMenu.style.display = 'none';
      portalMenu.innerHTML = '';
    }
  }

  function positionPortal(trigger) {
    if (!portalMenu) return;
    const rect = trigger.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const minW = Math.max(rect.width, 168);
    const maxW = Math.min(360, vw - 16);
    const width = Math.min(Math.max(minW, rect.width), maxW);

    portalMenu.style.minWidth = `${ Math.round(rect.width) }px`;
    portalMenu.style.width = `${ Math.round(width) }px`;

    const menuHeight = Math.min(portalMenu.scrollHeight || 260, 320);
    const spaceBelow = vh - rect.bottom - 10;
    const spaceAbove = rect.top - 10;
    const openUp = spaceBelow < Math.min(menuHeight, 200) && spaceAbove > spaceBelow;

    let left = rect.left;
    if (left + width > vw - 8) left = Math.max(8, vw - width - 8);

    portalMenu.classList.toggle('is-up', openUp);
    portalMenu.style.left = `${ Math.round(left) }px`;
    if (openUp) {
      portalMenu.style.top = 'auto';
      portalMenu.style.bottom = `${ Math.round(vh - rect.top + 6) }px`;
      portalMenu.style.maxHeight = `${ Math.min(320, Math.max(120, spaceAbove - 8)) }px`;
    } else {
      portalMenu.style.bottom = 'auto';
      portalMenu.style.top = `${ Math.round(rect.bottom + 6) }px`;
      portalMenu.style.maxHeight = `${ Math.min(320, Math.max(140, spaceBelow - 8)) }px`;
    }
  }

  function openMenu(inst) {
    if (inst.select.disabled) return;
    if (activeInstance === inst) {
      closeActiveMenu();
      return;
    }
    closeActiveMenu();
    activeInstance = inst;
    inst.wrap.classList.add('is-open');
    inst.trigger.setAttribute('aria-expanded', 'true');

    const menu = ensurePortal();
    menu.innerHTML = '';

    const options = Array.from(inst.select.options);
    const showSearch = options.length > 8;
    let searchInput = null;

    if (showSearch) {
      const searchWrap = document.createElement('div');
      searchWrap.className = 'cti-select-search-wrap';
      searchWrap.innerHTML = (window.ic ? window.ic('search', 13, 'cti-select-search-ic') : '') +
        '<input type="text" class="cti-select-search" placeholder="Filter options…" autocomplete="off" spellcheck="false">';
      menu.appendChild(searchWrap);
      searchInput = searchWrap.querySelector('input');
    }

    const listEl = document.createElement('div');
    listEl.className = 'cti-select-list';
    menu.appendChild(listEl);

    let focusedIdx = Math.max(0, inst.select.selectedIndex);
    let visibleItems = [];

    function renderItems(query) {
      listEl.innerHTML = '';
      visibleItems = [];
      const q = (query || '').trim().toLowerCase();

      options.forEach((opt, idx) => {
        const label = formatOptionLabel(opt);
        if (q && !label.toLowerCase().includes(q) && !String(opt.value).toLowerCase().includes(q)) {
          return;
        }
        const item = document.createElement('button');
        item.type = 'button';
        item.className = 'cti-select-option';
        item.setAttribute('role', 'option');
        item.dataset.index = String(idx);
        const isSelected = idx === inst.select.selectedIndex;
        if (isSelected) item.classList.add('is-selected');
        if (opt.disabled) {
          item.classList.add('is-disabled');
          item.disabled = true;
        }
        item.setAttribute('aria-selected', isSelected ? 'true' : 'false');

        const lblSpan = document.createElement('span');
        lblSpan.className = 'cti-select-option-label';
        lblSpan.textContent = label || '\u00A0';

        const chkSpan = document.createElement('span');
        chkSpan.className = 'cti-select-option-check';
        chkSpan.innerHTML = isSelected && window.ic ? window.ic('check', 13) : '';

        item.appendChild(lblSpan);
        item.appendChild(chkSpan);

        item.addEventListener('click', (e) => {
          e.preventDefault();
          e.stopPropagation();
          if (opt.disabled) return;
          selectByIndex(inst, idx);
        });

        item.addEventListener('mousemove', () => {
          visibleItems.forEach((el) => el.classList.remove('is-focused'));
          item.classList.add('is-focused');
        });

        listEl.appendChild(item);
        visibleItems.push(item);
      });

      if (visibleItems.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'cti-select-empty';
        empty.textContent = 'No matching options';
        listEl.appendChild(empty);
      }
    }

    renderItems('');

    menu.style.display = 'flex';
    positionPortal(inst.trigger);
    requestAnimationFrame(() => {
      menu.classList.add('is-visible');
      const selEl = listEl.querySelector('.cti-select-option.is-selected');
      if (selEl) {
        selEl.classList.add('is-focused');
        selEl.scrollIntoView({ block: 'nearest' });
      } else if (visibleItems[0]) {
        visibleItems[0].classList.add('is-focused');
      }
      if (searchInput) {
        searchInput.focus({ preventScroll: true });
      }
    });

    if (searchInput) {
      searchInput.addEventListener('input', () => {
        renderItems(searchInput.value);
        if (visibleItems[0]) visibleItems[0].classList.add('is-focused');
        positionPortal(inst.trigger);
      });
      searchInput.addEventListener('keydown', (e) => handleMenuKeydown(e, inst, visibleItems));
    }
  }

  function handleMenuKeydown(e, inst, visibleItems) {
    if (!visibleItems || !visibleItems.length) {
      if (e.key === 'Escape') {
        e.preventDefault();
        closeActiveMenu();
        inst.trigger.focus();
      }
      return;
    }
    const curIdx = visibleItems.findIndex((el) => el.classList.contains('is-focused'));
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      const next = curIdx < visibleItems.length - 1 ? curIdx + 1 : 0;
      visibleItems.forEach((el) => el.classList.remove('is-focused'));
      visibleItems[next].classList.add('is-focused');
      visibleItems[next].scrollIntoView({ block: 'nearest' });
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      const prev = curIdx > 0 ? curIdx - 1 : visibleItems.length - 1;
      visibleItems.forEach((el) => el.classList.remove('is-focused'));
      visibleItems[prev].classList.add('is-focused');
      visibleItems[prev].scrollIntoView({ block: 'nearest' });
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const focused = visibleItems[Math.max(0, curIdx)];
      if (focused && !focused.disabled) {
        selectByIndex(inst, parseInt(focused.dataset.index, 10));
        inst.trigger.focus();
      }
    } else if (e.key === 'Escape' || e.key === 'Tab') {
      closeActiveMenu();
    }
  }

  function selectByIndex(inst, idx) {
    const sel = inst.select;
    const prevIdx = sel.selectedIndex;
    NATIVE_INDEX_DESC.set.call(sel, idx);
    inst.sync();
    closeActiveMenu();
    if (prevIdx !== idx) {
      sel.dispatchEvent(new Event('input', { bubbles: true }));
      sel.dispatchEvent(new Event('change', { bubbles: true }));
    }
  }

  function upgradeSelect(sel) {
    if (!sel || sel.dataset.ctiUpgraded === '1') return;
    if (sel.multiple || (sel.size && sel.size > 1)) return;
    sel.dataset.ctiUpgraded = '1';

    const wrap = document.createElement('div');
    wrap.className = 'cti-select-wrap';
    if (sel.classList.contains('refresh-select')) {
      wrap.classList.add('cti-select-wrap--compact');
    }

    // Preserve explicit inline width/flex styles on wrapper
    const inlineWidth = sel.style.width;
    const inlineMinWidth = sel.style.minWidth;
    const inlineMaxWidth = sel.style.maxWidth;
    const inlineFlex = sel.style.flex;
    const inlineMarginLeft = sel.style.marginLeft;
    if (inlineWidth) wrap.style.width = inlineWidth;
    if (inlineMinWidth) wrap.style.minWidth = inlineMinWidth;
    if (inlineMaxWidth) wrap.style.maxWidth = inlineMaxWidth;
    if (inlineFlex) wrap.style.flex = inlineFlex;
    if (inlineMarginLeft) wrap.style.marginLeft = inlineMarginLeft;

    const trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.className = 'cti-select-trigger';
    trigger.setAttribute('aria-haspopup', 'listbox');
    trigger.setAttribute('aria-expanded', 'false');
    if (sel.title) trigger.title = sel.title;

    const prefixIcon = sel.id === 'refresh-interval' && window.ic
      ? `<span class="cti-select-prefix">${window.ic('refresh', 12)}</span>`
      : '';

    const labelEl = document.createElement('span');
    labelEl.className = 'cti-select-label';

    const arrowEl = document.createElement('span');
    arrowEl.className = 'cti-select-arrow';
    arrowEl.innerHTML = window.ic ? window.ic('chevron-down', 13) : '';

    if (prefixIcon) {
      trigger.insertAdjacentHTML('beforeend', prefixIcon);
    }
    trigger.appendChild(labelEl);
    trigger.appendChild(arrowEl);

    sel.parentNode.insertBefore(wrap, sel);
    wrap.appendChild(sel);
    wrap.appendChild(trigger);
    sel.classList.add('cti-native-select-hidden');
    sel.tabIndex = -1;

    const inst = {
      select: sel,
      wrap,
      trigger,
      labelEl,
      sync() {
        const opt = sel.options[sel.selectedIndex] || sel.options[0];
        const txt = formatOptionLabel(opt);
        labelEl.textContent = txt || 'Select…';
        const isPlaceholder = opt && opt.value === '' && sel.selectedIndex === 0;
        trigger.classList.toggle('is-placeholder', Boolean(isPlaceholder));
        trigger.disabled = Boolean(sel.disabled);
        wrap.classList.toggle('is-disabled', Boolean(sel.disabled));
        if (sel.style.display === 'none') {
          wrap.style.display = 'none';
        } else if (wrap.style.display === 'none') {
          wrap.style.display = '';
        }
      }
    };

    // Intercept programmatic .value and .selectedIndex assignments
    try {
      Object.defineProperty(sel, 'value', {
        configurable: true,
        get() {
          return NATIVE_VALUE_DESC.get.call(this);
        },
        set(v) {
          NATIVE_VALUE_DESC.set.call(this, v);
          inst.sync();
        }
      });
      Object.defineProperty(sel, 'selectedIndex', {
        configurable: true,
        get() {
          return NATIVE_INDEX_DESC.get.call(this);
        },
        set(i) {
          NATIVE_INDEX_DESC.set.call(this, i);
          inst.sync();
        }
      });
    } catch (_) {
      // Fallback if defineProperty is restricted
    }

    sel.addEventListener('change', () => inst.sync());

    trigger.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      openMenu(inst);
    });

    trigger.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        openMenu(inst);
      }
    });

    const mo = new MutationObserver(() => {
      inst.sync();
      if (activeInstance === inst) {
        positionPortal(inst.trigger);
      }
    });
    mo.observe(sel, {
      childList: true,
      subtree: true,
      characterData: true,
      attributes: true,
      attributeFilter: ['disabled', 'style', 'title']
    });

    inst.sync();
    sel._ctiSelect = inst;
  }

  function upgradeAll(root) {
    const scope = root || document;
    if (scope.nodeType === 1 && scope.tagName === 'SELECT') {
      upgradeSelect(scope);
      return;
    }
    if (scope.querySelectorAll) {
      scope.querySelectorAll('select').forEach(upgradeSelect);
    }
  }

  // Global listeners for closing & repositioning
  document.addEventListener('click', (e) => {
    if (!activeInstance) return;
    if (activeInstance.wrap.contains(e.target)) return;
    if (portalMenu && portalMenu.contains(e.target)) return;
    closeActiveMenu();
  });

  window.addEventListener('resize', () => {
    if (activeInstance) positionPortal(activeInstance.trigger);
  });

  window.addEventListener('scroll', (e) => {
    if (!activeInstance) return;
    if (portalMenu && portalMenu.contains(e.target)) return;
    positionPortal(activeInstance.trigger);
  }, true);

  function init() {
    upgradeAll(document);
    const bodyObserver = new MutationObserver((mutations) => {
      for (const m of mutations) {
        for (const node of m.addedNodes) {
          if (node.nodeType === 1 && node.tagName !== 'OPTION') {
            upgradeAll(node);
            if (window.hydrateCtiIcons) window.hydrateCtiIcons(node);
          }
        }
      }
    });
    bodyObserver.observe(document.body, { childList: true, subtree: true });
  }

  window.CtiSelect = { upgradeAll, upgradeSelect, closeActiveMenu };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
