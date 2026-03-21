(function () {
  'use strict';

  // ── Maps ────────────────────────────────────────────────────────────────────
  const EXT_MAP = {
    'hmac-secret':            { icon: '🔐', label: 'HMAC Secret' },
    'hmac-secret-mc':         { icon: '🔐', label: 'HMAC Secret MakeCredential' },
    'credProtect':            { icon: '🛡️', label: 'Credential Protection' },
    'largeBlobKey':           { icon: '🔑', label: 'Large Blob Key' },
    'credBlob':               { icon: '📦', label: 'Credential Blob' },
    'minPinLength':           { icon: '📏', label: 'Min PIN Length' },
    'devicePubKey':           { icon: '🗝️', label: 'Device Public Key' },
    'prf':                    { icon: '🎲', label: 'PRF' },
    'largeBlob':              { icon: '📁', label: 'Large Blob' },
    'uvm':                    { icon: '👤', label: 'User Verification Method' },
    'loc':                    { icon: '📍', label: 'Location' },
    'txAuthSimple':           { icon: '✍️',  label: 'Simple Transaction Auth' },
  };

  const OPT_MAP = {
    'plat':                          { icon: '💻', label: 'Platform' },
    'rk':                            { icon: '💾', label: 'Resident Key' },
    'clientPin':                     { icon: '🔢', label: 'Client PIN' },
    'up':                            { icon: '👆', label: 'User Presence' },
    'uv':                            { icon: '👁️',  label: 'User Verification' },
    'pinUvAuthToken':                { icon: '🎫', label: 'PIN/UV Auth Token' },
    'noMcGaPermissionsWithClientPin':{ icon: '🚫', label: 'No MC/GA w/ Client PIN' },
    'largeBlobs':                    { icon: '📁', label: 'Large Blobs' },
    'ep':                            { icon: '🏢', label: 'Enterprise Attestation' },
    'bioEnroll':                     { icon: '🧬', label: 'Bio Enrollment' },
    'userVerificationMgmtPreview':   { icon: '👤', label: 'UV Mgmt Preview' },
    'uvBioEnroll':                   { icon: '👁️',  label: 'UV Bio Enroll' },
    'authnrCfg':                     { icon: '⚙️',  label: 'Authenticator Config' },
    'uvAcfg':                        { icon: '🔒', label: 'UV Auth Config' },
    'credMgmt':                      { icon: '📋', label: 'Credential Management' },
    'perCredMgmtRO':                 { icon: '📄', label: 'Credential Read Only support' },
    'credentialMgmtPreview':         { icon: '📋', label: 'Cred Mgmt Preview' },
    'setMinPINLength':               { icon: '📏', label: 'Set Min PIN Length' },
    'makeCredUvNotRqd':              { icon: '✅', label: 'Make Cred UV Not Req.' },
    'alwaysUv':                      { icon: '🔒', label: 'Always UV' },
  };

  const STATUS_LABELS = {
    'FIDO_CERTIFIED':     'Certified',
    'NOT_FIDO_CERTIFIED': 'Not Certified',
    'REVOKED':            'Revoked',
  };

  // ── State ───────────────────────────────────────────────────────────────────
  let allEntries = [];
  let state = {
    filters: { protocol: [], status: [], extensions: [], options: [], query: '' },
    sort: { col: 'updated', dir: 'desc' },
  };

  function emptyFilters() {
    return { protocol: [], status: [], extensions: [], options: [], query: '' };
  }

  // ── Data helpers ─────────────────────────────────────────────────────────────
  function parseEntry(entry) {
    const ms = entry.metadataStatement;
    if (!ms) return null;
    const id = ms.aaguid || ms.aaid ||
               (ms.attestationCertificateKeyIdentifiers || [])[0] || '';
    const status = ((entry.statusReports || [])[0] || {}).status || 'N/A';
    return {
      id,
      description: ms.description || 'Unknown',
      protocol: ms.protocolFamily || 'N/A',
      status,
      date: entry.timeOfLastStatusChange || '',
      icon: ms.icon || null,
      // "exts" is a container marker, not an actual extension capability.
      extensions: ((ms.authenticatorGetInfo || {}).extensions || []).filter(ext => ext !== 'exts'),
      options:    (ms.authenticatorGetInfo || {}).options    || {},
      raw: entry,
    };
  }

  function formatDate(dateStr) {
    if (!dateStr) return '—';
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr;
    const y = d.getFullYear().toString().slice(-2);
    const w = String(isoWeek(d)).padStart(2, '0');
    return `${y}W${w}`;
  }

  function isoWeek(date) {
    const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
    d.setUTCDate(d.getUTCDate() + 4 - (d.getUTCDay() || 7));
    const y0 = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
    return Math.ceil((((d - y0) / 86400000) + 1) / 7);
  }

  function esc(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function formatStatusLabel(status) {
    if (STATUS_LABELS[status]) return STATUS_LABELS[status];
    const match = String(status).match(/^FIDO_CERTIFIED_L([1-3])(?:_?PLUS)?$/i);
    if (match) {
      const hasPlus = /PLUS$/i.test(String(status));
      return `Certified L${match[1]}${hasPlus ? '+' : ''}`;
    }
    return status;
  }

  // ── Routing ──────────────────────────────────────────────────────────────────
  function parseHash() {
    const hash = window.location.hash.replace(/^#\/?/, '');
    if (!hash) return { view: 'list', filters: emptyFilters() };

    if (hash.startsWith('device/')) {
      return { view: 'device', id: decodeURIComponent(hash.slice(7)) };
    }

    if (hash.startsWith('filter')) {
      const qi = hash.indexOf('?');
      const p  = qi >= 0 ? new URLSearchParams(hash.slice(qi + 1)) : new URLSearchParams();
      return {
        view: 'list',
        filters: {
          protocol:   p.getAll('protocol'),
          status:     p.getAll('status'),
          extensions: p.getAll('ext'),
          options:    p.getAll('opt'),
          query:      p.get('q') || '',
        },
      };
    }

    return { view: 'list', filters: emptyFilters() };
  }

  function buildHash(filters, deviceId) {
    if (deviceId) return `#device/${encodeURIComponent(deviceId)}`;
    const p = new URLSearchParams();
    (filters.protocol   || []).forEach(v => p.append('protocol', v));
    (filters.status     || []).forEach(v => p.append('status', v));
    (filters.extensions || []).forEach(v => p.append('ext', v));
    (filters.options    || []).forEach(v => p.append('opt', v));
    if (filters.query) p.set('q', filters.query);
    const qs = p.toString();
    return qs ? `#filter?${qs}` : '#';
  }

  function navigate(filters, deviceId) {
    const h = buildHash(filters, deviceId);
    // avoid pushing duplicate history entries
    if (window.location.hash === h || (h === '#' && window.location.hash === '')) return;
    window.location.hash = h;
  }

  // ── Filtering & sorting ───────────────────────────────────────────────────────
  function applyFilters(entries, f) {
    return entries.filter(e => {
      if (f.query) {
        const q = f.query.toLowerCase();
        if (!e.description.toLowerCase().includes(q) && !e.id.toLowerCase().includes(q)) return false;
      }
      if (f.protocol.length   && !f.protocol.includes(e.protocol))   return false;
      if (f.status.length     && !f.status.includes(e.status))       return false;
      if (f.extensions.length && !f.extensions.every(x => e.extensions.includes(x))) return false;
      if (f.options.length    && !f.options.every(o => o in e.options))               return false;
      return true;
    });
  }

  function sortEntries(entries, sort) {
    const dir = sort.dir === 'asc' ? 1 : -1;
    return [...entries].sort((a, b) => {
      const extKnown = Object.keys(EXT_MAP);
      const optKnown = Object.keys(OPT_MAP);
      const aExtensions = a.extensions.filter(x => extKnown.includes(x)).length;
      const bExtensions = b.extensions.filter(x => extKnown.includes(x)).length;
      const aOptions = optKnown.filter(k => k in a.options).length;
      const bOptions = optKnown.filter(k => k in b.options).length;

      const av = {
        description: a.description,
        protocol: a.protocol,
        status: a.status,
        updated: a.date,
        extensions: aExtensions,
        options: aOptions,
      }[sort.col] || '';
      const bv = {
        description: b.description,
        protocol: b.protocol,
        status: b.status,
        updated: b.date,
        extensions: bExtensions,
        options: bOptions,
      }[sort.col] || '';
      return av < bv ? -dir : av > bv ? dir : 0;
    });
  }

  // ── Rendering ─────────────────────────────────────────────────────────────────
  function badgesHtml(keys, map) {
    if (!keys || !keys.length) return '<span class="no-badges">—</span>';
    return '<div class="badges">' + keys.map(k => {
      const m = map[k] || { icon: '❓', label: k };
      return `<span class="badge"><span class="badge-tooltip">${esc(m.label)}</span>${m.icon}</span>`;
    }).join('') + '</div>';
  }

  function createFixedGrid(values, map, includeProprietaryColumn = false, optionValues = null) {
    const allKnownKeys = Object.keys(map).sort();
    const cols = allKnownKeys.length + (includeProprietaryColumn ? 1 : 0);
    const valueSet = new Set(values);

    let html = `<div class="fixed-grid" style="--grid-cols: ${cols}">`;

    // Add cells for all known values
    allKnownKeys.forEach(key => {
      if (valueSet.has(key)) {
        const m = map[key];
        const optValue = optionValues ? optionValues[key] : null;
        const tooltip = optValue !== null
          ? `${esc(m.label)} = ${esc(String(optValue))}`
          : esc(m.label);
        html += `<span class="grid-cell has-item"><span class="badge"><span class="badge-tooltip">${tooltip}</span>${m.icon}</span></span>`;
      } else {
        html += `<span class="grid-cell is-empty"></span>`;
      }
    });

    // If proprietary column, handle custom extensions/options
    if (includeProprietaryColumn) {
      const proprietary = values.filter(v => !allKnownKeys.includes(v));
      if (proprietary.length > 0) {
        html += `<span class="grid-cell proprietary-container">`;
        proprietary.forEach(prop => {
          const tooltip = optionValues ? `${esc(prop)} = ${esc(String(optionValues[prop]))}` : `Custom: ${esc(prop)}`;
          html += `<span class="badge proprietary"><span class="badge-tooltip">${tooltip}</span>⚙️</span>`;
        });
        html += `</span>`;
      } else {
        html += `<span class="grid-cell is-empty"></span>`;
      }
    }

    html += `</div>`;
    return html;
  }

  function capabilityBarsHtml(values, map, includeProprietaryColumn = false) {
    const knownKeys = Object.keys(map);
    const present = new Set(values || []);
    let html = '<div class="cap-bars">';

    knownKeys.forEach(key => {
      const m = map[key] || { label: key };
      const isPresent = present.has(key);
      html += `<span class="cap-bar ${isPresent ? 'present' : 'absent'}" title="${esc(m.label)}: ${isPresent ? 'present' : 'absent'}" aria-label="${esc(m.label)}: ${isPresent ? 'present' : 'absent'}"></span>`;
    });

    if (includeProprietaryColumn) {
      const proprietary = (values || []).filter(v => !(v in map));
      const hasProprietary = proprietary.length > 0;
      const proprietaryTitle = hasProprietary
        ? `Proprietary extension: ${proprietary.join(', ')}`
        : 'Proprietary extension: none';
      html += `<span class="cap-bar ${hasProprietary ? 'proprietary' : 'absent'}" title="${esc(proprietaryTitle)}" aria-label="${esc(proprietaryTitle)}"></span>`;
    }

    html += '</div>';
    return html;
  }

  function renderTable(entries) {
    const tbody = document.getElementById('table-body');
    if (!entries.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty">No devices match the current filters.</td></tr>';
      return;
    }
    tbody.innerHTML = entries.map(e => {
      const optKeys = Object.keys(e.options);
      const iconHtml = e.icon
        ? `<img src="${esc(e.icon)}" alt="" class="authenticator-icon" loading="lazy">`
        : '<div class="no-icon">🔑</div>';
      return `<tr data-id="${esc(e.id)}">
        <td class="col-icon">${iconHtml}</td>
        <td><div class="device-description">${esc(e.description)}</div><div class="device-id">${esc(e.id)}</div></td>
        <td><span class="protocol-tag">${esc(e.protocol.toUpperCase())}</span></td>
        <td><span class="status-badge status-${esc(e.status)}">${esc(formatStatusLabel(e.status))}</span></td>
        <td>${esc(formatDate(e.date))}</td>
        <td>${capabilityBarsHtml(e.extensions, EXT_MAP, true)}</td>
        <td>${capabilityBarsHtml(optKeys, OPT_MAP, false)}</td>
      </tr>`;
    }).join('');

    tbody.querySelectorAll('tr[data-id]').forEach(tr => {
      tr.addEventListener('click', () => navigate(state.filters, tr.dataset.id));
    });
  }

  function renderSortHeaders() {
    document.querySelectorAll('thead th.sortable').forEach(th => {
      th.classList.remove('sort-asc', 'sort-desc');
      if (th.dataset.col === state.sort.col) {
        th.classList.add(state.sort.dir === 'asc' ? 'sort-asc' : 'sort-desc');
      }
    });
  }

  function renderChips() {
    const chips = [
      ...state.filters.protocol.map(v   => ({ type: 'protocol',   value: v, label: v.toUpperCase() })),
      ...state.filters.status.map(v     => ({ type: 'status',     value: v, label: formatStatusLabel(v) })),
      ...state.filters.extensions.map(v => ({ type: 'extensions', value: v, label: `${(EXT_MAP[v] || {}).icon || '❓'} ${(EXT_MAP[v] || {}).label || v}` })),
      ...state.filters.options.map(v    => ({ type: 'options',    value: v, label: `${(OPT_MAP[v] || {}).icon || '❓'} ${(OPT_MAP[v] || {}).label || v}` })),
      ...(state.filters.query ? [{ type: 'query', value: state.filters.query, label: `"${state.filters.query}"` }] : []),
    ];

    document.getElementById('filter-chips').innerHTML = chips.map(c =>
      `<span class="chip">${esc(c.label)}<button data-type="${esc(c.type)}" data-value="${esc(c.value)}" title="Remove">×</button></span>`
    ).join('');

    document.getElementById('filter-chips').querySelectorAll('button').forEach(btn => {
      btn.addEventListener('click', e => { e.stopPropagation(); removeFilter(btn.dataset.type, btn.dataset.value); });
    });

    document.getElementById('clear-filters').classList.toggle('hidden', chips.length === 0);
  }

  function renderFilterPanel() {
    const protocols = [...new Set(allEntries.map(e => e.protocol))].sort();
    const statuses  = [...new Set(allEntries.map(e => e.status))].sort();
    const exts      = [...new Set(allEntries.flatMap(e => e.extensions))].sort();
    const opts      = [...new Set(allEntries.flatMap(e => Object.keys(e.options)))].sort();

    fillCheckboxGroup('filter-protocol',   protocols, state.filters.protocol,   'protocol',   v => v.toUpperCase());
    fillCheckboxGroup('filter-status',     statuses,  state.filters.status,     'status',     v => formatStatusLabel(v));
    fillCheckboxGroup('filter-extensions', exts,      state.filters.extensions, 'extensions', v => `${(EXT_MAP[v] || {}).icon || '❓'} ${(EXT_MAP[v] || {}).label || v}`);
    fillCheckboxGroup('filter-options',    opts,      state.filters.options,    'options',    v => `${(OPT_MAP[v] || {}).icon || '❓'} ${(OPT_MAP[v] || {}).label || v}`);
  }

  function fillCheckboxGroup(id, values, selected, type, labelFn) {
    const el = document.getElementById(id);
    if (!el) return;
    el.innerHTML = values.map(v => `
      <label>
        <input type="checkbox" data-type="${type}" data-value="${esc(v)}" ${selected.includes(v) ? 'checked' : ''}>
        ${esc(labelFn(v))}
      </label>`).join('');
    el.querySelectorAll('input').forEach(cb => {
      cb.addEventListener('change', () => toggleFilter(cb.dataset.type, cb.dataset.value, cb.checked));
    });
  }

  function renderResults() {
    const filtered = applyFilters(allEntries, state.filters);
    const sorted   = sortEntries(filtered, state.sort);
    document.getElementById('results-count').textContent =
      `${sorted.length.toLocaleString()} of ${allEntries.length.toLocaleString()} devices`;
    renderTable(sorted);
    renderSortHeaders();
    renderChips();
    renderFilterPanel();
  }

  // ── Device modal ──────────────────────────────────────────────────────────────
  function showModal(id) {
    const entry = allEntries.find(e => e.id === id);
    if (!entry) return;
    const ms      = entry.raw.metadataStatement;
    const optKeys = Object.keys(entry.options);
    const agi     = ms.authenticatorGetInfo || {};

    const iconHtml = entry.icon
      ? `<img src="${esc(entry.icon)}" alt="" class="modal-icon">`
      : '<div class="modal-icon no-icon">🔑</div>';

    const extraDetails = [
      agi.versions && agi.versions.length
        ? `<div class="detail-item"><label>CTAP Versions</label><span>${esc(agi.versions.join(', '))}</span></div>` : '',
      agi.maxMsgSize
        ? `<div class="detail-item"><label>Max Msg Size</label><span>${esc(String(agi.maxMsgSize))}</span></div>` : '',
      ms.authenticatorVersion
        ? `<div class="detail-item"><label>Auth Version</label><span>${esc(String(ms.authenticatorVersion))}</span></div>` : '',
    ].join('');

    const uvHtml = (ms.userVerificationDetails || [])
      .flat()
      .map(uv => `<span class="detail-badge">${esc(uv.userVerificationMethod || '')}</span>`)
      .join('');

    const kpHtml = (ms.keyProtection || []).map(k => `<span class="detail-badge">${esc(k)}</span>`).join('');
    const ahHtml = (ms.attachmentHint || []).map(k => `<span class="detail-badge">${esc(k)}</span>`).join('');

    document.getElementById('modal-content').innerHTML = `
      <div class="modal-header">
        ${iconHtml}
        <div class="modal-title">
          <h2>${esc(entry.description)}</h2>
          <div class="modal-id">${esc(entry.id)}</div>
        </div>
        <button class="modal-close" id="modal-close-btn" aria-label="Close">×</button>
      </div>
      <div class="modal-body">
        <div class="detail-grid">
          <div class="detail-item">
            <label>Protocol</label>
            <span>${esc(entry.protocol.toUpperCase())}</span>
          </div>
          <div class="detail-item">
            <label>Status</label>
            <span><span class="status-badge status-${esc(entry.status)}">${esc(formatStatusLabel(entry.status))}</span></span>
          </div>
          <div class="detail-item">
            <label>Last Updated</label>
            <span>${esc(entry.date || '—')}</span>
          </div>
          ${extraDetails}
        </div>

        <div class="detail-section">
          <h3>Extensions</h3>
          <div class="detail-badges">
            ${entry.extensions.length || Object.keys(EXT_MAP).length > 0
              ? createFixedGrid(entry.extensions, EXT_MAP, true, null)
              : '<span class="no-badges">None</span>'}
          </div>
        </div>

        <div class="detail-section">
          <h3>Options</h3>
          <div class="detail-badges">
            ${optKeys.length || Object.keys(OPT_MAP).length > 0
              ? createFixedGrid(optKeys, OPT_MAP, false, entry.options)
              : '<span class="no-badges">None</span>'}
          </div>
        </div>

        ${uvHtml ? `<div class="detail-section"><h3>User Verification</h3><div class="detail-badges">${uvHtml}</div></div>` : ''}
        ${kpHtml ? `<div class="detail-section"><h3>Key Protection</h3><div class="detail-badges">${kpHtml}</div></div>` : ''}
        ${ahHtml ? `<div class="detail-section"><h3>Attachment Hint</h3><div class="detail-badges">${ahHtml}</div></div>` : ''}
      </div>`;

    document.getElementById('device-modal').classList.remove('hidden');

    const close = () => navigate(state.filters, null);
    document.getElementById('modal-close-btn').addEventListener('click', close);
    document.getElementById('modal-backdrop').addEventListener('click', close);
    const onKey = e => { if (e.key === 'Escape') { close(); document.removeEventListener('keydown', onKey); } };
    document.addEventListener('keydown', onKey);
  }

  function closeModal() {
    document.getElementById('device-modal').classList.add('hidden');
  }

  // ── Filter mutations ──────────────────────────────────────────────────────────
  function toggleFilter(type, value, add) {
    const arr = [...(state.filters[type] || [])];
    const next = add ? (arr.includes(value) ? arr : [...arr, value]) : arr.filter(v => v !== value);
    navigate({ ...state.filters, [type]: next }, null);
  }

  function removeFilter(type, value) {
    if (type === 'query') {
      document.getElementById('search-input').value = '';
      navigate({ ...state.filters, query: '' }, null);
    } else {
      navigate({ ...state.filters, [type]: (state.filters[type] || []).filter(v => v !== value) }, null);
    }
  }

  // ── Hash-change handler ───────────────────────────────────────────────────────
  function handleHashChange() {
    const route = parseHash();
    if (route.view === 'device') {
      renderResults();           // keep table visible behind modal
      showModal(route.id);
    } else {
      closeModal();
      state.filters = route.filters || emptyFilters();
      document.getElementById('search-input').value = state.filters.query || '';
      renderResults();
    }
  }

  // ── Bootstrap ─────────────────────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', () => {
    // Sort headers
    document.querySelectorAll('thead th.sortable').forEach(th => {
      th.addEventListener('click', () => {
        const col = th.dataset.col;
        if (state.sort.col === col) {
          state.sort = { col, dir: state.sort.dir === 'asc' ? 'desc' : 'asc' };
        } else {
          state.sort = { col, dir: 'asc' };
        }
        renderResults();
      });
    });

    // Filter panel toggle
    const filterBtn   = document.getElementById('toggle-filters');
    const filterPanel = document.getElementById('filter-panel');
    filterBtn.addEventListener('click', () => {
      const open = !filterPanel.classList.contains('hidden');
      filterPanel.classList.toggle('hidden', open);
      filterBtn.classList.toggle('active', !open);
    });

    // Clear all filters
    document.getElementById('clear-filters').addEventListener('click', () => {
      document.getElementById('search-input').value = '';
      navigate({ protocol: [], status: [], extensions: [], options: [], query: '' }, null);
    });

    // Search (debounced)
    let searchTimer;
    document.getElementById('search-input').addEventListener('input', e => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => {
        navigate({ ...state.filters, query: e.target.value.trim() }, null);
      }, 280);
    });

    // Hash routing
    window.addEventListener('hashchange', handleHashChange);

    // Load data
    fetch('mds_metadata.json')
      .then(r => r.json())
      .then(data => {
        document.getElementById('metadata-version').textContent =
          `v${data.no} · Next update: ${data.nextUpdate}`;
        document.getElementById('legal-header').textContent = data.legalHeader || '';
        allEntries = (data.entries || []).map(parseEntry).filter(Boolean);
        handleHashChange();
      })
      .catch(err => {
        console.error('Error loading data:', err);
        document.getElementById('table-body').innerHTML =
          '<tr><td colspan="7" class="empty">Error loading data. Please try again.</td></tr>';
      });
  });
})();
