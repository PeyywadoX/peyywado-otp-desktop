(() => {
  const EPOCH = 946652400;
  const _tauri = (window.__TAURI__ && window.__TAURI__.core)
    ? window.__TAURI__.core
    : (window.__TAURI__ && window.__TAURI__.invoke) ? window.__TAURI__ : null;
  const hasTauri = !!(_tauri && _tauri.invoke);
  const invoke = (cmd, args) => _tauri.invoke(cmd, args);

  const PALETTE = [
    { id: 'ember', hex: '#f97316', name: 'Ember' },
    { id: 'emerald', hex: '#10b981', name: 'Zümrüt' },
    { id: 'cobalt', hex: '#3b82f6', name: 'Kobalt' },
    { id: 'amber', hex: '#eab308', name: 'Kehribar' },
    { id: 'rose', hex: '#f43f5e', name: 'Yakut' },
    { id: 'cyan', hex: '#06b6d4', name: 'Camgöbeği' },
  ];
  const colorHex = (id) => (PALETTE.find(c => c.id === id) || PALETTE[0]).hex;

  const _mem = {};
  const lsGet = (k, def = null) => {
    try { const v = localStorage.getItem(k); return v === null ? (_mem[k] ?? def) : v; }
    catch { return _mem[k] ?? def; }
  };
  const lsSet = (k, v) => {
    try { localStorage.setItem(k, v); } catch { _mem[k] = v; }
  };

  let accounts = loadLocalAccounts();
  let view = lsGet('pw_view', 'grid');
  let timeOffset = parseFloat(lsGet('pw_off', '0')) || 0;
  let activeTag = 'all';
  let searchQuery = '';
  let selectedFocusId = null;
  let hoveredAccountId = null;
  let ctxTargetId = null;
  let editingAccountId = null;
  let addTab = 'act';
  let selectedColor = 'ember';
  let isAlwaysTop = false;
  let isMiniMode = false;
  let isPrivacy = lsGet('pw_privacy', '0') === '1';
  let isSoundOn = lsGet('pw_sound', '1') === '1';
  let autoClearClip = lsGet('pw_autoclear', '1') === '1';
  let pinHash = lsGet('pw_pin_hash', '');
  let isLocked = false;

  const codeCache = new Map();
  let lastGlobalStep = -1;
  let isRefreshingCodes = false;
  let clipClearTimer = null;
  let clipClearInterval = null;
  let lastCopiedCode = '';
  let dragSrcId = null;

  if (!hasTauri && accounts.length === 0 && !lsGet('pw_seeded_v2')) {
    accounts = [
      { id: uid(), label: 'Knight Online Ana', realId: 'NT00KO2451100239', note: 'Agartha · 83 Warrior', seed: '3132333435363738393031323334353637383930313233343536373839303132', kind: 'plus', period: 60, digits: 6, pinned: true, tag: 'Ana', color: 'ember' },
      { id: uid(), label: 'KO PvP Rogue', realId: 'NT00KO2451100774', note: 'Zero · CZ Okçu', seed: '48656c6c6f20576f726c64205465737420536565642130313233343536373839', kind: 'plus', period: 60, digits: 6, pinned: false, tag: 'PvP', color: 'emerald' },
      { id: uid(), label: 'Pazar Tezgah', realId: 'NT00KO2451100912', note: 'Moradon Merchant', seed: '0123456789abcdef0123456789abcdef01234567', kind: 'classic', period: 60, digits: 6, pinned: false, tag: 'Pazar', color: 'cobalt' },
      { id: uid(), label: 'Farm Priest', realId: 'NT00KO2451101188', note: 'Pandora · Eslant', seed: 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789', kind: 'plus', period: 60, digits: 6, pinned: false, tag: 'Farm', color: 'amber' },
    ];
    persistLocal();
    lsSet('pw_seeded_v2', '1');
  }

  function loadLocalAccounts() {
    try { return JSON.parse(lsGet('pw_accounts', '[]')) || []; } catch { return []; }
  }
  function persistLocal() {
    lsSet('pw_accounts', JSON.stringify(accounts));
  }
  function uid() { return 'a' + Math.random().toString(36).slice(2, 10); }
  function nowSec() { return (Date.now() / 1000) + timeOffset; }
  function esc(s) {
    return String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  }
  function initials(s) {
    const parts = (s || '?').trim().split(/\s+/).filter(Boolean);
    if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
    return (parts[0] ? parts[0].slice(0, 2) : '?').toUpperCase();
  }
  function formatCodeSpaced(code) {
    if (!code || code.length !== 6) return code || '••••••';
    return code.slice(0, 3) + ' ' + code.slice(3);
  }
  function hexToBytes(h) {
    h = (h || '').replace(/[^0-9a-fA-F]/g, '');
    const out = new Uint8Array(Math.floor(h.length / 2));
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
  }
  async function sha256Hex(str) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async function computeStepCode(seedHex, kind, digits, step) {
    const msg = new Uint8Array([(step >>> 24) & 255, (step >>> 16) & 255, (step >>> 8) & 255, step & 255]);
    let key = hexToBytes(seedHex);
    const algo = kind === 'classic' ? 'SHA-1' : 'SHA-256';
    if (kind === 'classic') {
      key = key.slice(0, 20);
    } else {
      const k = new Uint8Array(32);
      k.set(key.slice(0, 32));
      key = k;
    }
    const ck = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: algo }, false, ['sign']);
    const sig = new Uint8Array(await crypto.subtle.sign('HMAC', ck, msg));
    const off = sig[sig.length - 1] & 0x0f;
    const bin = ((sig[off] & 0x7f) << 24) | ((sig[off + 1] & 0xff) << 16) | ((sig[off + 2] & 0xff) << 8) | (sig[off + 3] & 0xff);
    return (bin % Math.pow(10, digits)).toString().padStart(digits, '0');
  }

  async function totpBoth(seedHex, kind, period = 60, digits = 6, t = nowSec()) {
    period = period || 60;
    digits = digits || 6;
    const diff = t - EPOCH;
    const step = Math.floor(diff / period);
    const elapsed = ((diff % period) + period) % period;
    const remExact = period - elapsed;
    const [code, next] = await Promise.all([
      computeStepCode(seedHex, kind, digits, step),
      computeStepCode(seedHex, kind, digits, step + 1),
    ]);
    return { step, code, next, rem: Math.ceil(remExact), remExact, ratio: remExact / period };
  }

  let _canTransDisplay;
  function canTransitionDisplay() {
    if (_canTransDisplay !== undefined) return _canTransDisplay;
    if (!window.CSS?.supports?.('transition-behavior', 'allow-discrete') || !document.body) return false;
    const probe = document.createElement('div');
    probe.style.cssText = 'transition: display 1s allow-discrete !important; display: block;';
    document.body.appendChild(probe);
    getComputedStyle(probe).display;
    probe.style.display = 'none';
    _canTransDisplay = getComputedStyle(probe).display === 'block';
    probe.remove();
    return _canTransDisplay;
  }

  function supportsTopLayerExit() {
    return Boolean(window.CSS?.supports?.('overlay', 'auto') && canTransitionDisplay());
  }

  async function closeTopLayer(dialog, returnVal) {
    if (!dialog || !dialog.open) return;
    if (!supportsTopLayerExit()) {
      dialog.setAttribute('data-closing', '');
      const anims = dialog.getAnimations({ subtree: true });
      if (anims.length > 0) {
        await Promise.race([
          Promise.allSettled(anims.map(a => a.finished)),
          new Promise(r => setTimeout(r, 350)),
        ]);
      }
      if (!dialog.hasAttribute('data-closing')) return;
      dialog.removeAttribute('data-closing');
    }
    dialog.close(returnVal);
  }

  function initDialogs() {
    const hasClosedBy = 'closedBy' in HTMLDialogElement.prototype;
    const outside = (e, dlg) => {
      const r = dlg.getBoundingClientRect();
      return e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
    };
    document.querySelectorAll('dialog').forEach(dlg => {
      dlg.addEventListener('cancel', (e) => {
        if (!supportsTopLayerExit()) {
          e.preventDefault();
          closeTopLayer(dlg);
        }
      });
      if (!hasClosedBy && dlg.getAttribute('closedby') === 'any') {
        let downOut = false;
        dlg.addEventListener('pointerdown', (e) => { downOut = outside(e, dlg); });
        dlg.addEventListener('pointerup', (e) => {
          if (downOut && outside(e, dlg)) closeTopLayer(dlg);
        });
      }
    });
    document.querySelectorAll('[data-close]').forEach(btn => {
      btn.addEventListener('click', () => {
        const dlg = document.getElementById(btn.dataset.close);
        closeTopLayer(dlg);
      });
    });
  }

  function runViewTransition(fn) {
    if (document.startViewTransition && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      document.startViewTransition(() => fn());
    } else {
      fn();
    }
  }

  function getVisibleAccounts() {
    const q = searchQuery.trim().toLowerCase();
    const list = accounts.filter(a => {
      if (activeTag === '__pinned__' && !a.pinned) return false;
      if (activeTag !== 'all' && activeTag !== '__pinned__' && (a.tag || '') !== activeTag) return false;
      if (!q) return true;
      return (a.label || '').toLowerCase().includes(q)
        || (a.realId || '').toLowerCase().includes(q)
        || (a.note || '').toLowerCase().includes(q)
        || (a.tag || '').toLowerCase().includes(q);
    });

    return [...list.filter(a => a.pinned), ...list.filter(a => !a.pinned)];
  }

  function renderTags() {
    const bar = document.getElementById('tagBar');
    const tagCounts = new Map();
    let pinnedCount = 0;
    for (const a of accounts) {
      if (a.pinned) pinnedCount++;
      if (a.tag && a.tag.trim()) {
        tagCounts.set(a.tag.trim(), (tagCounts.get(a.tag.trim()) || 0) + 1);
      }
    }
    if (activeTag !== 'all' && activeTag !== '__pinned__' && !tagCounts.has(activeTag)) {
      activeTag = 'all';
    }
    if (activeTag === '__pinned__' && pinnedCount === 0) activeTag = 'all';

    const pills = [
      { id: 'all', label: 'Tümü', count: accounts.length },
      ...(pinnedCount > 0 ? [{ id: '__pinned__', label: 'Sabitlenenler', count: pinnedCount }] : []),
      ...Array.from(tagCounts.entries()).map(([t, c]) => ({ id: t, label: t, count: c })),
    ];

    bar.innerHTML = pills.map(p => `
      <button type="button" class="tag-pill ${activeTag === p.id ? 'on' : ''}" data-tag="${esc(p.id)}" role="tab" aria-selected="${activeTag === p.id}">
        ${esc(p.label)}<span class="pill-n">${p.count}</span>
      </button>
    `).join('');

    bar.querySelectorAll('.tag-pill').forEach(btn => {
      btn.addEventListener('click', () => {
        SoundFX.click();
        activeTag = btn.dataset.tag;
        renderTags();
        runViewTransition(renderStage);
      });
    });
  }

  function buildReelHtml(code = '000000') {
    const digits = (code || '000000').padStart(6, '0').split('');
    const spans = '<span>0</span><span>1</span><span>2</span><span>3</span><span>4</span><span>5</span><span>6</span><span>7</span><span>8</span><span>9</span>';
    return digits.map((ch, idx) => {
      const gap = idx === 3 ? '<span class="digit-gap" aria-hidden="true"></span>' : '';
      const dVal = /\d/.test(ch) ? ch : '0';
      return `${gap}<span class="digit-slot" aria-hidden="true"><span class="digit-reel" data-idx="${idx}" style="--i:${idx};--d:${dVal}">${spans}</span></span>`;
    }).join('');
  }

  function updateReelDigits(containerEl, code) {
    if (!containerEl || !code) return;
    containerEl.setAttribute('aria-label', `Aktif OTP kodu: ${formatCodeSpaced(code)}`);
    const reels = containerEl.querySelectorAll('.digit-reel');
    if (reels.length !== code.length) {
      containerEl.innerHTML = buildReelHtml(code);
      return;
    }
    for (let i = 0; i < code.length; i++) {
      reels[i].style.setProperty('--d', code[i]);
    }
  }

  function renderStage() {
    document.body.classList.toggle('compact-vault', accounts.length <= 1 && !searchQuery.trim());
    const visible = getVisibleAccounts();
    document.getElementById('accCount').textContent = visible.length;
    document.getElementById('sectionLabel').textContent = searchQuery.trim()
      ? `"${searchQuery.trim()}" sonuçları`
      : activeTag === '__pinned__' ? 'Sabitlenen Hesaplar'
      : activeTag === 'all' ? 'Hesaplarım' : activeTag;

    const stage = document.getElementById('stageContainer');

    if (visible.length === 0) {
      stage.innerHTML = `
        <div class="empty-state">
          <div class="empty-ic">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><rect x="5" y="2" width="14" height="20" rx="3"/><path d="M10 18h4"/></svg>
          </div>
          <h3>${accounts.length === 0 ? 'Henüz hesap yok' : 'Sonuç bulunamadı'}</h3>
          <p>${accounts.length === 0
            ? 'iPhone AnyOTP+ hesabını 1 dakikada ekle. Telefonun da aktif kalır.'
            : 'Aramayı temizle veya başka etiket seç.'}</p>
          <div class="empty-btns">
            ${accounts.length === 0
              ? `<button type="button" class="btn btn-primary" id="emptyCaptureBtn">iPhone'dan Yakala →</button>
                 <div class="empty-sub-btns">
                   <button type="button" class="btn btn-ghost btn-sm" id="emptyAddBtn">Elle Ekle</button>
                   <button type="button" class="btn btn-ghost btn-sm" id="emptyImportBtn">seed.json</button>
                   <button type="button" class="btn btn-ghost btn-sm" id="emptyGuideBtn">Rehber</button>
                 </div>`
              : `<button type="button" class="btn btn-ghost" id="emptyResetBtn">Filtreyi Temizle</button>`}
          </div>
          ${accounts.length === 0 ? `
          <div class="empty-trust">
            <span>🔒 %100 Yerel</span>
            <span>🛡 DPAPI Şifreli</span>
            <span>📱 Telefon Aktif</span>
          </div>` : ''}
        </div>`;
      stage.querySelector('#emptyCaptureBtn')?.addEventListener('click', () => openCaptureWizard());
      stage.querySelector('#emptyAddBtn')?.addEventListener('click', () => openAccountDialog());
      stage.querySelector('#emptyImportBtn')?.addEventListener('click', () => document.getElementById('importFile').click());
      stage.querySelector('#emptyGuideBtn')?.addEventListener('click', () => openGuideDialog('how'));
      stage.querySelector('#emptyResetBtn')?.addEventListener('click', () => {
        searchQuery = '';
        activeTag = 'all';
        document.getElementById('searchInput').value = '';
        document.getElementById('searchWrap').classList.remove('has-value');
        renderTags();
        runViewTransition(renderStage);
      });
      return;
    }

    if (view === 'focus' && !isMiniMode && window.innerWidth >= 740) {
      renderFocusStage(stage, visible);
      return;
    }

    stage.innerHTML = `<div class="grid ${view === 'list' && window.innerWidth >= 740 ? 'list' : ''}" id="cardGrid">${visible.map((a, idx) => {
      const cached = codeCache.get(a.id);
      const code = cached ? cached.code : '000000';
      const next = cached ? cached.next : '••••••';
      const hex = colorHex(a.color);
      const vtName = 'card-' + a.id.replace(/[^a-zA-Z0-9_-]/g, '');
      const hasMeta = Boolean((a.realId && a.realId.trim()) || (a.note && a.note.trim()));
      return `
        <article class="card" data-id="${esc(a.id)}" draggable="true" style="--card-accent:${hex};view-transition-name:${vtName}">
          <div class="copy-flash"></div>
          <div class="copied-badge">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"><path d="M20 6L9 17l-5-5"/></svg>
            Kopyalandı
          </div>
          <div class="card-body">
            <div class="card-top">
              <div class="card-ident">
                <div class="card-badge">
                  ${esc(initials(a.label))}
                  ${idx < 9 ? `<span class="index-num" title="Kısayol: ${idx + 1}">${idx + 1}</span>` : ''}
                </div>
                <div class="card-titles">
                  <div class="card-label-row">
                    <div class="card-label">${esc(a.label)}</div>
                  </div>
                  <div class="card-sub-row">
                    <span class="kind-tag ${a.kind === 'classic' ? 'classic' : ''}">${a.kind === 'classic' ? 'Klasik' : 'AnyOTP+'}</span>
                    ${a.tag ? `<span class="user-tag">${esc(a.tag)}</span>` : ''}
                  </div>
                </div>
              </div>
              <div class="card-actions">
                <button type="button" class="card-icon-btn ${a.pinned ? 'pinned' : ''}" data-pin="${esc(a.id)}" title="${a.pinned ? 'Sabitlemeyi kaldır' : 'Üste sabitle'}" aria-label="Sabitle">
                  <svg viewBox="0 0 24 24" fill="${a.pinned ? 'currentColor' : 'none'}" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"><path d="M12 17v5M9 10.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24V16h14v-.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6a1 1 0 0 1 1-1H8a1 1 0 0 1 1 1z"/></svg>
                </button>
                <button type="button" class="card-icon-btn" data-menu="${esc(a.id)}" title="Seçenekler" aria-label="Hesap menüsü">
                  <svg viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="5" r="1.8"/><circle cx="12" cy="12" r="1.8"/><circle cx="12" cy="19" r="1.8"/></svg>
                </button>
              </div>
            </div>

            <div class="otp-display-well">
              <div class="otp-code" id="code-${esc(a.id)}" aria-label="Aktif OTP kodu">${buildReelHtml(code)}</div>
              <div class="otp-well-bar"><div class="card-bar-fill" id="bar-${esc(a.id)}"></div></div>
              <div class="otp-well-foot">
                <div class="otp-timer-chip">
                  <div class="ring-box ring-compact">
                    <svg viewBox="0 0 48 48">
                      <circle class="ring-track" cx="24" cy="24" r="20" stroke-width="4.5" fill="none"/>
                      <circle class="ring-arc" id="ring-${esc(a.id)}" cx="24" cy="24" r="20" stroke-width="4.5" fill="none" stroke-dasharray="125.66" stroke-dashoffset="0"/>
                    </svg>
                    <div class="ring-num" id="rem-${esc(a.id)}">--</div>
                  </div>
                  <span class="otp-timer-lbl">sn kaldı</span>
                </div>
                <div class="copy-chip">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>
                  Kopyala
                </div>
              </div>
            </div>

            <div class="card-foot">
              <button type="button" class="next-pill" data-copynext="${esc(a.id)}" id="nextpill-${esc(a.id)}" title="Sonraki kodu kopyala">
                <span>Sonraki</span>
                <span class="next-code-val" id="next-${esc(a.id)}">${formatCodeSpaced(next)}</span>
              </button>
              ${hasMeta ? `
              <div class="card-meta-col">
                ${a.realId ? `<div class="card-realid">${esc(a.realId)}</div>` : ''}
                ${a.note ? `<div class="card-note">${esc(a.note)}</div>` : ''}
              </div>` : ''}
            </div>
          </div>
        </article>
      `;
    }).join('')}</div>`;

    bindCardInteractions();
    syncCodesImmediately();
  }

  function renderFocusStage(stage, visible) {
    if (!selectedFocusId || !visible.some(a => a.id === selectedFocusId)) {
      selectedFocusId = visible[0].id;
    }
    const sel = visible.find(a => a.id === selectedFocusId) || visible[0];
    const cached = codeCache.get(sel.id);
    const hex = colorHex(sel.color);

    stage.innerHTML = `
      <div class="focus-layout">
        <div class="focus-rail">
          ${visible.map(a => {
            const c = codeCache.get(a.id);
            return `
              <button type="button" class="focus-item ${a.id === sel.id ? 'on' : ''}" data-focus="${esc(a.id)}">
                <div class="card-badge" style="width:32px;height:32px;font-size:12px;--card-accent:${colorHex(a.color)}">${esc(initials(a.label))}</div>
                <div class="focus-item-info">
                  <div class="focus-item-name">${esc(a.label)}</div>
                  <div class="focus-item-code" id="fcode-${esc(a.id)}">${formatCodeSpaced(c?.code)}</div>
                </div>
                ${a.pinned ? '<span style="color:var(--accent-hi);font-size:11px">●</span>' : ''}
              </button>`;
          }).join('')}
        </div>

        <section class="focus-panel" style="--card-accent:${hex}">
          <div class="focus-head">
            <div class="card-ident">
              <div class="card-badge" style="width:44px;height:44px;font-size:16px;--card-accent:${hex}">${esc(initials(sel.label))}</div>
              <div>
                <h2 style="font-size:20px;font-weight:800;letter-spacing:-0.02em">${esc(sel.label)}</h2>
                <div class="card-sub-row">
                  <span class="kind-tag ${sel.kind === 'classic' ? 'classic' : ''}">${sel.kind === 'classic' ? 'Klasik SHA-1' : 'AnyOTP+ SHA-256'}</span>
                  ${sel.tag ? `<span class="user-tag">${esc(sel.tag)}</span>` : ''}
                </div>
              </div>
            </div>
            <div style="display:flex;gap:8px">
              <button type="button" class="btn btn-ghost btn-sm" id="focusEditBtn">Düzenle</button>
              <button type="button" class="btn btn-ghost btn-sm" id="focusQrBtn">QR</button>
              <button type="button" class="btn btn-ghost btn-sm" id="focusShareBtn">Paylaş</button>
            </div>
          </div>

          <div class="focus-hero">
            <button type="button" class="focus-code-btn" id="focusCopyMain" title="Tıkla ve kopyala">
              <div class="focus-code" id="focusBigCode">${buildReelHtml(cached?.code || '000000')}</div>
              <div style="font-size:12px;color:var(--tx3);display:flex;align-items:center;gap:8px">
                <span>Kopyalamak için tıklayın</span>
                <span>·</span>
                <span style="font-family:var(--mono);color:var(--tx2)" id="focusRemTxt">-- sn kaldı</span>
              </div>
            </button>
            <div class="focus-timer-bar"><div class="focus-timer-fill" id="focusTimerFill"></div></div>
            <button type="button" class="next-pill" id="focusNextBtn">
              <span>Sonraki Kod (N)</span>
              <span class="next-code-val" id="focusNextVal">${formatCodeSpaced(cached?.next)}</span>
            </button>
          </div>

          <div class="focus-details">
            <div class="f-stat">
              <div class="f-stat-k">Gerçek OTP ID</div>
              <div class="f-stat-v">${esc(sel.realId || 'Belirtilmedi')}</div>
            </div>
            <div class="f-stat">
              <div class="f-stat-k">Not / Karakter</div>
              <div class="f-stat-v" style="font-family:var(--sans)">${esc(sel.note || 'Not yok')}</div>
            </div>
            <div class="f-stat">
              <div class="f-stat-k">Periyot & Algoritma</div>
              <div class="f-stat-v">${sel.period || 60}sn · ${sel.digits || 6} hane</div>
            </div>
          </div>
        </section>
      </div>
    `;

    stage.querySelectorAll('[data-focus]').forEach(btn => {
      btn.addEventListener('click', () => {
        SoundFX.click();
        selectedFocusId = btn.dataset.focus;
        renderStage();
      });
    });
    document.getElementById('focusCopyMain')?.addEventListener('click', () => copyAccountCode(sel.id, false));
    document.getElementById('focusNextBtn')?.addEventListener('click', () => copyAccountCode(sel.id, true));
    document.getElementById('focusEditBtn')?.addEventListener('click', () => openAccountDialog(sel));
    document.getElementById('focusQrBtn')?.addEventListener('click', () => openQrDialog(sel));
    document.getElementById('focusShareBtn')?.addEventListener('click', () => exportSeed([sel], sel.label));
    syncCodesImmediately();
  }

  function bindCardInteractions() {
    document.querySelectorAll('.card').forEach(card => {
      const id = card.dataset.id;

      // Spotlight cursor border tracking
      card.addEventListener('pointermove', (e) => {
        const r = card.getBoundingClientRect();
        card.style.setProperty('--mx', (e.clientX - r.left) + 'px');
        card.style.setProperty('--my', (e.clientY - r.top) + 'px');
      });
      card.addEventListener('pointerenter', () => { hoveredAccountId = id; });
      card.addEventListener('pointerleave', () => { if (hoveredAccountId === id) hoveredAccountId = null; });

      // Click to copy active code
      card.addEventListener('click', (e) => {
        if (e.target.closest('[data-pin],[data-menu],[data-copynext]')) return;
        copyAccountCode(id, false);
      });

      // Right-click context menu
      card.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        openCtxMenu(id, e.clientX, e.clientY);
      });

      // Drag & Drop card reorder
      card.addEventListener('dragstart', (e) => {
        dragSrcId = id;
        card.classList.add('dragging');
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', id);
      });
      card.addEventListener('dragend', () => {
        card.classList.remove('dragging');
        document.querySelectorAll('.card.drag-over').forEach(el => el.classList.remove('drag-over'));
        dragSrcId = null;
      });
      card.addEventListener('dragover', (e) => {
        if (!dragSrcId || dragSrcId === id) return;
        e.preventDefault();
        card.classList.add('drag-over');
      });
      card.addEventListener('dragleave', () => card.classList.remove('drag-over'));
      card.addEventListener('drop', (e) => {
        e.preventDefault();
        card.classList.remove('drag-over');
        if (!dragSrcId || dragSrcId === id) return;
        reorderAccountIds(dragSrcId, id);
      });
    });

    document.querySelectorAll('[data-pin]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        togglePin(btn.dataset.pin);
      });
    });

    document.querySelectorAll('[data-menu]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const r = btn.getBoundingClientRect();
        openCtxMenu(btn.dataset.menu, r.right, r.bottom + 6);
      });
    });

    document.querySelectorAll('[data-copynext]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        copyAccountCode(btn.dataset.copynext, true);
      });
    });
  }

  /* ========================================================================
     60FPS LIVE CHRONOGRAPH & TOTP ENGINE
     ======================================================================== */
  async function refreshAllCodes(playRolloverSound = false) {
    if (isRefreshingCodes) return;
    isRefreshingCodes = true;
    try {
      const t = nowSec();
      let rolled = false;
      await Promise.all(accounts.map(async (a) => {
        try {
          const res = await totpBoth(a.seed, a.kind, a.period, a.digits, t);
          const prev = codeCache.get(a.id);
          if (prev && prev.code !== res.code) rolled = true;
          codeCache.set(a.id, res);

          const codeEl = document.getElementById('code-' + a.id);
          if (codeEl) updateReelDigits(codeEl, res.code);
          const nextEl = document.getElementById('next-' + a.id);
          if (nextEl) nextEl.textContent = formatCodeSpaced(res.next);

          const fcode = document.getElementById('fcode-' + a.id);
          if (fcode) fcode.textContent = formatCodeSpaced(res.code);
          if (a.id === selectedFocusId) {
            const big = document.getElementById('focusBigCode');
            if (big) updateReelDigits(big, res.code);
            const fn = document.getElementById('focusNextVal');
            if (fn) fn.textContent = formatCodeSpaced(res.next);
          }
        } catch {
          // invalid seed ignored safely
        }
      }));
      if (rolled && playRolloverSound && !isLocked) {
        SoundFX.rollover();
      }
    } finally {
      isRefreshingCodes = false;
    }
  }

  function syncCodesImmediately() {
    refreshAllCodes(false);
  }

  function frameLoop() {
    const t = nowSec();
    const d = new Date(t * 1000);
    const timeStr = d.toTimeString().slice(0, 8);
    const liveClockEl = document.getElementById('liveClock');
    if (liveClockEl && liveClockEl.textContent !== timeStr) {
      liveClockEl.textContent = timeStr;
      const dialTime = document.getElementById('clockDialTime');
      if (dialTime) dialTime.textContent = timeStr;
    }

    // Global 60s epoch bar
    const gDiff = t - EPOCH;
    const gStep = Math.floor(gDiff / 60);
    const gElapsed = ((gDiff % 60) + 60) % 60;
    const gRemExact = 60 - gElapsed;
    const gRatio = gRemExact / 60;

    const epochFill = document.getElementById('epochFill');
    if (epochFill) {
      epochFill.style.transform = `scaleX(${Math.max(0, Math.min(1, gRatio)).toFixed(4)})`;
      epochFill.className = 'epoch-fill' + (gRemExact <= 10 ? ' crit' : gRemExact <= 20 ? ' warn' : '');
    }

    if (gStep !== lastGlobalStep) {
      const hadPrev = lastGlobalStep !== -1;
      lastGlobalStep = gStep;
      refreshAllCodes(hadPrev);
    }

    // Per-account smooth 60fps ring & bar interpolation
    const C = 2 * Math.PI * 20; // r=20 -> 125.66
    for (const a of accounts) {
      const p = a.period || 60;
      const diff = t - EPOCH;
      const step = Math.floor(diff / p);
      const cached = codeCache.get(a.id);
      if (!cached || cached.step !== step) {
        refreshAllCodes(false);
      }
      const elapsed = ((diff % p) + p) % p;
      const remExact = p - elapsed;
      const remInt = Math.max(1, Math.ceil(remExact));
      const ratio = remExact / p;
      const stateCls = remExact <= 10 ? 'crit' : remExact <= 20 ? 'warn' : '';

      const ring = document.getElementById('ring-' + a.id);
      if (ring) {
        ring.style.strokeDashoffset = (C * (1 - ratio)).toFixed(2);
        ring.setAttribute('class', 'ring-arc' + (stateCls ? ' ' + stateCls : ''));
      }
      const remEl = document.getElementById('rem-' + a.id);
      if (remEl) {
        if (remEl.textContent !== String(remInt)) remEl.textContent = String(remInt);
        remEl.className = 'ring-num' + (remExact <= 10 ? ' crit' : '');
      }
      const bar = document.getElementById('bar-' + a.id);
      if (bar) {
        bar.style.transform = `scaleX(${ratio.toFixed(4)})`;
        bar.className = 'card-bar-fill' + (stateCls ? ' ' + stateCls : '');
      }
      const np = document.getElementById('nextpill-' + a.id);
      if (np) np.classList.toggle('imminent', remExact <= 15);

      if (a.id === selectedFocusId) {
        const fFill = document.getElementById('focusTimerFill');
        if (fFill) fFill.style.transform = `scaleX(${ratio.toFixed(4)})`;
        const fRem = document.getElementById('focusRemTxt');
        if (fRem) fRem.textContent = `${remInt} sn kaldı`;
        const fNextBtn = document.getElementById('focusNextBtn');
        if (fNextBtn) fNextBtn.classList.toggle('imminent', remExact <= 15);
      }
    }

    requestAnimationFrame(frameLoop);
  }

  /* ========================================================================
     COPY & AUTO-CLEAR CLIPBOARD SECURITY
     ======================================================================== */
  async function copyAccountCode(id, useNext = false) {
    const a = accounts.find(x => x.id === id);
    if (!a) return;
    const res = await totpBoth(a.seed, a.kind, a.period, a.digits, nowSec());
    const val = useNext ? res.next : res.code;
    try {
      await navigator.clipboard.writeText(val);
    } catch {
      // fallback textarea copy
      const ta = document.createElement('textarea');
      ta.value = val;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    lastCopiedCode = val;
    SoundFX.copy();

    const card = document.querySelector(`.card[data-id="${CSS.escape(id)}"]`);
    if (card) {
      card.classList.remove('copied');
      void card.offsetWidth;
      card.classList.add('copied');
    }

    toast(
      useNext
        ? `Sonraki kod kopyalandı · ${formatCodeSpaced(val)} (${a.label})`
        : `Kod kopyalandı · ${formatCodeSpaced(val)} (${a.label})`
    );
    scheduleClipboardClear();
  }

  function scheduleClipboardClear() {
    clearTimeout(clipClearTimer);
    clearInterval(clipClearInterval);
    const badge = document.getElementById('clipTimerBadge');
    if (!autoClearClip) {
      if (badge) badge.style.display = 'none';
      return;
    }
    let left = 30;
    if (badge) {
      badge.style.display = 'inline';
      badge.textContent = `Pano temizliği: ${left}sn`;
    }
    clipClearInterval = setInterval(() => {
      left--;
      if (badge && left > 0) badge.textContent = `Pano temizliği: ${left}sn`;
    }, 1000);
    clipClearTimer = setTimeout(async () => {
      clearInterval(clipClearInterval);
      if (badge) badge.style.display = 'none';
      try {
        const cur = await navigator.clipboard.readText().catch(() => '');
        if (!cur || cur === lastCopiedCode) {
          await navigator.clipboard.writeText('');
        }
      } catch {
        // clipboard read/write denied when unfocused
      }
    }, 30000);
  }

  /* ========================================================================
     ACCOUNT CRUD, PIN & REORDER
     ======================================================================== */
  async function togglePin(id) {
    const a = accounts.find(x => x.id === id);
    if (!a) return;
    a.pinned = !a.pinned;
    SoundFX.click();
    if (hasTauri) {
      try { await invoke('vault_save', { account: a }); } catch (e) { toast('Kasa hatası: ' + e, 'err'); return; }
    } else {
      persistLocal();
    }
    renderTags();
    runViewTransition(renderStage);
    toast(a.pinned ? `"${a.label}" üste sabitlendi` : `"${a.label}" sabitlemesi kaldırıldı`, 'info');
  }

  async function reorderAccountIds(fromId, toId) {
    const fromIdx = accounts.findIndex(a => a.id === fromId);
    const toIdx = accounts.findIndex(a => a.id === toId);
    if (fromIdx < 0 || toIdx < 0) return;
    const [moved] = accounts.splice(fromIdx, 1);
    accounts.splice(toIdx, 0, moved);
    SoundFX.click();
    if (hasTauri) {
      try { await invoke('vault_reorder', { ids: accounts.map(a => a.id) }); } catch {}
    } else {
      persistLocal();
    }
    runViewTransition(renderStage);
  }

  // Color swatch builder
  function renderSwatches() {
    const wrap = document.getElementById('colorSwatches');
    wrap.innerHTML = PALETTE.map(c => `
      <button type="button" class="swatch ${selectedColor === c.id ? 'on' : ''}" data-color="${c.id}" style="background:${c.hex}" title="${c.name}" aria-label="${c.name}"></button>
    `).join('');
    wrap.querySelectorAll('.swatch').forEach(btn => {
      btn.addEventListener('click', () => {
        selectedColor = btn.dataset.color;
        renderSwatches();
      });
    });
  }

  function setAddTab(t) {
    addTab = t;
    document.getElementById('tabAct').classList.toggle('on', t === 'act');
    document.getElementById('tabSeed').classList.toggle('on', t === 'seed');
    document.getElementById('paneAct').style.display = t === 'act' ? '' : 'none';
    document.getElementById('paneSeed').style.display = t === 'seed' ? '' : 'none';
    document.getElementById('accFormErr').textContent = '';
  }

  function openAccountDialog(accountToEdit = null) {
    editingAccountId = accountToEdit ? accountToEdit.id : null;
    document.getElementById('accFormErr').textContent = '';
    const tabs = document.getElementById('addTabs');
    const seedWrap = document.getElementById('seedFieldWrap');
    const preview = document.getElementById('liveSeedPreview');

    if (accountToEdit) {
      document.getElementById('accDlgTitle').textContent = 'Hesabı Düzenle';
      document.getElementById('accDlgSub').textContent = 'Etiket, kategori, not veya kart vurgu rengini güncelleyin.';
      document.getElementById('saveAccBtn').textContent = 'Güncelle';
      tabs.style.display = 'none';
      setAddTab('seed');
      seedWrap.style.display = 'none';
      preview.classList.add('hidden');
      document.getElementById('f_seed').value = accountToEdit.seed;
      document.getElementById('f_label').value = accountToEdit.label || '';
      document.getElementById('f_kind').value = accountToEdit.kind || 'plus';
      document.getElementById('f_tag_s').value = accountToEdit.tag || '';
      document.getElementById('f_realid').value = accountToEdit.realId || '';
      document.getElementById('f_note_s').value = accountToEdit.note || '';
      selectedColor = accountToEdit.color || 'ember';
    } else {
      document.getElementById('accDlgTitle').textContent = 'Hesap Ekle';
      document.getElementById('accDlgSub').textContent = 'AnyOTP+ hesabını aktive et ya da mevcut hex seed\'i kasaya ekle.';
      document.getElementById('saveAccBtn').textContent = 'Kaydet';
      tabs.style.display = '';
      seedWrap.style.display = '';
      preview.classList.add('hidden');
      ['f_id', 'f_code', 'f_tag_a', 'f_note_a', 'f_seed', 'f_label', 'f_tag_s', 'f_realid', 'f_note_s'].forEach(i => {
        document.getElementById(i).value = '';
      });
      document.getElementById('f_kind').value = 'plus';
      document.getElementById('seedLenMeta').textContent = '0 / 64 hex';
      selectedColor = 'ember';
      setAddTab('act');
    }
    renderSwatches();
    document.getElementById('accountDialog').showModal();
  }

  // Live hex seed preview & auto-detection while typing
  async function updateLiveSeedPreview() {
    const raw = document.getElementById('f_seed').value.replace(/\s/g, '');
    const meta = document.getElementById('seedLenMeta');
    const preview = document.getElementById('liveSeedPreview');
    const kindSel = document.getElementById('f_kind');
    meta.textContent = `${raw.length} hex`;

    if (/^[0-9a-fA-F]+$/.test(raw) && raw.length >= 32) {
      if (raw.length >= 64) kindSel.value = 'plus';
      const kind = kindSel.value;
      const r = await totpBoth(raw, kind, 60, 6, nowSec());
      document.getElementById('liveSeedCode').textContent = formatCodeSpaced(r.code);
      document.getElementById('liveSeedMeta').textContent = `${kind === 'classic' ? 'HMAC-SHA1 (Klasik)' : 'HMAC-SHA256 (AnyOTP+)'} · ${r.rem}sn`;
      preview.classList.remove('hidden');
    } else {
      preview.classList.add('hidden');
    }
  }

  async function handleAccountSubmit(e) {
    e.preventDefault();
    const errEl = document.getElementById('accFormErr');
    errEl.textContent = '';

    if (editingAccountId) {
      const existing = accounts.find(a => a.id === editingAccountId);
      if (!existing) return;
      const updated = {
        ...existing,
        label: document.getElementById('f_label').value.trim() || existing.label,
        kind: document.getElementById('f_kind').value,
        tag: document.getElementById('f_tag_s').value.trim(),
        realId: document.getElementById('f_realid').value.trim(),
        note: document.getElementById('f_note_s').value.trim(),
        color: selectedColor,
      };
      if (hasTauri) {
        try { await invoke('vault_save', { account: updated }); }
        catch (err) { errEl.textContent = 'Kasa hatası: ' + err; SoundFX.error(); return; }
      }
      const idx = accounts.findIndex(a => a.id === editingAccountId);
      accounts[idx] = updated;
      if (!hasTauri) persistLocal();
      codeCache.delete(updated.id);
      closeTopLayer(document.getElementById('accountDialog'));
      renderTags();
      runViewTransition(renderStage);
      SoundFX.sync();
      toast(`"${updated.label}" güncellendi`);
      return;
    }

    if (addTab === 'act') {
      const otpId = document.getElementById('f_id').value.trim();
      const code = document.getElementById('f_code').value.trim();
      const note = document.getElementById('f_note_a').value.trim();
      const tag = document.getElementById('f_tag_a').value.trim();
      if (!otpId || code.length < 6) {
        errEl.textContent = 'Geçerli OTP ID ve 6 haneli aktivasyon kodu gerekli.';
        SoundFX.error();
        return;
      }
      if (!hasTauri) {
        errEl.textContent = 'Canlı NTTGame aktivasyonu yalnızca masaüstü (.exe) sürümde çalışır.';
        SoundFX.error();
        return;
      }
      const btn = document.getElementById('saveAccBtn');
      btn.disabled = true;
      btn.textContent = 'Aktive ediliyor…';
      try {
        const res = await invoke('activate', { otpId, code, note, tag, color: selectedColor });
        accounts.push(res);
        closeTopLayer(document.getElementById('accountDialog'));
        renderTags();
        runViewTransition(renderStage);
        SoundFX.sync();
        toast('Aktivasyon tamamlandı · ' + res.label);
      } catch (err) {
        errEl.textContent = 'Aktivasyon hatası: ' + err;
        SoundFX.error();
      } finally {
        btn.disabled = false;
        btn.textContent = 'Kaydet';
      }
    } else {
      const seed = document.getElementById('f_seed').value.trim().replace(/\s/g, '');
      const label = document.getElementById('f_label').value.trim() || ('Hesap ' + (accounts.length + 1));
      if (!/^[0-9a-fA-F]+$/.test(seed) || seed.length < 32) {
        errEl.textContent = 'En az 32 haneli geçerli bir hex seed girin.';
        SoundFX.error();
        return;
      }
      const acc = {
        id: uid(),
        label,
        realId: document.getElementById('f_realid').value.trim(),
        note: document.getElementById('f_note_s').value.trim(),
        seed,
        kind: document.getElementById('f_kind').value,
        period: 60,
        digits: 6,
        pinned: false,
        tag: document.getElementById('f_tag_s').value.trim(),
        color: selectedColor,
      };
      if (hasTauri) {
        try {
          const saved = await invoke('vault_save', { account: acc });
          accounts.push(saved);
        } catch (err) {
          errEl.textContent = 'Kasa hatası: ' + err;
          SoundFX.error();
          return;
        }
      } else {
        accounts.push(acc);
        persistLocal();
      }
      closeTopLayer(document.getElementById('accountDialog'));
      renderTags();
      runViewTransition(renderStage);
      SoundFX.sync();
      toast(`"${acc.label}" şifreli kasaya kaydedildi`);
    }
  }

  async function requestDeleteAccount(id) {
    const a = accounts.find(x => x.id === id);
    if (!a) return;
    const dlg = document.getElementById('confirmDialog');
    document.getElementById('confirmTitle').textContent = `"${a.label}" silinsin mi?`;
    document.getElementById('confirmDesc').textContent = 'Bu hesabın seed verisi DPAPI kasasından kalıcı olarak kaldırılacak. Yedek almadıysanız geri getirilemez.';
    dlg.returnValue = '';
    dlg.showModal();
    dlg.addEventListener('close', async () => {
      const rv = dlg.returnValue;
      dlg.returnValue = '';
      if (rv !== 'confirm') return;
      if (hasTauri) {
        try { await invoke('vault_delete', { id }); }
        catch (err) { toast('Silme hatası: ' + err, 'err'); SoundFX.error(); return; }
      }
      accounts = accounts.filter(x => x.id !== id);
      codeCache.delete(id);
      if (!hasTauri) persistLocal();
      renderTags();
      runViewTransition(renderStage);
      SoundFX.click();
      toast(`"${a.label}" silindi`, 'info');
    }, { once: true });
  }

  /* ========================================================================
     CONTEXT MENU & QR SHARE / IMPORT / EXPORT
     ======================================================================== */
  function openCtxMenu(id, x, y) {
    ctxTargetId = id;
    const a = accounts.find(acc => acc.id === id);
    if (!a) return;
    document.querySelector('#ctxPinBtn span').textContent = a.pinned ? 'Sabitlemeyi Kaldır' : 'Üste Sabitle';
    const menu = document.getElementById('ctxMenu');
    menu.classList.add('open');
    const mw = menu.offsetWidth || 200;
    const mh = menu.offsetHeight || 250;
    const left = Math.max(10, Math.min(x - mw + 20, window.innerWidth - mw - 10));
    const top = Math.max(46, Math.min(y, window.innerHeight - mh - 10));
    menu.style.left = left + 'px';
    menu.style.top = top + 'px';
  }

  function closeCtxMenu() {
    document.getElementById('ctxMenu').classList.remove('open');
  }

  function openQrDialog(acc) {
    const dlg = document.getElementById('qrDialog');
    document.getElementById('qrTitle').textContent = acc.label;
    document.getElementById('qrSub').textContent = `${acc.kind === 'classic' ? 'Klasik (SHA-1)' : 'AnyOTP+ (SHA-256)'} · ${acc.realId || 'Yerel Seed'}`;
    const payload = JSON.stringify({
      label: acc.label,
      realId: acc.realId || '',
      seed: acc.seed,
      kind: acc.kind,
      period: acc.period || 60,
      digits: acc.digits || 6,
    });
    const svg = MiniQR.toSVG(payload);
    document.getElementById('qrFrame').innerHTML = svg || '<div style="color:#000;padding:24px;font-size:12px">QR oluşturulamadı</div>';
    document.getElementById('qrMeta').textContent = `Peyywado Seed QR · ${acc.seed.length} hex`;
    document.getElementById('btnQrExportJson').onclick = () => exportSeed([acc], acc.label);
    dlg.showModal();
  }

  function exportSeed(list, name) {
    if (!list.length) { toast('Dışa aktarılacak hesap yok', 'err'); return; }
    const data = {
      app: 'Peyywado OTP',
      version: 2,
      exportedAt: new Date().toISOString(),
      accounts: list.map(a => ({
        label: a.label, realId: a.realId || '', note: a.note || '',
        seed: a.seed, kind: a.kind, period: a.period || 60, digits: a.digits || 6,
        pinned: !!a.pinned, tag: a.tag || '', color: a.color || 'ember'
      })),
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = (name ? name.replace(/[^\w-]+/g, '_') : 'peyywado') + '_seed.json';
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1200);
    SoundFX.sync();
    toast('seed.json dışa aktarıldı');
  }

  async function importSeedFile(file) {
    if (!file) return;
    try {
      const data = JSON.parse(await file.text());
      const list = Array.isArray(data) ? data : (data.accounts || []);
      if (!list.length) { toast('Dosyada geçerli hesap bulunamadı', 'err'); return; }
      let added = 0;
      for (const it of list) {
        const seed = (it.seed || it.secret || it.seedHex || '').replace(/\s/g, '');
        if (!/^[0-9a-fA-F]+$/.test(seed) || seed.length < 32) continue;
        const acc = {
          id: uid(),
          label: it.label || ('Hesap ' + (accounts.length + 1)),
          realId: it.realId || it.serial || '',
          note: it.note || '',
          seed,
          kind: it.kind || (seed.length === 40 ? 'classic' : 'plus'),
          period: it.period || 60,
          digits: it.digits || 6,
          pinned: !!it.pinned,
          tag: it.tag || '',
          color: it.color || 'ember',
        };
        if (hasTauri) {
          try {
            const saved = await invoke('vault_save', { account: acc });
            accounts.push(saved);
            added++;
          } catch {}
        } else {
          accounts.push(acc);
          added++;
        }
      }
      if (!hasTauri) persistLocal();
      renderTags();
      runViewTransition(renderStage);
      SoundFX.sync();
      toast(`${added} hesap kasaya aktarıldı`);
    } catch {
      SoundFX.error();
      toast('Geçersiz JSON / seed dosyası', 'err');
    }
  }

  /* ========================================================================
     COMMAND PALETTE (Ctrl+K)
     ======================================================================== */
  let palItems = [];
  let palIndex = 0;

  function openPalette() {
    const dlg = document.getElementById('paletteDialog');
    const inp = document.getElementById('palInput');
    inp.value = '';
    palIndex = 0;
    renderPaletteItems('');
    dlg.showModal();
    setTimeout(() => inp.focus(), 20);
  }

  function renderPaletteItems(query) {
    const q = query.trim().toLowerCase();
    const listEl = document.getElementById('palList');
    const accMatches = getVisibleAccounts().filter(a =>
      !q || (a.label || '').toLowerCase().includes(q) || (a.note || '').toLowerCase().includes(q) || (a.tag || '').toLowerCase().includes(q) || (a.realId || '').toLowerCase().includes(q)
    );

    const actions = [
      { id: 'act-capture', label: 'iPhone\'dan AnyOTP+ Seed Yakala (Sihirbaz)', hint: 'iPhone', run: () => openCaptureWizard() },
      { id: 'act-guide', label: 'Kullanıcı Rehberi & Güven Merkezi', hint: 'Rehber', run: () => openGuideDialog('how') },
      { id: 'act-add', label: 'Yeni Hesap Ekle / Aktive Et', hint: 'Ctrl+N', run: () => openAccountDialog() },
      { id: 'act-clock', label: 'Atomik Saati Optimize Et', hint: 'Sync', run: () => openClockDialog() },
      { id: 'act-check', label: 'Canlı Sistem Tanılamasını Çalıştır', hint: 'Test', run: () => openCheckDialog() },
      { id: 'act-priv', label: isPrivacy ? 'Gizlilik Bulanıklığını Kapat' : 'Gizlilik Bulanıklığını Aç', hint: 'P', run: () => togglePrivacy() },
      { id: 'act-mini', label: isMiniMode ? 'Tam Masaüstü Görünümüne Dön' : 'Mini HUD Moduna Geç', hint: 'Alt+M', run: () => toggleMiniMode() },
      { id: 'act-top', label: isAlwaysTop ? 'Her Zaman Üstte Modunu Kapat' : 'Pencereyi Her Zaman Üstte Tut', hint: 'Pin', run: () => toggleAlwaysOnTop() },
      { id: 'act-export', label: 'Tüm Kasayı seed.json Olarak Yedekle', hint: 'Export', run: () => exportSeed(accounts, 'peyywado_yedek') },
      { id: 'act-settings', label: 'Ayarlar ve PIN Güvenliği', hint: 'Ayarlar', run: () => openSettingsDialog() },
    ].filter(act => !q || act.label.toLowerCase().includes(q) || act.hint.toLowerCase().includes(q));

    palItems = [
      ...accMatches.map(a => ({ type: 'acc', acc: a })),
      ...actions.map(act => ({ type: 'act', act })),
    ];
    if (palIndex >= palItems.length) palIndex = 0;

    let html = '';
    if (accMatches.length) {
      html += `<div class="pal-group">Hesaplar — Enter ile Kopyala</div>`;
      html += accMatches.map((a, i) => {
        const c = codeCache.get(a.id);
        return `
          <button type="button" class="pal-item ${i === palIndex ? 'sel' : ''}" data-pidx="${i}">
            <span class="pal-item-l">
              <span class="card-badge" style="width:24px;height:24px;font-size:10px;border-radius:7px;--card-accent:${colorHex(a.color)}">${esc(initials(a.label))}</span>
              <span>${esc(a.label)}</span>
              ${a.tag ? `<span class="user-tag">${esc(a.tag)}</span>` : ''}
            </span>
            <span class="pal-code">${formatCodeSpaced(c?.code)}</span>
          </button>`;
      }).join('');
    }
    if (actions.length) {
      html += `<div class="pal-group">Hızlı Komutlar</div>`;
      html += actions.map((act, idx) => {
        const gi = accMatches.length + idx;
        return `
          <button type="button" class="pal-item ${gi === palIndex ? 'sel' : ''}" data-pidx="${gi}">
            <span class="pal-item-l">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M5 12h14M13 5l7 7-7 7"/></svg>
              <span>${esc(act.label)}</span>
            </span>
            <span class="kbd">${esc(act.hint)}</span>
          </button>`;
      }).join('');
    }
    if (!palItems.length) {
      html = `<div style="padding:28px;text-align:center;font-size:13px;color:var(--tx3)">Sonuç bulunamadı</div>`;
    }
    listEl.innerHTML = html;

    listEl.querySelectorAll('.pal-item').forEach(btn => {
      btn.addEventListener('click', () => executePaletteItem(Number(btn.dataset.pidx), false));
      btn.addEventListener('pointerenter', () => {
        palIndex = Number(btn.dataset.pidx);
        listEl.querySelectorAll('.pal-item').forEach((el, i) => el.classList.toggle('sel', i === palIndex));
      });
    });
  }

  function executePaletteItem(idx, shiftKey) {
    const item = palItems[idx];
    if (!item) return;
    closeTopLayer(document.getElementById('paletteDialog'));
    if (item.type === 'acc') {
      copyAccountCode(item.acc.id, shiftKey);
    } else {
      item.act.run();
    }
  }

  const CHECKS = [
    { key: 'time1', name: 'DreamMirae Zaman Sunucusu #1', detail: 'time1.dreammirae.com' },
    { key: 'time2', name: 'DreamMirae Zaman Sunucusu #2', detail: 'time2.dreammirae.com' },
    { key: 'ntt', name: 'NTTGame Aktivasyon Sunucusu', detail: 'otpsvr.nttgame.com:27700' },
    { key: 'crypto', name: 'TOTP Kripto Öz-Testi', detail: 'HMAC-SHA1 / SHA-256 vektör kontrolü' },
  ];

  async function previewCheck(key) {
    if (key === 'crypto') {
      const r = await totpBoth('11'.repeat(32), 'plus', 60, 6, 1700000000);
      return r.code === '709288'
        ? { ok: true, detail: 'vektör doğrulandı (709288)' }
        : { ok: false, detail: 'vektör uyumsuz (' + r.code + ')' };
    }
    return { ok: true, detail: 'önizleme modu (masaüstünde canlı TCP test)' };
  }

  function setStatusIndicator(ok) {
    const dot = document.getElementById('statusDot');
    const txt = document.getElementById('statusTxt');
    dot.className = 'pulse-dot ' + (ok ? 'ok' : 'bad');
    txt.textContent = ok ? 'Sistemler aktif' : 'Bağlantı uyarısı';
  }

  async function openCheckDialog() {
    document.getElementById('checkDialog').showModal();
    await runDiagnostics();
  }

  async function runDiagnostics() {
    const box = document.getElementById('checkRows');
    box.innerHTML = CHECKS.map(c => `
      <div class="check-row">
        <div class="check-ic" id="cic-${c.key}"><svg class="spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.2-8.5"/></svg></div>
        <div class="check-body">
          <div class="check-name">${esc(c.name)}</div>
          <div class="check-detail" id="cd-${c.key}">${esc(c.detail)}</div>
        </div>
        <div class="check-stat st-run" id="cs-${c.key}">TEST</div>
      </div>`).join('');

    const vBox = document.getElementById('vaultInfoBox');
    if (hasTauri) {
      try {
        const info = await invoke('vault_info');
        vBox.style.display = 'flex';
        vBox.innerHTML = `
          <div style="font-weight:700;color:var(--ok)">Kasa Güvenliği: ${esc(info.encryption)}</div>
          <div>${info.count} kayıtlı hesap · ${info.bytes} bayt şifreli veri</div>
          <code>${esc(info.path)}</code>`;
      } catch {
        vBox.style.display = 'none';
      }
    } else {
      vBox.style.display = 'flex';
      vBox.innerHTML = `<div style="font-weight:700;color:var(--ok)">Tarayıcı Önizleme Modu</div><div>Masaüstü (.exe) sürümde tüm seed'ler Windows DPAPI ile şifrelenir.</div>`;
    }

    let allOk = true;
    for (const c of CHECKS) {
      await new Promise(r => setTimeout(r, 180));
      let res;
      if (hasTauri) {
        try { res = await invoke('check_one', { key: c.key }); }
        catch { res = { ok: false, detail: 'backend yanıt vermedi' }; }
      } else {
        res = await previewCheck(c.key);
      }
      const st = document.getElementById('cs-' + c.key);
      const cd = document.getElementById('cd-' + c.key);
      const cic = document.getElementById('cic-' + c.key);
      if (cic) {
        cic.style.background = res.ok ? 'var(--ok-dim)' : 'var(--bad-dim)';
        cic.style.color = res.ok ? 'var(--ok)' : 'var(--bad)';
        cic.innerHTML = res.ok
          ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M20 6L9 17l-5-5"/></svg>'
          : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg>';
      }
      if (st) {
        st.className = 'check-stat ' + (res.ok ? 'st-ok' : 'st-bad');
        st.textContent = res.ok ? 'AKTİF' : 'HATA';
      }
      if (cd) {
        cd.textContent = res.detail;
        cd.style.color = res.ok ? 'var(--tx3)' : 'var(--bad)';
      }
      if (!res.ok) allOk = false;
    }
    setStatusIndicator(allOk);
    if (allOk) SoundFX.sync();
  }

  async function runCheckSilent() {
    let ok = true;
    for (const c of CHECKS) {
      const r = hasTauri
        ? await invoke('check_one', { key: c.key }).catch(() => ({ ok: false }))
        : await previewCheck(c.key);
      if (!r.ok) ok = false;
    }
    setStatusIndicator(ok);
  }

  function updateOffsetDisplays() {
    const txt = (timeOffset >= 0 ? '+' : '') + timeOffset.toFixed(2) + 's';
    const warn = Math.abs(timeOffset) > 1.5;
    const pill = document.getElementById('liveOffset');
    if (pill) {
      pill.textContent = txt;
      pill.className = 'tel-offset' + (warn ? ' warn' : '');
    }
    const off = document.getElementById('clockOff');
    if (off) {
      off.textContent = txt;
      off.className = 'clock-off' + (warn ? ' bad' : '');
    }
  }

  function openClockDialog() {
    updateOffsetDisplays();
    document.getElementById('clockSrc').textContent = timeOffset ? 'Son senkron aktif' : 'Henüz senkronlanmadı';
    document.getElementById('clockDialog').showModal();
  }

  async function optimizeClock() {
    const dial = document.getElementById('syncDial');
    const offEl = document.getElementById('clockOff');
    const srcEl = document.getElementById('clockSrc');
    dial.classList.add('run');
    offEl.textContent = '…';
    let res = null;
    if (hasTauri) {
      try { res = await invoke('sync_time'); } catch { res = null; }
    }
    await new Promise(r => setTimeout(r, 750));
    dial.classList.remove('run');
    if (res) {
      timeOffset = res.offset;
      srcEl.textContent = `${res.source} · hizalandı`;
    } else if (!hasTauri) {
      timeOffset = Math.max(-0.25, Math.min(0.25, (Math.random() - 0.5) * 0.08));
      srcEl.textContent = 'time1.dreammirae.com · önizleme hizalandı';
    } else {
      srcEl.textContent = 'Saat sunucusuna ulaşılamadı';
      SoundFX.error();
      toast('Saat sunucusuna ulaşılamadı', 'err');
      updateOffsetDisplays();
      return;
    }
    lsSet('pw_off', String(timeOffset));
    updateOffsetDisplays();
    document.getElementById('syncArc').style.strokeDashoffset = '0';
    refreshAllCodes(false);
    SoundFX.sync();
    toast(`Saat optimize edildi (${(timeOffset >= 0 ? '+' : '') + timeOffset.toFixed(2)}s)`);
  }

  function applyPreferencesUI() {
    document.body.classList.toggle('privacy-blur', isPrivacy);
    document.getElementById('btnPrivacy').classList.toggle('active', isPrivacy);
    document.getElementById('btnSound').classList.toggle('active', isSoundOn);
    SoundFX.setEnabled(isSoundOn);

    document.getElementById('swPrivacy').setAttribute('aria-checked', String(isPrivacy));
    document.getElementById('swSound').setAttribute('aria-checked', String(isSoundOn));
    document.getElementById('swAutoClear').setAttribute('aria-checked', String(autoClearClip));

    const hasPin = Boolean(pinHash);
    document.getElementById('btnLockNow').style.display = hasPin ? 'grid' : 'none';
    document.getElementById('btnRemovePin').style.display = hasPin ? 'inline-flex' : 'none';
    document.getElementById('pinStatusDesc').textContent = hasPin
      ? 'PIN kilidi aktif. Ctrl+L ile anında kilitleyebilirsiniz.'
      : 'Uygulamaya 4-8 haneli yerel PIN koruması ekleyin.';
  }

  function togglePrivacy() {
    isPrivacy = !isPrivacy;
    lsSet('pw_privacy', isPrivacy ? '1' : '0');
    applyPreferencesUI();
    SoundFX.click();
    toast(isPrivacy ? 'Gizlilik bulanıklığı açıldı' : 'Gizlilik bulanıklığı kapatıldı', 'info');
  }

  function toggleSound() {
    isSoundOn = !isSoundOn;
    lsSet('pw_sound', isSoundOn ? '1' : '0');
    applyPreferencesUI();
    if (isSoundOn) SoundFX.click();
    toast(isSoundOn ? 'Ses efektleri açık' : 'Ses efektleri sessiz', 'info');
  }

  function openSettingsDialog() {
    applyPreferencesUI();
    document.getElementById('newPinInput').value = '';
    document.getElementById('settingsDialog').showModal();
  }

  function lockVault() {
    if (!pinHash) return;
    isLocked = true;
    document.getElementById('unlockErr').textContent = '';
    document.getElementById('unlockPinInput').value = '';
    document.getElementById('lockScreen').classList.add('open');
    setTimeout(() => document.getElementById('unlockPinInput').focus(), 40);
  }

  async function toggleAlwaysOnTop() {
    isAlwaysTop = !isAlwaysTop;
    if (hasTauri) {
      try { isAlwaysTop = await invoke('win_set_always_on_top', { on: isAlwaysTop }); } catch {}
    }
    document.getElementById('btnAlwaysTop').classList.toggle('active', isAlwaysTop);
    SoundFX.click();
    toast(isAlwaysTop ? 'Pencere her zaman üstte' : 'Üstte tutma kapatıldı', 'info');
  }

  async function toggleMiniMode() {
    isMiniMode = !isMiniMode;
    document.body.classList.toggle('mini-mode', isMiniMode);
    document.getElementById('btnMiniMode').classList.toggle('active', isMiniMode);
    if (hasTauri) {
      try {
        await invoke('win_set_mini_mode', { mini: isMiniMode });
        if (isMiniMode) {
          isAlwaysTop = true;
          document.getElementById('btnAlwaysTop').classList.add('active');
        }
      } catch {}
    }
    SoundFX.click();
    renderStage();
  }

  function setView(v) {
    const prev = view;
    view = v;
    lsSet('pw_view', v);
    document.getElementById('viewGrid').classList.toggle('on', v === 'grid');
    document.getElementById('viewList').classList.toggle('on', v === 'list');
    document.getElementById('viewFocus').classList.toggle('on', v === 'focus');
    if (prev === 'focus' || v === 'focus') {
      renderStage();
    } else {
      runViewTransition(renderStage);
    }
  }

  function toast(msg, type = 'ok') {
    const stack = document.getElementById('toastStack');
    const el = document.createElement('div');
    el.className = `toast-item ${type}`;
    const ic = type === 'err'
      ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/></svg>'
      : type === 'info'
      ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></svg>'
      : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M20 6L9 17l-5-5"/></svg>';
    el.innerHTML = `${ic}<span>${esc(msg)}</span>`;
    stack.appendChild(el);
    while (stack.children.length > 3) stack.firstElementChild.remove();
    setTimeout(() => {
      el.classList.add('out');
      setTimeout(() => el.remove(), 240);
    }, 2600);
  }

  function bindEvents() {

    document.getElementById('winMin').addEventListener('click', () => hasTauri && invoke('win_minimize'));
    document.getElementById('winMax').addEventListener('click', () => hasTauri && invoke('win_toggle_maximize'));
    document.getElementById('winClose').addEventListener('click', () => hasTauri ? invoke('win_close') : window.close());
    document.getElementById('titlebar').addEventListener('dblclick', (e) => {
      if (e.target.closest('button')) return;
      if (hasTauri) invoke('win_toggle_maximize');
    });

    document.getElementById('statusPill').addEventListener('click', openCheckDialog);
    document.getElementById('clockPill').addEventListener('click', openClockDialog);
    document.getElementById('btnPrivacy').addEventListener('click', togglePrivacy);
    document.getElementById('btnSound').addEventListener('click', toggleSound);
    document.getElementById('btnAlwaysTop').addEventListener('click', toggleAlwaysOnTop);
    document.getElementById('btnMiniMode').addEventListener('click', toggleMiniMode);
    document.getElementById('btnLockNow').addEventListener('click', lockVault);
    document.getElementById('btnGuide').addEventListener('click', () => openGuideDialog('how'));
    document.getElementById('btnSettings').addEventListener('click', openSettingsDialog);

    const searchInput = document.getElementById('searchInput');
    const searchWrap = document.getElementById('searchWrap');
    searchInput.addEventListener('input', () => {
      searchQuery = searchInput.value;
      searchWrap.classList.toggle('has-value', searchQuery.length > 0);
      renderStage();
    });
    document.getElementById('searchClear').addEventListener('click', () => {
      searchQuery = '';
      searchInput.value = '';
      searchWrap.classList.remove('has-value');
      renderStage();
      searchInput.focus();
    });
    document.getElementById('btnCmdPalette').addEventListener('click', openPalette);
    document.getElementById('viewGrid').addEventListener('click', () => { SoundFX.click(); setView('grid'); });
    document.getElementById('viewList').addEventListener('click', () => { SoundFX.click(); setView('list'); });
    document.getElementById('viewFocus').addEventListener('click', () => { SoundFX.click(); setView('focus'); });
    document.getElementById('btnCaptureIphone').addEventListener('click', () => openCaptureWizard());
    document.getElementById('btnAdd').addEventListener('click', () => openAccountDialog());
    document.getElementById('btnImport').addEventListener('click', () => document.getElementById('importFile').click());
    document.getElementById('importFile').addEventListener('change', (e) => {
      importSeedFile(e.target.files[0]);
      e.target.value = '';
    });
    document.getElementById('btnExportAll').addEventListener('click', () => exportSeed(accounts, 'tum_hesaplar'));
    document.getElementById('btnShortcuts').addEventListener('click', () => document.getElementById('shortcutsDialog').showModal());

    document.getElementById('tabAct').addEventListener('click', () => { SoundFX.click(); setAddTab('act'); });
    document.getElementById('tabSeed').addEventListener('click', () => { SoundFX.click(); setAddTab('seed'); });
    document.getElementById('f_seed').addEventListener('input', updateLiveSeedPreview);
    document.getElementById('f_kind').addEventListener('change', updateLiveSeedPreview);
    document.getElementById('accountForm').addEventListener('submit', handleAccountSubmit);

    document.getElementById('btnRerunCheck').addEventListener('click', runDiagnostics);
    document.getElementById('btnSyncClock').addEventListener('click', optimizeClock);

    document.getElementById('swAutoClear').addEventListener('click', () => {
      autoClearClip = !autoClearClip;
      lsSet('pw_autoclear', autoClearClip ? '1' : '0');
      applyPreferencesUI();
      SoundFX.click();
    });
    document.getElementById('swSound').addEventListener('click', toggleSound);
    document.getElementById('swPrivacy').addEventListener('click', togglePrivacy);

    document.getElementById('pinSetupForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const val = document.getElementById('newPinInput').value.trim();
      if (!/^\d{4,8}$/.test(val)) {
        SoundFX.error();
        toast('PIN 4 ile 8 rakam arasında olmalıdır', 'err');
        return;
      }
      pinHash = await sha256Hex('peyywado-salt-v2:' + val);
      lsSet('pw_pin_hash', pinHash);
      document.getElementById('newPinInput').value = '';
      applyPreferencesUI();
      SoundFX.sync();
      toast('Yerel PIN kilidi etkinleştirildi');
    });

    document.getElementById('btnRemovePin').addEventListener('click', () => {
      pinHash = '';
      lsSet('pw_pin_hash', '');
      applyPreferencesUI();
      SoundFX.click();
      toast('PIN kilidi kaldırıldı', 'info');
    });

    document.getElementById('unlockForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const val = document.getElementById('unlockPinInput').value.trim();
      const h = await sha256Hex('peyywado-salt-v2:' + val);
      if (h === pinHash) {
        isLocked = false;
        document.getElementById('lockScreen').classList.remove('open');
        SoundFX.sync();
      } else {
        SoundFX.error();
        document.getElementById('unlockErr').textContent = 'Hatalı PIN kodu';
        const card = document.getElementById('lockCard');
        card.classList.remove('shake');
        void card.offsetWidth;
        card.classList.add('shake');
        document.getElementById('unlockPinInput').select();
      }
    });

    document.getElementById('ctxMenu').addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-ctx]');
      if (!btn || !ctxTargetId) return;
      const id = ctxTargetId;
      const a = accounts.find(x => x.id === id);
      closeCtxMenu();
      if (!a) return;
      switch (btn.dataset.ctx) {
        case 'copy': copyAccountCode(id, false); break;
        case 'copyNext': copyAccountCode(id, true); break;
        case 'pin': togglePin(id); break;
        case 'edit': openAccountDialog(a); break;
        case 'qr': openQrDialog(a); break;
        case 'export': exportSeed([a], a.label); break;
        case 'delete': requestDeleteAccount(id); break;
      }
    });
    document.addEventListener('pointerdown', (e) => {
      if (!e.target.closest('#ctxMenu')) closeCtxMenu();
    });

    const palInput = document.getElementById('palInput');
    palInput.addEventListener('input', () => {
      palIndex = 0;
      renderPaletteItems(palInput.value);
    });
    palInput.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (palItems.length) palIndex = (palIndex + 1) % palItems.length;
        renderPaletteItems(palInput.value);
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (palItems.length) palIndex = (palIndex - 1 + palItems.length) % palItems.length;
        renderPaletteItems(palInput.value);
      } else if (e.key === 'Enter') {
        e.preventDefault();
        executePaletteItem(palIndex, e.shiftKey);
      }
    });

    let dragDepth = 0;
    const dropOverlay = document.getElementById('dropOverlay');
    window.addEventListener('dragenter', (e) => {
      if (dragSrcId) return;
      if (e.dataTransfer?.types?.includes('Files')) {
        dragDepth++;
        dropOverlay.classList.add('active');
      }
    });
    window.addEventListener('dragleave', () => {
      if (dragSrcId) return;
      dragDepth = Math.max(0, dragDepth - 1);
      if (dragDepth === 0) dropOverlay.classList.remove('active');
    });
    window.addEventListener('dragover', (e) => {
      if (!dragSrcId && e.dataTransfer?.types?.includes('Files')) e.preventDefault();
    });
    window.addEventListener('drop', (e) => {
      if (dragSrcId) return;
      dragDepth = 0;
      dropOverlay.classList.remove('active');
      const file = e.dataTransfer?.files?.[0];
      if (file) {
        e.preventDefault();
        importSeedFile(file);
      }
    });

    document.addEventListener('keydown', (e) => {
      if (isLocked) return;
      const inDialog = Boolean(document.querySelector('dialog[open]'));
      const inInput = ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName);

      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        openPalette();
        return;
      }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'f') {
        e.preventDefault();
        if (!inDialog) {
          searchInput.focus();
          searchInput.select();
        }
        return;
      }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'n') {
        e.preventDefault();
        if (!inDialog) openAccountDialog();
        return;
      }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'l' && pinHash) {
        e.preventDefault();
        lockVault();
        return;
      }
      if (e.altKey && e.key.toLowerCase() === 'm') {
        e.preventDefault();
        toggleMiniMode();
        return;
      }
      if (inDialog) return;

      if (e.key === 'Escape') {
        closeCtxMenu();
        if (searchQuery) {
          searchQuery = '';
          searchInput.value = '';
          searchWrap.classList.remove('has-value');
          renderStage();
        }
        return;
      }
      if (inInput) return;

      if (e.key === '/') {
        e.preventDefault();
        searchInput.focus();
        return;
      }
      if (e.key === '?') {
        e.preventDefault();
        document.getElementById('shortcutsDialog').showModal();
        return;
      }
      if (e.key.toLowerCase() === 'p') {
        e.preventDefault();
        togglePrivacy();
        return;
      }
      if (e.key.toLowerCase() === 'n' || e.key.toLowerCase() === 'c') {
        const visible = getVisibleAccounts();
        const targetId = hoveredAccountId || (view === 'focus' ? selectedFocusId : null) || visible[0]?.id;
        if (targetId) {
          e.preventDefault();
          copyAccountCode(targetId, e.key.toLowerCase() === 'n');
        }
        return;
      }
      if (/^[1-9]$/.test(e.key) && !e.ctrlKey && !e.metaKey && !e.altKey) {
        const visible = getVisibleAccounts();
        const target = visible[Number(e.key) - 1];
        if (target) {
          e.preventDefault();
          copyAccountCode(target.id, false);
        }
        return;
      }
    });
    bindCaptureWizardEvents();
  }

  let capStep = 1;
  let capSession = null;
  let capCaptured = null;
  let capShowSeed = false;
  let capUnlisten = null;
  let capLiveTimer = null;

  const CAP_SUBTITLES = [
    '',
    'Adım 1 / 6 — Aynı Wi-Fi ağına bağlanın.',
    'Adım 2 / 6 — QR okutup profili indirin.',
    'Adım 3 / 6 — Profili yükleyip Tam Güven açın.',
    'Adım 4 / 6 — Wi-Fi Proxy girip Test Et\'e dokunun.',
    'Adım 5 / 6 — iPhone AnyOTP+ uygulamasını aktive edin.',
    'Adım 6 / 6 — Kodu doğrulayıp kaydedin.',
  ];

  function setCapStep(n) {
    capStep = Math.max(1, Math.min(6, n));
    const fill = document.getElementById('capProgFill');
    if (fill) fill.style.width = ((capStep / 6) * 100).toFixed(1) + '%';
    const sub = document.getElementById('capStepSubtitle');
    if (sub) sub.textContent = CAP_SUBTITLES[capStep] || '';
    document.querySelectorAll('#capStepper .cap-step').forEach(btn => {
      const s = Number(btn.dataset.step);
      btn.classList.toggle('active', s === capStep);
      btn.classList.toggle('done', s < capStep);
    });
    for (let i = 1; i <= 6; i++) {
      const p = document.getElementById('capPane' + i);
      if (p) p.classList.toggle('active', i === capStep);
    }
  }

  function appendCapLog(text, level = '') {
    const box = document.getElementById('capLog');
    if (!box) return;
    const now = new Date();
    const ts = [now.getHours(), now.getMinutes(), now.getSeconds()]
      .map(v => String(v).padStart(2, '0')).join(':');
    const div = document.createElement('div');
    div.className = 'cap-log-line' + (level ? ' ' + level : '');
    div.textContent = `[${ts}] ${text}`;
    box.appendChild(div);
    box.scrollTop = box.scrollHeight;
  }

  function resetCaptureUi() {
    capSession = null;
    capCaptured = null;
    capShowSeed = false;
    if (capLiveTimer) { clearInterval(capLiveTimer); capLiveTimer = null; }
    document.getElementById('capStartErr').textContent = '';
    document.getElementById('capLog').innerHTML = '';
    document.getElementById('capTlsDiag').textContent = '';

    const pPill = document.getElementById('capPhonePill');
    pPill.className = 'cap-live-pill';
    pPill.querySelector('.pulse-dot').className = 'pulse-dot';
    document.getElementById('capPhoneStatus').textContent = 'iPhone kameranı QR koda tut…';
    document.getElementById('capChk1').classList.remove('done');
    document.getElementById('capChk2').classList.remove('done');

    const tPill = document.getElementById('capTlsPill');
    tPill.className = 'cap-live-pill';
    tPill.querySelector('.pulse-dot').className = 'pulse-dot';
    document.getElementById('capTlsStatus').textContent = 'Kaydet → Safari\'de "Test Et"e dokun…';
    setCapStep(1);
  }

  async function stopCaptureSession(silent = true) {
    if (capLiveTimer) { clearInterval(capLiveTimer); capLiveTimer = null; }
    if (capUnlisten) {
      try { capUnlisten(); } catch {}
      capUnlisten = null;
    }
    if (hasTauri && capSession) {
      try { await invoke('capture_stop'); } catch {}
    }
    capSession = null;
    if (!silent) toast('Yakalayıcı durduruldu ve geçici sertifika temizlendi', 'info');
  }

  async function closeCaptureWizard() {
    await stopCaptureSession(true);
    const dlg = document.getElementById('captureDialog');
    if (dlg.open) closeTopLayer(dlg);
  }

  function renderCapIpChips(adapters, currentIp) {
    const wrap = document.getElementById('capIpChips');
    if (!wrap) return;
    if (!adapters.length) { wrap.innerHTML = ''; return; }
    wrap.innerHTML = adapters.map(a => {
      const lbl = a.name ? `${a.name} · ${a.ip}` : a.ip;
      return `<button type="button" class="cap-ip-chip ${a.ip === currentIp ? 'on' : ''}" data-ip="${esc(a.ip)}" title="${esc(lbl)}">${esc(lbl)}</button>`;
    }).join('');
    wrap.querySelectorAll('.cap-ip-chip').forEach(btn => {
      btn.addEventListener('click', () => {
        const v = btn.dataset.ip;
        document.getElementById('capIpSelect').value = v;
        const sum = document.getElementById('capAdvSummary');
        if (sum) sum.textContent = `(${v} · ${document.getElementById('capModeSelect').value === 'dns' ? 'DNS' : 'Proxy'})`;
        renderCapIpChips(adapters, v);
        SoundFX.click();
      });
    });
  }

  async function openCaptureWizard() {
    if (isMiniMode) {
      await toggleMiniMode();
    }
    resetCaptureUi();
    const dlg = document.getElementById('captureDialog');
    const ipInput = document.getElementById('capIpSelect');
    const ipList = document.getElementById('capIpList');
    ipList.innerHTML = '';

    if (hasTauri) {
      try {
        const adapters = await invoke('capture_list_adapters');
        if (Array.isArray(adapters) && adapters.length) {
          ipInput.value = adapters[0].ip;
          ipList.innerHTML = adapters.map(a => `<option value="${esc(a.ip)}">${esc(a.name)}</option>`).join('');
          renderCapIpChips(adapters, adapters[0].ip);
          const sum = document.getElementById('capAdvSummary');
          if (sum) sum.textContent = `(${adapters[0].name} · ${adapters[0].ip})`;
        } else {
          renderCapIpChips([], '');
        }
      } catch {
        try {
          const ips = await invoke('capture_list_ips');
          const mapped = (ips || []).map(ip => ({ ip, name: 'Yerel Ağ' }));
          if (mapped.length) {
            ipInput.value = mapped[0].ip;
            renderCapIpChips(mapped, mapped[0].ip);
          }
        } catch {}
      }
    } else {
      const demo = [{ ip: '192.168.1.10', name: 'Wi-Fi' }];
      ipInput.value = demo[0].ip;
      renderCapIpChips(demo, demo[0].ip);
    }
    dlg.showModal();
  }

  async function openGuideDialog(tab = 'how') {
    if (isMiniMode) {
      await toggleMiniMode();
    }
    const isTrust = tab === 'trust';
    document.getElementById('gTabHow').classList.toggle('on', !isTrust);
    document.getElementById('gTabTrust').classList.toggle('on', isTrust);
    document.getElementById('guidePaneHow').style.display = isTrust ? 'none' : '';
    document.getElementById('guidePaneTrust').style.display = isTrust ? '' : 'none';
    document.getElementById('guideDialog').showModal();
  }

  async function startCaptureFromWizard() {
    const errEl = document.getElementById('capStartErr');
    errEl.textContent = '';
    const ipVal = document.getElementById('capIpSelect').value.trim();
    const mode = document.getElementById('capModeSelect').value;

    if (!hasTauri) {
      errEl.textContent = 'Canlı iPhone yakalama yalnızca masaüstü (.exe) sürümünde çalışır.';
      return;
    }

    const btn = document.getElementById('capStartBtn');
    btn.disabled = true;
    btn.textContent = 'Başlatılıyor…';

    try {

      if (capUnlisten) { try { capUnlisten(); } catch {} capUnlisten = null; }
      const evApi = window.__TAURI__ && window.__TAURI__.event;
      if (evApi && evApi.listen) {
        capUnlisten = await evApi.listen('capture-event', (event) => {
          handleCaptureEvent(event.payload);
        });
      }

      const info = await invoke('capture_start', {
        preferredIp: ipVal || null,
        mode,
      });
      capSession = info;

      document.getElementById('capQrFrame').innerHTML = MiniQR.toSVG(info.qrUrl);
      document.getElementById('capQrUrlBtn').textContent = info.qrUrl;

      const isDns = info.mode === 'dns';
      document.getElementById('capProxyInstr').style.display = isDns ? 'none' : '';
      document.getElementById('capDnsInstr').style.display = isDns ? '' : 'none';
      document.getElementById('capHostVal').textContent = info.lanIp;
      document.getElementById('capPortVal').textContent = String(info.proxyPort);
      const mh = document.getElementById('capMockHost'); if (mh) mh.textContent = info.lanIp;
      const mp = document.getElementById('capMockPort'); if (mp) mp.textContent = String(info.proxyPort);
      document.getElementById('capPacUrlBtn').textContent = info.pacUrl;
      document.getElementById('capDnsVal').textContent = info.lanIp;
      document.getElementById('capListenAddr').textContent = `${info.lanIp}:${info.proxyPort}`;
      document.getElementById('capCleanupText').innerHTML = isDns
        ? 'iPhone\'da Wi-Fi DNS → <b>Otomatik</b> yap.'
        : 'iPhone\'da Wi-Fi Proxy → <b>Kapalı</b> yap.';

      appendCapLog(`Yakalayıcı aktif: ${info.lanIp}:${info.proxyPort} (${isDns ? 'DNS' : 'Proxy'})`, 'ok');
      SoundFX.sync();
      setCapStep(2);
    } catch (err) {
      SoundFX.error();
      errEl.textContent = String(err || 'Yakalayıcı başlatılamadı.');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Başla →';
    }
  }

  function handleCaptureEvent(ev) {
    if (!ev || !ev.kind) return;
    switch (ev.kind) {
      case 'phone_connected': {
        const pill = document.getElementById('capPhonePill');
        pill.className = 'cap-live-pill ok';
        pill.querySelector('.pulse-dot').className = 'pulse-dot ok';
        document.getElementById('capPhoneStatus').textContent = '✓ iPhone bağlandı! "Profili İndir"e dokun.';
        document.getElementById('capChk1').classList.add('done');
        appendCapLog(ev.message, 'ok');
        SoundFX.click();
        break;
      }
      case 'cert_downloaded': {
        const pill = document.getElementById('capPhonePill');
        pill.className = 'cap-live-pill ok';
        pill.querySelector('.pulse-dot').className = 'pulse-dot ok';
        document.getElementById('capPhoneStatus').textContent = '✓ Profil indirildi! Geçiliyor…';
        document.getElementById('capChk1').classList.add('done');
        document.getElementById('capChk2').classList.add('done');
        appendCapLog(ev.message, 'ok');
        SoundFX.sync();
        if (capStep === 2) {
          setTimeout(() => { if (capStep === 2) setCapStep(3); }, 950);
        }
        break;
      }
      case 'pac_fetched':
      case 'dns_redirect': {
        appendCapLog(ev.message, 'ok');
        break;
      }
      case 'tls_error': {
        const pill = document.getElementById('capTlsPill');
        pill.className = 'cap-live-pill warn';
        pill.querySelector('.pulse-dot').className = 'pulse-dot bad';
        document.getElementById('capTlsStatus').textContent = '⚠ Tam Güven anahtarı henüz kapalı!';
        document.getElementById('capTlsDiag').textContent = 'Adım 3 → Sertifika Güven Ayarları\'ndan yeşil anahtarı aç.';
        appendCapLog(ev.message, 'warn');
        SoundFX.error();
        break;
      }
      case 'tls_ok': {
        const pill = document.getElementById('capTlsPill');
        pill.className = 'cap-live-pill ok';
        pill.querySelector('.pulse-dot').className = 'pulse-dot ok';
        document.getElementById('capTlsStatus').textContent = '✓ Doğrulandı! Aktivasyona geçiliyor…';
        document.getElementById('capTlsDiag').textContent = '';
        appendCapLog(ev.message, 'ok');
        if (capStep === 4) {
          SoundFX.sync();
          setTimeout(() => { if (capStep === 4) setCapStep(5); }, 900);
        }
        break;
      }
      case 'request': {
        appendCapLog(ev.message);
        const st = document.getElementById('capListenStatusText');
        if (st) st.textContent = `İstek alındı: ${ev.message} — işleniyor…`;
        break;
      }
      case 'activation_error': {
        appendCapLog(ev.message, 'err');
        const lp = document.getElementById('capListenStatusPill');
        const lt = document.getElementById('capListenStatusText');
        if (lp) {
          lp.className = 'cap-live-pill warn';
          lp.querySelector('.pulse-dot').className = 'pulse-dot bad';
        }
        if (lt) lt.textContent = `${ev.message} — Aktivasyon kodunu kontrol edip AnyOTP+'ta tekrar deneyin (dinleme açık).`;
        SoundFX.error();
        toast(ev.message + ' — kodu kontrol edip tekrar deneyin', 'err');
        break;
      }
      case 'warning': {
        appendCapLog(ev.message, 'warn');
        break;
      }
      case 'seed_captured': {
        if (!ev.result) return;
        capCaptured = ev.result;
        appendCapLog(ev.message, 'ok');
        SoundFX.sync();
        showCapturedResult(ev.result);

        stopCaptureSession(true);
        break;
      }
    }
  }

  function renderCapturedSeedMask() {
    if (!capCaptured) return;
    const el = document.getElementById('capResSeed');
    const btn = document.getElementById('capToggleSeedBtn');
    if (capShowSeed) {
      el.textContent = capCaptured.seed;
      btn.textContent = 'Gizle';
    } else {
      el.textContent = capCaptured.seed.slice(0, 6) + ' •••••••• ' + capCaptured.seed.slice(-4);
      btn.textContent = 'Göster';
    }
  }

  async function updateCapturedLiveCode() {
    if (!capCaptured) return;
    const r = await totpBoth(capCaptured.seed, 'plus', 60, 6, nowSec());
    document.getElementById('capResCode').textContent = formatCodeSpaced(r.code);
    document.getElementById('capResRem').textContent = `${r.rem}sn kalan`;
    const arc = document.getElementById('capRingArc');
    if (arc) {
      const circ = 87.96;
      const frac = Math.max(0, Math.min(1, r.rem / 60));
      arc.style.strokeDashoffset = String((circ * (1 - frac)).toFixed(2));
      arc.style.stroke = r.rem <= 8 ? 'var(--warn)' : 'var(--ok)';
    }
  }

  function showCapturedResult(res) {
    capShowSeed = false;
    document.getElementById('capResUid').textContent = res.uid || '—';
    document.getElementById('capResSerial').textContent = res.serial || '—';
    document.getElementById('capSaveLabel').value = res.uid || 'AnyOTP+ Hesap';
    document.getElementById('capSaveTag').value = 'Ana';
    renderCapturedSeedMask();
    setCapStep(6);
    updateCapturedLiveCode();
    if (capLiveTimer) clearInterval(capLiveTimer);
    capLiveTimer = setInterval(updateCapturedLiveCode, 500);
    toast('SEED başarıyla yakalandı! Telefondaki kodla doğrulayıp kaydedin.');
  }

  async function saveCapturedToVault() {
    if (!capCaptured) return;
    const label = document.getElementById('capSaveLabel').value.trim() || capCaptured.uid || 'AnyOTP+ Hesap';
    const tag = document.getElementById('capSaveTag').value.trim();

    const existing = accounts.find(a =>
      (capCaptured.uid && a.realId && a.realId.toLowerCase() === capCaptured.uid.toLowerCase()) ||
      (a.seed && a.seed.toUpperCase() === capCaptured.seed.toUpperCase())
    );
    const acc = {
      id: existing ? existing.id : '',
      label,
      realId: capCaptured.uid || '',
      note: capCaptured.serial ? `Seri: ${capCaptured.serial}` : '',
      seed: capCaptured.seed,
      kind: 'plus',
      period: 60,
      digits: 6,
      pinned: existing ? !!existing.pinned : false,
      tag,
      color: existing ? (existing.color || 'ember') : 'ember',
    };
    try {
      let saved = acc;
      if (hasTauri) {
        saved = await invoke('vault_save', { account: acc });
      } else {
        saved = { ...acc, id: existing ? existing.id : uid() };
      }
      if (existing) {
        const idx = accounts.findIndex(a => a.id === existing.id);
        if (idx >= 0) accounts[idx] = saved;
        codeCache.delete(saved.id);
      } else {
        accounts.push(saved);
      }
      if (!hasTauri) persistLocal();
      renderTags();
      runViewTransition(renderStage);
      SoundFX.sync();
      toast(existing ? `"${saved.label}" güncellendi!` : `"${saved.label}" DPAPI şifreli kasaya kaydedildi!`);
      await closeCaptureWizard();
    } catch (e) {
      SoundFX.error();
      toast('Kasaya kaydedilemedi: ' + e, 'err');
    }
  }

  function copyQuick(text, label) {
    if (!text) return;
    navigator.clipboard?.writeText(text).then(() => {
      SoundFX.click();
      toast(`${label} kopyalandı`, 'info');
    }).catch(() => {});
  }

  function bindCaptureWizardEvents() {
    document.getElementById('capCloseBtn').addEventListener('click', closeCaptureWizard);
    document.getElementById('capCancel1').addEventListener('click', closeCaptureWizard);
    document.getElementById('capDoneNoSave').addEventListener('click', closeCaptureWizard);
    document.getElementById('captureDialog').addEventListener('cancel', (e) => {
      e.preventDefault();
      closeCaptureWizard();
    });
    document.getElementById('captureDialog').addEventListener('close', () => {
      stopCaptureSession(true);
    });

    document.getElementById('capStartBtn').addEventListener('click', startCaptureFromWizard);
    document.getElementById('capStopBtn').addEventListener('click', async () => {
      await stopCaptureSession(false);
      setCapStep(1);
    });

    document.querySelectorAll('[data-cap-go]').forEach(btn => {
      btn.addEventListener('click', () => {
        SoundFX.click();
        setCapStep(Number(btn.dataset.capGo));
      });
    });

    document.querySelectorAll('#capStepper .cap-step').forEach(btn => {
      btn.addEventListener('click', () => {
        const target = Number(btn.dataset.step);
        if (target === 1 || (capSession && target <= 5) || (capCaptured && target === 6)) {
          SoundFX.click();
          setCapStep(target);
        }
      });
    });

    document.getElementById('capQrUrlBtn').addEventListener('click', () => {
      if (capSession) copyQuick(capSession.qrUrl, 'Kurulum URL');
    });
    document.getElementById('capCopyHost').addEventListener('click', () => {
      if (capSession) copyQuick(capSession.lanIp, 'Sunucu IP');
    });
    document.getElementById('capCopyPort').addEventListener('click', () => {
      if (capSession) copyQuick(String(capSession.proxyPort), 'Port');
    });
    document.getElementById('capPacUrlBtn').addEventListener('click', () => {
      if (capSession) copyQuick(capSession.pacUrl, 'PAC URL');
    });
    document.getElementById('capCopyDns').addEventListener('click', () => {
      if (capSession) copyQuick(capSession.lanIp, 'DNS IP');
    });

    document.getElementById('capToggleSeedBtn').addEventListener('click', () => {
      capShowSeed = !capShowSeed;
      renderCapturedSeedMask();
    });
    document.getElementById('capCopySeedBtn').addEventListener('click', () => {
      if (capCaptured) copyQuick(capCaptured.seed, 'SEED');
    });
    document.getElementById('capExportSeedBtn').addEventListener('click', () => {
      if (!capCaptured) return;
      const label = document.getElementById('capSaveLabel').value.trim() || capCaptured.uid || 'AnyOTP+';
      exportSeed([{
        label,
        realId: capCaptured.uid || '',
        note: capCaptured.serial ? `Seri: ${capCaptured.serial}` : '',
        seed: capCaptured.seed,
        kind: 'plus',
        period: 60,
        digits: 6,
        pinned: false,
        tag: document.getElementById('capSaveTag').value.trim(),
        color: 'ember',
      }], label);
    });
    document.getElementById('capSaveVaultBtn').addEventListener('click', saveCapturedToVault);

    document.getElementById('gTabHow').addEventListener('click', () => {
      SoundFX.click();
      document.getElementById('gTabHow').classList.add('on');
      document.getElementById('gTabTrust').classList.remove('on');
      document.getElementById('guidePaneHow').style.display = '';
      document.getElementById('guidePaneTrust').style.display = 'none';
    });
    document.getElementById('gTabTrust').addEventListener('click', () => {
      SoundFX.click();
      document.getElementById('gTabTrust').classList.add('on');
      document.getElementById('gTabHow').classList.remove('on');
      document.getElementById('guidePaneTrust').style.display = '';
      document.getElementById('guidePaneHow').style.display = 'none';
    });
    document.getElementById('guideLaunchCaptureBtn').addEventListener('click', () => {
      closeTopLayer(document.getElementById('guideDialog'));
      setTimeout(() => openCaptureWizard(), 220);
    });

    document.querySelectorAll('[data-ext-url]').forEach((el) => {
      el.addEventListener('click', (e) => {
        e.preventDefault();
        const url = el.getAttribute('data-ext-url');
        if (!url) return;
        SoundFX.click();
        if (hasTauri) {
          invoke('open_external_url', { url }).catch(() => {});
        } else {
          window.open(url, '_blank', 'noopener,noreferrer');
        }
      });
    });
  }

  async function boot() {
    initDialogs();
    bindEvents();
    applyPreferencesUI();
    updateOffsetDisplays();

    document.getElementById('viewGrid').classList.toggle('on', view === 'grid');
    document.getElementById('viewList').classList.toggle('on', view === 'list');
    document.getElementById('viewFocus').classList.toggle('on', view === 'focus');

    if (pinHash) lockVault();

    if (hasTauri) {
      try {
        const list = await invoke('vault_list');
        accounts = Array.isArray(list) ? list : [];
      } catch {
        accounts = [];
      }
    }

    renderTags();
    renderStage();
    requestAnimationFrame(frameLoop);
    runCheckSilent();

    if (hasTauri) {
      invoke('sync_time').then((r) => {
        if (r && typeof r.offset === 'number' && Number.isFinite(r.offset)) {
          timeOffset = r.offset;
          lsSet('pw_off', String(timeOffset));
          updateOffsetDisplays();
          lastGlobalStep = -1;
        }
      }).catch(() => {});
    }
  }

  boot();
})();
