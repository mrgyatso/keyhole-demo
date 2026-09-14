'use strict';

// The Keyhole companion: the signed-in technician's cards, polled every two
// seconds while the page is visible. Everything shown is set as text, never as
// HTML: paths, purposes and diffs come from machines Keyhole does not trust.
(function () {
  const K = window.Keyhole;
  const POLL_MS = 2000;
  const $ = (id) => document.getElementById(id);

  let state = null; // the last /api/state
  let skew = 0; // the server's clock minus this one, in ms
  let timer = 0;
  let polling = false;
  let signedIn = null;
  const busy = new Set(); // cards with a request in flight
  const notes = new Map(); // card ID → { kind, text }
  const receipts = new Map(); // unlock ID → receipt text, or null while loading
  const views = new Map(); // container → Map(card ID → { node, sig })
  let deepLink = parseDeepLink(location.pathname);

  function parseDeepLink(path) {
    const m = /^\/([uc])\/([A-Za-z0-9_]+)$/.exec(path);
    return m ? { kind: m[1] === 'u' ? 'unlock' : 'change', id: m[2] } : null;
  }

  function now() { return Date.now() + skew; }

  // el builds an element. Children are nodes or strings, and strings become
  // text nodes; nothing is ever parsed as HTML.
  function el(tag, attrs, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') e.className = v;
      else if (k === 'data') for (const [dk, dv] of Object.entries(v)) e.dataset[dk] = dv;
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v === true ? '' : v);
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      e.append(c instanceof Node ? c : String(c));
    }
    return e;
  }

  // ----- words and numbers -----

  const REASONS = {
    unanswered: 'nobody answered in time',
    idle: 'idle too long',
    locked: 'you pressed Lock',
    signed_out: 'you signed out',
    another_client: 'you unlocked another client',
    denied: 'denied',
    expired: 'reached its end',
  };
  const OPS = {
    read_file: 'READ', list_dir: 'LIST', stat: 'STAT', search_files: 'SEARCH', grep: 'GREP', hash_file: 'HASH',
    prepare_file_change: 'PREPARE', apply_file_change: 'APPLY', rollback_file_change: 'UNDO',
  };
  const UNLOCK_STATES = { denied: 'Denied', expired: 'Expired', locked: 'Locked' };
  const CHANGE_STATES = {
    applied: 'Applied', refused: 'Refused by the device', failed: 'Failed', denied: 'Denied', expired: 'Expired',
  };

  const plural = (n, one, many) => (n === 1 ? one : many);
  const opLabel = (op) => OPS[op] || String(op || '').toUpperCase();
  const reasonLabel = (r) => REASONS[r] || r || '';

  function fmtDuration(seconds) {
    const h = Math.floor(seconds / 3600);
    const m = Math.round((seconds % 3600) / 60);
    if (h && m) return h + ' h ' + m + ' min';
    if (h) return h + ' h';
    return m + ' min';
  }

  function fmtLeft(ms) {
    const s = Math.ceil(ms / 1000);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    if (h) return h + ' h ' + String(m).padStart(2, '0') + ' min';
    if (m) return m + ' min ' + String(sec).padStart(2, '0') + ' s';
    return sec + ' s';
  }

  function fmtClock(iso) {
    return iso ? new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
  }

  function fmtBytes(n) {
    if (n < 1024) return n + ' ' + plural(n, 'byte', 'bytes');
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KiB';
    return (n / 1024 / 1024).toFixed(1) + ' MiB';
  }

  // countdown is text the ticker keeps current until iso, then shows done.
  function countdown(iso, done) {
    return el('span', { class: 'countdown', data: { until: iso || '', done: done } }, '');
  }

  function tick() {
    for (const e of document.querySelectorAll('[data-until]')) {
      const until = Date.parse(e.dataset.until);
      if (isNaN(until)) continue;
      const left = until - now();
      e.textContent = left > 0 ? fmtLeft(left) : e.dataset.done;
      e.classList.toggle('soon', left > 0 && left < 60000);
    }
  }

  // ----- cards -----

  function noteFor(id) {
    const n = notes.get(id);
    return el('p', { class: 'note' + (n ? ' ' + n.kind : ''), role: 'status' }, n ? n.text : '');
  }

  function card(id, cls, ...children) {
    return el('article', { class: 'card ' + cls, id: 'card-' + id, data: { id } }, ...children);
  }

  function actions(kind, id) {
    return el('div', { class: 'actions' },
      el('button', { type: 'button', class: 'primary', onclick: () => approve(kind, id) }, 'Approve'),
      el('button', { type: 'button', onclick: () => deny(kind, id) }, 'Deny'));
  }

  function pendingUnlock(u) {
    return card(u.id, 'pending',
      el('header', null, el('span', { class: 'kind' }, 'Unlock'), el('h3', null, u.client_name)),
      u.purpose ? el('p', { class: 'purpose' }, u.purpose) : null,
      el('dl', null,
        el('dt', null, 'Lasts'), el('dd', null, fmtDuration(u.duration_seconds) + ' once approved'),
        el('dt', null, 'Idle limit'),
        el('dd', null, u.idle_timeout_seconds ? 'ends after ' + fmtDuration(u.idle_timeout_seconds) + ' without a call' : 'none'),
        el('dt', null, 'Answer within'), el('dd', null, countdown(u.deadline, 'expired'))),
      noteFor(u.id),
      actions('unlocks', u.id));
  }

  function diffBlock(diff) {
    const pre = el('pre', { class: 'diff', tabindex: '0' });
    const lines = diff.split('\n');
    if (lines.length && lines[lines.length - 1] === '') lines.pop();
    for (const line of lines) {
      let cls = 'ctx';
      if (line.startsWith('+++') || line.startsWith('---')) cls = 'file';
      else if (line.startsWith('@@')) cls = 'hunk';
      else if (line.startsWith('+')) cls = 'add';
      else if (line.startsWith('-')) cls = 'del';
      const span = document.createElement('span');
      span.className = cls;
      span.textContent = line + '\n';
      pre.append(span);
    }
    return pre;
  }

  function hashes(p) {
    return el('dl', { class: 'hashes' },
      el('dt', null, 'Before'), el('dd', { class: 'mono' }, 'sha256 ' + (p.before_sha256 || '(new file)') + ' · ' + fmtBytes(p.before_size)),
      el('dt', null, 'After'), el('dd', { class: 'mono' }, 'sha256 ' + p.after_sha256 + ' · ' + fmtBytes(p.after_size)));
  }

  function planBody(p) {
    const parts = [];
    if (p.binary) parts.push(el('p', { class: 'meta' }, 'Binary file: there is no text diff. Compare the hashes.'));
    else if (p.diff) parts.push(diffBlock(p.diff));
    else parts.push(el('p', { class: 'meta' }, 'The content does not change.'));
    if (p.diff_truncated) {
      parts.push(el('p', { class: 'warn' }, 'The diff was cut short to fit. The change replaces the whole file: compare the hashes.'));
    }
    parts.push(hashes(p));
    return parts;
  }

  function pendingChange(c) {
    const p = c.plan;
    const undo = c.op === 'rollback_file_change';
    const open = c.state === 'awaiting_approval';
    return card(c.id, 'pending change',
      el('header', null,
        el('span', { class: 'kind ' + (undo ? 'undo' : 'change') }, undo ? 'Undo' : 'Change'),
        el('h3', null, c.client_name + ' · ' + c.hostname)),
      p ? el('p', { class: 'path' }, p.path) : el('p', { class: 'warn' }, 'The relay no longer holds the plan behind this change.'),
      p && p.reason ? el('p', { class: 'purpose' }, p.reason) : null,
      undo ? el('p', { class: 'meta' }, 'Undo puts the file back as it was before this plan was applied.') : null,
      p ? planBody(p) : null,
      open
        ? el('p', { class: 'meta' }, 'Expires in ', countdown(c.expires_at, 'now'))
        : el('p', { class: 'meta' }, 'Approved. Sending it to ' + c.hostname + '…'),
      noteFor(c.id),
      open ? actions('changes', c.id) : null);
  }

  function activeUnlock(u) {
    const devices = u.devices.length ? u.devices.map((d) => d.hostname).join(', ') : 'none yet';
    return card(u.id, 'active',
      el('header', null, el('span', { class: 'kind live' }, 'Unlocked'), el('h3', null, u.client_name)),
      u.purpose ? el('p', { class: 'purpose' }, u.purpose) : null,
      el('dl', null,
        el('dt', null, 'Time left'), el('dd', null, countdown(u.expires_at, 'ending')),
        el('dt', null, 'Idle ends it in'), el('dd', null, u.idle_at ? countdown(u.idle_at, 'ending') : 'never'),
        el('dt', null, 'Calls'), el('dd', null, String(u.calls)),
        el('dt', null, 'Devices'), el('dd', null, devices)),
      noteFor(u.id),
      el('button', { type: 'button', class: 'lock', onclick: () => lock(u.id) }, 'Lock'));
  }

  function endedUnlock(u) {
    ensureReceipt(u.id);
    const when = fmtClock(u.requested_at) + (u.ended_at ? ' – ' + fmtClock(u.ended_at) : '');
    const devices = u.devices.map((d) => d.hostname).join(', ');
    const meta = [when, reasonLabel(u.reason), u.calls + ' ' + plural(u.calls, 'call', 'calls'), devices].filter(Boolean);
    return card(u.id, 'ended',
      el('header', null, el('span', { class: 'kind' }, UNLOCK_STATES[u.state] || u.state), el('h3', null, u.client_name)),
      u.purpose ? el('p', { class: 'purpose' }, u.purpose) : null,
      el('p', { class: 'meta' }, meta.join(' · ')),
      noteFor(u.id),
      el('div', { class: 'actions' },
        el('button', { type: 'button', onclick: () => copyReceipt(u.id) }, 'Copy receipt')));
  }

  function doneChange(c) {
    const p = c.plan;
    const detail = [c.error_code, reasonLabel(c.reason)].filter(Boolean);
    const until = c.state === 'applied' && c.result && c.result.rollback_until;
    return card(c.id, 'done state-' + c.state,
      el('header', null,
        el('span', { class: 'kind state' }, CHANGE_STATES[c.state] || c.state),
        el('h3', null, (c.op === 'rollback_file_change' ? 'Undo · ' : '') + c.client_name + ' · ' + c.hostname)),
      el('p', { class: 'path' }, p ? p.path : c.plan_id),
      p ? hashes(p) : null,
      detail.length ? el('p', { class: 'meta' }, detail.join(' · ')) : null,
      until ? el('p', { class: 'meta' }, 'Can be undone until ' + new Date(until).toLocaleString()) : null,
      el('p', { class: 'meta' }, fmtClock(c.completed_at || c.decided_at || c.requested_at)),
      noteFor(c.id));
  }

  function activityRow(a) {
    const bad = a.result !== 'ok';
    return el('li', { class: bad ? 'bad' : 'ok' },
      el('span', { class: 'op' }, opLabel(a.op)),
      el('span', { class: 'dev' }, a.hostname || a.device),
      el('time', { datetime: a.time }, fmtClock(a.time)),
      a.path ? el('span', { class: 'path' }, a.path) : null,
      bad ? el('span', { class: 'res' }, a.error_code || a.result) : null);
  }

  // ----- rendering -----

  function item(id, build, data) {
    return { id, build, sig: JSON.stringify(data) + '|' + JSON.stringify(notes.get(id) || null) };
  }

  // fill shows items in a container, in order. A card is rebuilt only when
  // its data changed, and never while a request for it is in flight.
  function fill(name, items) {
    const container = $(name);
    let known = views.get(name);
    if (!known) views.set(name, (known = new Map()));
    const seen = new Set();
    let prev = null;
    for (const it of items) {
      seen.add(it.id);
      let v = known.get(it.id);
      if (!v || (v.sig !== it.sig && !busy.has(it.id))) {
        const node = it.build();
        if (v) v.node.replaceWith(node);
        v = { node, sig: it.sig };
        known.set(it.id, v);
      }
      const want = prev ? prev.nextSibling : container.firstChild;
      if (v.node !== want) container.insertBefore(v.node, want);
      prev = v.node;
    }
    for (const [id, v] of known) {
      if (!seen.has(id)) {
        v.node.remove();
        known.delete(id);
      }
    }
  }

  function render() {
    if (!state) return;
    $('who').textContent = state.technician;
    const open = (c) => c.state === 'awaiting_approval' || c.state === 'approved';
    const active = state.unlocks.filter((u) => u.state === 'active');
    const pending = [
      ...state.unlocks.filter((u) => u.state === 'awaiting_approval').map((u) => [u.requested_at, item(u.id, () => pendingUnlock(u), u)]),
      ...state.changes.filter(open).map((c) => [c.requested_at, item(c.id, () => pendingChange(c), c)]),
    ].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map((x) => x[1]); // oldest first: answer in order
    const done = state.changes.filter((c) => !open(c)).map((c) => item(c.id, () => doneChange(c), c));
    const ended = state.unlocks.filter((u) => UNLOCK_STATES[u.state]).map((u) => item(u.id, () => endedUnlock(u), u));

    fill('active', active.map((u) => item(u.id, () => activeUnlock(u), u)));
    fill('pending', pending);
    fill('done', done);
    fill('history', ended);
    $('active-section').hidden = active.length === 0;
    $('pending-empty').hidden = pending.length > 0;
    $('done-section').hidden = done.length === 0;
    $('history-section').hidden = ended.length === 0;
    $('activity').replaceChildren(...state.activity.map(activityRow));
    $('activity-section').hidden = state.activity.length === 0;
    tick();
    followDeepLink();
  }

  // followDeepLink scrolls to the card a /u/… or /c/… link named, once.
  function followDeepLink() {
    if (!deepLink) return;
    const link = deepLink;
    deepLink = null;
    history.replaceState(null, '', '/');
    const target = document.getElementById('card-' + link.id);
    if (!target) {
      notice((link.kind === 'unlock' ? 'That unlock' : 'That change') +
        ' is not among your cards. It may have been answered already, or be for another technician.');
      return;
    }
    target.scrollIntoView({ behavior: 'smooth', block: 'center' });
    target.classList.add('highlight');
    setTimeout(() => target.classList.remove('highlight'), 4000);
  }

  function notice(text) {
    $('notice').textContent = text;
    $('notice').hidden = !text;
  }

  function banner(text) {
    $('banner').textContent = text;
    $('banner').hidden = !text;
  }

  function setNote(id, kind, text) {
    if (text) notes.set(id, { kind, text });
    else notes.delete(id);
    for (const e of document.querySelectorAll('[data-id="' + CSS.escape(id) + '"] .note')) {
      e.className = 'note' + (text ? ' ' + kind : '');
      e.textContent = text || '';
    }
  }

  function setBusy(id, on) {
    if (on) busy.add(id);
    else busy.delete(id);
    for (const b of document.querySelectorAll('[data-id="' + CSS.escape(id) + '"] button')) b.disabled = on;
  }

  // ----- decisions -----

  function changeOutcome(row) {
    switch (row.state) {
      case 'applied': return { kind: 'ok', text: 'Applied on ' + row.hostname + '.' };
      case 'refused': return { kind: 'error', text: 'The device refused the change' + (row.error_code ? ' (' + row.error_code + ')' : '') + '. Nothing was written.' };
      case 'failed': return { kind: 'error', text: 'The change could not be delivered' + (row.reason ? ' (' + reasonLabel(row.reason) + ')' : '') + '.' };
    }
    return { kind: 'info', text: 'Approved.' };
  }

  async function run(id, pending, work) {
    if (busy.has(id)) return;
    setBusy(id, true);
    setNote(id, 'info', pending);
    try {
      const n = await work();
      setNote(id, n.kind, n.text);
    } catch (err) {
      if (err.status === 401) {
        showSignIn('Your sign-in has ended. Sign in again to continue.');
        return;
      }
      setNote(id, 'error', K.explain(err));
    } finally {
      setBusy(id, false);
      poll();
    }
  }

  // Approving rides the sign-in: the passkey was asked for once, when the
  // technician signed in, and is not asked for again on each card.
  function approve(kind, id) {
    run(id, kind === 'changes' ? 'Approved. Sending it to the device…' : 'Approved. Unlocking…', async () => {
      const row = await K.api('POST', '/api/' + kind + '/' + encodeURIComponent(id) + '/approve', {});
      return kind === 'changes' ? changeOutcome(row) : { kind: 'ok', text: 'Unlocked.' };
    });
  }

  function deny(kind, id) {
    run(id, 'Denying…', async () => {
      await K.api('POST', '/api/' + kind + '/' + encodeURIComponent(id) + '/deny', {});
      return { kind: 'info', text: 'Denied.' };
    });
  }

  function lock(id) {
    run(id, 'Locking…', async () => {
      await K.api('POST', '/api/unlocks/' + encodeURIComponent(id) + '/lock', {});
      return { kind: 'info', text: 'Locked.' };
    });
  }

  // Receipts are fetched ahead, so Copy can write to the clipboard at once:
  // browsers allow that only while the click is fresh.
  function ensureReceipt(id) {
    if (receipts.has(id)) return;
    receipts.set(id, null);
    K.api('GET', '/api/unlocks/' + encodeURIComponent(id) + '/receipt')
      .then((text) => receipts.set(id, text))
      .catch(() => receipts.delete(id));
  }

  function copyReceipt(id) {
    const text = receipts.get(id);
    if (!text) {
      ensureReceipt(id);
      setNote(id, 'info', 'The receipt is still loading. Try again in a moment.');
      return;
    }
    const show = () => {
      // Without clipboard access, show the text selected for copying by hand.
      const box = el('textarea', { class: 'receipt', readonly: true, rows: '12', 'aria-label': 'Receipt' });
      box.value = text;
      const c = document.querySelector('[data-id="' + CSS.escape(id) + '"]');
      if (c && !c.querySelector('textarea')) c.append(box);
      box.focus();
      box.select();
      setNote(id, 'info', 'Copy the receipt below.');
    };
    if (!navigator.clipboard) return show();
    navigator.clipboard.writeText(text).then(() => setNote(id, 'ok', 'Receipt copied.'), show);
  }

  // ----- sign-in and polling -----

  function showSignIn(message) {
    signedIn = false;
    clearTimeout(timer);
    state = null;
    for (const [, known] of views) for (const [, v] of known) v.node.remove();
    views.clear();
    $('app').hidden = true;
    $('signout').hidden = true;
    $('who').textContent = '';
    $('signin').hidden = false;
    $('signin-msg').textContent = message || '';
    banner('');
    if (!K.supported()) {
      $('signin-btn').disabled = true;
      $('signin-msg').textContent = 'This browser cannot use passkeys here. Use an up-to-date Safari, Chrome, Edge or Firefox.';
    }
  }

  function showApp() {
    signedIn = true;
    $('signin').hidden = true;
    $('app').hidden = false;
    $('signout').hidden = false;
  }

  async function signIn() {
    const button = $('signin-btn');
    button.disabled = true;
    $('signin-msg').textContent = '';
    try {
      const begin = await K.api('POST', '/api/login/begin', {});
      const assertion = await K.assert(begin.options);
      assertion.ceremony = begin.ceremony;
      await K.api('POST', '/api/login/finish', assertion);
      signedIn = null;
      await poll();
    } catch (err) {
      $('signin-msg').textContent = K.explain(err);
    } finally {
      button.disabled = false;
    }
  }

  async function signOut() {
    try {
      await K.api('POST', '/api/logout', {});
      showSignIn('You are signed out, everywhere. Your unlocked client, if you had one, is locked.');
    } catch (err) {
      if (err.status === 401) showSignIn();
      else notice(K.explain(err));
    }
  }

  async function poll() {
    clearTimeout(timer);
    if (polling) return;
    polling = true;
    try {
      const s = await K.api('GET', '/api/state');
      skew = Date.parse(s.server_time) - Date.now();
      state = s;
      showApp();
      banner('');
      render();
    } catch (err) {
      if (err.status === 401) {
        showSignIn();
        return;
      }
      banner(K.explain(err) + ' Retrying…');
    } finally {
      polling = false;
      schedule();
    }
  }

  function schedule() {
    clearTimeout(timer);
    if (signedIn !== false && document.visibilityState === 'visible') timer = setTimeout(poll, POLL_MS);
  }

  $('signin-btn').addEventListener('click', signIn);
  $('signout').addEventListener('click', signOut);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && signedIn !== false) poll();
    else clearTimeout(timer);
  });
  setInterval(tick, 1000);
  poll();
})();
