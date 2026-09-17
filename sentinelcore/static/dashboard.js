/* SentinelCore dashboard.
 *
 * SECURITY NOTE, and it is the reason this file exists separately from the
 * HTML: every value rendered here can originate from attacker-controlled
 * input -- tool names, MCP server names, finding types, feedback notes.
 * A stored XSS was found in the previous version of this dashboard, where
 * a tool name was interpolated into innerHTML unescaped and any caller who
 * could reach /scan/tool-call could attack the admin viewing the page.
 *
 * Two rules follow, and they are not optional:
 *   1. NOTHING untrusted reaches innerHTML. Use el() / text() below.
 *   2. The page carries a strict CSP with script-src 'self', which is only
 *      possible because this script is a separate file rather than inline.
 */

const state = { apiKey: '', tab: 'activity', paused: false, timer: null };

/* ---------- safe DOM construction ---------- */

function text(value) {
  return document.createTextNode(value === null || value === undefined ? '' : String(value));
}

function el(tag, attrs, children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined) continue;
    if (k === 'class') node.className = String(v);
    else if (k === 'onclick') node.addEventListener('click', v);
    else node.setAttribute(k, String(v));   // setAttribute, never innerHTML
  }
  for (const child of (children || [])) {
    node.appendChild(typeof child === 'string' || typeof child === 'number' ? text(child) : child);
  }
  return node;
}

function replace(containerId, ...nodes) {
  const c = document.getElementById(containerId);
  c.replaceChildren(...nodes);
}

function fmtTime(iso) {
  try { return new Date(iso).toLocaleTimeString(); } catch (_) { return String(iso || ''); }
}

function headers() {
  return state.apiKey ? { 'X-API-Key': state.apiKey, 'Content-Type': 'application/json' }
                      : { 'Content-Type': 'application/json' };
}

async function api(path, options) {
  const res = await fetch(path, Object.assign({ headers: headers() }, options || {}));
  if (res.status === 401 || res.status === 403) {
    const e = new Error(res.status === 401 ? 'Authentication required' :
      'Your key does not have the role this action needs');
    e.status = res.status;
    throw e;
  }
  if (!res.ok) throw new Error('Request failed (' + res.status + ')');
  return res.json();
}

function notice(message, kind) {
  const bar = document.getElementById('notice');
  bar.replaceChildren(text(message));
  bar.className = 'notice ' + (kind || 'info') + ' show';
  setTimeout(() => { bar.className = 'notice'; }, 6000);
}

function emptyState(message, hint) {
  return el('div', { class: 'empty' }, [el('p', {}, [message]), hint ? el('p', { class: 'hint' }, [hint]) : el('span', {})]);
}

/* ---------- activity ---------- */

async function loadActivity() {
  let data;
  try { data = await api('/api/v1/audit/recent?limit=40'); }
  catch (e) { return replace('panel', emptyState(e.message, 'Enter an API key above if authentication is enabled.')); }

  const events = data.events || [];
  const counts = {};
  for (const ev of events) counts[ev.decision] = (counts[ev.decision] || 0) + 1;

  const stats = el('div', { class: 'stats' },
    ['allow', 'warn', 'sanitize', 'human_approval', 'block'].map(d =>
      el('div', { class: 'stat', 'data-d': d }, [
        el('span', { class: 'n' }, [counts[d] || 0]),
        el('span', { class: 'l' }, [d.replace('_', ' ')]),
      ])));

  if (!events.length) {
    return replace('panel', stats, emptyState('No activity yet.',
      'Send a request to POST /api/v1/scan or the proxy to see decisions here.'));
  }

  const rows = events.map(ev => {
    const findings = (ev.findings || []).slice(0, 3)
      .map(f => el('span', { class: 'chip' }, [f.type]));
    if ((ev.findings || []).length > 3) findings.push(el('span', { class: 'more' }, ['+' + (ev.findings.length - 3)]));
    if (!findings.length) findings.push(el('span', { class: 'none' }, [ev.detail ? ev.detail + ' — no content findings' : 'no findings']));

    return el('div', { class: 'row', 'data-d': ev.decision }, [
      el('span', { class: 'time' }, [fmtTime(ev.timestamp)]),
      el('span', { class: 'decision' }, [ev.decision]),
      el('span', { class: 'risk' }, [ev.risk_score]),
      el('span', { class: 'endpoint' }, [ev.endpoint]),
      el('span', { class: 'findings' }, findings),
      el('button', {
        class: 'link', title: 'Report this decision as wrong',
        onclick: () => reportWrong(ev.scan_id, ev.decision),
      }, ['report']),
    ]);
  });

  replace('panel', stats, el('div', { class: 'list' }, rows));
}

async function reportWrong(scanId, decision) {
  const verdict = ['block', 'sanitize', 'human_approval'].includes(decision)
    ? 'false_positive' : 'false_negative';
  try {
    await api('/api/v1/feedback', {
      method: 'POST',
      body: JSON.stringify({ scan_id: scanId, verdict: verdict, note: 'reported from dashboard' }),
    });
    notice('Recorded as ' + verdict.replace('_', ' ') + '. Text is NOT stored unless an admin attaches it.', 'ok');
  } catch (e) { notice(e.message, 'err'); }
}

/* ---------- approvals ---------- */

async function loadApprovals() {
  let data;
  try { data = await api('/api/v1/approvals/pending'); }
  catch (e) { return replace('panel', emptyState(e.message)); }

  const items = data.approvals || [];
  if (!items.length) return replace('panel', emptyState('No approvals waiting.',
    'Tool calls that reach a HUMAN_APPROVAL decision appear here. Unanswered approvals expire, and expiry is a refusal.'));

  replace('panel', el('div', { class: 'list' }, items.map(a =>
    el('div', { class: 'card' }, [
      el('div', { class: 'card-head' }, [
        el('strong', {}, [a.tool_name]),
        el('span', { class: 'chip risk' }, ['risk ' + a.risk_score]),
      ]),
      el('div', { class: 'meta' }, ['requested ' + fmtTime(a.created_at) + ' · expires ' + fmtTime(a.expires_at)]),
      el('div', { class: 'meta' }, ['arguments digest: ' + a.arguments_digest]),
      el('div', { class: 'actions' }, [
        el('button', { class: 'btn ok', onclick: () => decide(a.id, true) }, ['Approve']),
        el('button', { class: 'btn danger', onclick: () => decide(a.id, false) }, ['Deny']),
      ]),
    ]))));
}

async function decide(id, approved) {
  const who = window.prompt('Your identifier (recorded, but NOT verified — there is no identity system behind this):', '');
  if (who === null) return;
  try {
    await api('/api/v1/approvals/' + encodeURIComponent(id) + '/decide', {
      method: 'POST',
      body: JSON.stringify({ approved: approved, decided_by: who, reason: '' }),
    });
    notice(approved ? 'Approved.' : 'Denied.', approved ? 'ok' : 'warn');
    loadApprovals();
  } catch (e) { notice(e.message, 'err'); }
}

/* ---------- mcp changes ---------- */

async function loadMcp() {
  let data;
  try { data = await api('/api/v1/mcp/changes?unacknowledged_only=true'); }
  catch (e) { return replace('panel', emptyState(e.message)); }

  const items = data.changes || [];
  if (!items.length) return replace('panel', emptyState('No unacknowledged definition changes.',
    'Trust on first use: a server already poisoned when pinned becomes the baseline. This detects change, not badness.'));

  replace('panel', el('div', { class: 'list' }, items.map(ch =>
    el('div', { class: 'card', 'data-sev': ch.severity }, [
      el('div', { class: 'card-head' }, [
        el('span', { class: 'sev' }, [ch.severity]),
        el('strong', {}, [ch.server + ' / ' + ch.tool_name]),
      ]),
      el('div', { class: 'meta' }, [ch.change_type + ' · detected ' + fmtTime(ch.detected_at)]),
      el('p', {}, [ch.summary]),
      el('div', { class: 'actions' }, [
        el('button', { class: 'btn', onclick: () => acknowledge(ch.id) }, ['Acknowledge']),
        el('span', { class: 'hint' }, ['Acknowledging does not re-pin. Use sentinel mcp pin to trust the new definition.']),
      ]),
    ]))));
}

async function acknowledge(id) {
  try {
    await api('/api/v1/mcp/changes/' + encodeURIComponent(id) + '/acknowledge', { method: 'POST' });
    notice('Acknowledged. The baseline is unchanged.', 'ok');
    loadMcp();
  } catch (e) { notice(e.message, 'err'); }
}

/* ---------- health ---------- */

async function loadHealth() {
  const nodes = [];
  try {
    const s = await api('/api/v1/storage/health');
    const st = s.stats || {};
    nodes.push(el('div', { class: 'card' }, [
      el('div', { class: 'card-head' }, [el('strong', {}, ['Storage']),
        el('span', { class: 'chip ' + (s.reachable ? 'ok' : 'err') }, [s.reachable ? 'reachable' : 'unreachable'])]),
      el('div', { class: 'meta' }, [s.backend + ' · ' + (s.location || '') + ' · schema v' + s.schema_version +
        (s.up_to_date ? ' (current)' : ' (NOT current)')]),
      el('div', { class: 'meta' }, ['writes ' + (st.writes || 0) + ' · failures ' + (st.write_failures || 0) +
        ' · rows deleted by retention ' + (st.rows_deleted || 0)]),
      s.note ? el('p', { class: 'warn-note' }, [s.note]) : el('span', {}),
    ]));
  } catch (e) { nodes.push(emptyState('Storage health unavailable: ' + e.message)); }

  try {
    const a = await api('/api/v1/alerts/status');
    const st = a.stats || {};
    nodes.push(el('div', { class: 'card' }, [
      el('div', { class: 'card-head' }, [el('strong', {}, ['Alerting'])]),
      el('div', { class: 'meta' }, ['sinks: ' + ((a.sinks || []).join(', ') || 'none configured')]),
      el('div', { class: 'meta' }, ['dispatched ' + (st.dispatched || 0) + ' · delivered ' + (st.delivered || 0) +
        ' · failed ' + (st.failed || 0) + ' · dropped ' + (st.dropped_queue_full || 0) +
        ' · suppressed by cooldown ' + (st.suppressed_cooldown || 0)]),
    ]));
  } catch (e) { nodes.push(emptyState('Alert status unavailable: ' + e.message)); }

  try {
    const f = await api('/api/v1/feedback/summary');
    nodes.push(el('div', { class: 'card' }, [
      el('div', { class: 'card-head' }, [el('strong', {}, ['Operator feedback'])]),
      el('div', { class: 'meta' }, [Object.entries(f.counts || {}).map(([k, v]) => k + ': ' + v).join(' · ') || 'none yet']),
      el('p', { class: 'hint' }, [f.caveat || '']),
    ]));
  } catch (e) { /* feedback summary is optional context */ }

  replace('panel', el('div', { class: 'list' }, nodes));
}

/* ---------- wiring ---------- */

const TABS = { activity: loadActivity, approvals: loadApprovals, mcp: loadMcp, health: loadHealth };

function selectTab(name) {
  state.tab = name;
  for (const btn of document.querySelectorAll('.tab')) {
    btn.classList.toggle('active', btn.dataset.tab === name);
  }
  refresh();
}

function refresh() {
  const fn = TABS[state.tab];
  if (fn) fn();
}

function init() {
  for (const btn of document.querySelectorAll('.tab')) {
    btn.addEventListener('click', () => selectTab(btn.dataset.tab));
  }
  const keyInput = document.getElementById('apikey');
  // sessionStorage, not localStorage: the key should not outlive the tab.
  state.apiKey = sessionStorage.getItem('sc_key') || '';
  keyInput.value = state.apiKey;
  keyInput.addEventListener('change', () => {
    state.apiKey = keyInput.value.trim();
    sessionStorage.setItem('sc_key', state.apiKey);
    refresh();
  });

  const pause = document.getElementById('pause');
  pause.addEventListener('click', () => {
    state.paused = !state.paused;
    pause.replaceChildren(text(state.paused ? 'Resume' : 'Pause'));
    pause.classList.toggle('paused', state.paused);
  });

  refresh();
  state.timer = setInterval(() => {
    // Never auto-refresh a tab the operator may be acting on: a list
    // reordering under a cursor causes the wrong button to be clicked.
    if (!state.paused && state.tab === 'activity') refresh();
  }, 5000);
}

document.addEventListener('DOMContentLoaded', init);
