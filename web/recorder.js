import { scenarios } from './engine/scenarios.js';
import { runScenario } from './engine/simulator.js';
import { GENESIS, chainHash, digestArgs, verifyChain } from './engine/audit.js';

const $ = (s) => document.querySelector(s);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };

// A real log: the multi-vector attack, run through the guard, one record per decision, chained exactly as the proxy does it.
function buildLog() {
  const sc = scenarios.find((s) => s.id === 'multi-vector');
  const steps = runScenario(sc, { guarded: true }).steps;
  const base = Date.UTC(2026, 10, 20, 9, 0, 0);
  const rows = [{ event: 'start', detail: 'node server.js' }, { event: 'tools/list', detail: '6 tools; findings: 0; hidden: none' },
    ...steps.map((s) => ({ event: 'tools/call', tool: s.tool, decision: s.decision === 'unguarded' ? 'allow' : s.decision, rules: s.rules.map((r) => r.id), args: s.args }))];
  let prev = GENESIS;
  return rows.map((r, seq) => {
    const { args, ...rest } = r;
    const body = { seq, ts: new Date(base + seq * 1700).toISOString(), ...rest, ...(rest.rules && !rest.rules.length ? { rules: undefined } : {}), ...(args !== undefined ? { argsSha256: digestArgs(args) } : {}), prev };
    const clean = JSON.parse(JSON.stringify(body)); // drop undefined
    const rec = { ...clean, hash: chainHash(prev, clean) };
    prev = rec.hash; return JSON.stringify(rec);
  });
}

const original = buildLog();
const anchor = JSON.parse(original[original.length - 1]).hash;
const lines = () => $('#recText').value.split('\n').filter((l) => l.trim());
const set = (arr) => { $('#recText').value = arr.join('\n'); verify(); };

function verify() {
  const rows = lines();
  const anchored = $('#recAnchor').value.trim();
  const r = verifyChain(rows);
  const ra = verifyChain(rows, anchored || undefined);
  const out = $('#recOut'); out.replaceChildren();
  out.append(el('div', 'verdict ' + (ra.ok ? 'pass' : 'block'), ra.ok ? 'CHAIN INTACT' : 'CHAIN BROKEN'));
  out.append(el('p', 'decoder', ra.ok ? `${ra.entries} entries verify, from the genesis hash to the head.` : (ra.brokenAt !== undefined ? `First broken entry: #${ra.brokenAt}. ${ra.reason}.` : ra.reason + '.')));
  if (r.ok && !ra.ok) out.append(el('p', 'limit', 'Without the stored anchor this log would still look valid: cutting entries off the END cannot be detected from the log alone. That is a documented limit. Store the head hash somewhere else and verify against it.'));
  const list = el('ol', 'entries');
  rows.forEach((l, i) => {
    let rec = null; try { rec = JSON.parse(l); } catch { /* shown as malformed */ }
    const state = r.ok || (r.brokenAt !== undefined && i < r.brokenAt) ? 'ok' : (r.brokenAt === i ? 'bad' : 'after');
    const li = el('li', 'entry ' + state);
    const desc = rec ? `${rec.event}${rec.tool ? ' ' + rec.tool : ''}${rec.decision ? ' ' + rec.decision.toUpperCase() : ''}${rec.rules ? ' ' + rec.rules.join(',') : ''}` : 'malformed entry';
    li.append(el('span', 'mark', state === 'ok' ? 'verified' : state === 'bad' ? 'BROKEN' : 'untrusted'), el('b', '', `#${i} ${desc}`), el('code', '', rec?.hash ? rec.hash.slice(0, 12) + '...' : ''));
    list.append(li);
  });
  out.append(list);
}

const index = (pred) => lines().findIndex(pred);
$('#recTamper').onclick = () => { const a = lines(); const i = a.findIndex((l) => l.includes('"decision":"deny"')); if (i >= 0) { a[i] = a[i].replace('"decision":"deny"', '"decision":"allow"'); set(a); } };
$('#recDelete').onclick = () => { const a = lines(); if (a.length > 3) { a.splice(3, 1); set(a); } };
$('#recSwap').onclick = () => { const a = lines(); if (a.length > 5) { [a[3], a[4]] = [a[4], a[3]]; set(a); } };
$('#recCut').onclick = () => { const a = lines(); if (a.length > 3) { set(a.slice(0, -2)); } };
$('#recReset').onclick = () => set(original);
$('#recText').addEventListener('input', verify);
$('#recAnchor').addEventListener('input', verify);
$('#recAnchor').value = anchor;
void index;
set(original);
