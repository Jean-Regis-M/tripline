import { PRESETS, SECRET, runArena } from './engine/arena.js';
import { segments } from './engine/explain.js';

const $ = (s) => document.querySelector(s);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };

const OUTCOME = {
  stopped: { cls: 'block', word: 'STOPPED' },
  held: { cls: 'review', word: 'HELD FOR APPROVAL' },
  leaked: { cls: 'leak', word: 'YOU GOT IT OUT' },
  approved: { cls: 'pass', word: 'APPROVED DESTINATION' },
  nothing: { cls: 'pass', word: 'NOTHING TO STEAL' },
};
const CHIPS = PRESETS.filter((p) => p.id !== 'harmless');
const STORE = 'tripline-arena-v1';
let current = null;                  // id of the preset whose text is in the box, or null for the visitor's own text
let board = {};                      // preset id -> outcome of the last time it was sent
let own = { sent: 0, through: 0 };   // the visitor's own messages
try { const s = JSON.parse(localStorage.getItem(STORE) || 'null'); if (s) { board = s.board ?? {}; own = s.own ?? own; } } catch { /* storage unavailable */ }
const save = () => { try { localStorage.setItem(STORE, JSON.stringify({ board, own })); } catch { /* ignore */ } };

const options = () => ({ body: $('#payload').value, to: $('#dest').value.trim(), labelSecretAsPrivate: $('#tProv').checked, contentDetector: $('#tDet').checked, untrustedInSession: $('#tUnt').checked });

function renderXray(body, spans) {
  const box = el('div', 'xray');
  if (!body) { box.textContent = '(empty message)'; return box; }
  for (const seg of segments(body, spans)) {
    if (!seg.spans.length) { box.append(document.createTextNode(seg.text)); continue; }
    const top = seg.spans.find((s) => s.kind === 'private') ?? seg.spans.find((s) => s.kind === 'secret') ?? seg.spans[0];
    const m = el('mark', 'x ' + top.kind, seg.text);
    m.title = [...new Set(seg.spans.map((s) => s.label))].join(' + ');
    box.append(m);
  }
  return box;
}

function render(r, o) {
  const out = $('#arenaOut'); out.replaceChildren();
  const v = OUTCOME[r.outcome];
  out.append(el('div', 'verdict ' + v.cls, v.word));

  const dec = el('p', 'decoder');
  if (r.technique) { dec.append('The attacker\'s decoder can recover the secret from this message: ', el('b', '', r.technique), '.'); }
  else dec.append('The attacker\'s decoder cannot recover the secret from this message.');
  out.append(dec);

  out.append(el('span', 'lab', 'X-ray: where Tripline sees secrets hiding'));
  out.append(renderXray(o.body, r.spans));
  const labels = [...new Map(r.spans.map((s) => [s.kind, s])).values()];
  if (labels.length) {
    const lg = el('div', 'legend');
    for (const s of labels) lg.append(el('span', s.kind, s.kind === 'private' ? 'private data (any disguise)' : s.kind === 'secret' ? 'secret recognised by content' : 'suspicious shape'));
    out.append(lg);
  } else if (o.body) out.append(el('p', 'note', 'Nothing lit up. Either there is nothing to find, or this disguise is beyond the enabled defences.'));

  for (const rule of r.rules) { const d = el('div', 'find'); d.append(el('b', '', `${rule.id} ${rule.title}. `), rule.detail); out.append(d); }
  if (r.knownLimitation) out.append(el('div', 'limit', 'Documented limitation. ' + r.knownLimitation));
  if (r.outcome === 'leaked' && !r.knownLimitation) {
    const body = `Technique: ${r.technique}\nDefences: provenance ${o.labelSecretAsPrivate}, content ${o.contentDetector}, untrusted in session ${o.untrustedInSession}\nMessage (synthetic secret only):\n\n${o.body}\n`;
    const a = el('a', 'btn small', 'Found a way through? Open an issue');
    a.href = `https://github.com/Jean-Regis-M/tripline/issues/new?title=${encodeURIComponent('Bypass found: ' + r.technique)}&body=${encodeURIComponent(body)}`;
    a.target = '_blank'; a.rel = 'noopener';
    out.append(a);
  }
}

function renderScore() {
  const box = $('#score'); box.replaceChildren();
  const tried = CHIPS.filter((p) => board[p.id]);
  const stopped = tried.filter((p) => board[p.id] === 'stopped' || board[p.id] === 'held').length;
  const through = tried.filter((p) => board[p.id] === 'leaked').length;
  box.append(el('h3', '', tried.length ? `${stopped} of ${tried.length} disguises stopped or held` + (through ? `, ${through} got through` : '') : 'Scoreboard'));
  box.append(el('p', '', tried.length ? 'Press a disguise, then "Send it". Switch defences off to see which layer stops what.' : 'Pick a disguise, press "Send it", and your results collect here.'));
  const chips = el('div', 'chips');
  for (const p of CHIPS) chips.append(el('span', 'chip ' + (board[p.id] ?? ''), p.title + (board[p.id] ? ` (${board[p.id]})` : '')));
  box.append(chips);
  if (own.sent) box.append(el('p', '', `Your own messages: ${own.sent} sent, ${own.through} got the secret out.`));
}

function preview() { const o = options(); render(runArena(o), o); }

function send() {
  const o = options(); const r = runArena(o);
  render(r, o);
  if (current) board[current] = r.outcome; else { own.sent++; if (r.outcome === 'leaked') own.through++; }
  save(); renderScore();
  const stamp = $('#arenaOut .verdict'); if (stamp) { stamp.classList.add('flash'); }
}

const bar = $('#presets');
for (const p of PRESETS) {
  const b = el('button', 'btn', p.title); b.type = 'button'; b.dataset.id = p.id;
  b.onclick = () => {
    current = p.id; $('#payload').value = p.body;
    bar.querySelectorAll('.btn').forEach((x) => x.classList.toggle('on', x === b));
    preview();
  };
  bar.append(b);
}
$('#vaultSecret').textContent = 'deploy_key = ' + SECRET;
$('#payload').addEventListener('input', () => { current = null; bar.querySelectorAll('.btn').forEach((x) => x.classList.remove('on')); preview(); });
for (const id of ['#dest', '#tProv', '#tDet', '#tUnt']) $(id).addEventListener('input', preview);
$('#sendBtn').onclick = send;
bar.querySelector('[data-id="plain"]').click();
renderScore();
