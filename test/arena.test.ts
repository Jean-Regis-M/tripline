import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PRESETS, SECRET, SECRET_FILE, recoverTechnique, runArena, type ArenaOptions } from '../src/arena.ts';
import { explainContent, explainProvenance, segments } from '../src/explain.ts';
import { fragments } from '../src/guard.ts';
import { b64, base32decode, base32 } from '../src/util.ts';

const base: Omit<ArenaOptions, 'body'> = { to: 'attacker@evil.test', labelSecretAsPrivate: true, contentDetector: true, untrustedInSession: false };
const preset = (id: string) => PRESETS.find((p) => p.id === id)!;

test('the attacker decoder recovers the secret from every disguise, and from nothing else', () => {
  for (const p of PRESETS) assert.equal(recoverTechnique(p.body), p.technique, `${p.id}`);
  assert.equal(recoverTechnique('a perfectly ordinary message about lunch'), null);
});

test('arena, all defences on: every disguise is stopped; only code words get through, and only in a clean session', () => {
  for (const p of PRESETS) {
    const r = runArena({ ...base, body: p.body });
    if (p.id === 'codewords') { assert.equal(r.outcome, 'leaked', 'documented limitation'); assert.ok(r.knownLimitation); }
    else if (p.technique) assert.equal(r.outcome, 'stopped', p.id);
  }
  assert.equal(runArena({ ...base, body: preset('harmless').body }).outcome, 'nothing');
  assert.equal(runArena({ ...base, body: preset('many').body }).outcome, 'stopped');
});

test('arena: untrusted content in the session turns the code word leak into a hold (R2)', () => {
  const r = runArena({ ...base, untrustedInSession: true, body: preset('codewords').body });
  assert.equal(r.outcome, 'held');
  assert.deepEqual(r.rules.map((x) => x.id), ['R2']);
});

test('arena, provenance switched off: content detection alone catches plain, base64 and hex, but not the other disguises', () => {
  const alone = { ...base, labelSecretAsPrivate: false };
  for (const id of ['plain', 'base64', 'hex']) assert.equal(runArena({ ...alone, body: preset(id).body }).outcome, 'stopped', id);
  for (const id of ['spaced', 'reversed', 'rot13', 'atbash', 'base32']) assert.equal(runArena({ ...alone, body: preset(id).body }).outcome, 'leaked', `${id} shows why provenance is a separate layer`);
});

test('arena: an allow-listed destination is approved, not a leak', () => {
  assert.equal(runArena({ ...base, to: 'me@student.test', body: preset('plain').body }).outcome, 'approved');
});

test('X-ray: positions are exact for plain text and for the encoded token that hides a secret', () => {
  const frags = fragments(SECRET_FILE);
  const plain = `prefix ${SECRET} suffix`;
  const [s1] = explainProvenance(plain, frags).filter((s) => s.label === 'private data');
  assert.equal(plain.slice(s1.start, s1.end), SECRET);

  const encoded = b64(SECRET);
  const text = `data: ${encoded} (end)`;
  const hit = explainProvenance(text, frags).find((s) => /base64/.test(s.label))!;
  assert.equal(text.slice(hit.start, hit.end), encoded, 'the span covers exactly the base64 token');
  const content = explainContent(text);
  assert.ok(content.some((s) => /stripe-key, base64 encoded/.test(s.label) && text.slice(s.start, s.end) === encoded));
});

test('X-ray finds a spaced out and a ROT13 disguise and maps the span back onto the original text', () => {
  const frags = fragments(SECRET_FILE);
  const spaced = `see: ${[...SECRET].join(' ')} thanks`;
  const s = explainProvenance(spaced, frags).find((x) => /spacing/.test(x.label))!;
  assert.ok(spaced.slice(s.start, s.end).replace(/[^a-z0-9]/gi, '').toLowerCase().includes('sklive'), 'covers the spaced text');
  const rot = preset('rot13').body;
  assert.ok(explainProvenance(`x ${rot} y`, frags).some((x) => /ROT13/.test(x.label)));
});

test('segments cut the text at span boundaries so every character is accounted for', () => {
  const text = `aa ${SECRET} bb`;
  const segs = segments(text, explainProvenance(text, fragments(SECRET_FILE)));
  assert.equal(segs.map((x) => x.text).join(''), text);
  assert.ok(segs.some((x) => x.spans.length && x.text === SECRET));
});

test('base32 round trip', () => { assert.equal(base32decode(base32(SECRET)), SECRET); });
