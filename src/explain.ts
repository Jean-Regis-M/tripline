// X-ray: show WHERE in an outbound message private or secret shaped data is hiding, by position.
// It uses the same re-encodings the guard checks, plus the content detector, so what lights up is what Tripline sees.
import { detectSecrets } from './detect.ts';
import { atbash, b64, base32, caesar, hex, reverse, rot47 } from './util.ts';

export interface Span { start: number; end: number; kind: 'private' | 'secret' | 'suspicious'; label: string }

const sq = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, '');
function squashMap(s: string): { out: string; map: number[] } {
  let out = ''; const map: number[] = [];
  for (let i = 0; i < s.length; i++) { const c = s[i].toLowerCase(); if (/[a-z0-9]/.test(c)) { out += c; map.push(i); } }
  return { out, map };
}

/** Every exact re-encoding of a fragment, with a human label. */
export function labelledVariants(f: string): [string, string][] {
  const list: [string, string][] = [
    ['as is', f], ['base64', b64(f)], ['base64, unpadded', b64(f).replace(/=+$/, '')],
    ['base64url', b64(f).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')], ['double base64', b64(b64(f))],
    ['hex', hex(f)], ['hex, upper case', hex(f).toUpperCase()], ['base32', base32(f)], ['URL encoded', encodeURIComponent(f)],
    ['reversed', reverse(f)], ['ROT47', rot47(f)], ['Atbash', atbash(f)], ['ROT13', caesar(f, 13)],
  ];
  for (let n = 1; n <= 25; n++) if (n !== 13) list.push([`Caesar +${n}`, caesar(f, n)]);
  const seen = new Set<string>();
  return list.filter(([, v]) => v.length >= 6 && !seen.has(v) && !!seen.add(v));
}

function findAll(text: string, needle: string): number[] {
  const hits: number[] = [];
  for (let i = text.indexOf(needle); i >= 0; i = text.indexOf(needle, i + 1)) hits.push(i);
  return hits;
}

/** Spans of `text` that contain data derived from any private fragment, however it was disguised. */
export function explainProvenance(text: string, fragments: string[]): Span[] {
  const spans: Span[] = [];
  const { out: squashed, map } = squashMap(text);
  for (const f of fragments.filter((x) => x.length >= 6).slice(0, 200)) {
    for (const [label, v] of labelledVariants(f)) for (const i of findAll(text, v)) spans.push({ start: i, end: i + v.length, kind: 'private', label: label === 'as is' ? 'private data' : `private data, ${label}` });
    // case, spacing and punctuation changes, and ciphers combined with them
    for (const [label, v] of [['changed case or spacing', f] as const, ...labelledVariants(f).filter(([l]) => /ROT13|Caesar|Atbash|reversed/.test(l)).map(([l, x]) => [`${l}, changed case or spacing`, x] as const)]) {
      const target = sq(v);
      if (target.length < 8) continue;
      for (const i of findAll(squashed, target)) spans.push({ start: map[i], end: map[i + target.length - 1] + 1, kind: 'private', label: `private data, ${label}` });
    }
  }
  return dedupe(spans);
}

/** Spans recognised by content alone (keys, tokens, cards...), including the encoded token that hides one. */
export function explainContent(text: string): Span[] {
  return dedupe(detectSecrets(text).filter((f) => f.start !== undefined && f.end !== undefined && f.end > f.start)
    .map((f) => ({ start: f.start!, end: f.end!, kind: f.definite ? 'secret' as const : 'suspicious' as const, label: f.kind + (f.encoded ? `, ${f.encoded} encoded` : '') })));
}

function dedupe(spans: Span[]): Span[] {
  const sorted = [...spans].sort((a, b) => a.start - b.start || b.end - a.end);
  const kept: Span[] = [];
  for (const s of sorted) if (!kept.some((k) => k.kind === s.kind && k.start <= s.start && k.end >= s.end)) kept.push(s);
  return kept;
}

export interface Segment { text: string; spans: Span[] }
/** Cut the text at every span boundary so each piece knows which spans cover it. */
export function segments(text: string, spans: Span[]): Segment[] {
  const cuts = new Set<number>([0, text.length]);
  for (const s of spans) { cuts.add(Math.max(0, s.start)); cuts.add(Math.min(text.length, s.end)); }
  const points = [...cuts].sort((a, b) => a - b);
  const out: Segment[] = [];
  for (let i = 0; i < points.length - 1; i++) {
    const [a, b] = [points[i], points[i + 1]];
    if (b > a) out.push({ text: text.slice(a, b), spans: spans.filter((s) => s.start <= a && s.end >= b) });
  }
  return out;
}
