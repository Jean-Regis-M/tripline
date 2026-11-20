// Isomorphic helpers: identical behaviour in Node and in the browser (no Buffer, no node:crypto).
const encoder = new TextEncoder();
const bytesOf = (s: string) => encoder.encode(s);

export function b64(s: string): string {
  let bin = '';
  for (const b of bytesOf(s)) bin += String.fromCharCode(b);
  return btoa(bin);
}
export function b64decode(s: string): string {
  const bin = atob(s);
  return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
}
export const hex = (s: string): string => [...bytesOf(s)].map((b) => b.toString(16).padStart(2, '0')).join('');
export const rot13 = (s: string): string => s.replace(/[a-z]/gi, (c) => { const b = c <= 'Z' ? 65 : 97; return String.fromCharCode(((c.charCodeAt(0) - b + 13) % 26) + b); });
/** Caesar shift of letters only, preserving case. ROT13 is caesar(s, 13). */
export const caesar = (s: string, n: number): string =>
  s.replace(/[a-z]/gi, (c) => { const b = c <= 'Z' ? 65 : 97; return String.fromCharCode(((c.charCodeAt(0) - b + n) % 26) + b); });
export const atbash = (s: string): string =>
  s.replace(/[a-z]/gi, (c) => { const b = c <= 'Z' ? 65 : 97; return String.fromCharCode(b + 25 - (c.charCodeAt(0) - b)); });
export const rot47 = (s: string): string =>
  s.replace(/[!-~]/g, (c) => String.fromCharCode(33 + ((c.charCodeAt(0) - 33 + 47) % 94)));
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function base32(s: string): string {
  let bits = '', out = '';
  for (const b of new TextEncoder().encode(s)) bits += b.toString(2).padStart(8, '0');
  for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)];
  return out;
}
export function base32decode(s: string): string {
  const clean = s.toUpperCase().replace(/=+$/, '');
  let bits = '';
  for (const c of clean) { const i = B32.indexOf(c); if (i < 0) return ''; bits += i.toString(2).padStart(5, '0'); }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return new TextDecoder().decode(Uint8Array.from(bytes));
}
const CODE_WORDS: Record<string, string> = {};
'alfa bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike november oscar papa quebec romeo sierra tango uniform victor whiskey xray yankee zulu'.split(' ').forEach((w, i) => { CODE_WORDS[String.fromCharCode(97 + i)] = w; });
'zero one two three four five six seven eight nine'.split(' ').forEach((w, i) => { CODE_WORDS[String(i)] = w; });
/** Spell a string out in code words (NATO style). Used by the attack simulator as an evasion no transform check can undo. */
export const CODE_WORD_TO_CHAR: Record<string, string> = {};
for (const [ch, w] of Object.entries(CODE_WORDS)) CODE_WORD_TO_CHAR[w] = ch;
export const spellOut = (s: string): string => [...s.toLowerCase()].map((c) => CODE_WORDS[c] ?? c).join(' ');
export const reverse = (s: string): string => [...s].reverse().join('');

// SHA-256 (FIPS 180-4). Constants are derived from the fractional parts of prime roots.
const primes: number[] = [];
for (let n = 2; primes.length < 64; n++) if (primes.every((p) => n % p)) primes.push(n);
const frac = (x: number) => Math.floor((x - Math.floor(x)) * 2 ** 32) >>> 0;
const K = primes.map((p) => frac(Math.cbrt(p)));
const H0 = primes.slice(0, 8).map((p) => frac(Math.sqrt(p)));
const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));

export function sha256(message: string): string {
  const data = bytesOf(message);
  const len = data.length;
  const padded = new Uint8Array(((len + 9 + 63) >> 6) << 6);
  padded.set(data);
  padded[len] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor((len * 8) / 2 ** 32));
  view.setUint32(padded.length - 4, (len * 8) >>> 0);
  const h = H0.slice();
  const w = new Uint32Array(64);
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    [a, b, c, d, e, f, g, hh].forEach((v, i) => { h[i] = (h[i] + v) >>> 0; });
  }
  return h.map((v) => v.toString(16).padStart(8, '0')).join('');
}
