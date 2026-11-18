// Content based detection of secret shaped data. It needs no provenance: it recognises WHAT the data is,
// so it works even when the secret came from a source nobody labelled private. Many kinds are checked at once.
import { b64decode } from './util.ts';

export type SecretKind =
  | 'aws-access-key' | 'aws-secret-key' | 'github-token' | 'google-api-key' | 'slack-token' | 'stripe-key'
  | 'jwt' | 'private-key' | 'credit-card' | 'us-ssn' | 'iban' | 'bearer-token' | 'connection-string'
  | 'credential-assignment' | 'high-entropy-token';

export interface SecretFinding { kind: SecretKind; /** A masked sample, never the full value. */ sample: string; definite: boolean; encoded?: string }

const mask = (s: string) => (s.length <= 8 ? '***' : `${s.slice(0, 4)}...(${s.length} chars)`);

export function luhn(digits: string): boolean {
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d; alt = !alt;
  }
  return sum % 10 === 0;
}
export function ibanValid(iban: string): boolean {
  const s = iban.replace(/\s/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(s)) return false;
  const moved = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const ch of moved) rem = (rem * (/\d/.test(ch) ? 10 : 100) + (/\d/.test(ch) ? Number(ch) : ch.charCodeAt(0) - 55)) % 97;
  return rem === 1;
}
export function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const c of s) counts.set(c, (counts.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

interface Rule { kind: SecretKind; re: RegExp; check?: (m: string) => boolean }
const RULES: Rule[] = [
  { kind: 'aws-access-key', re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b/g },
  { kind: 'aws-secret-key', re: /aws_secret_access_key\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}\b/gi },
  { kind: 'github-token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/g },
  { kind: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { kind: 'slack-token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g },
  { kind: 'stripe-key', re: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { kind: 'jwt', re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { kind: 'private-key', re: /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----/g },
  { kind: 'credit-card', re: /\b(?:\d[ -]?){13,19}\b/g, check: (m) => { const d = m.replace(/\D/g, ''); return d.length >= 13 && d.length <= 19 && !/^(\d)\1+$/.test(d) && luhn(d); } },
  { kind: 'us-ssn', re: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },
  { kind: 'iban', re: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/g, check: ibanValid },
  { kind: 'bearer-token', re: /\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*/g },
  { kind: 'connection-string', re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:[^\s@/]{3,}@[^\s/]+/gi },
  { kind: 'credential-assignment', re: /\b(?:api[_-]?key|secret|token|passw(?:or)?d|pwd|private[_-]?key|access[_-]?key)\b["']?\s*[=:]\s*["']?[A-Za-z0-9_\-/+=.!@#$%^&*]{12,}/gi },
];
/** Shapes that are only suspicious, not conclusive. They ask for approval instead of denying. */
const HEURISTIC: SecretKind[] = ['credential-assignment', 'high-entropy-token'];

function scanOne(text: string, encoded?: string): SecretFinding[] {
  const out: SecretFinding[] = [];
  const explained: string[] = []; // raw text already explained by a conclusive rule
  for (const r of RULES) {
    for (const m of text.matchAll(r.re)) {
      if (r.check && !r.check(m[0])) continue;
      if (!HEURISTIC.includes(r.kind)) explained.push(m[0]);
      out.push({ kind: r.kind, sample: mask(m[0]), definite: !HEURISTIC.includes(r.kind), ...(encoded ? { encoded } : {}) });
    }
  }
  for (const tok of text.split(/[\s"',;()<>]+/)) {
    if (explained.some((e) => e.includes(tok) || tok.includes(e))) continue; // already reported as something specific
    if (tok.length >= 32 && /^[A-Za-z0-9+/=_-]+$/.test(tok) && /[a-z]/.test(tok) && /[A-Z]/.test(tok) && /\d/.test(tok) && entropy(tok) >= 4.3)
      out.push({ kind: 'high-entropy-token', sample: mask(tok), definite: false, ...(encoded ? { encoded } : {}) });
  }
  return out;
}

/** Candidate encoded payloads: base64 (standard and url safe), hex and percent encoding, decoded one level. */
function decodedViews(text: string): [string, string][] {
  const views: [string, string][] = [];
  for (const m of text.matchAll(/[A-Za-z0-9+/_-]{24,}={0,2}/g)) {
    try { const d = b64decode(m[0].replace(/-/g, '+').replace(/_/g, '/')); if (/^[\x09\x0a\x0d\x20-\x7e]+$/.test(d)) views.push([d, 'base64']); } catch { /* not base64 */ }
  }
  for (const m of text.matchAll(/(?:[0-9a-fA-F]{2}){12,}/g)) {
    const d = m[0].match(/../g)!.map((h) => String.fromCharCode(parseInt(h, 16))).join('');
    if (/^[\x09\x0a\x0d\x20-\x7e]+$/.test(d)) views.push([d, 'hex']);
  }
  if (/%[0-9a-fA-F]{2}/.test(text)) { try { views.push([decodeURIComponent(text), 'url']); } catch { /* malformed */ } }
  return views;
}

/** Find every kind of secret shaped data in the text, including one level of base64, hex and URL encoding. */
export function detectSecrets(text: string): SecretFinding[] {
  const found = scanOne(text);
  for (const [decoded, how] of decodedViews(text)) found.push(...scanOne(decoded, how).filter((f) => f.kind !== 'high-entropy-token'));
  // When the decoded contents are conclusive, the encoded wrapper itself is not worth reporting as a vague high entropy blob.
  const decodedConclusive = found.some((f) => f.encoded && f.definite);
  const kept = found.filter((f) => !(decodedConclusive && f.kind === 'high-entropy-token' && !f.encoded));
  kept.sort((a, b) => Number(b.definite) - Number(a.definite));
  const seen = new Set<string>();
  return kept.filter((f) => { const k = `${f.kind}|${f.sample}|${f.encoded ?? ''}`; if (seen.has(k)) return false; seen.add(k); return true; });
}
