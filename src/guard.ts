import { atbash, b64, base32, caesar, hex, reverse, rot47 } from './util.ts';

export interface ToolPolicy {
  /** Output of this tool is sensitive; values derived from it must not leave. */
  reads?: 'private';
  /** Output of this tool is attacker-influenceable (web, inbox, third-party server). */
  ingestsUntrusted?: boolean;
  /** Tool can send data outside the trust boundary. */
  egress?: boolean;
  /** Argument that names the destination (address, URL). */
  destinationParam?: string;
}
export interface Policy {
  tools: Record<string, ToolPolicy>;
  allowedDestinations: string[];
  mode?: 'enforce' | 'monitor';
}
export type Decision = 'allow' | 'deny' | 'ask';
export interface RuleHit { id: string; title: string; detail: string }
export interface Verdict { decision: Decision; rules: RuleHit[]; labels: { untrusted: boolean; privateRead: boolean } }

const MAX_FRAGMENTS = 5000;
const MAX_CIPHER_FRAGMENT = 120;
const MAX_CIPHERED = 800;

/** Break an output into fragments we can later recognise inside tool arguments. */
export function fragments(text: string): string[] {
  const out = new Set<string>();
  const whole = text.trim();
  if (whole.length >= 6) out.add(whole);
  for (const line of text.split(/\r?\n/)) if (line.trim().length >= 10) out.add(line.trim());
  for (const tok of text.split(/[\s,;:=]+/)) {
    if (tok.length >= 12 || (tok.length >= 6 && /\d/.test(tok))) out.add(tok);
  }
  return [...out].slice(0, MAX_FRAGMENTS);
}

const squash = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, '');
const b64url = (s: string) => b64(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const SHIFTS = Array.from({ length: 25 }, (_, i) => i + 1);
/** Exact textual re-encodings of a fragment that an attacker can apply with a one line script. */
const variants = (f: string) => [f, b64(f), b64(f).replace(/=+$/, ''), b64url(f), b64(b64(f)), hex(f), hex(f).toUpperCase(), base32(f), base32(f).replace(/=+$/, '').toLowerCase(), encodeURIComponent(f), reverse(f), rot47(f)];
/** Letter-substitution ciphers. Only worth checking for fragments that contain enough letters to be meaningful. */
const cipherVariants = (f: string) => (f.replace(/[^a-z]/gi, '').length >= 6 ? [...SHIFTS.map((n) => caesar(f, n)), atbash(f), reverse(atbash(f))] : []);


const PREFIX = 6;
type PatternIndex = Map<string, [pattern: string, fragment: string][]>;
function addPattern(index: PatternIndex, pattern: string, fragment: string) {
  if (pattern.length < PREFIX) return;
  const key = pattern.slice(0, PREFIX);
  const list = index.get(key);
  if (list) list.push([pattern, fragment]); else index.set(key, [[pattern, fragment]]);
}
/** One linear pass: look up the 6 character window at every position, then verify the candidate patterns. */
function scanPatterns(text: string, index: PatternIndex): string | undefined {
  for (let i = 0; i + PREFIX <= text.length; i++) {
    const list = index.get(text.slice(i, i + PREFIX));
    if (list) for (const [pattern, fragment] of list) if (text.startsWith(pattern, i)) return fragment;
  }
  return undefined;
}

function argStrings(v: unknown, out: string[] = []): string[] {
  if (typeof v === 'string') out.push(v);
  else if (Array.isArray(v)) v.forEach((x) => argStrings(x, out));
  else if (v && typeof v === 'object') Object.values(v).forEach((x) => argStrings(x, out));
  return out;
}
const mask = (s: string) => (s.length <= 6 ? '***' : `${s.slice(0, 4)}...(${s.length} chars)`);

const addressAllowed = (addr: string, allowed: string[]) => {
  const a = addr.toLowerCase();
  const domain = a.slice(a.lastIndexOf('@') + 1);
  return allowed.some((x0) => {
    const x = x0.toLowerCase();
    return x.includes('@') ? x === a : domain === x || domain.endsWith('.' + x);
  });
};
const hostAllowed = (host: string, allowed: string[]) =>
  allowed.some((x0) => { const x = x0.toLowerCase(); return !x.includes('@') && (host === x || host.endsWith('.' + x)); });

/** True only if EVERY recipient or host in the value is allow-listed. Unparseable values are not allowed. */
export function destinationAllowed(dest: unknown, allowed: string[]): boolean {
  if (typeof dest !== 'string' || !dest.trim()) return false;
  const d = dest.trim();
  if (!d.includes('://') && !d.includes('/') && d.includes('@')) {
    const emails = d.match(/[^\s,;<>"']+@[^\s,;<>"']+/g);
    return !!emails && emails.every((e) => addressAllowed(e, allowed));
  }
  return d.split(/[,;\s]+/).filter(Boolean).every((t) => {
    try { return hostAllowed(new URL(t.includes('://') ? t : 'https://' + t).hostname.toLowerCase(), allowed); } catch { return false; }
  });
}

const URL_IN_TEXT = /https?:\/\/[^\s"'<>)]+/gi;
function urlHosts(strings: string[]): string[] {
  const hosts: string[] = [];
  for (const s of strings) for (const m of s.match(URL_IN_TEXT) ?? []) { try { hosts.push(new URL(m).hostname.toLowerCase()); } catch { hosts.push('?'); } }
  return hosts;
}

export class Guard {
  private priv: string[] = [];
  private untrusted: string[] = [];
  private labels = { untrusted: false, privateRead: false };
  policy: Policy;
  constructor(policy: Policy) { this.policy = policy; }

  /** Record a tool result so later arguments can be checked for derived data. */
  observe(tool: string, output: string): void {
    const p = this.policy.tools[tool];
    if (p?.reads === 'private') { this.priv.push(...fragments(output)); this.labels.privateRead = true; }
    if (p?.ingestsUntrusted) { this.untrusted.push(...fragments(output)); this.labels.untrusted = true; }
  }

  /**
   * Multi pattern index over every re-encoding of every private fragment, built once per change in
   * the private data. A scan of an argument is then linear in its length, not (fragments x variants x length).
   */
  private index = { exact: new Map() as PatternIndex, squashed: new Map() as PatternIndex, upTo: 0, ciphered: 0 };
  /** Adds only the fragments seen since the last call, so repeated reads do not rebuild everything. */
  private ensureIndex() {
    const ix = this.index;
    for (; ix.upTo < this.priv.length; ix.upTo++) {
      const f = this.priv[ix.upTo];
      for (const v of variants(f)) addPattern(ix.exact, v, f);
      const sf = squash(f);
      if (sf.length >= 6) addPattern(ix.squashed, sf, f); // case, spacing and punctuation changes, split across arguments
      // Letter substitution ciphers are the expensive part (27 variants), so they are limited to short fragments
      // (secrets, tokens, short lines) and to a bounded number per session.
      if (f.length <= MAX_CIPHER_FRAGMENT && ix.ciphered < MAX_CIPHERED) {
        const cv = cipherVariants(f);
        if (cv.length) ix.ciphered++;
        for (const v of cv) {
          addPattern(ix.exact, v, f);
          const sv = squash(v);
          if (sv.length >= 8) addPattern(ix.squashed, sv, f); // a cipher AND a spacing or case change
        }
      }
    }
    return ix;
  }

  private find(strings: string[], _frags: string[]): string | undefined {
    if (!this.priv.length) return undefined;
    const { exact, squashed } = this.ensureIndex();
    return scanPatterns(strings.join('\u0000'), exact) ?? scanPatterns(squash(strings.join('')), squashed);
  }

  check(tool: string, args: Record<string, unknown>): Verdict {
    const p = this.policy.tools[tool] ?? {};
    const allowed = this.policy.allowedDestinations;
    const strings = argStrings(args);
    // Any tool that carries an external URL can be used as a channel (e.g. a GET with data in the query string).
    const externalUrl = urlHosts(strings).some((h) => !hostAllowed(h, allowed));
    const rules: RuleHit[] = [];
    let decision: Decision = 'allow';
    if (p.egress || externalUrl) {
      const dest = p.destinationParam ? args[p.destinationParam] : undefined;
      const ok = p.egress ? destinationAllowed(dest, allowed) : !externalUrl;
      const privHit = this.find(strings, this.priv);
      const untrustedDest = typeof dest === 'string' && this.untrusted.some((u) => u.includes(dest));
      if (privHit && !ok) {
        decision = 'deny';
        rules.push({ id: 'R1', title: 'Private data leaving the trust boundary',
          detail: `Argument contains data read from a private source (${mask(privHit)}; also checked encodings, Caesar and ROT ciphers, case and spacing changes) and the destination is not allow-listed.` });
      }
      if (untrustedDest && !ok) {
        decision = 'deny';
        rules.push({ id: 'R3', title: 'Destination chosen by untrusted content',
          detail: 'The destination appeared in untrusted tool output, not in the user request or policy allow-list.' });
      }
      if (decision === 'allow' && this.labels.untrusted && this.labels.privateRead && !ok) {
        decision = 'ask';
        rules.push({ id: 'R2', title: 'Lethal trifecta: untrusted input + private data + egress',
          detail: 'This session has read untrusted content and private data; an external send needs human approval even if no copied data is detected (it could be paraphrased).' });
      }
    }
    if (this.policy.mode === 'monitor' && decision !== 'allow') {
      rules.push({ id: 'MON', title: 'Monitor mode', detail: `Would have returned "${decision}"; allowed because policy mode is monitor.` });
      decision = 'allow';
    }
    return { decision, rules, labels: { ...this.labels } };
  }
}
