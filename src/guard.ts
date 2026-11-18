import { b64, hex, reverse } from './util.ts';

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
const variants = (f: string) => [f, b64(f), b64(f).replace(/=+$/, ''), b64url(f), hex(f), hex(f).toUpperCase(), encodeURIComponent(f), reverse(f)];

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

  private find(strings: string[], frags: string[]): string | undefined {
    const joined = strings.join('\u0000');
    const squashed = squash(strings.join(''));
    for (const f of frags) {
      if (variants(f).some((v) => joined.includes(v))) return f;
      const sf = squash(f);
      if (sf.length >= 6 && squashed.includes(sf)) return f; // case, spacing and punctuation changes, split across arguments
    }
    return undefined;
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
          detail: `Argument contains data read from a private source (${mask(privHit)}; also checked encodings, case and spacing changes) and the destination is not allow-listed.` });
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
