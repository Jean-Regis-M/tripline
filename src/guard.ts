import { b64, hex } from './util.ts';

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

/** Break an output into fragments we can later recognise inside tool arguments. */
export function fragments(text: string): string[] {
  const out = new Set<string>();
  const whole = text.trim();
  if (whole.length >= 8) out.add(whole);
  for (const line of text.split(/\r?\n/)) if (line.trim().length >= 10) out.add(line.trim());
  for (const tok of text.split(/[\s,;:=]+/)) {
    if (tok.length >= 12 || (tok.length >= 8 && /\d/.test(tok) && /[a-z]/i.test(tok))) out.add(tok);
  }
  return [...out].slice(0, 300);
}
const variants = (f: string) => [
  f,
  b64(f),
  hex(f),
  encodeURIComponent(f),
];
function argStrings(v: unknown, out: string[] = []): string[] {
  if (typeof v === 'string') out.push(v);
  else if (Array.isArray(v)) v.forEach((x) => argStrings(x, out));
  else if (v && typeof v === 'object') Object.values(v).forEach((x) => argStrings(x, out));
  return out;
}
const mask = (s: string) => (s.length <= 6 ? '***' : `${s.slice(0, 4)}...(${s.length} chars)`);

export function destinationAllowed(dest: unknown, allowed: string[]): boolean {
  if (typeof dest !== 'string' || !dest) return false;
  let host = dest.toLowerCase();
  try { host = new URL(dest).hostname.toLowerCase(); } catch { /* not a URL */ }
  const at = host.lastIndexOf('@');
  const domain = at >= 0 ? host.slice(at + 1) : host;
  return allowed.some((a) => {
    const x = a.toLowerCase();
    return x === host || x === domain || (!x.includes('@') && domain.endsWith('.' + x));
  });
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

  private find(args: unknown, frags: string[]): string | undefined {
    const hay = argStrings(args);
    for (const f of frags) for (const v of variants(f)) if (hay.some((h) => h.includes(v))) return f;
    return undefined;
  }

  check(tool: string, args: Record<string, unknown>): Verdict {
    const p = this.policy.tools[tool] ?? {};
    const rules: RuleHit[] = [];
    let decision: Decision = 'allow';
    if (p.egress) {
      const dest = p.destinationParam ? args[p.destinationParam] : undefined;
      const ok = destinationAllowed(dest, this.policy.allowedDestinations);
      const privHit = this.find(args, this.priv);
      const untrustedDest = typeof dest === 'string' && this.untrusted.some((u) => u.includes(dest));
      if (privHit && !ok) {
        decision = 'deny';
        rules.push({ id: 'R1', title: 'Private data leaving the trust boundary',
          detail: `Argument contains data read from a private source (${mask(privHit)}; also checked base64/hex/URL encodings) and destination is not allow-listed.` });
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
