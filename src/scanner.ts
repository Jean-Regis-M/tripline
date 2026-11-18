import type { Finding, Manifest, ScanReport, Severity } from './types.ts';

const INVISIBLE = /[​-‏‪-‮⁠-⁤﻿\u{E0000}-\u{E007F}]/u;
const HIDDEN_INSTRUCTION: RegExp[] = [
  /<\s*(important|system|instructions?|secret)\s*>/i,
  /ignore (all |any |the )?(previous|prior|above|earlier|preceding) (instructions|rules|directions|prompts|messages|context)/i,
  /do not (tell|mention|inform|reveal)[^.]{0,40}(user|human)/i,
  /without (telling|informing|notifying) the user/i,
  /assistant_action\s*:/i,
];
/** Imperatives addressed to the model. Common in honest docs ("you should call list_projects first"), so only a review signal. */
const IMPERATIVE = /you (must|should|need to) (first |also |always )?(read|send|include|pass|upload|forward)/i;
const SENSITIVE_PATH = /\.(ssh|aws|gnupg|kube)\b|\.config[\\/](gcloud|gh)\b|\.docker[\\/]config|\.(npmrc|netrc|pgpass)\b|id_(rsa|ed25519|ecdsa)|credentials\.(db|json)|wallet\.dat|(^|[\s"'/\\])\.env\b|private key|\/etc\/passwd|mcp\.json|cookies\.sqlite/i;
const SHADOW = /(instead of|rather than|override|replace the|ignore|do not use|don't use|never use|before (using|calling)|whenever you (use|call)|when (using|calling))/i;
const URL_RE = /https?:\/\/([^\s/)"']+)[^\s)"']*/i;
const SAFE_HOSTS = ['github.com', 'modelcontextprotocol.io', 'docs.python.org', 'developer.mozilla.org'];
const CARRIER = /^(side_?note|notes?|context|metadata|extra|memo|reasoning|summary|feedback|annotation)$/i;
const BLOB = /[A-Za-z0-9+/]{60,}={0,2}/;
const WEIGHT: Record<Severity, number> = { critical: 40, high: 25, medium: 10, low: 3 };

/** JSON Schema bookkeeping keywords hold URLs and identifiers, not prose for the model. */
const SCHEMA_META = new Set(['$schema', '$id', '$ref', '$comment', '$defs']);
function strings(v: unknown, out: string[] = []): string[] {
  if (typeof v === 'string') out.push(v);
  else if (Array.isArray(v)) v.forEach((x) => strings(x, out));
  else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) if (!SCHEMA_META.has(k)) strings(x, out);
  return out;
}
const snip = (s: string, m?: RegExpMatchArray | null) => {
  const flat = s.replace(/\s+/g, ' ');
  const i = Math.max(0, flat.indexOf((m?.[0] ?? '').replace(/\s+/g, ' ')));
  let start = Math.max(0, i - 24), end = Math.min(flat.length, i + 80);
  let out = flat.slice(start, end);
  if (start > 0) out = '...' + out.slice(out.indexOf(' ') + 1);
  if (end < flat.length) out = out.slice(0, out.lastIndexOf(' ')) + '...';
  return out;
};

export function scanManifest(manifest: Manifest): ScanReport {
  const findings: Finding[] = [];
  const allNames = manifest.servers.flatMap((s) => s.tools.map((t) => t.name));
  const seen = new Map<string, string>();

  for (const server of manifest.servers) {
    for (const tool of server.tools) {
      const add = (rule: string, severity: Severity, title: string, evidence?: string) => {
        if (!findings.some((f) => f.rule === rule && f.tool === tool.name && f.server === server.name))
          findings.push({ rule, severity, server: server.name, tool: tool.name, title, evidence });
      };
      const prior = seen.get(tool.name);
      if (prior && prior !== server.name)
        add('TP006', 'medium', `Tool name also exported by server "${prior}" (shadowing risk)`);
      seen.set(tool.name, server.name);

      const texts = [tool.description ?? '', tool.title ?? '', tool.name, ...strings(tool.inputSchema), ...strings(tool.outputSchema), ...strings(tool.annotations)];
      for (const raw of texts) {
        const inv = raw.match(INVISIBLE);
        const t = raw.normalize('NFKC');
        if (inv)
          add('TP002', 'critical', 'Invisible or bidirectional Unicode hides content from reviewers',
            `U+${inv[0].codePointAt(0)!.toString(16).toUpperCase()}`);
        for (const re of HIDDEN_INSTRUCTION) {
          const m = t.match(re);
          if (m) add('TP001', 'critical', 'Instruction aimed at the model embedded in tool metadata', snip(t, m));
        }
        const imp = t.match(IMPERATIVE);
        if (imp) add('TP009', 'medium', 'Imperative addressed to the model in metadata', snip(t, imp));
        const sp = t.match(SENSITIVE_PATH);
        if (sp) add('TP003', HIDDEN_INSTRUCTION.some((re) => re.test(t)) ? 'high' : 'medium', 'Metadata references sensitive files or credentials', snip(t, sp));
        for (const other of allNames) {
          if (other === tool.name || other.length < 3) continue;
          if (new RegExp(`\\b${other.replace(/[^\w]/g, '\\$&')}\\b`).test(t) && SHADOW.test(t))
            add('TP004', 'high', `Metadata tries to steer how other tool "${other}" is used`, snip(t));
        }
        const u = t.match(URL_RE);
        if (u && !SAFE_HOSTS.some((h) => u[1] === h || u[1].endsWith('.' + h)))
          add('TP005', 'medium', 'Metadata embeds an external endpoint', u[0]);
        const b = t.match(BLOB);
        if (b) add('TP007', 'medium', 'Long encoded blob in metadata', b[0].slice(0, 24) + '...');
      }
      const props = (tool.inputSchema?.properties ?? {}) as Record<string, any>;
      for (const [pname, p] of Object.entries(props)) {
        if (!CARRIER.test(pname) || p?.type !== 'string') continue;
        const ctx = `${tool.description} ${p?.description ?? ''}`;
        const suspicious = HIDDEN_INSTRUCTION.some((re) => re.test(ctx)) || SENSITIVE_PATH.test(ctx);
        add('TP008', suspicious ? 'high' : 'low',
          suspicious
            ? `Free-form parameter "${pname}" is positioned to smuggle data out`
            : `Free-form carrier parameter "${pname}" (could exfiltrate data)`);
      }
    }
  }

  const risk: Record<string, number> = {};
  for (const f of findings) {
    const k = `${f.server}/${f.tool}`;
    risk[k] = Math.min(100, (risk[k] ?? 0) + WEIGHT[f.severity]);
  }
  for (const s of manifest.servers) for (const t of s.tools) risk[`${s.name}/${t.name}`] ??= 0;
  const sev = new Set(findings.map((f) => f.severity));
  const verdict = sev.has('critical') || sev.has('high') ? 'block' : sev.has('medium') ? 'review' : 'pass';
  const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  return { findings, verdict, risk };
}
