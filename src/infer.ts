import type { ToolPolicy } from './guard.ts';
import type { ToolDef } from './types.ts';

const tokens = (s: string) => s.replace(/([a-z])([A-Z])/g, '$1_$2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
const EGRESS = new Set(['send', 'post', 'upload', 'publish', 'email', 'mail', 'webhook', 'notify', 'share', 'push', 'tweet', 'forward', 'reply', 'submit', 'transmit']);
const PRIVATE = new Set(['secret', 'secrets', 'credential', 'credentials', 'env', 'keychain', 'password', 'passwords', 'token', 'vault', 'ssh', 'dump']);
const PRIVATE_COMBO = [['read', 'file'], ['get', 'file'], ['cat', 'file'], ['read', 'text'], ['query', 'database'], ['run', 'sql']];
const UNTRUSTED = new Set(['fetch', 'browse', 'scrape', 'search', 'inbox', 'crawl', 'download', 'rss', 'web', 'url', 'issues', 'comments', 'messages', 'mail']);
const FETCHERS = new Set(['fetch', 'get', 'http', 'request', 'download', 'browse', 'open', 'visit', 'curl', 'scrape', 'crawl']);
const DEST = /^(to|recipient|recipients|email|url|endpoint|webhook|webhook_url|address|channel|destination|target)$/i;

/**
 * Heuristic labelling of tools from names and schemas. This is a starting point a human should review:
 * it can mislabel unusual tool names, and explicit policy entries always win over inferred ones.
 */
export function inferPolicy(tools: ToolDef[]): Record<string, ToolPolicy> {
  const out: Record<string, ToolPolicy> = {};
  for (const t of tools) {
    const toks = tokens(t.name);
    const p: ToolPolicy = {};
    if (toks.some((x) => EGRESS.has(x))) {
      p.egress = true;
      const props = Object.keys((t.inputSchema?.properties ?? {}) as object);
      const d = props.find((k) => DEST.test(k));
      if (d) p.destinationParam = d;
    }
    if (toks.some((x) => PRIVATE.has(x)) || PRIVATE_COMBO.some(([a, b]) => toks.includes(a) && toks.includes(b))) p.reads = 'private';
    if (toks.some((x) => UNTRUSTED.has(x))) p.ingestsUntrusted = true;
    // A tool that takes a URL can be abused as a channel (data in the query string), so treat URL fetchers as egress too.
    const urlParam = Object.keys((t.inputSchema?.properties ?? {}) as object).find((k) => /^(url|uri|endpoint|href)$/i.test(k));
    if (urlParam && !p.egress && toks.some((x) => FETCHERS.has(x))) { p.egress = true; p.destinationParam = urlParam; }
    if (Object.keys(p).length) out[t.name] = p;
  }
  return out;
}
