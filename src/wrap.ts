// Put every stdio MCP server in a client config (Claude Desktop, Cursor, VS Code style) behind Tripline's proxy,
// and take it out again. Pure functions over the parsed JSON, so they are easy to test.
import { join } from 'node:path';

type Entry = Record<string, any>;
export type McpConfig = Record<string, any>;
export interface WrapOptions {
  /** Absolute path of the Node binary that will run Tripline (must support running .ts, Node 22.18 or newer). */
  node: string;
  /** Absolute path of src/cli.ts. */
  cli: string;
  allow: string[];
  /** Where per server lockfiles and audit logs are kept. */
  stateDir: string;
  approveCmd?: string;
}
export interface WrapReport { wrapped: string[]; alreadyWrapped: string[]; skipped: { name: string; reason: string }[] }

const CONTAINERS = ['mcpServers', 'servers'];
const safe = (name: string) => name.replace(/[^A-Za-z0-9._-]+/g, '_');

export const isWrapped = (e: Entry): boolean => Array.isArray(e.args) && e.args.length >= 3 && /(^|[\\/])cli\.ts$/.test(String(e.args[0])) && e.args[1] === 'proxy' && e.args.includes('--');

export function wrapConfig(config: McpConfig, o: WrapOptions): { config: McpConfig; report: WrapReport } {
  const out: McpConfig = structuredClone(config);
  const report: WrapReport = { wrapped: [], alreadyWrapped: [], skipped: [] };
  for (const key of CONTAINERS) {
    const servers = out[key];
    if (!servers || typeof servers !== 'object' || Array.isArray(servers)) continue;
    for (const [name, entry] of Object.entries<Entry>(servers)) {
      if (!entry || typeof entry !== 'object') continue;
      if (isWrapped(entry)) { report.alreadyWrapped.push(name); continue; }
      if (typeof entry.command !== 'string') { report.skipped.push({ name, reason: entry.url ? 'remote (HTTP or SSE) server: the proxy wraps stdio servers only' : 'no stdio command' }); continue; }
      const args = [
        o.cli, 'proxy',
        ...(o.allow.length ? ['--allow', o.allow.join(',')] : []),
        '--lock', join(o.stateDir, `${safe(name)}.lock.json`),
        '--audit-log', join(o.stateDir, `${safe(name)}.audit.jsonl`),
        ...(o.approveCmd ? ['--approve-cmd', o.approveCmd] : []),
        '--', entry.command, ...(Array.isArray(entry.args) ? entry.args : []),
      ];
      servers[name] = { ...entry, command: o.node, args };
      report.wrapped.push(name);
    }
  }
  return { config: out, report };
}

/** Restore the original command and arguments of every wrapped server. */
export function unwrapConfig(config: McpConfig): { config: McpConfig; restored: string[] } {
  const out: McpConfig = structuredClone(config);
  const restored: string[] = [];
  for (const key of CONTAINERS) {
    const servers = out[key];
    if (!servers || typeof servers !== 'object' || Array.isArray(servers)) continue;
    for (const [name, entry] of Object.entries<Entry>(servers)) {
      if (!entry || !isWrapped(entry)) continue;
      const sep = entry.args.indexOf('--');
      const [command, ...args] = entry.args.slice(sep + 1) as string[];
      servers[name] = { ...entry, command, args };
      if (!args.length) delete servers[name].args;
      restored.push(name);
    }
  }
  return { config: out, restored };
}
