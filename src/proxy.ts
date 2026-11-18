import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import type { Readable, Writable } from 'node:stream';
import { Guard, type Policy } from './guard.ts';
import { inferPolicy } from './infer.ts';
import { scanManifest } from './scanner.ts';
import type { ToolDef } from './types.ts';

export interface ProxyOptions {
  command: string;
  args: string[];
  allowedDestinations: string[];
  /** Explicit per tool labels. They override inferred labels. */
  tools?: Policy['tools'];
  /** Hide tools whose manifest scan returns critical or high findings. Default true. */
  hidePoisonedTools?: boolean;
  log?: (message: string) => void;
}

const text = (content: unknown): string =>
  Array.isArray(content) ? content.map((c) => (c && typeof c === 'object' && 'text' in c ? String((c as any).text) : '')).join('\n') : '';

/**
 * A man in the middle for MCP over stdio (newline delimited JSON-RPC 2.0).
 * - tools/list responses are scanned; poisoned tools are removed before the agent ever sees them.
 * - tools/call requests are checked by the guard; blocked calls get an MCP error result and never reach the server.
 * - tools/call responses are observed so later calls can be checked for derived data.
 */
export function runProxy(opts: ProxyOptions, input: Readable = process.stdin, output: Writable = process.stdout) {
  const log = opts.log ?? ((m: string) => process.stderr.write(`[tripline] ${m}\n`));
  const guard = new Guard({ allowedDestinations: opts.allowedDestinations, tools: { ...(opts.tools ?? {}) } });
  const hide = opts.hidePoisonedTools ?? true;
  const hidden = new Set<string>();
  const pending = new Map<string | number, { method: string; tool?: string }>();
  const child = spawn(opts.command, opts.args, { stdio: ['pipe', 'pipe', 'inherit'] });
  const toClient = (msg: unknown) => output.write(JSON.stringify(msg) + '\n');
  const refuse = (id: unknown, why: string) => toClient({ jsonrpc: '2.0', id, result: { isError: true, content: [{ type: 'text', text: `Blocked by Tripline: ${why}` }] } });

  createInterface({ input }).on('line', (line) => {
    let msg: any;
    try { msg = JSON.parse(line); } catch { child.stdin.write(line + '\n'); return; }
    if (msg?.method === 'tools/list' && msg.id !== undefined) pending.set(msg.id, { method: 'tools/list' });
    if (msg?.method === 'tools/call' && msg.id !== undefined) {
      const tool = String(msg.params?.name ?? '');
      const args = (msg.params?.arguments ?? {}) as Record<string, unknown>;
      if (hidden.has(tool)) { log(`blocked call to hidden tool ${tool}`); return refuse(msg.id, `tool "${tool}" was removed because its manifest failed the scan.`); }
      const v = guard.check(tool, args);
      if (v.decision !== 'allow') {
        const why = v.rules.map((r) => `${r.id} ${r.title}`).join('; ');
        log(`${v.decision} ${tool}: ${why}`);
        return refuse(msg.id, v.decision === 'ask' ? `${why}. Human approval is required and was not granted.` : why);
      }
      pending.set(msg.id, { method: 'tools/call', tool });
    }
    child.stdin.write(line + '\n');
  }).on('close', () => child.stdin.end());

  createInterface({ input: child.stdout }).on('line', (line) => {
    let msg: any;
    try { msg = JSON.parse(line); } catch { output.write(line + '\n'); return; }
    const p = msg?.id !== undefined ? pending.get(msg.id) : undefined;
    if (p && msg.result) {
      pending.delete(msg.id);
      if (p.method === 'tools/list' && Array.isArray(msg.result.tools)) {
        const tools = msg.result.tools as ToolDef[];
        const report = scanManifest({ servers: [{ name: 'server', tools }] });
        const bad = new Set(report.findings.filter((f) => f.severity === 'critical' || f.severity === 'high').map((f) => f.tool));
        for (const f of report.findings) log(`scan ${f.severity} ${f.rule} ${f.tool}: ${f.title}`);
        guard.policy.tools = { ...inferPolicy(tools), ...(opts.tools ?? {}) };
        if (hide && bad.size) {
          for (const t of bad) hidden.add(t);
          msg.result.tools = tools.filter((t) => !bad.has(t.name));
          log(`hid ${bad.size} poisoned tool(s): ${[...bad].join(', ')}`);
        }
        return toClient(msg);
      }
      if (p.method === 'tools/call' && p.tool) guard.observe(p.tool, text(msg.result.content));
    } else if (p) pending.delete(msg.id);
    toClient(msg);
  });

  child.on('exit', (code) => { output.end(); if (output === process.stdout) process.exit(code ?? 0); });
  return { child, guard };
}
