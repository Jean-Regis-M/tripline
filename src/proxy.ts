import { spawn } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import type { Readable, Writable } from 'node:stream';
import { Guard, type Policy, type Verdict } from './guard.ts';
import { inferPolicy } from './infer.ts';
import { createLock, verifyLock } from './pin.ts';
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
  /** Path of a lockfile. Created on first use (trust on first use); later drift hides changed or added tools. */
  lockPath?: string;
  /** Called when rule R2 asks for approval. Return true to allow. Without it, "ask" is treated as deny (fail closed). */
  approve?: (tool: string, args: Record<string, unknown>, verdict: Verdict) => Promise<boolean> | boolean;
  log?: (message: string) => void;
}

/** Everything in a tool result that could carry data: text, structured content and embedded resources. */
export function resultText(result: any): string {
  const parts: string[] = [];
  if (Array.isArray(result?.content)) {
    for (const c of result.content) {
      if (typeof c?.text === 'string') parts.push(c.text);
      if (typeof c?.resource?.text === 'string') parts.push(c.resource.text);
      if (typeof c?.resource?.blob === 'string') parts.push(c.resource.blob);
      if (typeof c?.data === 'string') parts.push(c.data);
    }
  }
  if (result?.structuredContent !== undefined) parts.push(JSON.stringify(result.structuredContent));
  return parts.join('\n');
}

/**
 * A man in the middle for MCP over stdio (newline delimited JSON-RPC 2.0), failing closed:
 * - tools/list responses are scanned; poisoned or drifted tools are removed before the agent sees them.
 * - tools/call requests are checked by the guard; blocked calls get an MCP error result and never reach the server.
 * - batches containing tools/call, tools/call notifications, and unparseable lines are dropped, not forwarded.
 * - calls made before the first tools/list are refused, because the policy is not known yet.
 * - tools/call results are observed (text, structured content, resources) for provenance tracking.
 */
export function runProxy(opts: ProxyOptions, input: Readable = process.stdin, output: Writable = process.stdout) {
  const log = opts.log ?? ((m: string) => process.stderr.write(`[tripline] ${m}\n`));
  const guard = new Guard({ allowedDestinations: opts.allowedDestinations, tools: { ...(opts.tools ?? {}) } });
  const hide = opts.hidePoisonedTools ?? true;
  let hidden = new Set<string>();
  let listed = false;
  const pending = new Map<string | number, { method: string; tool?: string }>();
  const child = spawn(opts.command, opts.args, { stdio: ['pipe', 'pipe', 'inherit'] });
  const toClient = (msg: unknown) => output.write(JSON.stringify(msg) + '\n');
  const refuse = (id: unknown, why: string) => toClient({ jsonrpc: '2.0', id, result: { isError: true, content: [{ type: 'text', text: `Blocked by Tripline: ${why}` }] } });
  const rpcError = (id: unknown, message: string) => toClient({ jsonrpc: '2.0', id: id ?? null, error: { code: -32600, message: `Blocked by Tripline: ${message}` } });
  const isCall = (m: any) => m && typeof m === 'object' && m.method === 'tools/call';

  const handleLine = async (line: string) => {
    let msg: any;
    try { msg = JSON.parse(line); } catch { log('dropped a line that is not valid JSON'); return; }
    if (Array.isArray(msg)) {
      if (msg.some(isCall)) { log('dropped a JSON-RPC batch containing tools/call'); return rpcError(null, 'batched tools/call requests are not supported'); }
      return void child.stdin.write(line + '\n');
    }
    if (isCall(msg)) {
      if (msg.id === undefined || msg.id === null) { log('dropped a tools/call sent as a notification'); return; }
      const tool = String(msg.params?.name ?? '');
      const args = (msg.params?.arguments ?? {}) as Record<string, unknown>;
      if (!listed) { log(`refused ${tool}: tools/list has not been seen`); return refuse(msg.id, 'call tools/list first so the policy can be derived.'); }
      if (hidden.has(tool)) { log(`blocked call to hidden tool ${tool}`); return refuse(msg.id, `tool "${tool}" was removed because its manifest failed the scan or changed since it was pinned.`); }
      const v = guard.check(tool, args);
      let allowed = v.decision === 'allow';
      if (v.decision === 'ask' && opts.approve) allowed = await opts.approve(tool, args, v);
      if (!allowed) {
        const why = v.rules.map((r) => `${r.id} ${r.title}`).join('; ');
        log(`${v.decision} ${tool}: ${why}`);
        return refuse(msg.id, v.decision === 'ask' ? `${why}. Human approval is required and was not granted.` : why);
      }
      pending.set(msg.id, { method: 'tools/call', tool });
    } else if (msg?.method === 'tools/list' && msg.id !== undefined) pending.set(msg.id, { method: 'tools/list' });
    child.stdin.write(line + '\n');
  };
  // Process lines strictly in order so an approval prompt cannot be overtaken by later requests.
  let chain: Promise<unknown> = Promise.resolve();
  createInterface({ input }).on('line', (line) => { chain = chain.then(() => handleLine(line)).catch((e) => log(`error: ${e?.message ?? e}`)); })
    .on('close', () => { chain = chain.then(() => void child.stdin.end()); });

  createInterface({ input: child.stdout }).on('line', (line) => {
    let msg: any;
    try { msg = JSON.parse(line); } catch { log('dropped a non-JSON line from the server'); return; }
    const p = msg && !Array.isArray(msg) && msg.id !== undefined ? pending.get(msg.id) : undefined;
    if (p && msg.result) {
      pending.delete(msg.id);
      if (p.method === 'tools/list' && Array.isArray(msg.result.tools)) {
        const tools = msg.result.tools as ToolDef[];
        const manifest = { servers: [{ name: 'server', tools }] };
        const report = scanManifest(manifest);
        const bad = new Set(report.findings.filter((f) => f.severity === 'critical' || f.severity === 'high').map((f) => f.tool));
        for (const f of report.findings) log(`scan ${f.severity} ${f.rule} ${f.tool}: ${f.title}`);
        if (opts.lockPath) {
          if (existsSync(opts.lockPath)) {
            const d = verifyLock(manifest, JSON.parse(readFileSync(opts.lockPath, 'utf8')));
            for (const k of [...d.changed, ...d.added]) { bad.add(k.replace(/^server\//, '')); log(`lockfile drift: ${k}`); }
          } else { writeFileSync(opts.lockPath, JSON.stringify(createLock(manifest), null, 2) + '\n'); log(`pinned ${tools.length} tools in ${opts.lockPath}`); }
        }
        guard.policy.tools = { ...inferPolicy(tools), ...(opts.tools ?? {}) };
        hidden = hide ? bad : new Set();
        listed = true;
        if (hidden.size) { msg.result.tools = tools.filter((t) => !hidden.has(t.name)); log(`hid ${hidden.size} tool(s): ${[...hidden].join(', ')}`); }
        return toClient(msg);
      }
      if (p.method === 'tools/call' && p.tool) guard.observe(p.tool, resultText(msg.result));
    } else if (p) pending.delete(msg.id);
    toClient(msg);
  });

  child.on('exit', (code) => { output.end(); if (output === process.stdout) process.exit(code ?? 0); });
  return { child, guard };
}
