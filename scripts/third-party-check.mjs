// Runs a real third party stdio MCP server twice (directly, then behind Tripline's proxy) and compares.
// Usage: node scripts/third-party-check.mjs <label> <entry.js> [server args...]
// The server must already be installed (for example into a temp folder with `npm install <package>`).
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';

const [label, entry, ...serverArgs] = process.argv.slice(2);
if (!label || !entry) { console.error('usage: third-party-check.mjs <label> <entry.js> [args...]'); process.exit(2); }
const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

function session(viaProxy) {
  const argv = viaProxy ? [cli, 'proxy', '--allow', 'student.test', '--', process.execPath, entry, ...serverArgs] : [entry, ...serverArgs];
  const p = spawn(process.execPath, argv, { stdio: ['pipe', 'pipe', 'pipe'] });
  const stderr = []; p.stderr.on('data', (d) => stderr.push(String(d)));
  const waiters = new Map();
  createInterface({ input: p.stdout }).on('line', (l) => { try { const m = JSON.parse(l); waiters.get(m.id)?.(m); } catch { /* not JSON */ } });
  let n = 0;
  const rpc = (method, params) => new Promise((res, rej) => {
    const id = ++n; const t = setTimeout(() => rej(new Error(`timeout: ${method}`)), 30000);
    waiters.set(id, (m) => { clearTimeout(t); res(m); });
    p.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
  const notify = (method) => p.stdin.write(JSON.stringify({ jsonrpc: '2.0', method }) + '\n');
  return { rpc, notify, stderr, kill: () => p.kill() };
}
const text = (m) => (m.result?.content ?? []).map((c) => c.text ?? `[${c.type}]`).join('\n');

const out = { label, serverArgs: serverArgs.length };
const direct = session(false), proxied = session(true);
try {
  for (const s of [direct, proxied]) {
    await s.rpc('initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'tripline-check', version: '1' } });
    s.notify('notifications/initialized');
  }
  const d = (await direct.rpc('tools/list')).result.tools;
  const x = (await proxied.rpc('tools/list')).result.tools;
  const directNames = d.map((t) => t.name), proxyNames = x.map((t) => t.name);
  out.toolsDirect = d.length; out.toolsThroughProxy = x.length;
  out.hiddenByTripline = directNames.filter((n) => !proxyNames.includes(n));
  out.policyLines = proxied.stderr.join('').split('\n').filter((l) => /scan|hid|drift/.test(l));

  // Replay the read-only tools that need no arguments through both paths and compare.
  const probes = (process.env.PROBES ?? '').split(';').filter(Boolean).map((s) => JSON.parse(s));
  out.probes = [];
  for (const { name, arguments: args } of probes) {
    const a = await direct.rpc('tools/call', { name, arguments: args });
    const b = await proxied.rpc('tools/call', { name, arguments: args });
    out.probes.push({ name, identical: text(a) === text(b), blocked: !!b.result?.isError && !a.result?.isError, preview: text(b).replace(/\s+/g, ' ').slice(0, 70) });
  }
  console.log(JSON.stringify(out, null, 2));
} catch (e) { console.log(JSON.stringify({ ...out, error: e.message, stderr: proxied.stderr.join('').slice(0, 500) }, null, 2)); process.exitCode = 1; }
direct.kill(); proxied.kill();
