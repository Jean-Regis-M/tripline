import { spawn } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanManifest } from './scanner.ts';
import { createLock, verifyLock } from './pin.ts';
import { runProxy } from './proxy.ts';
import { verifyChain } from './audit.ts';
import { unwrapConfig, wrapConfig } from './wrap.ts';
import type { Manifest } from './types.ts';

const argv = process.argv.slice(2);
const usage = (): never => {
  console.error([
    'usage:',
    '  tripline wrap <mcp-config.json> [--allow a.com,b@c.org] [--approve-cmd "<cmd>"] [--dry-run] [--out file]',
    '  tripline unwrap <mcp-config.json>',
    '  tripline proxy [--allow ...] [--policy policy.json] [--lock file] [--audit-log file] [--approve-cmd "<cmd>"] -- <server command> [args]',
    '  tripline verify-log <audit.jsonl> [--anchor <head hash>]',
    '  tripline scan|lock|verify <manifest.json> [lockfile]',
  ].join('\n'));
  process.exit(2);
};
const load = (f: string) => JSON.parse(readFileSync(f, 'utf8'));

/**
 * Human approval for rule R2 without sharing the proxy's stdin: run a command you control (a desktop dialog,
 * a chat bot, a ticket check). Exit code 0 approves. Any other exit code, a crash or a timeout denies (fail closed).
 * The command sees TRIPLINE_TOOL, TRIPLINE_RULES and TRIPLINE_ARGS (JSON, truncated) in its environment.
 */
function approvalCommand(command: string) {
  return (tool: string, args: Record<string, unknown>, verdict: { rules: { id: string }[] }) => new Promise<boolean>((resolve) => {
    const child = spawn(command, { shell: true, stdio: 'ignore', env: { ...process.env, TRIPLINE_TOOL: tool, TRIPLINE_RULES: verdict.rules.map((r) => r.id).join(','), TRIPLINE_ARGS: JSON.stringify(args).slice(0, 4000) } });
    const timer = setTimeout(() => { child.kill(); resolve(false); }, 60_000);
    child.on('error', () => { clearTimeout(timer); resolve(false); });
    child.on('exit', (code) => { clearTimeout(timer); resolve(code === 0); });
  });
}

if (argv[0] === 'proxy') {
  const sep = argv.indexOf('--');
  if (sep < 0 || sep === argv.length - 1) usage();
  const flags = argv.slice(1, sep);
  const get = (name: string) => { const i = flags.indexOf(name); return i >= 0 ? flags[i + 1] : undefined; };
  const policy = get('--policy') ? load(get('--policy')!) : {};
  runProxy({
    command: argv[sep + 1], args: argv.slice(sep + 2),
    allowedDestinations: [...(get('--allow')?.split(',').filter(Boolean) ?? []), ...(policy.allowedDestinations ?? [])],
    tools: policy.tools,
    lockPath: get('--lock'),
    auditPath: get('--audit-log'),
    approve: get('--approve-cmd') ? approvalCommand(get('--approve-cmd')!) : undefined,
  });
} else if (argv[0] === 'wrap' || argv[0] === 'unwrap') {
  const file = argv[1];
  if (!file) usage();
  const flag = (n: string) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
  const config = JSON.parse(readFileSync(file, 'utf8'));
  const outPath = flag('--out') ?? file;
  const backup = `${file}.tripline-backup`;
  const save = (data: unknown) => {
    if (outPath === file && !existsSync(backup)) copyFileSync(file, backup);
    writeFileSync(outPath, JSON.stringify(data, null, 2) + '\n');
  };
  if (argv[0] === 'wrap') {
    const stateDir = resolve(dirname(file), 'tripline-state');
    const { config: wrapped, report } = wrapConfig(config, {
      node: process.execPath, cli: fileURLToPath(new URL('./cli.ts', import.meta.url)), stateDir,
      allow: flag('--allow')?.split(',').filter(Boolean) ?? [], approveCmd: flag('--approve-cmd'),
    });
    for (const n of report.wrapped) console.log(`  wrapped   ${n}`);
    for (const n of report.alreadyWrapped) console.log(`  already   ${n}`);
    for (const s of report.skipped) console.log(`  skipped   ${s.name}: ${s.reason}`);
    if (argv.includes('--dry-run')) console.log('\ndry run: nothing was written.');
    else {
      if (report.wrapped.length) mkdirSync(stateDir, { recursive: true });
      save(wrapped);
      console.log(`\nwrote ${outPath}${outPath === file ? ` (backup: ${backup})` : ''}\nlockfiles and audit logs: ${stateDir}\nRestart your MCP client to apply. Undo with: tripline unwrap ${file}`);
    }
  } else {
    const { config: restored, restored: names } = unwrapConfig(config);
    for (const n of names) console.log(`  restored  ${n}`);
    save(restored);
    console.log(`\nwrote ${outPath}`);
  }
} else if (argv[0] === 'verify-log') {
  const file = argv[1];
  if (!file) usage();
  const anchorAt = argv.indexOf('--anchor');
  const r = verifyChain(readFileSync(file, 'utf8').split('\n'), anchorAt >= 0 ? argv[anchorAt + 1] : undefined);
  console.log(r.ok ? `OK: ${r.entries} entries, chain intact.\nhead: ${r.head}` : `BROKEN at entry ${r.brokenAt ?? r.entries}: ${r.reason}`);
  process.exit(r.ok ? 0 : 1);
} else {
  const [cmd, file, lockFile = 'tripline.lock.json'] = argv;
  if (!cmd || !file) usage();
  if (cmd === 'scan') {
    const r = scanManifest(load(file) as Manifest);
    for (const f of r.findings) console.log(`[${f.severity.toUpperCase().padEnd(8)}] ${f.rule} ${f.server}/${f.tool}: ${f.title}${f.evidence ? `\n           > ${f.evidence}` : ''}`);
    console.log(`\nverdict: ${r.verdict.toUpperCase()} (${r.findings.length} findings)`);
    process.exit(r.verdict === 'block' ? 1 : 0);
  } else if (cmd === 'lock') {
    writeFileSync(lockFile, JSON.stringify(createLock(load(file)), null, 2) + '\n');
    console.log(`wrote ${lockFile}`);
  } else if (cmd === 'verify') {
    const d = verifyLock(load(file), load(lockFile));
    console.log(d.ok ? 'OK: manifest matches lockfile' : `DRIFT: changed=${d.changed} added=${d.added} removed=${d.removed}`);
    process.exit(d.ok ? 0 : 1);
  } else usage();
}
