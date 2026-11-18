import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { scanManifest } from './scanner.ts';
import { createLock, verifyLock } from './pin.ts';
import { runProxy } from './proxy.ts';
import type { Manifest } from './types.ts';

const argv = process.argv.slice(2);
const usage = (): never => {
  console.error('usage:\n  tripline scan|lock|verify <manifest.json> [lockfile]\n  tripline proxy [--allow a.com,b@c.org] [--policy policy.json] [--lock tripline.lock.json] [--approve-cmd "<command>"] -- <server command> [args]');
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
    approve: get('--approve-cmd') ? approvalCommand(get('--approve-cmd')!) : undefined,
  });
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
