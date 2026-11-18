// Turns raw live experiment outcomes (the --out files of scripts/live-agent.ts) into a markdown table.
// Usage: node scripts/summarise-live.ts results1.json [results2.json ...]
// Runs that errored (quota, overload) never reach the JSON, so every counted run completed.
import { readFileSync } from 'node:fs';

interface Outcome { model: string; attack: string; run: number; protectedRun: boolean; leaked: boolean; blockedCalls: number; calls: string[] }
// Runs recorded before injection styles existed carry no "attack" field: they all used the original hidden-text injection.
const rows: Outcome[] = process.argv.slice(2).flatMap((f) => (JSON.parse(readFileSync(f, 'utf8')) as Outcome[]).map((o) => ({ ...o, attack: o.attack ?? 'hidden' })));
if (!rows.length) { console.error('usage: summarise-live.ts <results.json>...'); process.exit(2); }

const key = (o: Outcome) => `${o.model}|${o.attack}`;
const groups = new Map<string, Outcome[]>();
for (const o of rows) groups.set(key(o), [...(groups.get(key(o)) ?? []), o]);

console.log('| Model | Injection style | Unprotected: secret leaked | Behind Tripline: secret leaked | Behind Tripline: call blocked |');
console.log('|---|---|:---:|:---:|:---:|');
let u = [0, 0], p = [0, 0], b = [0, 0];
for (const [k, os] of [...groups].sort()) {
  const [model, attack] = k.split('|');
  const off = os.filter((o) => !o.protectedRun), on = os.filter((o) => o.protectedRun);
  const lo = off.filter((o) => o.leaked).length, lp = on.filter((o) => o.leaked).length, bl = on.filter((o) => o.blockedCalls > 0).length;
  u = [u[0] + lo, u[1] + off.length]; p = [p[0] + lp, p[1] + on.length]; b = [b[0] + bl, b[1] + on.length];
  console.log(`| \`${model}\` | ${attack} | ${lo} of ${off.length} | ${lp} of ${on.length} | ${bl} of ${on.length} |`);
}
console.log(`| **All completed runs** | | **${u[0]} of ${u[1]}** | **${p[0]} of ${p[1]}** | **${b[0]} of ${b[1]}** |`);
