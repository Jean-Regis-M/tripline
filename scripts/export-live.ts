// Turns raw live experiment runs into the data the web page shows, and scrubs personal paths on the way.
// Usage: node scripts/export-live.ts <transcripts.json> [more raw result files...]
//   writes  docs/live-results/transcripts.json   (sanitised copy of the runs that carry full transcripts)
//           web/data/real-runs.json              (summary table + one unprotected and one protected run to replay)
// Every file passed in is counted in the summary; only runs with a transcript can be replayed.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertClean, scrub } from '../src/scrub.ts';

interface Event { kind: string; [k: string]: unknown }
interface Run { model: string; attack?: string; run: number; protectedRun: boolean; leaked: boolean; blockedCalls: number; calls: string[]; final: string; transcript?: Event[] }

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const files = process.argv.slice(2);
if (!files.length) { console.error('usage: export-live.ts <results.json>...'); process.exit(2); }
const runs: Run[] = files.flatMap((f) => (JSON.parse(readFileSync(f, 'utf8')) as Run[]).map((r) => ({ ...r, attack: r.attack ?? 'hidden' })));

// Summary: every completed run, grouped by model and injection style.
const groups = new Map<string, Run[]>();
for (const r of runs) groups.set(`${r.model}|${r.attack}`, [...(groups.get(`${r.model}|${r.attack}`) ?? []), r]);
const summary = [...groups].sort().map(([k, rs]) => {
  const [model, attack] = k.split('|');
  const off = rs.filter((r) => !r.protectedRun), on = rs.filter((r) => r.protectedRun);
  return { model, attack, unprotected: { leaked: off.filter((r) => r.leaked).length, total: off.length }, protected: { leaked: on.filter((r) => r.leaked).length, blocked: on.filter((r) => r.blockedCalls > 0).length, total: on.length } };
});

// Replays: the first attack style that has BOTH a leaking unprotected run and a blocked protected run with transcripts.
const withT = runs.filter((r) => r.transcript?.length);
let pair: [Run, Run] | undefined;
for (const attack of ['visible', 'user-claim', 'operator', 'hidden']) {
  const leak = withT.find((r) => r.attack === attack && !r.protectedRun && r.leaked);
  const block = withT.find((r) => r.attack === attack && r.protectedRun && !r.leaked && r.blockedCalls > 0);
  if (leak && block) { pair = [leak, block]; break; }
}
if (!pair) { console.error('no unprotected leak and protected block pair with transcripts yet'); process.exit(1); }

const slim = (r: Run) => ({ model: r.model, attack: r.attack, protectedRun: r.protectedRun, leaked: r.leaked, transcript: r.transcript });
const data = { recordedOn: new Date().toISOString().slice(0, 10), summary, runs: pair.map(slim) };
const out = scrub(JSON.stringify(data, null, 1));
const copy = scrub(JSON.stringify(withT.map((r) => ({ ...r })), null, 1));
assertClean(out); assertClean(copy);
mkdirSync(resolve(root, 'web/data'), { recursive: true });
writeFileSync(resolve(root, 'web/data/real-runs.json'), out);
writeFileSync(resolve(root, 'docs/live-results/transcripts.json'), copy);
const total = runs.length;
console.log(`exported ${total} runs (${withT.length} with transcripts); replaying "${pair[0].attack}" from ${pair[0].model}`);
