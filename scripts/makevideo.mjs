// Records a real walkthrough of the running app, synced to synthesized narration, and muxes an MP4.
// Usage: node scripts/makevideo.mjs <baseUrl> <workDir> <outMp4>   (audio wavs expected in <workDir>/audio)
import { chromium } from 'playwright-core';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, readdirSync, rmSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const [base = 'http://localhost:3000/', work = '../deliverables/work', out = '../deliverables/tripline-demo.mp4'] = process.argv.slice(2);
const W = resolve(work), OUT = resolve(out);
const narration = JSON.parse(readFileSync(fileURLToPath(new URL('./narration.json', import.meta.url)), 'utf8'));
const GAP = 0.45;
const dur = (f) => Number(spawnSync('ffprobe', ['-v', 'error', '-show_entries', 'format=duration', '-of', 'csv=p=0', f]).stdout.toString());
const durations = Object.fromEntries(narration.map((n) => [n.id, dur(join(W, 'audio', `${n.id}.wav`))]));
const total = Object.values(durations).reduce((a, b) => a + b + GAP, 0);
if (total > 175) throw new Error(`video would be ${total}s, over the safe limit`);

rmSync(join(W, 'rec'), { recursive: true, force: true }); mkdirSync(join(W, 'rec'), { recursive: true });
const browser = await chromium.launch({ executablePath: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });
const created = Date.now();
const ctx = await browser.newContext({ viewport: { width: 1920, height: 1080 }, colorScheme: 'light', recordVideo: { dir: join(W, 'rec'), size: { width: 1920, height: 1080 } } });
const page = await ctx.newPage();
await page.addInitScript(() => {
  addEventListener('DOMContentLoaded', () => {
    const c = document.createElement('div');
    c.style.cssText = 'position:fixed;z-index:99999;width:22px;height:22px;border-radius:50%;border:3px solid #fff;background:rgba(255,93,74,.55);pointer-events:none;transform:translate(-50%,-50%);left:-50px;top:-50px;box-shadow:0 0 0 2px rgba(0,0,0,.4)';
    document.body.append(c);
    addEventListener('mousemove', (e) => { c.style.left = e.clientX + 'px'; c.style.top = e.clientY + 'px'; });
  });
});
await page.goto(base, { waitUntil: 'networkidle' });
await page.waitForTimeout(600);
const offset = (Date.now() - created) / 1000;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const glide = async (sel) => { const b = await page.locator(sel).boundingBox(); await page.mouse.move(b.x + b.width / 2, b.y + b.height / 2, { steps: 28 }); };
const click = async (sel) => { await glide(sel); await sleep(250); await page.locator(sel).click(); };
const scrollTo = (sel, pad = 90) => page.evaluate(([s, p]) => { const y = document.querySelector(s).getBoundingClientRect().top + scrollY - p; scrollTo({ top: y, behavior: 'smooth' }); }, [sel, pad]);
const scrollBy = (px) => page.evaluate((p) => scrollBy({ top: p, behavior: 'smooth' }), px);

const replay = (id, extra = []) => [
  [300, () => scrollTo('#replay', 70)],
  [1500, () => click(`#picker button[data-id="${id}"]`)],
  [2800, () => click('#replayBtn')],
  ...extra,
];
const plan = {
  s1: [[3000, () => glide('.cta .primary')]],
  s2: [[500, () => page.mouse.move(1400, 520, { steps: 30 })]],
  s3: [...replay('email-injection', [[10000, () => scrollBy(430)]])],
  s4: replay('encoded-exfil', [[6500, () => scrollBy(380)]]),
  s5: replay('paraphrased-exfil', [[6500, () => scrollBy(380)]]),
  s6: replay('benign-forward', [[4800, () => scrollBy(300)]]),
  s7: [[300, () => scrollTo('#scan', 70)], [1500, () => click('#doScan')], [9500, () => click('#doLock')], [11500, () => click('#doPull')], [13800, () => click('#doVerify')]],
  s8: [[300, () => scrollTo('#bench', 70)], [14000, () => scrollTo('#limits', 70)], [26500, () => scrollTo('#top', 0)]],
};

const captions = []; let clock = 0;
for (const n of narration) {
  const target = (durations[n.id] + GAP) * 1000;
  const t0 = Date.now();
  const steps = (plan[n.id] ?? []).slice();
  const runner = (async () => { for (const [at, fn] of steps) { const wait = t0 + at - Date.now(); if (wait > 0) await sleep(wait); await fn(); } })();
  await Promise.all([runner, sleep(target)]);
  const sentences = n.text.match(/[^.!?]+[.!?]/g) ?? [n.text];
  const totalChars = sentences.reduce((a, s) => a + s.length, 0);
  let t = clock;
  for (const s of sentences) { const d = (s.length / totalChars) * durations[n.id]; captions.push([t, t + d, s.trim()]); t += d; }
  clock += durations[n.id] + GAP;
}
await ctx.close(); await browser.close();

const fmt = (s) => { const ms = Math.round(s * 1000); const p = (n, l = 2) => String(n).padStart(l, '0'); return `${p(Math.floor(ms / 3600000))}:${p(Math.floor(ms / 60000) % 60)}:${p(Math.floor(ms / 1000) % 60)},${p(ms % 1000, 3)}`; };
writeFileSync(join(W, 'captions.srt'), captions.map(([a, b, t], i) => `${i + 1}\n${fmt(a)} --> ${fmt(b)}\n${t}\n`).join('\n'));

const webm = join(W, 'rec', readdirSync(join(W, 'rec')).find((f) => f.endsWith('.webm')));
const inputs = narration.flatMap((n) => ['-i', join(W, 'audio', `${n.id}.wav`)]);
const filt = narration.map((_, i) => `[${i + 1}:a]apad=pad_dur=${GAP}[a${i}]`).join(';') + ';' + narration.map((_, i) => `[a${i}]`).join('') + `concat=n=${narration.length}:v=0:a=1[aud]`;
const style = 'FontName=Segoe UI,FontSize=11,Bold=1,PrimaryColour=&H00FFFFFF,OutlineColour=&H00000000,BackColour=&H80000000,BorderStyle=3,Outline=1,Shadow=0,MarginV=22';
const r = spawnSync('ffmpeg', ['-y', '-ss', String(offset), '-i', webm, ...inputs, '-filter_complex', `${filt}`, '-map', '0:v', '-map', '[aud]',
  '-vf', `fps=30,subtitles=captions.srt:force_style='${style}'`, '-t', String(total), '-c:v', 'libx264', '-crf', '18', '-preset', 'medium', '-pix_fmt', 'yuv420p', '-c:a', 'aac', '-b:a', '160k', '-movflags', '+faststart', OUT],
  { cwd: W, stdio: 'inherit' });
if (r.status !== 0) process.exit(r.status ?? 1);
console.log(`done: ${OUT} (${total.toFixed(1)}s)`);
