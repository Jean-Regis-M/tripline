// Records the Arena in action and converts it to an animated GIF. Usage: node scripts/arena-gif.mjs [baseUrl] [out.gif]
import { chromium } from 'playwright-core';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const base = process.argv[2] ?? 'http://localhost:3000/';
const out = resolve(process.argv[3] ?? fileURLToPath(new URL('../docs/images/arena.gif', import.meta.url)));
const dir = mkdtempSync(join(tmpdir(), 'arena-gif-'));

const browser = await chromium.launch({ executablePath: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });
const ctx = await browser.newContext({ viewport: { width: 1280, height: 760 }, colorScheme: 'light', recordVideo: { dir, size: { width: 1280, height: 760 } } });
const page = await ctx.newPage();
await page.goto(base, { waitUntil: 'networkidle' });
await page.addStyleTag({ content: '.top{position:static!important}' });
await page.evaluate(() => { document.querySelector('#arena').scrollIntoView(); scrollBy(0, 60); });
const wait = (ms) => page.waitForTimeout(ms);
const send = async (id, hold = 1500) => { await page.locator(`#presets [data-id="${id}"]`).click(); await wait(500); await page.locator('#sendBtn').click(); await wait(hold); };
await wait(900);
const t0 = Date.now();
await send('plain'); await send('base64'); await send('rot13'); await send('spaced', 1200);
await send('codewords', 2200);
await page.locator('#tUnt').check(); await wait(1700);
await page.locator('#sendBtn').click(); await wait(1800);
await page.locator('#tUnt').uncheck(); await page.locator('#tProv').uncheck(); await wait(900);
await send('rot13', 2200);
await ctx.close(); await browser.close();

const webm = join(dir, readdirSync(dir).find((f) => f.endsWith('.webm')));
const r = spawnSync('ffmpeg', ['-y', '-v', 'error', '-i', webm, '-vf', 'fps=7,scale=820:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=48:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle', out], { stdio: 'inherit' });
if (r.status !== 0) process.exit(r.status ?? 1);
console.log('wrote', out, `(${((Date.now() - t0) / 1000).toFixed(0)}s of activity)`);
