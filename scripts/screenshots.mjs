// Captures real screenshots of the running app. Usage: node scripts/screenshots.mjs [baseUrl]
import { chromium } from 'playwright-core';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const base = process.argv[2] ?? 'http://localhost:3000/';
const outDir = fileURLToPath(new URL('../docs/images/', import.meta.url));
mkdirSync(outDir, { recursive: true });
const edge = 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe';

const browser = await chromium.launch({ executablePath: edge, headless: true });
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, colorScheme: 'light', reducedMotion: 'reduce' });
const page = await ctx.newPage();
await page.goto(base, { waitUntil: 'networkidle' });
await page.mouse.move(2, 2);
const shot = async (name, target) => {
  if (!target) return page.screenshot({ path: `${outDir}${name}.png` });
  await page.mouse.move(2, 2);
  const loc = page.locator(target);
  await loc.evaluate((e) => { e.style.paddingLeft = e.style.paddingRight = '28px'; e.style.paddingBottom = '28px'; });
  await loc.screenshot({ path: `${outDir}${name}.png` });
  await loc.evaluate((e) => { e.style.paddingLeft = e.style.paddingRight = e.style.paddingBottom = ''; });
};

await shot('01-hero');
await shot('02-how-it-works', '#how');
for (const [i, id] of [[3, 'email-injection'], [4, 'encoded-exfil'], [5, 'paraphrased-exfil'], [6, 'benign-forward']]) {
  await page.locator(`#picker button[data-id="${id}"]`).click();
  await shot(`0${i}-replay-${id}`, '#replay');
}
await page.locator('#doScan').click();
await page.locator('#scan').scrollIntoViewIfNeeded();
await shot('07-scanner-blocked', '#scan');
await page.locator('#doLock').click();
await page.locator('#doPull').click();
await page.locator('#doVerify').click();
const drift = await page.locator('#scanOut .verdict').innerText();
if (!/DRIFT/.test(drift)) throw new Error('UI smoke test failed: rug pull was not detected, got: ' + drift);
await shot('08-rug-pull-drift', '#scan');
await page.locator('#picker button[data-id="multi-vector"]').click();
await shot('13-replay-multi-vector', '#replay');
await page.locator('#doDetect').click();
const detected = await page.locator('#detectOut .verdict').innerText();
if (!/BLOCKED/.test(detected)) throw new Error('UI smoke test failed: the detector did not block the mixed sample, got: ' + detected);
await shot('14-detector-mixed', '#detect');
await page.locator('#loadEncoded').click(); await page.locator('#doDetect').click();
await shot('15-detector-encoded', '#detect');
await shot('09-results', '#bench');
await shot('10-limits', '#limits');
const m = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 3, colorScheme: 'light', isMobile: true, reducedMotion: 'reduce' });
const mp = await m.newPage();
await mp.goto(base, { waitUntil: 'networkidle' });
await mp.screenshot({ path: `${outDir}11-mobile-hero.png` });
await mp.locator('#replay').scrollIntoViewIfNeeded();
await mp.screenshot({ path: `${outDir}12-mobile-replay.png` });
const overflow = await mp.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
console.log('mobile horizontal overflow:', overflow);
await browser.close();
