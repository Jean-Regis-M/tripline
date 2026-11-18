// Renders the two cover images from HTML using the real hero SVG styling. Usage: node scripts/thumbnails.mjs <outDir>
import { chromium } from 'playwright-core';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';

const out = resolve(process.argv[2] ?? '../deliverables');
mkdirSync(out, { recursive: true });

const css = `
*{box-sizing:border-box;margin:0}
body{width:var(--w);height:var(--h);background:#0b0f14;color:#e8eef4;font-family:"Segoe UI",Inter,system-ui,sans-serif;position:relative;overflow:hidden}
.glow{position:absolute;inset:0;background:radial-gradient(700px 420px at 85% 0%,rgba(255,93,74,.30),transparent 70%),radial-gradient(600px 400px at 0% 100%,rgba(124,196,255,.18),transparent 70%)}
.wrap{position:relative;height:100%;padding:var(--pad);display:grid;grid-template-columns:1.1fr .9fr;gap:40px;align-items:center}
.logo{display:flex;align-items:center;gap:14px;font-weight:800;font-size:var(--logo);letter-spacing:-.01em}
.logo i{width:var(--lg);height:var(--lg);border-radius:20%;background:#ff5d4a;display:grid;place-items:center}
h1{font-size:var(--h1);line-height:1.02;letter-spacing:-.035em;font-weight:850;margin:22px 0 18px}
h1 em{font-style:normal;color:#ff5d4a}h1 b{color:#3ddc97}
p{font-size:var(--p);color:#93a1b0;line-height:1.35;max-width:22em}
.tag{display:inline-block;margin-top:24px;padding:9px 18px;border:1px solid #2a3846;border-radius:999px;color:#c7d2de;font-size:var(--tag);background:#0f151c}
.card{background:linear-gradient(180deg,#121a23,#0f151c);border:1px solid #1f2b37;border-radius:26px;padding:26px}
.row{display:flex;justify-content:space-between;align-items:center;padding:14px 18px;border:1px solid #1f2b37;border-left:5px solid;border-radius:14px;margin-bottom:12px;font-size:var(--row);background:#0b0f14}
.row span{font-family:Consolas,monospace;color:#93a1b0}.row b{font-size:.8em;padding:3px 12px;border-radius:999px;border:1px solid}
.ok{border-left-color:#3ddc97}.ok b{color:#3ddc97}.no{border-left-color:#ff5d4a;background:#2a1519}.no b{color:#ff5d4a}
`;
const body = (v) => `
<div class="glow"></div>
<div class="wrap">
  <div>
    <div class="logo"><i><svg width="60%" viewBox="0 0 32 32"><path d="M6 23 L13 9 L19 18 L26 7" fill="none" stroke="#0b0f14" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round"/></svg></i>Tripline</div>
    <h1>Stop AI agents from <em>leaking</em> your secrets.</h1>
    <p>An information-flow firewall for agent tool calls. ${v === 'yt' ? '' : 'Scanner, lockfile and runtime guard in one open source engine.'}</p>
    <div class="tag">${v === 'yt' ? 'Live attack demo &middot; 2:30' : 'GenHacks 2026 &middot; AI, Agentic Systems and Cybersecurity'}</div>
  </div>
  <div class="card">
    <div class="row ok"><span>read_inbox</span><b>ALLOW</b></div>
    <div class="row ok"><span>read_file ~/.aws/credentials</span><b>ALLOW</b></div>
    <div class="row no"><span>send_email attacker@evil.test</span><b>BLOCKED</b></div>
    <div class="row ok"><span>send_email me@student.test</span><b>ALLOW</b></div>
  </div>
</div>`;

const browser = await chromium.launch({ executablePath: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });
for (const [name, w, h, vars, v] of [
  ['tripline-youtube-thumbnail.png', 1280, 720, '--pad:64px;--logo:34px;--lg:48px;--h1:78px;--p:27px;--tag:22px;--row:21px', 'yt'],
  ['tripline-devpost-thumbnail.png', 1200, 800, '--pad:60px;--logo:32px;--lg:46px;--h1:66px;--p:25px;--tag:20px;--row:19px', 'dp'],
]) {
  const page = await browser.newPage({ viewport: { width: w, height: h } });
  await page.setContent(`<style>:root{--w:${w}px;--h:${h}px;${vars}}${css}</style>${body(v)}`);
  await page.screenshot({ path: `${out}/${name}` });
  await page.close();
}
await browser.close();
console.log('thumbnails written to', out);
