// Renders the two cover images from HTML. Usage: node scripts/thumbnails.mjs <outDir>
import { chromium } from 'playwright-core';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';

const out = resolve(process.argv[2] ?? '../deliverables');
mkdirSync(out, { recursive: true });

const css = `
*{box-sizing:border-box;margin:0}
body{width:var(--w);height:var(--h);background:#f4f0e6;color:#15130f;font-family:"Segoe UI",system-ui,sans-serif;position:relative;overflow:hidden}
.frame{position:absolute;inset:var(--inset);border:2px solid #15130f}
.wrap{position:relative;height:100%;padding:var(--pad);display:grid;grid-template-columns:1.15fr .85fr;gap:44px;align-items:center}
.logo{display:flex;align-items:center;gap:14px;font:700 var(--logo) Georgia,"Palatino Linotype",serif}
.kick{font:600 var(--kick) Consolas,monospace;letter-spacing:.14em;text-transform:uppercase;color:#655f53;margin-bottom:22px}
h1{font:700 var(--h1)/1.02 Georgia,"Palatino Linotype",serif;letter-spacing:-.03em;margin:24px 0 20px}
h1 em{font-style:italic;color:#d8391b}
p{font:400 var(--p)/1.35 Georgia,serif;color:#3b372f;max-width:21em}
.rule{height:4px;width:90px;background:#d8391b;margin-top:26px}
.ledger{border:2px solid #15130f;background:#faf7ef}
.row{display:flex;justify-content:space-between;align-items:center;padding:16px 18px;border-bottom:1px solid #d5cdb9;font:var(--row) Consolas,monospace}
.row:last-child{border-bottom:0}.row b{font-size:.78em;letter-spacing:.1em}
.ok b{color:#1f6f4a}.no{background:#f6dfd6;box-shadow:inset 6px 0 0 #d8391b}.no b{color:#d8391b}
.stamp{position:absolute;right:calc(var(--pad) - 6px);bottom:calc(var(--pad) - 14px);font:700 var(--stamp) Consolas,monospace;letter-spacing:.12em;color:#d8391b;border:4px solid #d8391b;padding:6px 18px;transform:rotate(-6deg);background:rgba(244,240,230,.85)}
`;
const mark = `<svg width="var(--mk)" height="var(--mk)" viewBox="0 0 32 32" style="width:var(--mk);height:var(--mk)"><rect x="3" y="19" width="4" height="9" fill="#15130f"/><rect x="25" y="19" width="4" height="9" fill="#15130f"/><path d="M7 21.5 L13.5 21.5 L16 6 L18.5 21.5 L25 21.5" fill="none" stroke="#d8391b" stroke-width="2.4"/></svg>`;
const body = (v) => `
<div class="frame"></div>
<div class="wrap">
  <div>
    <div class="logo">${mark}Tripline</div>
    <h1>Agents obey text.<br>We decide what they <em>may do</em>.</h1>
    <p>${v === 'yt' ? 'A firewall for AI agent tool calls. Watch a stolen key get stopped.' : 'An information flow firewall and MCP scanner for AI agents. Open source, tested, live.'}</p>
    <div class="rule"></div>
  </div>
  <div class="ledger">
    <div class="row ok"><span>read_inbox</span><b>ALLOW</b></div>
    <div class="row ok"><span>read_file ~/.aws/credentials</span><b>ALLOW</b></div>
    <div class="row no"><span>send_email attacker@evil.test</span><b>DENY</b></div>
    <div class="row ok"><span>send_email me@student.test</span><b>ALLOW</b></div>
  </div>
</div>
<div class="stamp">BLOCKED</div>`;

const browser = await chromium.launch({ executablePath: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });
for (const [name, w, h, vars, v] of [
  ['tripline-youtube-thumbnail.png', 1280, 720, '--inset:22px;--pad:70px;--logo:40px;--mk:52px;--h1:74px;--p:28px;--kick:16px;--row:20px;--stamp:44px', 'yt'],
  ['tripline-devpost-thumbnail.png', 1200, 800, '--inset:20px;--pad:64px;--logo:38px;--mk:50px;--h1:66px;--p:26px;--kick:15px;--row:19px;--stamp:40px', 'dp'],
]) {
  const page = await browser.newPage({ viewport: { width: w, height: h } });
  await page.setContent(`<style>:root{--w:${w}px;--h:${h}px;${vars}}${css}</style>${body(v)}`);
  await page.screenshot({ path: `${out}/${name}` });
  await page.close();
}
await browser.close();
console.log('thumbnails written to', out);
