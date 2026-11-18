# Third party tools and acknowledgements

| Tool | Use | License |
|---|---|---|
| Node.js | Runtime and test runner | MIT |
| TypeScript | Type checking and browser build (dev only) | Apache 2.0 |
| playwright-core | Driving Microsoft Edge to take screenshots and record the demo (dev only) | Apache 2.0 |
| Microsoft Edge | Headless browser for capture | Proprietary, not redistributed |
| FFmpeg | Encoding the demo video (dev only) | LGPL or GPL, not redistributed |
| Windows speech synthesis (Microsoft Zira) | Demo narration | Not redistributed |
| Google Gemini API (gemini-3.1-flash-lite, gemini-3-flash-preview) | Live prompt injection experiment only (`scripts/live-agent.ts`), using the author's own API key supplied through an environment variable and never stored | Google API terms |
| Claude Code (Anthropic) | AI assisted development, disclosed per hackathon rules | n/a |

The runtime engine and the web app use no third party code and no external network requests.

## Ideas credited

* Debenedetti et al., *Defeating Prompt Injections by Design* (CaMeL), arXiv 2503.18813.
* Simon Willison, the "lethal trifecta" framing.
* OWASP Top 10 for LLM Applications, prompt injection.
* Public write ups on MCP tool poisoning and rug pull attacks.
