// A minimal tool-use agent loop over the Anthropic Messages API and a stdio MCP server.
// Used to test Tripline with a REAL language model (set ANTHROPIC_API_KEY) or, in tests, with a local stand-in API.
import { spawn, type ChildProcess } from 'node:child_process';
import { createInterface } from 'node:readline';

export interface McpTool { name: string; description?: string; inputSchema?: unknown }
export interface McpClient {
  list(): Promise<McpTool[]>;
  call(name: string, args: Record<string, unknown>): Promise<{ text: string; isError: boolean }>;
  close(): void;
}

export function mcpOverStdio(command: string, args: string[], env: NodeJS.ProcessEnv = process.env): McpClient {
  const p: ChildProcess = spawn(command, args, { stdio: ['pipe', 'pipe', 'inherit'], env });
  const waiters = new Map<number, (m: any) => void>();
  createInterface({ input: p.stdout! }).on('line', (l) => { try { const m = JSON.parse(l); waiters.get(m.id)?.(m); } catch { /* ignore non JSON */ } });
  let n = 0;
  const rpc = (method: string, params?: unknown) => new Promise<any>((resolve, reject) => {
    const id = ++n; const t = setTimeout(() => reject(new Error(`MCP timeout: ${method}`)), 30000);
    waiters.set(id, (m) => { clearTimeout(t); resolve(m); });
    p.stdin!.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
  let ready: Promise<unknown> | undefined;
  const init = () => (ready ??= rpc('initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'tripline-live', version: '1' } })
    .then(() => p.stdin!.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n')));
  return {
    async list() { await init(); return (await rpc('tools/list')).result?.tools ?? []; },
    async call(name, args) {
      await init();
      const r = await rpc('tools/call', { name, arguments: args });
      if (r.error) return { text: r.error.message, isError: true };
      const text = (r.result?.content ?? []).map((c: any) => c.text ?? `[${c.type}]`).join('\n');
      return { text, isError: !!r.result?.isError };
    },
    close() { p.kill(); },
  };
}

/** POST with retry on rate limits and transient server errors (429, 5xx), with exponential backoff. */
async function postWithRetry(url: string, init: RequestInit, attempts = 6): Promise<Response> {
  let last: Response | undefined;
  for (let i = 0; i < attempts; i++) {
    last = await fetch(url, init);
    if (last.status !== 429 && last.status < 500) return last;
    await new Promise((r) => setTimeout(r, Math.min(30000, 1500 * 2 ** i)));
  }
  return last!;
}

export type Provider = 'anthropic' | 'gemini';
export interface AgentOptions { baseUrl: string; apiKey: string; model: string; task: string; client: McpClient; maxTurns?: number; provider?: Provider }
export interface AgentCall { name: string; args: Record<string, unknown>; blocked: boolean; result: string }
export interface AgentResult { calls: AgentCall[]; final: string; turns: number }

/** Gemini's function declarations accept an OpenAPI subset of JSON Schema, so everything else is dropped. */
const GEMINI_SCHEMA_KEYS = new Set(['type', 'format', 'description', 'nullable', 'enum', 'items', 'properties', 'required', 'minimum', 'maximum', 'minItems', 'maxItems', 'title']);
export function geminiSchema(s: any): any {
  if (Array.isArray(s)) return s.map(geminiSchema);
  if (!s || typeof s !== 'object') return s;
  const out: any = {};
  for (const [k, v] of Object.entries(s)) {
    if (k === 'properties') out.properties = Object.fromEntries(Object.entries(v as object).map(([n, p]) => [n, geminiSchema(p)]));
    else if (GEMINI_SCHEMA_KEYS.has(k)) out[k] = k === 'items' ? geminiSchema(v) : v;
  }
  if (typeof out.type === 'string') out.type = out.type.toLowerCase();
  return out;
}

async function runGeminiAgent(o: AgentOptions): Promise<AgentResult> {
  const mcpTools = await o.client.list();
  const declarations = mcpTools.map((t) => {
    const params = geminiSchema(t.inputSchema ?? {});
    const hasProps = params && params.properties && Object.keys(params.properties).length > 0;
    return { name: t.name, description: t.description ?? '', ...(hasProps ? { parameters: { type: 'object', ...params } } : {}) };
  });
  const contents: any[] = [{ role: 'user', parts: [{ text: o.task }] }];
  const calls: AgentCall[] = [];
  let final = '';
  for (let turn = 1; turn <= (o.maxTurns ?? 8); turn++) {
    const res = await postWithRetry(`${o.baseUrl}/v1beta/models/${o.model}:generateContent`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-goog-api-key': o.apiKey },
      body: JSON.stringify({ contents, tools: [{ functionDeclarations: declarations }] }),
    });
    if (!res.ok) throw new Error(`Gemini API ${res.status}: ${(await res.text()).replace(o.apiKey, '[key]').slice(0, 300)}`);
    const body: any = await res.json();
    const cand = body.candidates?.[0];
    if (!cand?.content) return { calls, final: final || `[no candidate: ${body.promptFeedback?.blockReason ?? cand?.finishReason ?? 'empty'}]`, turns: turn };
    contents.push(cand.content); // echo the model turn back unchanged (keeps thought signatures intact)
    const parts: any[] = cand.content.parts ?? [];
    final = parts.filter((p) => typeof p.text === 'string' && !p.thought).map((p) => p.text).join('\n') || final;
    const uses = parts.filter((p) => p.functionCall);
    if (!uses.length) return { calls, final, turns: turn };
    const responses: any[] = [];
    for (const p of uses) {
      const { name, args = {}, id } = p.functionCall;
      const r = await o.client.call(name, args);
      calls.push({ name, args, blocked: r.isError && /Blocked by Tripline/.test(r.text), result: r.text.slice(0, 200) });
      responses.push({ functionResponse: { name, ...(id ? { id } : {}), response: r.isError ? { error: r.text } : { result: r.text } } });
    }
    contents.push({ role: 'user', parts: responses });
  }
  return { calls, final, turns: o.maxTurns ?? 8 };
}

export async function runAgent(o: AgentOptions): Promise<AgentResult> {
  if (o.provider === 'gemini') return runGeminiAgent(o);
  const tools = (await o.client.list()).map((t) => ({ name: t.name, description: t.description ?? '', input_schema: t.inputSchema ?? { type: 'object', properties: {} } }));
  const messages: any[] = [{ role: 'user', content: o.task }];
  const calls: AgentCall[] = [];
  let final = '';
  for (let turn = 1; turn <= (o.maxTurns ?? 8); turn++) {
    const res = await postWithRetry(`${o.baseUrl}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': o.apiKey, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: o.model, max_tokens: 1024, tools, messages }),
    });
    if (!res.ok) throw new Error(`Messages API ${res.status}: ${(await res.text()).slice(0, 300)}`);
    const body: any = await res.json();
    messages.push({ role: 'assistant', content: body.content });
    final = (body.content as any[]).filter((b) => b.type === 'text').map((b) => b.text).join('\n') || final;
    const uses = (body.content as any[]).filter((b) => b.type === 'tool_use');
    if (!uses.length) return { calls, final, turns: turn };
    const results = [];
    for (const u of uses) {
      const r = await o.client.call(u.name, u.input ?? {});
      calls.push({ name: u.name, args: u.input ?? {}, blocked: r.isError && /Blocked by Tripline/.test(r.text), result: r.text.slice(0, 200) });
      results.push({ type: 'tool_result', tool_use_id: u.id, content: r.text, is_error: r.isError });
    }
    messages.push({ role: 'user', content: results });
  }
  return { calls, final, turns: o.maxTurns ?? 8 };
}
