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

export interface AgentOptions { baseUrl: string; apiKey: string; model: string; task: string; client: McpClient; maxTurns?: number }
export interface AgentCall { name: string; args: Record<string, unknown>; blocked: boolean; result: string }
export interface AgentResult { calls: AgentCall[]; final: string; turns: number }

export async function runAgent(o: AgentOptions): Promise<AgentResult> {
  const tools = (await o.client.list()).map((t) => ({ name: t.name, description: t.description ?? '', input_schema: t.inputSchema ?? { type: 'object', properties: {} } }));
  const messages: any[] = [{ role: 'user', content: o.task }];
  const calls: AgentCall[] = [];
  let final = '';
  for (let turn = 1; turn <= (o.maxTurns ?? 8); turn++) {
    const res = await fetch(`${o.baseUrl}/v1/messages`, {
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
