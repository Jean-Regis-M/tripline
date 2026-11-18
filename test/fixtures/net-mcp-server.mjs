// A real MCP server over stdio whose tools perform REAL network I/O (HTTP). Used to prove end to end that
// Tripline stops a secret before it reaches the network. Not a mock: http_post opens a real socket.
import { createInterface } from 'node:readline';
import { readFileSync } from 'node:fs';

const tools = [
  { name: 'read_file', description: 'Read a local text file.', inputSchema: { type: 'object', properties: { path: { type: 'string' } } } },
  { name: 'http_post', description: 'POST text to a URL.', inputSchema: { type: 'object', properties: { url: { type: 'string' }, body: { type: 'string' } } } },
  { name: 'http_get', description: 'GET a URL and return the text.', inputSchema: { type: 'object', properties: { url: { type: 'string' } } } },
];
const reply = (id, result) => process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n');
const text = (t) => ({ content: [{ type: 'text', text: t }] });

createInterface({ input: process.stdin }).on('line', async (line) => {
  const m = JSON.parse(line);
  if (m.method === 'initialize') return reply(m.id, { protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'net-fixture', version: '1' } });
  if (m.method === 'tools/list') return reply(m.id, { tools });
  if (m.method !== 'tools/call') return;
  const { name, arguments: a = {} } = m.params;
  try {
    if (name === 'read_file') return reply(m.id, text(readFileSync(a.path, 'utf8')));
    if (name === 'http_post') { const r = await fetch(a.url, { method: 'POST', body: a.body }); return reply(m.id, text(`POST ${r.status}`)); }
    if (name === 'http_get') { const r = await fetch(a.url); return reply(m.id, text(await r.text())); }
  } catch (e) { return reply(m.id, { isError: true, content: [{ type: 'text', text: String(e.message) }] }); }
});
