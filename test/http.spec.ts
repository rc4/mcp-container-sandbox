import { env, exports } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { createLink } from '../src/links';

/** Matches MCP_TOKENS in vitest.config.mts. */
const TOKEN = 'test-token-0123456789abcdef';

const rpc = (body: unknown, token = TOKEN) =>
  exports.default.fetch('http://localhost/mcp', {
    method: 'POST',
    headers: {
      // The MCP handler's DNS-rebinding check needs a Host header, which real clients always send.
      'Host': 'localhost',
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      'Accept': 'application/json, text/event-stream',
    },
    body: JSON.stringify(body),
  });

/** Reads the JSON-RPC message from a JSON or single-event SSE response body. */
const parseSse = (body: string) => JSON.parse(body.startsWith('{') ? body : body.split('\ndata: ')[1]!.split('\n')[0]!);

const callTool = (name: string, args: Record<string, unknown>) =>
  rpc({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } });

describe('MCP endpoint', () => {
  it('requires a bearer token', async () => {
    const response = await rpc({ jsonrpc: '2.0', id: 1, method: 'tools/list' }, 'wrong-token');
    expect(response.status).toBe(401);
    expect(response.headers.get('WWW-Authenticate')).toBe('Bearer');
  });

  it('lists the sandbox tools', async () => {
    const init = await rpc({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } },
    });
    expect(init.status).toBe(200);
    expect(await init.text()).toContain('container-sandbox');

    const response = await rpc({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
    expect(response.status).toBe(200);
    const body = await response.text();
    for (
      const tool of [
        'sandbox_create',
        'sandbox_exec',
        'sandbox_job_list',
        'file_fetch_url',
        'artifact_download_url',
        'sandbox_sinkhole_rules',
        'sandbox_network_log',
      ]
    ) {
      expect(body).toContain(`"${tool}"`);
    }
    // Execution results are structured.
    const tools = parseSse(body).result.tools as { name: string; outputSchema?: { properties: object } }[];
    expect(Object.keys(tools.find((t) => t.name === 'sandbox_exec')!.outputSchema!.properties)).toContain('exitCode');
  });

  it('reports unknown sandboxes as tool errors', async () => {
    const body = await (await callTool('sandbox_status', { name: 'missing' })).text();
    expect(body).toContain('"isError":true');
    expect(body).toContain('sandbox_create');
  });

  it('lists an empty registry', async () => {
    expect(await (await callTool('sandbox_list', {})).text()).toContain('[]');
  });
});

describe('signed artifact links', () => {
  const KEY = 'artifacts/test/links/sample.bin';
  const link = (method: 'GET' | 'PUT', ttl = 60, key = KEY) =>
    createLink(env.LINK_SIGNING_KEY, 'http://localhost', method, key, ttl);

  it('uploads with PUT and downloads with GET', async () => {
    const body = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 0xff]);
    const put = await exports.default.fetch((await link('PUT')).url, {
      method: 'PUT',
      headers: { 'Content-Length': String(body.byteLength) },
      body,
    });
    expect(put.status).toBe(201);

    const get = await exports.default.fetch((await link('GET')).url);
    expect(get.status).toBe(200);
    expect(get.headers.get('Content-Disposition')).toBe('attachment; filename="sample.bin"');
    expect(get.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(new Uint8Array(await get.arrayBuffer())).toEqual(body);
  });

  it('rejects tampered, mismatched and expired links', async () => {
    const { url } = await link('GET');
    expect((await exports.default.fetch(url.replace('sample.bin', 'other.bin'))).status).toBe(403);
    expect((await exports.default.fetch(url.replace(/sig=[^&]+/, 'sig=AAAA'))).status).toBe(403);
    // A download link cannot be used to upload.
    expect((await exports.default.fetch(url, { method: 'PUT', body: 'x' })).status).toBe(403);
    expect((await exports.default.fetch((await link('GET', -1)).url)).status).toBe(403);
  });

  it('encodes keys with special characters', async () => {
    const key = 'artifacts/test/links/report #1 (final).txt';
    const up = await link('PUT', 60, key);
    expect(up.url).not.toContain(' ');
    const put = await exports.default.fetch(up.url, { method: 'PUT', headers: { 'Content-Length': '2' }, body: 'ok' });
    expect(put.status).toBe(201);
    expect(await (await exports.default.fetch((await link('GET', 60, key)).url)).text()).toBe('ok');
  });
});
