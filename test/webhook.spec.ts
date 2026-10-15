import { createHmac } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { callbackUrl, postWebhook, sendWebhook, signature, signingKey } from '../src/webhook';

const secret = `whsec_${new Uint8Array(32).fill(7).toBase64()}`;

describe('webhook signing and delivery', () => {
  it('uses Standard Webhooks HMAC over the exact id, timestamp and body bytes', async () => {
    const body = '{"data":"é"}';
    const expected = createHmac('sha256', new Uint8Array(32).fill(7)).update(`evt_1.123.${body}`).digest('base64');
    expect(await signature(secret, 'evt_1', 123, body)).toBe(`v1,${expected}`);
    for (
      const value of [
        'bad',
        'whsec_###',
        `whsec_${new Uint8Array(23).toBase64()}`,
        `whsec_${new Uint8Array(65).toBase64()}`,
      ]
    ) {
      expect(() => signingKey(value)).toThrow('Expected whsec_');
    }
  });

  it('rejects invalid callback URLs', () => {
    for (
      const url of [
        'http://example.com/',
        'https://user:pass@example.com/',
        'https://example.com:8443/',
        'https://example.com/#fragment',
      ]
    ) {
      expect(() => callbackUrl(url)).toThrow('Callbacks require HTTPS');
    }
  });

  it('signs the exact transmitted body with both rotation keys', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(null, { status: 204 }));
    const oldSecret = `whsec_${new Uint8Array(32).fill(8).toBase64()}`;
    const subscription = {
      id: 'sub_1',
      url: 'https://receiver.example/',
      secret,
      oldSecret,
      rotateUntil: Date.now() + 60_000,
    };
    expect((await sendWebhook(subscription, 'evt_1', { eventId: 'evt_1', data: { text: 'é' } })).status).toBe(204);
    const [url, init] = fetch.mock.calls[0]!;
    const headers = init!.headers as Record<string, string>;
    const body = init!.body as string;
    const timestamp = Number(headers['webhook-timestamp']);
    expect([url, init!.method, init!.redirect]).toEqual(['https://receiver.example/', 'POST', 'manual']);
    expect(headers['webhook-id']).toBe('evt_1');
    expect(headers['X-MCP-Subscription-Id']).toBe('sub_1');
    expect(headers['webhook-signature']).toBe(
      `${await signature(secret, 'evt_1', timestamp, body)} ${await signature(oldSecret, 'evt_1', timestamp, body)}`,
    );
    await expect(sendWebhook(subscription, 'evt_2', { data: 'x'.repeat(262_144) })).rejects.toThrow('256 KiB');
    fetch.mockRestore();
  });

  it('limits callback responses to 16 KiB', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch');
    fetch.mockResolvedValueOnce(new Response('x'.repeat(16_384)));
    expect(await (await postWebhook('https://receiver.example/', {}, '{}')).text()).toHaveLength(16_384);
    fetch.mockResolvedValueOnce(new Response('x'.repeat(16_385)));
    await expect(postWebhook('https://receiver.example/', {}, '{}')).rejects.toThrow('exceeds 16 KiB');
    expect(fetch).toHaveBeenCalledTimes(2);
    fetch.mockRestore();
  });
});
