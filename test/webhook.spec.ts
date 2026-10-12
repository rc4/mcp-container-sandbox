import { withEnv } from 'cloudflare:workers';
import { createHmac } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { callbackUrl, postWebhook, sendWebhook, signature, signingKey } from '../src/webhook';

const secret = `whsec_${new Uint8Array(32).fill(7).toBase64()}`;

describe('webhook signing and gateway', () => {
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

  it('rejects invalid callback URLs before contacting the gateway', () => {
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

  it('signs the exact transmitted body with both rotation keys and keeps secrets out of the gateway', async () => {
    const post = vi.fn<
      (
        input: { url: string; headers: Record<string, string>; body: string },
      ) => Promise<{ status: number; body: string }>
    >().mockResolvedValue({ status: 204, body: '' });
    const env = { WEBHOOKS: { getByName: () => ({ post }) } } as unknown as Env;
    await withEnv(env, async () => {
      const oldSecret = `whsec_${new Uint8Array(32).fill(8).toBase64()}`;
      const subscription = {
        id: 'sub_1',
        url: 'https://receiver.example/',
        secret,
        oldSecret,
        rotateUntil: Date.now() + 60_000,
      };
      expect((await sendWebhook(subscription, 'evt_1', { eventId: 'evt_1', data: { text: 'é' } })).status).toBe(204);
      const input = post.mock.calls[0]![0];
      const timestamp = Number(input.headers['webhook-timestamp']);
      expect(input.headers['webhook-id']).toBe('evt_1');
      expect(input.headers['X-MCP-Subscription-Id']).toBe('sub_1');
      expect(input.headers['webhook-signature']).toBe(
        `${await signature(secret, 'evt_1', timestamp, input.body)} ${await signature(
          oldSecret,
          'evt_1',
          timestamp,
          input.body,
        )}`,
      );
      expect(JSON.stringify(input)).not.toContain(secret);
      expect(JSON.stringify(input)).not.toContain(oldSecret);
      await expect(sendWebhook(subscription, 'evt_2', { data: 'x'.repeat(262_144) })).rejects.toThrow('256 KiB');
    });
  });

  it('preserves categorized gateway timeouts', async () => {
    const env = { WEBHOOKS: { getByName: () => ({ post: async () => ({ error: 'timeout' }) }) } } as unknown as Env;
    await withEnv(env, async () => {
      await expect(postWebhook('https://receiver.example/', {}, '{}')).rejects.toMatchObject({ name: 'TimeoutError' });
    });
  });
});
