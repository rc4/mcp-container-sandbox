import { ProtocolError } from '@modelcontextprotocol/server';

export function callbackUrl(value: string): URL {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || (url.port && url.port !== '443')) {
    throw new ProtocolError(-32602, 'Callbacks require HTTPS on port 443, without credentials or fragments');
  }
  return url;
}

export function signingKey(secret: string): Uint8Array {
  try {
    if (!/^whsec_[A-Za-z0-9+/]+={0,2}$/.test(secret)) throw new Error();
    const key = Uint8Array.fromBase64(secret.slice(6));
    if (key.length < 24 || key.length > 64) throw new Error();
    return key;
  } catch {
    throw new ProtocolError(-32602, 'Expected whsec_ followed by a base64 signing key of 24–64 bytes');
  }
}

export async function signature(secret: string, id: string, timestamp: number, body: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', signingKey(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
  ]);
  const signed = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${id}.${timestamp}.${body}`));
  return `v1,${new Uint8Array(signed).toBase64()}`;
}

const MAX_RESPONSE_BYTES = 16_384;

/**
 * Posts from the Worker. Redirects are returned rather than followed, the whole exchange times out
 * after ten seconds, and the callback's response body is limited to 16 KiB.
 */
export async function postWebhook(url: string, headers: Record<string, string>, body: string): Promise<Response> {
  callbackUrl(url);
  const response = await fetch(url, {
    method: 'POST',
    headers,
    body,
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });
  const received = new Uint8Array(MAX_RESPONSE_BYTES);
  let size = 0;
  if (response.body) {
    for await (const chunk of response.body) {
      // Leaving the loop cancels the rest of the response.
      if (size + chunk.byteLength > MAX_RESPONSE_BYTES) {
        throw new Error('Callback response exceeds 16 KiB');
      }
      received.set(chunk, size);
      size += chunk.byteLength;
    }
  }
  return new Response(size ? received.slice(0, size) : null, { status: response.status });
}

export async function sendWebhook(
  subscription: { id: string; url: string; secret: string; oldSecret?: string; rotateUntil?: number },
  id: string,
  payload: unknown,
): Promise<Response> {
  const body = JSON.stringify(payload);
  if (new TextEncoder().encode(body).length > 262_144) throw new Error('Event exceeds 256 KiB');
  const timestamp = Math.floor(Date.now() / 1000);
  let signed = await signature(subscription.secret, id, timestamp, body);
  if (subscription.oldSecret && (subscription.rotateUntil ?? 0) > Date.now()) {
    signed += ` ${await signature(subscription.oldSecret, id, timestamp, body)}`;
  }
  return postWebhook(subscription.url, {
    'Content-Type': 'application/json',
    'webhook-id': id,
    'webhook-timestamp': String(timestamp),
    'webhook-signature': signed,
    'X-MCP-Subscription-Id': subscription.id,
  }, body);
}
