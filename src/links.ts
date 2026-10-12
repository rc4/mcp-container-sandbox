import { env } from 'cloudflare:workers';
/**
 * Short-lived signed links that move artifacts between R2 and the outside world directly, without
 * base64 in MCP messages. A link names one R2 object, one method and an expiry, signed with
 * HMAC-SHA256 under `LINK_SIGNING_KEY`. Anyone holding the link can use it until it expires.
 */
const PREFIX = '/files/';

export type LinkMethod = 'GET' | 'PUT';

/**
 * Signs a link that allows one method on one R2 object until it expires.
 * @param secret `LINK_SIGNING_KEY`.
 * @param origin Scheme and host the link points at, normally the origin of the MCP request.
 * @param method `GET` to download, `PUT` to upload. A link only works for the method it was signed for.
 * @param objectKey Full R2 key, including the `artifacts/<principal>/` prefix.
 * @param ttlSeconds How long the link works. Negative values create an expired link.
 * @returns The link, and its expiry as an ISO 8601 timestamp.
 */
export async function createLink(
  secret: string,
  origin: string,
  method: LinkMethod,
  objectKey: string,
  ttlSeconds: number,
): Promise<{ url: string; expiresAt: string }> {
  const expires = Math.floor(Date.now() / 1000) + ttlSeconds;
  const signature = new Uint8Array(await hmac(secret, payload(method, objectKey, expires))).toBase64({
    alphabet: 'base64url',
    omitPadding: true,
  });
  const path = objectKey.split('/').map(encodeURIComponent).join('/');
  return {
    url: `${origin}${PREFIX}${path}?expires=${expires}&sig=${signature}`,
    expiresAt: new Date(expires * 1000).toISOString(),
  };
}

export function isLinkRequest(url: URL): boolean {
  return url.pathname.startsWith(PREFIX);
}

/** Serves a signed link: GET streams the object out of R2, PUT streams the body into R2. */
export async function handleLink(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const method = request.method === 'HEAD' ? 'GET' : request.method;
  if (method !== 'GET' && method !== 'PUT') {
    return new Response('Method not allowed\n', { status: 405, headers: { Allow: 'GET, HEAD, PUT' } });
  }
  const objectKey = url.pathname.slice(PREFIX.length).split('/').map(decodeURIComponent).join('/');
  const expires = Number(url.searchParams.get('expires'));
  const signature = url.searchParams.get('sig') ?? '';
  if (
    !Number.isInteger(expires)
    || expires < Date.now() / 1000
    || !(await verify(env.LINK_SIGNING_KEY, payload(method, objectKey, expires), signature))
  ) {
    return new Response('Link is invalid or expired\n', { status: 403 });
  }

  if (method === 'GET') {
    const object = await env.BUCKET.get(objectKey);
    if (!object) {
      return new Response('Not found\n', { status: 404 });
    }
    const headers = new Headers({
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(object.size),
      'Content-Disposition': `attachment; filename="${objectKey.split('/').pop()!.replace(/["\\]/g, '_')}"`,
      'ETag': object.httpEtag,
      // Artifacts can be malware. Never let a browser render or sniff them.
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': 'sandbox',
    });
    return new Response(request.method === 'HEAD' ? null : object.body, { headers });
  }

  const length = Number(request.headers.get('Content-Length'));
  if (!request.body || !Number.isSafeInteger(length) || length < 0) {
    return new Response('Content-Length is required\n', { status: 411 });
  }
  // R2 needs a stream of known length; the body of a request with Content-Length is one, but
  // FixedLengthStream makes the length explicit and rejects a body that does not match it.
  const sized = new FixedLengthStream(length);
  const [object] = await Promise.all([
    env.BUCKET.put(objectKey, sized.readable, { customMetadata: { uploadedVia: 'signed-link' } }),
    request.body.pipeTo(sized.writable),
  ]);
  return Response.json({ size: object.size, etag: object.etag }, { status: 201 });
}

function payload(method: LinkMethod, objectKey: string, expires: number): string {
  return `${method}\n${objectKey}\n${expires}`;
}

async function key(secret: string, usage: 'sign' | 'verify'): Promise<CryptoKey> {
  if (secret.length < 32) {
    throw new Error('LINK_SIGNING_KEY must be at least 32 characters');
  }
  return crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
    usage,
  ]);
}

async function hmac(secret: string, data: string): Promise<ArrayBuffer> {
  return crypto.subtle.sign('HMAC', await key(secret, 'sign'), new TextEncoder().encode(data));
}

async function verify(secret: string, data: string, signature: string): Promise<boolean> {
  let bytes: Uint8Array;
  try {
    bytes = Uint8Array.fromBase64(signature, { alphabet: 'base64url' });
  } catch {
    return false;
  }
  // crypto.subtle.verify compares in constant time.
  return crypto.subtle.verify('HMAC', await key(secret, 'verify'), bytes, new TextEncoder().encode(data));
}
