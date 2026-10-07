import { WorkerEntrypoint } from 'cloudflare:workers';

export interface SinkholeProps {
  sandboxId: string;
}

export interface NetworkEvent {
  method: string;
  url: string;
  headers: Record<string, string>;
  bodySize: number;
  bodyPreview: string;
}

/**
 * How the sinkhole answers matching requests. The first rule whose host, path and method all
 * match wins; a request that matches no rule gets an empty 200.
 */
export interface SinkholeRule {
  /**
   * Hostname pattern in URLPattern syntax, for example `*.example.com`. Matching ignores case.
   * @default '*'
   */
  host?: string;
  /**
   * URL path pattern in URLPattern syntax, for example `/gate.php`, `/api/*` or `/bot/:id`. The
   * query string is ignored. `:`, `(`, `)`, `{`, `}`, `?` and `+` are pattern syntax; put a backslash
   * before one to match it literally.
   * @default '*'
   */
  path?: string;
  /** HTTP method, case-insensitive. Unset matches any method. */
  method?: string;
  status: number;
  headers: Record<string, string>;
  /** Inline response body. Set this or `artifact`, not both. */
  body?: string;
  bodyEncoding?: 'utf8' | 'base64';
  /** Serve this artifact (a key under the owner's artifacts) as the body instead. */
  artifact?: string;
}

/** What the Durable Object tells the sinkhole to answer. */
export interface SinkholeAnswer {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array | null;
  /** Full R2 key to stream as the body. */
  objectKey: string | null;
}

export const EMPTY_ANSWER: SinkholeAnswer = { status: 200, headers: {}, body: null, objectKey: null };

const BODY_PREVIEW_BYTES = 4096;

/**
 * Receives every HTTP and HTTPS request a `sinkhole` sandbox makes. Nothing leaves Cloudflare:
 * the sandbox's Durable Object records the request and picks the answer from its sinkhole rules
 * (an empty 200 by default), so a sample that phones home keeps running and reveals its next
 * request.
 */
export class NetworkSinkhole extends WorkerEntrypoint<Env, SinkholeProps> {
  override async fetch(request: Request): Promise<Response> {
    const body = request.body ? new Uint8Array(await request.arrayBuffer()) : new Uint8Array();
    const event: NetworkEvent = {
      method: request.method,
      url: request.url,
      headers: Object.fromEntries(request.headers),
      bodySize: body.byteLength,
      bodyPreview: new TextDecoder().decode(body.subarray(0, BODY_PREVIEW_BYTES)),
    };
    const sandbox = this.env.SANDBOX.get(this.env.SANDBOX.idFromString(this.ctx.props.sandboxId));
    let answer: SinkholeAnswer;
    try {
      answer = await sandbox.answerNetworkRequest(event);
    } catch (error) {
      // Keep the sample running even if the rules cannot be read.
      console.error('sinkhole: could not get an answer', error);
      answer = EMPTY_ANSWER;
    }

    if (answer.objectKey) {
      const object = await this.env.BUCKET.get(answer.objectKey);
      if (!object) {
        return new Response(null, { status: 404 });
      }
      return new Response(object.body, {
        status: answer.status,
        headers: { 'Content-Length': String(object.size), ...answer.headers },
      });
    }
    return new Response(answer.body, { status: answer.status, headers: answer.headers });
  }
}

/** @returns The index of the first rule that matches the request, or -1. */
export function matchRule(rules: SinkholeRule[], method: string, url: string): number {
  return rules.findIndex((rule) =>
    (rule.method === undefined || rule.method.toUpperCase() === method.toUpperCase())
    && new URLPattern({ hostname: rule.host, pathname: rule.path }).test(url)
  );
}
