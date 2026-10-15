import { WorkerEntrypoint } from 'cloudflare:workers';
import { encodeBytes } from './output';
import { artifactKey } from './sandbox';

export interface SinkholeProps {
  sandboxId: string;
  /** Bodies larger than the preview are saved as this sandbox's artifacts. Without it, only the preview is kept. */
  owner?: { principal: string; name: string };
}

export interface NetworkEvent {
  method: string;
  url: string;
  headers: Record<string, string>;
  bodySize: number;
  /** The first BODY_PREVIEW_BYTES of the body: UTF-8 text, or base64 for binary bodies. */
  bodyPreview: string;
  bodyEncoding: 'utf8' | 'base64';
  /** Artifact key holding the body, up to MAX_CAPTURE_BYTES, when it is larger than the preview. */
  bodyArtifact: string | null;
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
/** Larger bodies are saved to R2 up to this size; bodySize still counts all of it. */
const MAX_CAPTURE_BYTES = 64 * 1024 * 1024;
/** R2 multipart parts other than the last must all be one size, at least 5 MiB. */
const PART_BYTES = 8 * 1024 * 1024;

/**
 * Streams a body larger than the preview to R2 as it arrives, holding at most one part in memory.
 * Storage errors are logged and end the capture without interrupting the request.
 */
class BodyCapture {
  #pending: Uint8Array[] = [];
  #pendingBytes = 0;
  #stored = 0;
  #upload: R2MultipartUpload | null = null;
  #parts: R2UploadedPart[] = [];
  #failed = false;

  constructor(
    private readonly bucket: R2Bucket,
    private readonly key: string,
    private readonly options: R2MultipartOptions,
  ) {}

  async write(chunk: Uint8Array): Promise<void> {
    const keep = chunk.subarray(0, MAX_CAPTURE_BYTES - this.#stored);
    if (this.#failed || !keep.byteLength) return;
    this.#pending.push(keep);
    this.#pendingBytes += keep.byteLength;
    this.#stored += keep.byteLength;
    while (this.#pendingBytes >= PART_BYTES) {
      await this.#attempt(async () => {
        this.#upload ??= await this.bucket.createMultipartUpload(this.key, this.options);
        this.#parts.push(await this.#upload.uploadPart(this.#parts.length + 1, this.#take(PART_BYTES)));
      });
    }
  }

  /** Returns whether the body was saved. */
  async finish(): Promise<boolean> {
    await this.#attempt(async () => {
      const rest = this.#take(this.#pendingBytes);
      if (!this.#upload) {
        await this.bucket.put(this.key, rest, this.options);
        return;
      }
      if (rest.byteLength) this.#parts.push(await this.#upload.uploadPart(this.#parts.length + 1, rest));
      await this.#upload.complete(this.#parts);
    });
    return !this.#failed;
  }

  async #attempt(step: () => Promise<void>): Promise<void> {
    if (this.#failed) return;
    try {
      await step();
    } catch (error) {
      console.error('sinkhole: could not save request body', error);
      this.#failed = true;
      this.#pending = [];
      this.#pendingBytes = 0;
      await this.#upload?.abort().catch(() => {});
    }
  }

  #take(size: number): Uint8Array {
    const out = new Uint8Array(size);
    let filled = 0;
    while (filled < size) {
      const chunk = this.#pending[0]!;
      const take = Math.min(chunk.byteLength, size - filled);
      out.set(chunk.subarray(0, take), filled);
      filled += take;
      if (take === chunk.byteLength) this.#pending.shift();
      else this.#pending[0] = chunk.subarray(take);
    }
    this.#pendingBytes -= size;
    return out;
  }
}

/**
 * Receives every HTTP and HTTPS request a `sinkhole` sandbox makes. Nothing leaves Cloudflare:
 * the sandbox's Durable Object records the request and picks the answer from its sinkhole rules
 * (an empty 200 by default), so a sample that phones home keeps running and reveals its next
 * request.
 */
export class NetworkSinkhole extends WorkerEntrypoint<Env, SinkholeProps> {
  override async fetch(request: Request): Promise<Response> {
    // Keep the start of the body for the log; save a larger body to R2 without holding it in memory.
    const preview = new Uint8Array(BODY_PREVIEW_BYTES);
    let previewLength = 0;
    let bodySize = 0;
    let capture: BodyCapture | null = null;
    const { owner } = this.ctx.props;
    const bodyArtifact = owner ? `sinkhole/${owner.name}/${Date.now()}-${crypto.randomUUID()}.bin` : null;
    if (request.body) {
      for await (const chunk of request.body) {
        const take = Math.min(chunk.byteLength, BODY_PREVIEW_BYTES - previewLength);
        preview.set(chunk.subarray(0, take), previewLength);
        previewLength += take;
        bodySize += chunk.byteLength;
        if (!capture && bodySize > BODY_PREVIEW_BYTES && owner && bodyArtifact) {
          capture = new BodyCapture(this.env.BUCKET, artifactKey(owner.principal, bodyArtifact), {
            httpMetadata: { contentType: request.headers.get('content-type') ?? 'application/octet-stream' },
            customMetadata: { sandbox: owner.name, sinkhole: `${request.method} ${request.url}`.slice(0, 1024) },
          });
          await capture.write(preview);
          await capture.write(chunk.subarray(take));
        } else {
          await capture?.write(chunk);
        }
      }
    }
    const { encoding, content } = encodeBytes(preview.subarray(0, previewLength), 'auto');
    const event: NetworkEvent = {
      method: request.method,
      url: request.url,
      headers: Object.fromEntries(request.headers),
      bodySize,
      bodyPreview: content,
      bodyEncoding: encoding,
      bodyArtifact: capture && (await capture.finish()) ? bodyArtifact : null,
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
