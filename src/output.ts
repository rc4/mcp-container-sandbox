/**
 * Bounded capture of process output. Keeps the first and last bytes of a stream so that a
 * long build log or a chatty sample still shows how it started and how it ended, without
 * holding the whole stream in Durable Object memory.
 */
export interface CapturedOutput {
  text: string;
  totalBytes: number;
  truncated: boolean;
}

export class OutputCapture {
  readonly #limit: number;
  readonly #head: Uint8Array;
  #headLength = 0;
  #tail: Uint8Array[] = [];
  #tailLength = 0;
  #total = 0;

  /**
   * @param limit Bytes to keep: all of the output when it fits, otherwise the first and last
   *   `limit / 2` bytes. Raised to at least 2.
   */
  constructor(limit: number) {
    this.#limit = Math.max(2, Math.floor(limit));
    this.#head = new Uint8Array(this.#limit);
  }

  push(chunk: Uint8Array): void {
    this.#total += chunk.byteLength;
    const toHead = Math.min(chunk.byteLength, this.#limit - this.#headLength);
    if (toHead > 0) {
      this.#head.set(chunk.subarray(0, toHead), this.#headLength);
      this.#headLength += toHead;
    }
    if (toHead === chunk.byteLength) {
      return;
    }
    this.#tail.push(chunk.subarray(toHead));
    this.#tailLength += chunk.byteLength - toHead;
    // Drop whole chunks from the front once they can no longer reach the kept tail.
    const keep = Math.floor(this.#limit / 2);
    while (this.#tail.length > 1 && this.#tailLength - this.#tail[0]!.byteLength >= keep) {
      this.#tailLength -= this.#tail.shift()!.byteLength;
    }
  }

  result(): CapturedOutput {
    const decoder = new TextDecoder();
    if (this.#tailLength === 0) {
      return {
        text: decoder.decode(this.#head.subarray(0, this.#headLength)),
        totalBytes: this.#total,
        truncated: false,
      };
    }
    const half = Math.floor(this.#limit / 2);
    // The last `half` bytes can start inside the head buffer when the overflow is short.
    const tail = concat([this.#head.subarray(half, this.#headLength), ...this.#tail]);
    const keptTail = tail.subarray(Math.max(0, tail.byteLength - half));
    const omitted = this.#total - half - keptTail.byteLength;
    return {
      text: `${decoder.decode(this.#head.subarray(0, half))}\n…[${omitted} bytes omitted]…\n${
        decoder.decode(keptTail)
      }`,
      totalBytes: this.#total,
      truncated: true,
    };
  }
}

export async function capture(
  stream: ReadableStream<Uint8Array> | null | undefined,
  limit: number,
): Promise<CapturedOutput> {
  const out = new OutputCapture(limit);
  if (stream) {
    for await (const chunk of stream) {
      out.push(chunk);
    }
  }
  return out.result();
}

function concat(chunks: Uint8Array[]): Uint8Array {
  if (chunks.length === 1) {
    return chunks[0]!;
  }
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.byteLength, 0));
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

/** Decodes bytes as UTF-8 when they look like text, otherwise returns base64. */
export function encodeBytes(
  bytes: Uint8Array,
  encoding: 'auto' | 'utf8' | 'base64',
): { encoding: 'utf8' | 'base64'; content: string } {
  if (encoding === 'base64' || (encoding === 'auto' && !looksLikeText(bytes))) {
    return { encoding: 'base64', content: bytes.toBase64() };
  }
  return { encoding: 'utf8', content: new TextDecoder().decode(bytes) };
}

function looksLikeText(bytes: Uint8Array): boolean {
  if (bytes.includes(0)) {
    return false;
  }
  try {
    new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes);
    return true;
  } catch {
    return false;
  }
}
