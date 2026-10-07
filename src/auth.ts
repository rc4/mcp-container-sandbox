/**
 * Bearer-token authentication. `MCP_TOKENS` holds comma-separated `principal:token` pairs, and
 * the principal prefixes everything a caller can reach: sandbox names, backups and artifacts.
 */
const PRINCIPAL = /^[a-z0-9][a-z0-9_-]{0,31}$/;

/**
 * Parses `MCP_TOKENS`. Blank entries are skipped.
 * @returns Principals keyed by token.
 * @throws If an entry is not `principal:token` with a valid principal and token.
 */
export function parseTokens(raw: string): Map<string, string> {
  const tokens = new Map<string, string>();
  for (const entry of raw.split(',')) {
    const trimmed = entry.trim();
    if (!trimmed) {
      continue;
    }
    const separator = trimmed.indexOf(':');
    const principal = trimmed.slice(0, separator);
    const token = trimmed.slice(separator + 1);
    if (separator <= 0 || !PRINCIPAL.test(principal) || token.length < 16) {
      throw new Error('MCP_TOKENS entries must be `principal:token` with a token of at least 16 characters');
    }
    tokens.set(token, principal);
  }
  return tokens;
}

/** @returns The caller's principal, or null when the request carries no valid token. */
export async function authenticate(request: Request, tokens: Map<string, string>): Promise<string | null> {
  const match = /^Bearer\s+(\S+)$/i.exec(request.headers.get('Authorization') ?? '');
  if (!match) {
    return null;
  }
  const presented = await sha256(match[1]!);
  let principal: string | null = null;
  // Compare against every token so timing does not reveal which one matched.
  for (const [token, owner] of tokens) {
    if (crypto.subtle.timingSafeEqual(presented, await sha256(token))) {
      principal = owner;
    }
  }
  return principal;
}

async function sha256(text: string): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
}
