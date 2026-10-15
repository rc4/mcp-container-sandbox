/**
 * Worker entry point. `/mcp` is a stateless MCP endpoint that requires a bearer token, and
 * `/files/…` serves signed artifact links, which carry their own authorization. The classes
 * that wrangler.jsonc binds are re-exported here.
 */
import { createMcpHandler } from 'agents/mcp/server';
import { env } from 'cloudflare:workers';
import { authenticate, parseTokens } from './auth';
import { handleLink, isLinkRequest } from './links';
import { createServer } from './mcp';

export { DirectoryBackupGateway } from '@cloudflare/sandbox';
export { SandboxRegistry } from './registry';
export { Sandbox } from './sandbox';
export { NetworkSinkhole } from './sinkhole';

export default {
  async fetch(request): Promise<Response> {
    const url = new URL(request.url);
    if (isLinkRequest(url)) {
      // The signature authenticates the request; no bearer token is involved.
      return handleLink(request);
    }
    if (url.pathname !== '/mcp') {
      return new Response(url.pathname === '/' ? 'MCP endpoint: /mcp\n' : 'Not found\n', {
        status: url.pathname === '/' ? 200 : 404,
      });
    }

    // CORS preflights carry no credentials; the handler answers them without touching sandboxes.
    let principal = '';
    if (request.method !== 'OPTIONS') {
      const found = await authenticate(request, parseTokens(env.MCP_TOKENS));
      if (!found) {
        return new Response('Unauthorized\n', { status: 401, headers: { 'WWW-Authenticate': 'Bearer' } });
      }
      principal = found;
    }

    const allowedHostnames = env.ALLOWED_HOSTNAMES.split(',').map((h) => h.trim()).filter(Boolean);
    // An empty list would reject every host; leave it out to keep the localhost/workers.dev default.
    return createMcpHandler(
      () => createServer(principal, url.origin),
      allowedHostnames.length > 0 ? { allowedHostnames } : {},
    ).fetch(request);
  },
} satisfies ExportedHandler<Env>;
