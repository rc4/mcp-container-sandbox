import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.jsonc' },
      miniflare: {
        bindings: {
          MCP_TOKENS: 'test:test-token-0123456789abcdef',
          LINK_SIGNING_KEY: 'test-link-signing-key-0123456789abcdef',
        },
      },
    }),
  ],
});
