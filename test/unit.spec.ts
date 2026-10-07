import { describe, expect, it } from 'vitest';
import { authenticate, parseTokens } from '../src/auth';
import { encodeBytes, OutputCapture } from '../src/output';
import { matchRule } from '../src/sinkhole';

const bytes = (text: string) => new TextEncoder().encode(text);
const rule = (fields: { host?: string; path?: string; method?: string }) => ({ status: 200, headers: {}, ...fields });
const request = (header?: string) =>
  new Request('https://example.com/mcp', { headers: header ? { Authorization: header } : {} });

describe('OutputCapture', () => {
  it('keeps short output whole', () => {
    const out = new OutputCapture(10);
    out.push(bytes('hello'));
    out.push(bytes('!'));
    expect(out.result()).toEqual({ text: 'hello!', totalBytes: 6, truncated: false });
  });

  it('keeps head and tail of long output', () => {
    const out = new OutputCapture(10);
    for (const chunk of ['01234', '56789', 'abcde', 'fghij', 'KLMNO']) {
      out.push(bytes(chunk));
    }
    expect(out.result()).toEqual({ text: '01234\n…[15 bytes omitted]…\nKLMNO', totalBytes: 25, truncated: true });
  });

  it('takes the tail from the head buffer when the overflow is short', () => {
    const out = new OutputCapture(10);
    out.push(bytes('0123456789ab'));
    expect(out.result().text).toBe('01234\n…[2 bytes omitted]…\n789ab');
  });
});

describe('encodeBytes', () => {
  it('returns text as utf8 and binary as base64', () => {
    expect(encodeBytes(bytes('plain text'), 'auto')).toEqual({ encoding: 'utf8', content: 'plain text' });
    const binary = new Uint8Array([0x4d, 0x5a, 0x00, 0xff]);
    const encoded = encodeBytes(binary, 'auto');
    expect(encoded.encoding).toBe('base64');
    expect(Uint8Array.fromBase64(encoded.content)).toEqual(binary);
  });
});

describe('auth', () => {
  const ALICE = 'alice-token-0123456789';
  const BOB = 'bob-token-0123456789';
  const tokens = parseTokens(`alice:${ALICE}, bob:${BOB}`);

  it('maps tokens to principals', async () => {
    expect(await authenticate(request(`Bearer ${ALICE}`), tokens)).toBe('alice');
    expect(await authenticate(request(`Bearer ${BOB}`), tokens)).toBe('bob');
  });

  it('rejects missing or wrong tokens', async () => {
    expect(await authenticate(request(), tokens)).toBeNull();
    expect(await authenticate(request('Bearer nope'), tokens)).toBeNull();
    expect(await authenticate(request(ALICE), tokens)).toBeNull();
  });

  it('rejects malformed configuration', () => {
    expect(() => parseTokens('no-separator')).toThrow('principal:token');
    expect(() => parseTokens('alice:short')).toThrow('principal:token');
    expect(() => parseTokens('Bad Name:long-enough-token-123')).toThrow('principal:token');
    expect(parseTokens('').size).toBe(0);
  });
});

describe('sinkhole rule matching', () => {
  it('matches host and path globs and methods', () => {
    const rules = [rule({ host: '*.evil.test', path: '/api/*', method: 'POST' }), rule({ host: 'EVIL.test' })];
    expect(matchRule(rules, 'post', 'https://x.evil.test/api/v1?q=1')).toBe(0);
    expect(matchRule(rules, 'GET', 'https://x.evil.test/api/v1')).toBe(-1);
    expect(matchRule(rules, 'GET', 'http://evil.test/anything')).toBe(1);
    expect(matchRule(rules, 'GET', 'http://evil.test.example/')).toBe(-1);
  });

  it('treats dots literally and needs other syntax escaped', () => {
    expect(matchRule([rule({ path: '/a.php' })], 'GET', 'http://h/aXphp')).toBe(-1);
    expect(matchRule([rule({ path: '/a.php' })], 'GET', 'http://h/a.php')).toBe(0);
    expect(matchRule([rule({ path: '/a\\+b' })], 'GET', 'http://h/a+b')).toBe(0);
  });

  it('matches named path segments', () => {
    const rules = [rule({ path: '/bot/:id' })];
    expect(matchRule(rules, 'GET', 'http://h/bot/42')).toBe(0);
    expect(matchRule(rules, 'GET', 'http://h/bot/42/cmd')).toBe(-1);
  });
});
