import dns from 'node:dns';
import https from 'node:https';
import { BlockList, isIP } from 'node:net';
import { pathToFileURL } from 'node:url';

const blocked = new BlockList();
for (
  const [address, prefix] of [
    ['0.0.0.0', 8],
    ['10.0.0.0', 8],
    ['100.64.0.0', 10],
    ['127.0.0.0', 8],
    ['169.254.0.0', 16],
    ['172.16.0.0', 12],
    ['192.0.0.0', 24],
    ['192.0.2.0', 24],
    ['192.88.99.0', 24],
    ['192.168.0.0', 16],
    ['198.18.0.0', 15],
    ['198.51.100.0', 24],
    ['203.0.113.0', 24],
    ['224.0.0.0', 3],
  ]
) blocked.addSubnet(address, prefix, 'ipv4');
for (const [address, prefix] of [['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['3fff::', 20]]) {
  blocked.addSubnet(address, prefix, 'ipv6');
}
const globalV6 = new BlockList();
globalV6.addSubnet('2000::', 3, 'ipv6');

export function publicAddress(address) {
  const family = isIP(address);
  return family === 4
    ? !blocked.check(address, 'ipv4')
    : family === 6 && globalV6.check(address, 'ipv6') && !blocked.check(address, 'ipv6');
}

// Node connects directly to the addresses returned by this lookup, preserving TLS hostname checks.
export function publicLookup(hostname, options, callback) {
  dns.lookup(hostname, { all: true }, (error, addresses) => {
    if (error) return callback(error);
    if (!addresses.length || addresses.some(({ address }) => !publicAddress(address))) {
      return callback(Object.assign(new Error('Non-public callback destination'), { code: 'BLOCKED_ADDRESS' }));
    }
    if (options.all) callback(null, addresses);
    else callback(null, addresses[0].address, addresses[0].family);
  });
}

export async function post(input) {
  const url = new URL(input.url);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || (url.port && url.port !== '443')) {
    return { error: 'invalid_url' };
  }
  // Node bypasses lookup for literal IPs, so validate those before creating a request.
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  if (isIP(hostname) && !publicAddress(hostname)) return { error: 'blocked_address' };
  const signal = AbortSignal.timeout(10_000);
  try {
    return await new Promise((resolve, reject) => {
      const body = Buffer.from(input.body, 'utf8');
      const request = https.request(url, {
        method: 'POST',
        agent: false,
        lookup: publicLookup,
        signal,
        headers: { ...input.headers, 'Content-Length': body.length },
      }, (response) => {
        const chunks = [];
        let size = 0;
        response.on('data', (chunk) => {
          size += chunk.length;
          if (size > 16_384) {
            request.destroy(
              Object.assign(new Error('Callback response exceeds 16 KiB'), { code: 'RESPONSE_TOO_LARGE' }),
            );
          } else chunks.push(chunk);
        });
        response.on('error', reject);
        response.on(
          'end',
          () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString('utf8') }),
        );
      });
      request.on('error', reject);
      request.end(body);
    });
  } catch (error) {
    return {
      error: signal.aborted
        ? 'timeout'
        : error.code === 'BLOCKED_ADDRESS'
        ? 'blocked_address'
        : error.code === 'RESPONSE_TOO_LARGE'
        ? 'response_too_large'
        : 'connection_failed',
    };
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const result = await post(JSON.parse(Buffer.concat(chunks).toString('utf8')));
  process.stdout.write(JSON.stringify(result));
}
