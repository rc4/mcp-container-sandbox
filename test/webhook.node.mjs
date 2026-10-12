import assert from 'node:assert/strict';
import dns from 'node:dns';
import { EventEmitter } from 'node:events';
import https from 'node:https';
import { test } from 'node:test';
import { post, publicAddress, publicLookup } from '../container/webhook.js';

test('only public IPv4 and native global IPv6 addresses are accepted', () => {
  for (
    const address of [
      '127.0.0.1',
      '10.1.2.3',
      '172.16.0.1',
      '192.168.1.1',
      '169.254.169.254',
      '100.64.0.1',
      '0.0.0.0',
      '224.0.0.1',
      '198.18.0.1',
      '192.0.2.1',
      '198.51.100.1',
      '203.0.113.1',
      '::1',
      'fc00::1',
      'fe80::1',
      '::ffff:127.0.0.1',
      '2001:db8::1',
      '2002:7f00:1::',
    ]
  ) {
    assert.equal(publicAddress(address), false, address);
  }
  assert.equal(publicAddress('93.184.216.34'), true);
  assert.equal(publicAddress('2606:4700:4700::1111'), true);
});

test('connection lookup returns checked addresses and rejects mixed public/private DNS', async (t) => {
  const addresses = [{ address: '93.184.216.34', family: 4 }];
  t.mock.method(dns, 'lookup', (hostname, options, callback) => {
    assert.equal(hostname, 'receiver.example');
    assert.equal(options.all, true);
    callback(null, addresses);
  });
  const result = await new Promise((resolve, reject) =>
    publicLookup('receiver.example', { all: true }, (error, resolved) => error ? reject(error) : resolve(resolved))
  );
  assert.deepEqual(result, addresses);
  addresses.push({ address: '127.0.0.1', family: 4 });
  await assert.rejects(
    new Promise((resolve, reject) =>
      publicLookup('receiver.example', {}, (error) => error ? reject(error) : resolve())
    ),
    { code: 'BLOCKED_ADDRESS' },
  );
});

test('HTTPS keeps the original hostname, uses checked lookup, and does not follow redirects', async (t) => {
  let calls = 0;
  t.mock.method(https, 'request', (url, options, callback) => {
    calls++;
    assert.equal(url.hostname, 'receiver.example');
    assert.equal(options.lookup, publicLookup);
    assert.equal(options.agent, false);
    assert.equal(options.rejectUnauthorized, undefined);
    const request = new EventEmitter();
    request.end = (body) => {
      assert.equal(options.headers['Content-Length'], body.length);
      assert.equal(body.toString(), '{"data":"é"}');
      const response = new EventEmitter();
      response.statusCode = 302;
      response.headers = { location: 'http://127.0.0.1/' };
      callback(response);
      response.emit('data', Buffer.from('{}'));
      response.emit('end');
    };
    return request;
  });
  assert.deepEqual(await post({ url: 'https://receiver.example/', headers: {}, body: '{"data":"é"}' }), {
    status: 302,
    body: '{}',
  });
  assert.equal(calls, 1);
});

test('literal local addresses and insecure URLs are rejected before HTTPS is called', async (t) => {
  const request = t.mock.method(https, 'request', () => {
    throw new Error('unexpected request');
  });
  assert.deepEqual(await post({ url: 'https://127.0.0.1/', headers: {}, body: '{}' }), { error: 'blocked_address' });
  assert.deepEqual(await post({ url: 'https://[::ffff:127.0.0.1]/', headers: {}, body: '{}' }), {
    error: 'blocked_address',
  });
  assert.deepEqual(await post({ url: 'http://receiver.example/', headers: {}, body: '{}' }), { error: 'invalid_url' });
  assert.equal(request.mock.callCount(), 0);
});
