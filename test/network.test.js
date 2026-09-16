const { test } = require('node:test');
const assert = require('node:assert/strict');
const { isPrivateIPv4, selectLanAddress, detectLanAddress } = require('../src/network');

const interfaces = {
  'Virtual Adapter': [{ family: 'IPv4', address: '10.10.0.1', internal: false }],
  'Wi-Fi': [{ family: 'IPv4', address: '192.168.1.42', internal: false }],
  Loopback: [{ family: 'IPv4', address: '127.0.0.1', internal: true }]
};

test('recognizes RFC1918 private IPv4 ranges', () => {
  for (const address of ['10.0.0.1', '172.16.0.1', '172.31.255.254', '192.168.50.3']) assert.equal(isPrivateIPv4(address), true);
  for (const address of ['127.0.0.1', '172.32.0.1', '8.8.8.8', '::1']) assert.equal(isPrivateIPv4(address), false);
});

test('prefers the active routed private address over virtual adapters', () => {
  assert.equal(selectLanAddress(interfaces, '192.168.1.42'), '192.168.1.42');
  assert.equal(selectLanAddress(interfaces), '192.168.1.42');
});

test('falls back to loopback without a private network', () => {
  assert.equal(selectLanAddress({ Ethernet: [{ family: 'IPv4', address: '169.254.1.2', internal: false }] }), '127.0.0.1');
});

test('live address detection returns a valid local IPv4 address', async () => {
  assert.match(await detectLanAddress(), /^\d{1,3}(?:\.\d{1,3}){3}$/);
});
