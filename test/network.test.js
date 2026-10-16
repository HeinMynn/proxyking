const { test } = require('node:test');
const assert = require('node:assert/strict');
const { isPrivateIPv4, selectLanAddress, buildNetworkProfile, detectLanAddress, vpnProvider } = require('../src/network');

const interfaces = {
  'Virtual Adapter': [{ family: 'IPv4', address: '10.10.0.1', internal: false }],
  'Wi-Fi': [{ family: 'IPv4', address: '192.168.1.42', internal: false }],
  Loopback: [{ family: 'IPv4', address: '127.0.0.1', internal: true }]
};

test('recognizes RFC1918 private IPv4 ranges', () => {
  for (const address of ['10.0.0.1', '172.16.0.1', '172.31.255.254', '192.168.50.3']) assert.equal(isPrivateIPv4(address), true);
  for (const address of ['127.0.0.1', '172.32.0.1', '8.8.8.8', '::1']) assert.equal(isPrivateIPv4(address), false);
});

test('prefers a physical LAN listener over the active VPN route', () => {
  assert.equal(selectLanAddress(interfaces, '192.168.1.42'), '192.168.1.42');
  assert.equal(selectLanAddress(interfaces, '10.10.0.1'), '192.168.1.42');
  assert.equal(selectLanAddress(interfaces), '192.168.1.42');
});

test('recognizes common VPN adapter providers', () => {
  assert.equal(vpnProvider('NordLynx'), 'NordVPN');
  assert.equal(vpnProvider('ExpressVPN Wintun'), 'ExpressVPN');
  assert.equal(vpnProvider('utun4'), 'VPN');
  assert.equal(vpnProvider('Wi-Fi'), '');
});

test('network profile separates the LAN listener from a NordVPN route', () => {
  const profile = buildNetworkProfile({
    NordLynx: [{ family: 'IPv4', address: '10.5.0.2', internal: false }],
    'Wi-Fi': [{ family: 'IPv4', address: '192.168.1.42', internal: false }]
  }, '10.5.0.2');
  assert.equal(profile.listener.address, '192.168.1.42');
  assert.equal(profile.outbound.address, '10.5.0.2');
  assert.deepEqual(profile.vpn, { detected: true, provider: 'NordVPN', interface: 'NordLynx' });
});

test('unknown virtual adapters are not exposed as automatic LAN listeners', () => {
  const profile = buildNetworkProfile({
    'Virtual Adapter': [{ family: 'IPv4', address: '10.10.0.1', internal: false }]
  }, '10.10.0.1');
  assert.equal(profile.listener.address, '127.0.0.1');
  assert.equal(profile.vpn.provider, 'Possible VPN');
});

test('physical ten-dot LANs are not mistaken for VPN adapters', () => {
  const profile = buildNetworkProfile({
    Ethernet: [{ family: 'IPv4', address: '10.20.30.40', internal: false }],
    'ExpressVPN Tunnel': [{ family: 'IPv4', address: '10.99.0.2', internal: false }]
  }, '10.99.0.2');
  assert.equal(profile.listener.address, '10.20.30.40');
  assert.equal(profile.vpn.provider, 'ExpressVPN');
});

test('listener preferences support localhost and named physical interfaces', () => {
  assert.equal(buildNetworkProfile(interfaces, '192.168.1.42', 'localhost').listener.address, '127.0.0.1');
  assert.equal(buildNetworkProfile(interfaces, '192.168.1.42', 'interface:Wi-Fi').listener.address, '192.168.1.42');
});

test('missing listener preferences fall back with a warning', () => {
  const profile = buildNetworkProfile(interfaces, '192.168.1.42', 'interface:Disconnected Ethernet');
  assert.equal(profile.listener.address, '192.168.1.42');
  assert.match(profile.warnings[0], /unavailable/i);
});

test('falls back to loopback without a private network', () => {
  assert.equal(selectLanAddress({ Ethernet: [{ family: 'IPv4', address: '169.254.1.2', internal: false }] }), '127.0.0.1');
});

test('live address detection returns a valid local IPv4 address', async () => {
  assert.match(await detectLanAddress(), /^\d{1,3}(?:\.\d{1,3}){3}$/);
});
