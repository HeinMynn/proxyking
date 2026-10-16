const dgram = require('node:dgram');
const os = require('node:os');
const net = require('node:net');

const VPN_PATTERNS = [
  [/nord(?:lynx|vpn)?/i, 'NordVPN'],
  [/express\s?vpn/i, 'ExpressVPN'],
  [/proton/i, 'Proton VPN'],
  [/mullvad/i, 'Mullvad'],
  [/surfshark/i, 'Surfshark'],
  [/tailscale/i, 'Tailscale'],
  [/zerotier/i, 'ZeroTier'],
  [/wireguard|wintun/i, 'WireGuard'],
  [/openvpn|\btap\b|\btun\b|utun\d*/i, 'VPN']
];

function isPrivateIPv4(address) {
  if (net.isIP(address) !== 4) return false;
  const parts = address.split('.').map(Number);
  return parts[0] === 10 || parts[0] === 192 && parts[1] === 168 || parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31;
}

function vpnProvider(name = '') {
  return VPN_PATTERNS.find(([pattern]) => pattern.test(name))?.[1] || '';
}

function interfaceKind(name = '') {
  if (vpnProvider(name)) return 'vpn';
  if (/virtual|hyper-v|vmware|virtualbox|vbox|docker|bluetooth/i.test(name)) return 'virtual';
  if (/wi-?fi|wireless|wlan|airport/i.test(name)) return 'wifi';
  if (/ethernet|local area|\beth\d*\b|^en\d+$/i.test(name)) return 'ethernet';
  return 'lan';
}

function interfaceEntries(interfaces = {}) {
  return Object.entries(interfaces).flatMap(([name, entries]) => (entries || [])
    .filter(item => (item.family === 'IPv4' || item.family === 4) && !item.internal && net.isIP(item.address) === 4)
    .map(item => ({ id: `interface:${name}`, name, address: item.address, kind: interfaceKind(name), provider: vpnProvider(name) })));
}

function listenerCandidates(interfaces = {}) {
  const kindRank = { wifi: 0, ethernet: 1, lan: 2 };
  const addressRank = address => address.startsWith('192.168.') ? 0 : address.startsWith('10.') ? 1 : 2;
  return interfaceEntries(interfaces)
    .filter(item => !['vpn', 'virtual'].includes(item.kind) && isPrivateIPv4(item.address))
    .sort((a, b) => kindRank[a.kind] - kindRank[b.kind] || addressRank(a.address) - addressRank(b.address) || a.name.localeCompare(b.name) || a.address.localeCompare(b.address));
}

function selectListener(interfaces, preference = 'auto') {
  const candidates = listenerCandidates(interfaces);
  if (preference === 'localhost') return { id: 'localhost', name: 'Localhost', address: '127.0.0.1', kind: 'localhost', available: true };
  if (preference.startsWith('interface:')) {
    const selected = candidates.find(item => item.id === preference);
    if (selected) return { ...selected, available: true };
  }
  const selected = candidates[0];
  return selected ? { ...selected, id: preference === 'auto' ? 'auto' : selected.id, available: true } : { id: 'localhost', name: 'Localhost', address: '127.0.0.1', kind: 'localhost', available: true };
}

function selectLanAddress(interfaces, _routedAddress, preference = 'auto') {
  return selectListener(interfaces, preference).address;
}

function buildNetworkProfile(interfaces, routedAddress, listenerPreference = 'auto') {
  const entries = interfaceEntries(interfaces);
  const options = listenerCandidates(interfaces);
  const requested = listenerPreference || 'auto';
  const listener = selectListener(interfaces, requested);
  const outboundEntry = entries.find(item => item.address === routedAddress);
  const outbound = routedAddress ? {
    address: routedAddress,
    interface: outboundEntry?.name || 'System route',
    kind: outboundEntry?.kind || 'unknown',
    provider: outboundEntry?.provider || ''
  } : { address: '', interface: 'Unavailable', kind: 'unknown', provider: '' };
  const vpn = ['vpn', 'virtual'].includes(outbound.kind)
    ? { detected: true, provider: outbound.kind === 'virtual' ? 'Possible VPN' : outbound.provider || 'VPN', interface: outbound.interface }
    : { detected: false, provider: '', interface: '' };
  const warnings = [];
  if (requested.startsWith('interface:') && !options.some(item => item.id === requested)) warnings.push('The selected listening interface is unavailable. Automatic LAN selection is being used.');
  if (!options.length) warnings.push('No private Wi-Fi or Ethernet address is available. Proxyking is listening on this computer only.');
  return {
    listener,
    outbound,
    vpn,
    listenerPreference: requested,
    interfaces: options.map(item => ({ id: item.id, name: item.name, address: item.address, kind: item.kind })),
    warnings
  };
}

function routeAddress(timeout = 600) {
  return new Promise(resolve => {
    const socket = dgram.createSocket('udp4');
    let settled = false;
    let timer;
    const finish = address => { if (settled) return; settled = true; clearTimeout(timer); try { socket.close(); } catch {} resolve(address); };
    socket.once('error', () => finish());
    timer = setTimeout(() => finish(), timeout);
    socket.connect(53, '1.1.1.1', () => {
      try { finish(socket.address().address); } catch { finish(); }
    });
  });
}

async function detectNetworkProfile({ interfaces = os.networkInterfaces(), routedAddress, listenerPreference = 'auto' } = {}) {
  const outboundAddress = routedAddress === undefined ? await routeAddress() : routedAddress;
  return buildNetworkProfile(interfaces, outboundAddress, listenerPreference);
}

async function detectLanAddress() {
  return (await detectNetworkProfile()).listener.address;
}

module.exports = {
  isPrivateIPv4, vpnProvider, interfaceKind, interfaceEntries, listenerCandidates,
  selectListener, selectLanAddress, buildNetworkProfile, routeAddress, detectNetworkProfile, detectLanAddress
};
