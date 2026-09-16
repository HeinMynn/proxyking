const dgram = require('node:dgram');
const os = require('node:os');
const net = require('node:net');

function isPrivateIPv4(address) {
  if (net.isIP(address) !== 4) return false;
  const parts = address.split('.').map(Number);
  return parts[0] === 10 || parts[0] === 192 && parts[1] === 168 || parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31;
}

function selectLanAddress(interfaces, routedAddress) {
  const candidates = Object.entries(interfaces).flatMap(([name, entries]) =>
    (entries || []).filter(item => item.family === 'IPv4' && !item.internal && isPrivateIPv4(item.address)).map(item => ({ name, address: item.address }))
  );
  if (isPrivateIPv4(routedAddress) && candidates.some(item => item.address === routedAddress)) return routedAddress;
  const rank = address => address.startsWith('192.168.') ? 0 : address.startsWith('10.') ? 1 : 2;
  candidates.sort((a, b) => rank(a.address) - rank(b.address) || a.name.localeCompare(b.name) || a.address.localeCompare(b.address));
  return candidates[0]?.address || '127.0.0.1';
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

async function detectLanAddress() {
  return selectLanAddress(os.networkInterfaces(), await routeAddress());
}

module.exports = { isPrivateIPv4, selectLanAddress, detectLanAddress };
