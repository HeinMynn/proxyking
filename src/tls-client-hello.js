// Returns the ALPN protocols from a complete TLS ClientHello. A null result
// means more bytes are needed or the payload is not a ClientHello.
function readAlpnProtocols(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 9 || buffer[0] !== 0x16) return null;
  const recordLength = buffer.readUInt16BE(3);
  if (buffer.length < 5 + recordLength || buffer[5] !== 0x01) return null;
  const helloLength = buffer.readUIntBE(6, 3);
  if (buffer.length < 9 + helloLength) return null;

  let offset = 9 + 2 + 32;
  const end = 9 + helloLength;
  if (offset + 1 > end) return null;
  offset += 1 + buffer[offset];
  if (offset + 2 > end) return null;
  offset += 2 + buffer.readUInt16BE(offset);
  if (offset + 1 > end) return null;
  offset += 1 + buffer[offset];
  if (offset === end) return [];
  if (offset + 2 > end) return null;
  const extensionsEnd = offset + 2 + buffer.readUInt16BE(offset);
  offset += 2;
  if (extensionsEnd > end) return null;

  while (offset + 4 <= extensionsEnd) {
    const type = buffer.readUInt16BE(offset);
    const length = buffer.readUInt16BE(offset + 2);
    offset += 4;
    if (offset + length > extensionsEnd) return null;
    if (type === 0x0010) {
      if (length < 2) return null;
      const listEnd = offset + 2 + buffer.readUInt16BE(offset);
      let item = offset + 2;
      if (listEnd > offset + length) return null;
      const protocols = [];
      while (item < listEnd) {
        const itemLength = buffer[item++];
        if (item + itemLength > listEnd) return null;
        protocols.push(buffer.subarray(item, item + itemLength).toString('ascii'));
        item += itemLength;
      }
      return protocols;
    }
    offset += length;
  }
  return [];
}

function requiresPassthrough(buffer) {
  const protocols = readAlpnProtocols(buffer);
  return Array.isArray(protocols) && protocols.length > 0 && !protocols.some(protocol => protocol === 'h2' || protocol === 'http/1.1');
}

module.exports = { readAlpnProtocols, requiresPassthrough };
