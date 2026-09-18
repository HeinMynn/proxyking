const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const forge = require('node-forge');

const LEAF_CACHE_VERSION = 'ios-compatible-v1';

async function refreshLeafCertificateCache(directory) {
  const markerPath = path.join(directory, '.leaf-cache-version');
  try {
    if ((await fs.readFile(markerPath, 'utf8')).trim() === LEAF_CACHE_VERSION) return false;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const locations = [
    { directory: path.join(directory, 'certs'), keep: new Set(['ca.pem']), extension: '.pem' },
    { directory: path.join(directory, 'keys'), keep: new Set(['ca.private.key', 'ca.public.key']), extension: '.key' }
  ];
  for (const location of locations) {
    const entries = await fs.readdir(location.directory, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isFile() && entry.name.endsWith(location.extension) && !location.keep.has(entry.name)) {
        await fs.unlink(path.join(location.directory, entry.name));
      }
    }
  }
  await fs.writeFile(markerPath, LEAF_CACHE_VERSION, { mode: 0o600 });
  return true;
}

async function ensureCertificate(directory) {
  await fs.mkdir(path.join(directory, 'keys'), { recursive: true, mode: 0o700 });
  await fs.mkdir(path.join(directory, 'certs'), { recursive: true, mode: 0o700 });
  const certPath = path.join(directory, 'certs', 'ca.pem');
  try { await fs.access(certPath); return certPath; } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const keys = await promisify(crypto.generateKeyPair)('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.publicKeyFromPem(keys.publicKey);
  cert.serialNumber = '01' + crypto.randomBytes(15).toString('hex');
  cert.validity.notBefore = new Date(Date.now() - 86400000);
  cert.validity.notAfter = new Date(Date.now() + 365 * 86400000);
  const subject = [{ name: 'commonName', value: 'Proxyking Local CA' }, { name: 'organizationName', value: 'Proxyking' }];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
    { name: 'subjectKeyIdentifier' }
  ]);
  cert.sign(forge.pki.privateKeyFromPem(keys.privateKey), forge.md.sha256.create());
  await fs.writeFile(path.join(directory, 'keys', 'ca.private.key'), keys.privateKey, { mode: 0o600 });
  await fs.writeFile(path.join(directory, 'keys', 'ca.public.key'), keys.publicKey, { mode: 0o600 });
  // Write the certificate last, so its presence indicates a complete key pair.
  await fs.writeFile(certPath, forge.pki.certificateToPem(cert), { mode: 0o600 });
  return certPath;
}

module.exports = { ensureCertificate, refreshLeafCertificateCache, LEAF_CACHE_VERSION };
