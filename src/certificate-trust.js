const { execFile } = require('node:child_process');
const fs = require('node:fs/promises');
const { X509Certificate } = require('node:crypto');
const path = require('node:path');
const os = require('node:os');

function run(file, args, { timeout = 120000 } = {}) {
  return new Promise((resolve, reject) => {
    execFile(file, args, { timeout, windowsHide: true, maxBuffer: 1024 * 1024 }, (error, stdout, stderr) => {
      if (error) return reject(new Error(`${path.basename(file)} failed: ${stderr.trim() || error.message}`));
      resolve(stdout.trim());
    });
  });
}

function keychains() {
  return [
    path.join(os.homedir(), 'Library', 'Keychains', 'login.keychain-db'),
    '/Library/Keychains/System.keychain'
  ];
}

function fingerprints(pemText) {
  return [...String(pemText).matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)]
    .map(match => { try { return new X509Certificate(match[0]).fingerprint256; } catch { return ''; } })
    .filter(Boolean);
}

async function certificateSha1(certificatePath) {
  if (typeof certificatePath !== 'string' || !path.isAbsolute(certificatePath)) throw new Error('A valid certificate path is required.');
  return new X509Certificate(await fs.readFile(certificatePath)).fingerprint.replaceAll(':', '');
}

async function macCertificateTrustStatus(certificatePath, execute = run) {
  if (process.platform !== 'darwin' && execute === run) return { state: 'unsupported', label: 'Manual setup' };
  if (typeof certificatePath !== 'string' || !path.isAbsolute(certificatePath)) throw new Error('A valid certificate path is required.');
  const localFingerprint = new X509Certificate(await fs.readFile(certificatePath)).fingerprint256;
  let installed = false;
  for (const keychain of keychains()) {
    try {
      const output = await execute('/usr/bin/security', ['find-certificate', '-a', '-c', 'Proxyking Local CA', '-p', keychain], { timeout: 30000 });
      if (fingerprints(output).includes(localFingerprint)) { installed = true; break; }
    } catch {}
  }
  if (!installed) return { state: 'missing', label: 'Not installed' };
  try {
    await execute('/usr/bin/security', ['verify-cert', '-c', certificatePath, '-p', 'ssl'], { timeout: 30000 });
    return { state: 'trusted', label: 'Installed & trusted' };
  } catch {
    return { state: 'untrusted', label: 'Installed, not trusted' };
  }
}

async function matchingKeychains(certificatePath, execute = run) {
  const localFingerprint = new X509Certificate(await fs.readFile(certificatePath)).fingerprint256;
  const matches = [];
  for (const keychain of keychains()) {
    try {
      const output = await execute('/usr/bin/security', ['find-certificate', '-a', '-c', 'Proxyking Local CA', '-p', keychain], { timeout: 30000 });
      if (fingerprints(output).includes(localFingerprint)) matches.push(keychain);
    } catch {}
  }
  return { fingerprint: localFingerprint.replaceAll(':', ''), matches };
}

async function removeMacCertificate(certificatePath, execute = run) {
  if (process.platform !== 'darwin' && execute === run) throw new Error('Automatic certificate removal is supported only on macOS.');
  if (typeof certificatePath !== 'string' || !path.isAbsolute(certificatePath)) throw new Error('A valid certificate path is required.');
  const loginKeychain = keychains()[0];
  const systemKeychain = keychains()[1];
  const { fingerprint, matches } = await matchingKeychains(certificatePath, execute);
  if (matches.includes(loginKeychain)) {
    try {
      await execute('/usr/bin/security', ['remove-trusted-cert', certificatePath], { timeout: 120000 });
    } catch (error) {
      if (!/could not be found|not found/i.test(error.message)) throw error;
    }
    await execute('/usr/bin/security', ['delete-certificate', '-Z', fingerprint, loginKeychain], { timeout: 30000 });
  }
  return { removed: matches.includes(loginKeychain), systemCopy: matches.includes(systemKeychain) };
}

async function installMacCertificate(certificatePath, execute = run) {
  if (process.platform !== 'darwin' && execute === run) throw new Error('Automatic certificate trust is supported only on macOS.');
  if (typeof certificatePath !== 'string' || !path.isAbsolute(certificatePath)) throw new Error('A valid certificate path is required.');
  // Use the current user's keychain and trust domain. System-keychain writes
  // require a signed privileged helper for reliable one-click installation;
  // combining sudo/osascript with add-trusted-cert creates nested authorization
  // failures on current macOS releases.
  const keychain = keychains()[0];
  await execute('/usr/bin/security', ['add-trusted-cert', '-r', 'trustRoot', '-p', 'ssl', '-k', keychain, certificatePath], { timeout: 120000 });
  await execute('/usr/bin/security', ['verify-cert', '-c', certificatePath, '-p', 'ssl'], { timeout: 30000 });
  return true;
}

async function windowsCertificateTrustStatus(certificatePath, execute = run) {
  if (process.platform !== 'win32' && execute === run) return { state: 'unsupported', label: 'Manual setup' };
  const fingerprint = await certificateSha1(certificatePath);
  try {
    await execute('certutil.exe', ['-user', '-store', 'Root', fingerprint], { timeout: 30000 });
    return { state: 'trusted', label: 'Installed & trusted' };
  } catch {
    return { state: 'missing', label: 'Not installed' };
  }
}

async function installWindowsCertificate(certificatePath, execute = run) {
  if (process.platform !== 'win32' && execute === run) throw new Error('Automatic certificate trust is supported only on Windows.');
  await certificateSha1(certificatePath);
  await execute('certutil.exe', ['-user', '-f', '-addstore', 'Root', certificatePath], { timeout: 120000 });
  const status = await windowsCertificateTrustStatus(certificatePath, execute);
  if (status.state !== 'trusted') throw new Error('Windows did not trust the Proxyking CA after installation.');
  return true;
}

async function removeWindowsCertificate(certificatePath, execute = run) {
  if (process.platform !== 'win32' && execute === run) throw new Error('Automatic certificate removal is supported only on Windows.');
  const fingerprint = await certificateSha1(certificatePath);
  const status = await windowsCertificateTrustStatus(certificatePath, execute);
  if (status.state === 'missing') return { removed: false, systemCopy: false };
  await execute('certutil.exe', ['-user', '-delstore', 'Root', fingerprint], { timeout: 30000 });
  const remaining = await windowsCertificateTrustStatus(certificatePath, execute);
  if (remaining.state !== 'missing') throw new Error('The Proxyking CA is still present in the Windows user trust store.');
  return { removed: true, systemCopy: false };
}

module.exports = {
  installMacCertificate, removeMacCertificate, macCertificateTrustStatus,
  installWindowsCertificate, removeWindowsCertificate, windowsCertificateTrustStatus,
  certificateSha1, fingerprints, run
};
