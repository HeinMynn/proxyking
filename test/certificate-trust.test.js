const { test } = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs/promises');
const { X509Certificate } = require('node:crypto');
const { installMacCertificate, removeMacCertificate, macCertificateTrustStatus } = require('../src/certificate-trust');
const { ensureCertificate } = require('../src/certificate');

async function certificateFixture(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'proxyking-ca-status-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  return { certificatePath: await ensureCertificate(directory), pem: await fs.readFile(path.join(directory, 'certs', 'ca.pem'), 'utf8') };
}

test('macOS CA installation delegates the interactive prompt directly to security', async () => {
  const calls = [];
  const certificatePath = "/tmp/Proxyking CA'; touch unsafe; '.pem";
  const execute = async (file, args, options) => { calls.push({ file, args, options }); return ''; };
  assert.equal(await installMacCertificate(certificatePath, execute), true);
  assert.deepEqual(calls[0], {
    file: '/usr/bin/security',
    args: ['add-trusted-cert', '-r', 'trustRoot', '-p', 'ssl', '-k', path.join(os.homedir(), 'Library', 'Keychains', 'login.keychain-db'), certificatePath],
    options: { timeout: 120000 }
  });
  assert.deepEqual(calls[1], {
    file: '/usr/bin/security',
    args: ['verify-cert', '-c', certificatePath, '-p', 'ssl'],
    options: { timeout: 30000 }
  });
});

test('macOS CA installation requires an absolute internal certificate path', async () => {
  await assert.rejects(installMacCertificate('relative-ca.pem', async () => ''), /valid certificate path/);
});

test('macOS CA installation reports trust verification failures', async () => {
  let calls = 0;
  await assert.rejects(installMacCertificate('/tmp/ca.pem', async () => {
    calls++;
    if (calls === 2) throw new Error('certificate is not trusted');
  }), /not trusted/);
});

test('certificate status requires the exact Proxyking CA fingerprint and SSL trust', async t => {
  const { certificatePath, pem } = await certificateFixture(t);
  const trusted = await macCertificateTrustStatus(certificatePath, async (_file, args) => {
    if (args[0] === 'find-certificate') return pem;
    if (args[0] === 'verify-cert') return '';
    throw new Error('unexpected command');
  });
  assert.deepEqual(trusted, { state: 'trusted', label: 'Installed & trusted' });

  const untrusted = await macCertificateTrustStatus(certificatePath, async (_file, args) => {
    if (args[0] === 'find-certificate') return pem;
    throw new Error('not trusted');
  });
  assert.deepEqual(untrusted, { state: 'untrusted', label: 'Installed, not trusted' });
});

test('certificate status reports a missing matching CA', async t => {
  const { certificatePath } = await certificateFixture(t);
  const status = await macCertificateTrustStatus(certificatePath, async () => { throw new Error('not found'); });
  assert.deepEqual(status, { state: 'missing', label: 'Not installed' });
});

test('certificate removal revokes trust and deletes only the exact login-keychain fingerprint', async t => {
  const { certificatePath, pem } = await certificateFixture(t);
  const loginKeychain = path.join(os.homedir(), 'Library', 'Keychains', 'login.keychain-db');
  const fingerprint = new X509Certificate(pem).fingerprint256.replaceAll(':', '');
  const calls = [];
  const result = await removeMacCertificate(certificatePath, async (file, args, options) => {
    calls.push({ file, args, options });
    if (args[0] === 'find-certificate') {
      if (args.at(-1) === loginKeychain) return pem;
      throw new Error('not found');
    }
    return '';
  });
  assert.deepEqual(result, { removed: true, systemCopy: false });
  assert.ok(calls.some(call => call.args[0] === 'remove-trusted-cert' && call.args[1] === certificatePath));
  assert.ok(calls.some(call => call.args[0] === 'delete-certificate' && call.args[2] === fingerprint && call.args[3] === loginKeychain));
});
