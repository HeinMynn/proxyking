const { test } = require('node:test');
const { X509Certificate } = require('node:crypto');
const assert = require('node:assert/strict');
const http = require('node:http');
const https = require('node:https');
const http2 = require('node:http2');
const tls = require('node:tls');
const net = require('node:net');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const forge = require('node-forge');
const { CaptureEngine, bodyCollector, inferApplication, mainDomain, normalizeClientAddress, remoteDeviceAddress, BODY_LIMIT } = require('../src/engine');
const { ensureCertificate } = require('../src/certificate');
const { readAlpnProtocols, requiresPassthrough } = require('../src/tls-client-hello');
const { isCertificateRejection, isIncompatibleTls, isExpectedSocketClosure, parseConnectTarget } = require('../src/inspection-proxy');
const { SETUP_VERIFY_HOST, inferDevicePlatform } = require('../src/device-setup');

async function fixture(t, options = {}) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'proxyking-test-'));
  const engine = new CaptureEngine({ directory, ...options });
  t.after(async () => { await engine.stop(); await fs.rm(directory, { recursive: true, force: true }); });
  await engine.start(0);
  return { engine, directory };
}
async function listen(t, server) {
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  const sockets = new Set();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { for (const socket of sockets) socket.destroy(); server.close(); });
  return server.address().port;
}
function request(port, url, body = '', headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: url, method: body ? 'POST' : 'GET', headers: { host: new URL(url).host, ...headers } }, res => {
      const chunks = []; res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject); req.end(body);
  });
}
function secureRequest(proxyPort, targetPort, ca, proxyHost = '127.0.0.1') {
  return new Promise((resolve, reject) => {
    const connect = http.request({ host: proxyHost, port: proxyPort, method: 'CONNECT', path: `localhost:${targetPort}` });
    connect.on('error', reject);
    connect.on('connect', (_res, socket) => {
      const secure = tls.connect({ socket, servername: 'localhost', ca }, () => {
        secure.write(`GET /secure HTTP/1.1\r\nHost: localhost:${targetPort}\r\nConnection: close\r\n\r\n`);
      });
      const chunks = []; secure.on('data', chunk => chunks.push(chunk));
      secure.on('error', reject); secure.on('end', () => resolve(Buffer.concat(chunks).toString()));
    });
    connect.end();
  });
}
function secureSetupRequest(proxyPort, ca) {
  return new Promise((resolve, reject) => {
    const connect = http.request({ host: '127.0.0.1', port: proxyPort, method: 'CONNECT', path: `${SETUP_VERIFY_HOST}:443` });
    connect.on('error', reject);
    connect.on('connect', (_res, socket) => {
      const secure = tls.connect({ socket, servername: SETUP_VERIFY_HOST, ca, ALPNProtocols: ['http/1.1'] }, () => {
        secure.write(`GET /verify HTTP/1.1\r\nHost: ${SETUP_VERIFY_HOST}\r\nConnection: close\r\n\r\n`);
      });
      const chunks = [];
      secure.on('data', chunk => chunks.push(chunk));
      secure.on('error', reject);
      secure.on('end', () => resolve(Buffer.concat(chunks).toString()));
    });
    connect.end();
  });
}
function secureAlpnTunnel(proxyPort, targetPort, ca, protocol = 'h2') {
  return new Promise((resolve, reject) => {
    const connect = http.request({ host: '127.0.0.1', port: proxyPort, method: 'CONNECT', path: `localhost:${targetPort}` });
    connect.on('error', reject);
    connect.on('connect', (_res, socket) => {
      const secure = tls.connect({ socket, servername: 'localhost', ca, ALPNProtocols: [protocol] });
      const chunks = [];
      secure.on('secureConnect', () => assert.equal(secure.alpnProtocol, protocol));
      secure.on('data', chunk => chunks.push(chunk));
      secure.on('error', reject);
      secure.on('end', () => resolve(Buffer.concat(chunks).toString()));
    });
    connect.end();
  });
}
function secureHttp2Request(proxyPort, targetPort, ca) {
  return new Promise((resolve, reject) => {
    const connect = http.request({ host: '127.0.0.1', port: proxyPort, method: 'CONNECT', path: `localhost:${targetPort}` });
    connect.on('error', reject);
    connect.on('connect', (_res, socket) => {
      const secure = tls.connect({ socket, servername: 'localhost', ca, ALPNProtocols: ['h2'] });
      secure.on('error', reject);
      secure.once('secureConnect', () => {
        const client = http2.connect(`https://localhost:${targetPort}`, { createConnection: () => secure });
        client.on('error', reject);
        const req = client.request({ ':path': '/playlist.m3u8', accept: '*/*' });
        const chunks = [];
        req.on('data', chunk => chunks.push(chunk));
        req.on('error', reject);
        req.on('end', () => { client.close(); resolve(Buffer.concat(chunks).toString()); });
        req.end();
      });
    });
    connect.end();
  });
}
async function serverCertificate(directory) {
  const ca = forge.pki.certificateFromPem(await fs.readFile(path.join(directory, 'certs', 'ca.pem'), 'utf8'));
  const key = forge.pki.privateKeyFromPem(await fs.readFile(path.join(directory, 'keys', 'ca.private.key'), 'utf8'));
  const cert = forge.pki.createCertificate(); cert.publicKey = ca.publicKey;
  cert.serialNumber = '02'; cert.validity.notBefore = ca.validity.notBefore; cert.validity.notAfter = ca.validity.notAfter;
  cert.setSubject([{ name: 'commonName', value: 'localhost' }]); cert.setIssuer(ca.subject.attributes);
  cert.setExtensions([{ name: 'subjectAltName', altNames: [{ type: 2, value: 'localhost' }] }]);
  cert.sign(key, forge.md.sha256.create());
  return { key: forge.pki.privateKeyToPem(key), cert: forge.pki.certificateToPem(cert) };
}

test('HTTP POST forwards intact, strips proxy credentials, captures bodies and exports HAR', async t => {
  const { engine } = await fixture(t);
  const port = await listen(t, http.createServer((req, res) => {
    assert.equal(req.headers['proxy-authorization'], undefined);
    const chunks = []; req.on('data', c => chunks.push(c)); req.on('end', () => {
      res.writeHead(201, { 'content-type': 'application/json' }); res.end(JSON.stringify({ received: Buffer.concat(chunks).toString() }));
    });
  }));
  const result = await request(engine.state.port, `http://127.0.0.1:${port}/echo?q=yes`, 'hello', { 'content-type': 'text/plain', 'proxy-authorization': 'secret' });
  assert.equal(result.status, 201); assert.deepEqual(JSON.parse(result.body), { received: 'hello' });
  const record = engine.detail(engine.list()[0].id);
  assert.equal(record.requestBody.text, 'hello'); assert.equal(record.state, 'complete');
  assert.equal(record.responseBody.text, '{"received":"hello"}');
  const har = engine.exportHar(); assert.equal(har.log.entries[0].response.status, 201);
  assert.deepEqual(har.log.entries[0].request.queryString, [{ name: 'q', value: 'yes' }]);
  engine.clear(); assert.equal(engine.list().length, 0);
});

test('upstream response headers larger than Node defaults are captured', async t => {
  const { engine } = await fixture(t);
  const largeHeader = 'v'.repeat(32 * 1024);
  const port = await listen(t, http.createServer((_req, res) => {
    res.writeHead(200, { 'x-large-test': largeHeader, 'content-type': 'text/plain' });
    res.end('large header response');
  }));
  const url = `http://127.0.0.1:${port}/large-header`;
  const result = await new Promise((resolve, reject) => {
    const req = http.get({ host: '127.0.0.1', port: engine.state.port, path: url,
      headers: { host: `127.0.0.1:${port}` }, maxHeaderSize: 128 * 1024 }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, header: res.headers['x-large-test'], body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
  });
  assert.equal(result.status, 200);
  assert.equal(result.header, largeHeader);
  assert.equal(result.body, 'large header response');
  assert.equal(engine.list()[0].state, 'complete');
});

test('replay resends an editable request and records its response', async t => {
  const { engine } = await fixture(t);
  const received = [];
  const port = await listen(t, http.createServer((req, res) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      received.push({ method: req.method, body: Buffer.concat(chunks).toString(), header: req.headers['x-replay-test'] });
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(received.at(-1)));
    });
  }));
  await request(engine.state.port, `http://127.0.0.1:${port}/original`, 'before');
  const first = engine.list()[0];
  const replayed = await engine.replay(first.id, {
    method: 'PUT', url: `http://127.0.0.1:${port}/changed`,
    headers: { 'content-type': 'text/plain', 'x-replay-test': 'yes' }, body: 'after'
  });
  assert.equal(received.length, 2);
  assert.deepEqual(received[1], { method: 'PUT', body: 'after', header: 'yes' });
  assert.equal(replayed.replayOf, first.id);
  assert.equal(replayed.status, 200);
  assert.match(replayed.responseBody.text, /"body":"after"/);
});

test('request and response breakpoints edit text bodies in flight', async t => {
  const { engine } = await fixture(t);
  const received = [];
  const port = await listen(t, http.createServer((req, res) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      received.push(Buffer.concat(chunks).toString());
      res.setHeader('content-type', 'text/plain');
      res.end('origin response');
    });
  }));
  const host = `127.0.0.1:${port}`;
  engine.setBreakpoint(host, 'request', true);
  engine.setBreakpoint(host, 'response', true);
  const hit = [];
  engine.on('breakpoint', item => {
    hit.push(item.side);
    engine.resolveBreakpoint(item.id, { action: 'edit', body: item.side === 'request' ? 'edited request' : 'edited response' });
  });
  const result = await request(engine.state.port, `http://${host}/edit`, 'original request', { 'content-type': 'text/plain' });
  assert.equal(received[0], 'edited request');
  assert.equal(result.body.toString(), 'edited response');
  assert.deepEqual(hit, ['request', 'response']);
  assert.equal(engine.list()[0].requestSize, Buffer.byteLength('edited request'));
  assert.equal(engine.list()[0].size, Buffer.byteLength('edited response'));
});

test('mobile setup serves Android and iOS guidance, the CA, and a local HTTPS trust check', async t => {
  const { engine, directory } = await fixture(t);
  const setupUrl = `http://127.0.0.1:${engine.state.port}/setup`;
  const page = await request(engine.state.port, setupUrl, '', { 'user-agent': 'Mozilla/5.0 (Linux; Android 15)' });
  assert.equal(page.status, 200);
  assert.match(page.body.toString(), /iPhone &amp; iPad/);
  assert.match(page.body.toString(), /iOS does not enable SSL trust automatically/);
  assert.match(page.body.toString(), /Enable Full Trust for Root Certificates/);
  assert.match(page.body.toString(), /Android/);
  assert.doesNotMatch(page.body.toString(), /onclick=/);
  assert.match(page.headers['content-security-policy'], /script-src 'self'/);
  assert.ok(page.headers['content-security-policy'].includes("connect-src 'self' https://proxyking.test"));
  const script = await request(engine.state.port, setupUrl + '/app.js');
  assert.ok(script.body.toString().includes("fetch('https://proxyking.test/verify'"));
  assert.match(page.body.toString(), /checks automatically/);

  const certificate = await request(engine.state.port, setupUrl + '/ca.crt');
  assert.equal(certificate.status, 200);
  assert.match(certificate.headers['content-type'], /application\/x-x509-ca-cert/);
  assert.match(certificate.body.toString(), /BEGIN CERTIFICATE/);
  assert.doesNotMatch(certificate.body.toString(), /PRIVATE KEY/);

  const ca = await fs.readFile(path.join(directory, 'certs', 'ca.pem'));
  const verification = await secureSetupRequest(engine.state.port, ca);
  assert.match(verification, /200 OK/);
  assert.match(verification, /HTTPS verified/);
  const rootCertificate = new X509Certificate(ca);
  const serverCertificate = new X509Certificate(await fs.readFile(path.join(directory, 'certs', SETUP_VERIFY_HOST + '.pem')));
  assert.doesNotMatch(serverCertificate.serialNumber, /^-/);
  assert.equal(serverCertificate.subjectAltName, 'DNS:' + SETUP_VERIFY_HOST);
  assert.ok(serverCertificate.keyUsage.includes('1.3.6.1.5.5.7.3.1'));
  assert.ok(new Date(serverCertificate.validTo) <= new Date(rootCertificate.validTo));
  assert.ok(new Date(serverCertificate.validTo) - new Date(serverCertificate.validFrom) <= 92 * 86400000);

  const status = await request(engine.state.port, setupUrl + '/api/status', '', { 'user-agent': 'Mozilla/5.0 (Linux; Android 15)' });
  assert.equal(JSON.parse(status.body).trusted, true);
  assert.equal(engine.list().length, 0);
});

test('mobile platform detection recognizes Android and Apple mobile clients', () => {
  assert.equal(inferDevicePlatform('Mozilla/5.0 (Linux; Android 15)'), 'Android');
  assert.equal(inferDevicePlatform('Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X)'), 'iOS');
  assert.equal(inferDevicePlatform('curl/8.0'), 'Unknown device');
});

test('HTTPS CONNECT decrypts traffic with a trusted local CA and validates upstream TLS', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'proxyking-upstream-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await ensureCertificate(root);
  const ca = await fs.readFile(path.join(root, 'certs', 'ca.pem'));
  const { engine, directory } = await fixture(t, { httpsAgent: new https.Agent({ ca }) });
  // Bind localhost's IPv4 address and use explicit DNS resolution for the test agent.
  engine.httpsAgent.options.lookup = (_host, _opts, callback) => callback(null, [{ address: '127.0.0.1', family: 4 }]);
  const port = await listen(t, https.createServer(await serverCertificate(root), (_req, res) => { res.setHeader('content-type', 'text/plain'); res.end('encrypted origin payload'); }));
  const response = await secureRequest(engine.state.port, port, await fs.readFile(path.join(directory, 'certs', 'ca.pem')));
  assert.match(response, /200 OK/); assert.match(response, /encrypted origin payload/);
  const record = engine.detail(engine.list()[0].id);
  assert.equal(record.secure, true); assert.equal(record.responseBody.text, 'encrypted origin payload');
});

test('HTTPS inspection reaches its internal listener when the proxy uses a non-default local address', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'proxyking-local-address-upstream-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await ensureCertificate(root);
  const ca = await fs.readFile(path.join(root, 'certs', 'ca.pem'));
  const proxyHost = Object.values(os.networkInterfaces()).flat().find(item => item?.family === 'IPv4' && !item.internal)?.address;
  if (!proxyHost) return t.skip('No non-loopback IPv4 interface is available.');
  const { engine, directory } = await fixture(t, { host: proxyHost, httpsAgent: new https.Agent({ ca }) });
  engine.httpsAgent.options.lookup = (_host, _opts, callback) => callback(null, [{ address: '127.0.0.1', family: 4 }]);
  const port = await listen(t, https.createServer(await serverCertificate(root), (_req, res) => res.end('wildcard binding works')));
  const response = await secureRequest(engine.state.port, port, await fs.readFile(path.join(directory, 'certs', 'ca.pem')), proxyHost);
  assert.match(response, /200 OK/);
  assert.match(response, /wildcard binding works/);
});

test('private ALPN protocols are passed through unchanged and identified as a tunnel', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'proxyking-h2-origin-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await ensureCertificate(root);
  const ca = await fs.readFile(path.join(root, 'certs', 'ca.pem'));
  const { engine } = await fixture(t);
  const server = tls.createServer({ ...(await serverCertificate(root)), ALPNProtocols: ['private-media'] }, socket => socket.end('private protocol payload'));
  const port = await listen(t, server);
  const result = await secureAlpnTunnel(engine.state.port, port, ca, 'private-media');
  assert.equal(result, 'private protocol payload');
  const record = engine.list()[0];
  assert.equal(record.method, 'TUNNEL'); assert.equal(record.tunneled, true);
  assert.equal(engine.detail(record.id).requestHeaders['tls-alpn'], 'private-media');
});

test('HTTP/2-only TLS is inspected and translated through the capture pipeline', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'proxyking-h2-inspection-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await ensureCertificate(root);
  const ca = await fs.readFile(path.join(root, 'certs', 'ca.pem'));
  const { engine, directory } = await fixture(t, { httpsAgent: new https.Agent({ ca }) });
  engine.httpsAgent.options.lookup = (_host, _opts, callback) => callback(null, [{ address: '127.0.0.1', family: 4 }]);
  const port = await listen(t, https.createServer(await serverCertificate(root), (req, res) => {
    assert.equal(req.url, '/playlist.m3u8'); res.end('#EXTM3U');
  }));
  const response = await secureHttp2Request(engine.state.port, port, await fs.readFile(path.join(directory, 'certs', 'ca.pem')));
  assert.equal(response, '#EXTM3U');
  const record = engine.list().find(item => item.path === '/playlist.m3u8');
  assert.ok(record); assert.equal(record.tunneled, undefined); assert.equal(record.secure, true); assert.equal(record.httpVersion, 'HTTP/2');
});

test('a connection reset does not disable HTTPS inspection for later requests to the host', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'proxyking-pinned-origin-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await ensureCertificate(root);
  const originCa = await fs.readFile(path.join(root, 'certs', 'ca.pem'));
  const { engine } = await fixture(t);
  const port = await listen(t, https.createServer(await serverCertificate(root), (_req, res) => res.end('origin reached')));
  await assert.rejects(secureRequest(engine.state.port, port, originCa), /certificate|issuer|verify/i);
  await new Promise(resolve => setTimeout(resolve, 20));
  await assert.rejects(secureRequest(engine.state.port, port, originCa), /certificate|issuer|verify/i);
  assert.equal(engine.list().some(record => record.tunneled), false);
});

test('only explicit TLS certificate alerts trigger encrypted fallback', () => {
  assert.equal(isCertificateRejection({ code: 'ERR_SSL_SSLV3_ALERT_CERTIFICATE_UNKNOWN' }), true);
  assert.equal(isCertificateRejection({ code: 'ERR_SSL_TLSV1_ALERT_UNKNOWN_CA' }), true);
  assert.equal(isCertificateRejection({ code: 'ECONNRESET' }), false);
  assert.equal(isCertificateRejection({ code: 'ERR_SSL_NO_APPLICATION_PROTOCOL' }), false);
});

test('unsupported TLS is remembered for pass-through without classifying resets as incompatible', () => {
  assert.equal(isIncompatibleTls({ code: 'ERR_SSL_UNSUPPORTED_PROTOCOL' }), true);
  assert.equal(isIncompatibleTls({ code: 'ECONNRESET' }), false);
  assert.equal(isIncompatibleTls({ code: 'ERR_SSL_TLSV1_ALERT_UNKNOWN_CA' }), false);
});

test('normal socket shutdown races are not reported as proxy failures', () => {
  assert.equal(isExpectedSocketClosure({ code: 'ECONNRESET' }), true);
  assert.equal(isExpectedSocketClosure({ code: 'EPIPE' }), true);
  assert.equal(isExpectedSocketClosure({ code: 'ENOTFOUND' }), false);
});

test('CONNECT targets are parsed without allowing malformed authorities to throw', () => {
  assert.deepEqual(parseConnectTarget('iframe.mediadelivery.net:443'), { hostname: 'iframe.mediadelivery.net', port: 443 });
  assert.deepEqual(parseConnectTarget('[::1]:8443'), { hostname: '::1', port: 8443 });
  for (const target of ['', 'https://example.com', 'example.com:bad', 'example.com:443/path', 'user@example.com:443', ' example.com:443']) {
    assert.equal(parseConnectTarget(target), null);
  }
});

test('ClientHello ALPN parser distinguishes inspectable and pass-through protocols', async t => {
  async function hello(protocols) {
    let resolveData;
    const received = new Promise(resolve => { resolveData = resolve; });
    const server = net.createServer(socket => socket.once('data', resolveData));
    const port = await listen(t, server);
    const client = tls.connect({ host: '127.0.0.1', port, rejectUnauthorized: false, ALPNProtocols: protocols });
    client.on('error', () => {});
    const data = await received; client.destroy();
    return data;
  }
  const h2 = await hello(['h2']);
  assert.deepEqual(readAlpnProtocols(h2), ['h2']); assert.equal(requiresPassthrough(h2), false);
  const browser = await hello(['h2', 'http/1.1']);
  assert.deepEqual(readAlpnProtocols(browser), ['h2', 'http/1.1']); assert.equal(requiresPassthrough(browser), false);
});

test('large responses stream completely while capture is bounded', async t => {
  const { engine } = await fixture(t);
  const payload = Buffer.alloc(BODY_LIMIT * 3, 'a');
  const port = await listen(t, http.createServer((_req, res) => { res.setHeader('content-type', 'text/plain'); res.end(payload); }));
  const result = await request(engine.state.port, `http://127.0.0.1:${port}/large`);
  assert.deepEqual(result.body, payload);
  const record = engine.detail(engine.list()[0].id);
  assert.equal(record.responseBody.text.length, BODY_LIMIT); assert.equal(record.responseBody.truncated, true); assert.equal(record.size, payload.length);
});

test('untrusted upstream HTTPS certificate is rejected', async t => {
  const { engine, directory } = await fixture(t);
  const port = await listen(t, https.createServer(await serverCertificate(directory), (_req, res) => res.end('must not be accepted')));
  const response = await secureRequest(engine.state.port, port, await fs.readFile(path.join(directory, 'certs', 'ca.pem')));
  assert.doesNotMatch(response, /200 OK/);
  assert.doesNotMatch(response, /must not be accepted/);
  const record = engine.detail(engine.list()[0].id);
  assert.equal(record.state, 'failed');
  assert.match(record.error, /certificate|self.signed/i);
});

test('CA persists across restarts and direct proxy loops are blocked', async t => {
  const { engine, directory } = await fixture(t);
  const before = await fs.readFile(path.join(directory, 'certs', 'ca.pem'), 'utf8');
  await engine.stop(); await engine.start(0);
  assert.equal(await fs.readFile(path.join(directory, 'certs', 'ca.pem'), 'utf8'), before);
  const response = await request(engine.state.port, `http://127.0.0.1:${engine.state.port}/loop`);
  assert.equal(response.status, 508);
});

test('compressed previews decode without changing wire data', () => {
  const collector = bodyCollector(); collector.add(zlib.gzipSync(Buffer.from('{"ok":true}')));
  assert.equal(collector.read({ 'content-encoding': 'gzip', 'content-type': 'application/json' }).text, '{"ok":true}');
  const bomb = bodyCollector(); bomb.add(zlib.gzipSync(Buffer.alloc(BODY_LIMIT * 2, 'x')));
  assert.equal(bomb.read({ 'content-encoding': 'gzip' }).encoding, 'base64');
});

test('application grouping recognizes common client user agents', () => {
  assert.equal(inferApplication({ 'user-agent': 'Mozilla/5.0 Chrome/140.0 Safari/537.36 Edg/140.0' }), 'Microsoft Edge');
  assert.equal(inferApplication({ 'user-agent': 'Mozilla/5.0 Chrome/140.0 Safari/537.36' }), 'Google Chrome');
  assert.equal(inferApplication({ 'user-agent': 'PostmanRuntime/7.46.0' }), 'Postman');
  assert.equal(inferApplication({}), 'Unknown app');
});

test('remote device addresses exclude the local computer and normalize IPv4-mapped clients', () => {
  assert.equal(normalizeClientAddress('::ffff:192.168.1.25'), '192.168.1.25');
  assert.equal(normalizeClientAddress('::1'), '127.0.0.1');
  assert.equal(remoteDeviceAddress('192.168.1.25', '192.168.1.10'), '192.168.1.25');
  assert.equal(remoteDeviceAddress('192.168.1.10', '192.168.1.10'), '');
  assert.equal(remoteDeviceAddress('127.0.0.1', '192.168.1.10'), '');
});

test('remote device setup tracks platform and HTTPS verification state', () => {
  const engine = new CaptureEngine({ host: '192.168.1.10' });
  const seen = [];
  engine.on('device', device => seen.push(device));
  engine.observeClientRequest('::ffff:192.168.1.25', 'Mozilla/5.0 (Linux; Android 15)', false);
  assert.equal(engine.setupStatus('192.168.1.25').trusted, false);
  engine.observeClientRequest('192.168.1.25', 'Mozilla/5.0 (Linux; Android 15)', true);
  assert.equal(engine.deviceList().length, 1);
  assert.equal(engine.deviceList()[0].address, '192.168.1.25');
  assert.equal(engine.deviceList()[0].platform, 'Android');
  assert.ok(engine.deviceList()[0].trustedAt);
  assert.equal(seen.length, 2);
  engine.observeClientRequest('192.168.1.25', 'Mozilla/5.0 (Linux; Android 15)', true);
  assert.equal(seen.length, 2);
  engine.clear();
  assert.equal(engine.deviceList().length, 1);
  assert.ok(engine.setupStatus('192.168.1.25', 'Mozilla/5.0 (Linux; Android 15)').trusted);
});

test('domain grouping collapses subdomains using public suffix rules', () => {
  assert.equal(mainDomain('docs.google.com'), 'google.com');
  assert.equal(mainDomain('signaler-pa.clients6.google.com'), 'google.com');
  assert.equal(mainDomain('api.service.example.co.uk'), 'example.co.uk');
  assert.equal(mainDomain('127.0.0.1'), '127.0.0.1');
  assert.equal(mainDomain('localhost'), 'localhost');
});

test('records remain until explicitly cleared', () => {
  const engine = new CaptureEngine();
  for (let index = 0; index < 250; index++) {
    engine.addPassthrough({ host: `media-${index}.example.com`, port: 443, protocols: ['private-media'], reason: 'unsupported-alpn' });
  }
  assert.equal(engine.list().length, 250);
  engine.clear();
  assert.equal(engine.list().length, 0);
});

test('HAR export can be limited to one selected record', () => {
  const engine = new CaptureEngine();
  engine.addPassthrough({ host: 'one.example.com', port: 443, protocols: ['private-media'], reason: 'unsupported-alpn' });
  engine.addPassthrough({ host: 'two.example.com', port: 443, protocols: ['private-media'], reason: 'unsupported-alpn' });
  const selected = engine.detail(engine.list()[0].id);
  const har = engine.exportHar([selected]);
  assert.equal(har.log.entries.length, 1);
  assert.equal(har.log.entries[0].request.url, selected.url);
});

test('encrypted pass-through records do not show a global notice', () => {
  const engine = new CaptureEngine();
  const notices = [];
  engine.on('notice', message => notices.push(message));
  engine.addPassthrough({ host: 'pinned.example.com', port: 443, protocols: ['h2'], reason: 'certificate-rejected' });
  engine.addPassthrough({ host: 'private.example.com', port: 443, protocols: ['private-media'], reason: 'unsupported-alpn' });
  assert.equal(engine.list().length, 2);
  assert.deepEqual(notices, []);
});

test('paused capture ignores new records until resumed', () => {
  const engine = new CaptureEngine();
  engine.state = { ...engine.state, running: true };
  const connection = { host: 'media.example.com', port: 443, protocols: ['private-media'], reason: 'unsupported-alpn' };
  engine.pause(); engine.addPassthrough(connection);
  assert.equal(engine.list().length, 0);
  engine.resume(); engine.addPassthrough(connection);
  assert.equal(engine.list().length, 1);
});

test('occupied port fails cleanly and stop allows restart', async t => {
  const { engine } = await fixture(t); const port = engine.state.port;
  await engine.stop(); await engine.start(port); assert.equal(engine.state.running, true);
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'proxyking-conflict-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const second = new CaptureEngine({ directory });
  await assert.rejects(second.start(port), /EADDRINUSE/);
  await second.stop();
});
