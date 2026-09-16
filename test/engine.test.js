const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const https = require('node:https');
const tls = require('node:tls');
const net = require('node:net');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const forge = require('node-forge');
const { CaptureEngine, bodyCollector, inferApplication, mainDomain, BODY_LIMIT } = require('../src/engine');
const { ensureCertificate } = require('../src/certificate');
const { readAlpnProtocols, requiresPassthrough } = require('../src/tls-client-hello');

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
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
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
function secureAlpnTunnel(proxyPort, targetPort, ca) {
  return new Promise((resolve, reject) => {
    const connect = http.request({ host: '127.0.0.1', port: proxyPort, method: 'CONNECT', path: `localhost:${targetPort}` });
    connect.on('error', reject);
    connect.on('connect', (_res, socket) => {
      const secure = tls.connect({ socket, servername: 'localhost', ca, ALPNProtocols: ['h2'] });
      const chunks = [];
      secure.on('secureConnect', () => assert.equal(secure.alpnProtocol, 'h2'));
      secure.on('data', chunk => chunks.push(chunk));
      secure.on('error', reject);
      secure.on('end', () => resolve(Buffer.concat(chunks).toString()));
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
  const proxyHost = '127.0.0.2';
  const { engine, directory } = await fixture(t, { host: proxyHost, httpsAgent: new https.Agent({ ca }) });
  engine.httpsAgent.options.lookup = (_host, _opts, callback) => callback(null, [{ address: '127.0.0.1', family: 4 }]);
  const port = await listen(t, https.createServer(await serverCertificate(root), (_req, res) => res.end('wildcard binding works')));
  const response = await secureRequest(engine.state.port, port, await fs.readFile(path.join(directory, 'certs', 'ca.pem')), proxyHost);
  assert.match(response, /200 OK/);
  assert.match(response, /wildcard binding works/);
});

test('HTTP/2-only TLS is passed through unchanged and identified as a tunnel', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'proxyking-h2-origin-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await ensureCertificate(root);
  const ca = await fs.readFile(path.join(root, 'certs', 'ca.pem'));
  const { engine } = await fixture(t);
  const server = tls.createServer({ ...(await serverCertificate(root)), ALPNProtocols: ['h2'] }, socket => socket.end('private protocol payload'));
  const port = await listen(t, server);
  const result = await secureAlpnTunnel(engine.state.port, port, ca);
  assert.equal(result, 'private protocol payload');
  const record = engine.list()[0];
  assert.equal(record.method, 'TUNNEL'); assert.equal(record.tunneled, true);
  assert.equal(engine.detail(record.id).requestHeaders['tls-alpn'], 'h2');
});

test('a host rejected by the client certificate check is passed through on retry', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'proxyking-pinned-origin-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await ensureCertificate(root);
  const originCa = await fs.readFile(path.join(root, 'certs', 'ca.pem'));
  const { engine } = await fixture(t);
  const port = await listen(t, https.createServer(await serverCertificate(root), (_req, res) => res.end('origin reached')));
  await assert.rejects(secureRequest(engine.state.port, port, originCa), /certificate|issuer|verify/i);
  await new Promise(resolve => setTimeout(resolve, 20));
  const response = await secureRequest(engine.state.port, port, originCa);
  assert.match(response, /200 OK/); assert.match(response, /origin reached/);
  const tunnel = engine.list().find(record => record.tunneled);
  assert.ok(tunnel); assert.match(engine.detail(tunnel.id).responseBody.note, /rejected Proxyking/);
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
  assert.deepEqual(readAlpnProtocols(h2), ['h2']); assert.equal(requiresPassthrough(h2), true);
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

test('domain grouping collapses subdomains using public suffix rules', () => {
  assert.equal(mainDomain('docs.google.com'), 'google.com');
  assert.equal(mainDomain('signaler-pa.clients6.google.com'), 'google.com');
  assert.equal(mainDomain('api.service.example.co.uk'), 'example.co.uk');
  assert.equal(mainDomain('127.0.0.1'), '127.0.0.1');
  assert.equal(mainDomain('localhost'), 'localhost');
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
