const { EventEmitter } = require('node:events');
const { randomUUID } = require('node:crypto');
const net = require('node:net');
const fs = require('node:fs/promises');
const { InspectionProxy } = require('./inspection-proxy');
const { BreakpointFilter, EDIT_LIMIT, editableBody } = require('./traffic-tools');
const { replay } = require('./replay');
const zlib = require('node:zlib');
const { getDomain } = require('tldts');
const { ensureCertificate, refreshLeafCertificateCache } = require('./certificate');
const { SETUP_VERIFY_HOST, inferDevicePlatform, renderSetupPage, renderVerifiedPage, setupScript } = require('./device-setup');
const { normalizeDoNotInspectRules } = require('./do-not-inspect');
const { version } = require('../package.json');

const BODY_LIMIT = 128 * 1024;
const UPSTREAM_HEADER_LIMIT = 128 * 1024;
const QUIET_TLS_ERRORS = new Set([
  'ERR_SSL_NO_APPLICATION_PROTOCOL',
  'ERR_SSL_UNSUPPORTED_PROTOCOL',
  'ERR_SSL_SSLV3_ALERT_CERTIFICATE_UNKNOWN',
  'ERR_SSL_TLSV1_ALERT_UNKNOWN_CA',
  'ECONNRESET',
  'EPIPE'
]);

function mainDomain(hostname = '') {
  const normalized = String(hostname).toLowerCase().replace(/\.$/, '');
  return getDomain(normalized) || normalized;
}

function normalizeClientAddress(address = '') {
  const value = String(address).split('%')[0];
  if (value === '::1') return '127.0.0.1';
  if (value.startsWith('::ffff:') && net.isIP(value.slice(7)) === 4) return value.slice(7);
  return value;
}

function remoteDeviceAddress(address, listeningHost) {
  const client = normalizeClientAddress(address);
  const local = normalizeClientAddress(listeningHost);
  if (!client || client === local || client === '127.0.0.1' || client === '0.0.0.0' || client === '::') return '';
  return client;
}

function inferApplication(headers = {}) {
  const agent = String(headers['user-agent'] || '');
  const signatures = [
    [/\bEdg\//, 'Microsoft Edge'], [/\bOPR\//, 'Opera'], [/\bChrome\//, 'Google Chrome'],
    [/\bFirefox\//, 'Mozilla Firefox'], [/\bVersion\/[^ ]+.*\bSafari\//, 'Safari'],
    [/\bElectron\//, 'Electron app'], [/\bPostmanRuntime\//, 'Postman'], [/\binsomnia\//i, 'Insomnia'],
    [/\bcurl\//i, 'curl'], [/PowerShell/i, 'PowerShell'], [/python-requests/i, 'Python Requests'],
    [/\bokhttp\//i, 'OkHttp app'], [/\bDart\//, 'Dart app'], [/\baxios\//i, 'Axios app']
  ];
  for (const [pattern, name] of signatures) if (pattern.test(agent)) return name;
  if (!agent) return 'Unknown app';
  const product = agent.match(/^([A-Za-z][A-Za-z0-9 ._-]{1,30})(?:\/|$)/)?.[1];
  return product || 'Other app';
}

function bodyCollector(limit = BODY_LIMIT) {
  const chunks = [];
  let captured = 0;
  let size = 0;
  return {
    add(chunk) {
      size += chunk.length;
      if (captured < limit) {
        const part = Buffer.from(chunk.subarray(0, limit - captured));
        chunks.push(part); captured += part.length;
      }
    },
    read(headers = {}) {
      let buffer = Buffer.concat(chunks);
      const truncated = size > captured;
      const encoding = String(headers['content-encoding'] || '').toLowerCase();
      let note = truncated ? `Preview limited to ${limit / 1024} KiB; full traffic was forwarded.` : '';
      try {
        const options = { maxOutputLength: BODY_LIMIT };
        if (!truncated && encoding === 'gzip') buffer = zlib.gunzipSync(buffer, options);
        else if (!truncated && encoding === 'br') buffer = zlib.brotliDecompressSync(buffer, options);
        else if (!truncated && encoding === 'deflate') buffer = zlib.inflateSync(buffer, options);
        else if (encoding && encoding !== 'identity') return { text: buffer.toString('base64'), encoding: 'base64', size, truncated, note: note || 'Encoded body shown as base64.' };
      } catch { return { text: buffer.toString('base64'), encoding: 'base64', size, truncated, note: 'Compressed body could not be decoded within the preview limit.' }; }
      const type = String(headers['content-type'] || '');
      const binary = buffer.includes(0) || (type && !/text|json|xml|javascript|form-urlencoded|graphql|svg/i.test(type));
      return { text: buffer.toString(binary ? 'base64' : 'utf8'), encoding: binary ? 'base64' : 'utf8', size, truncated, note };
    }
  };
}

class CaptureEngine extends EventEmitter {
  constructor({ directory, httpsAgent, host = '127.0.0.1', doNotInspect = [] } = {}) {
    super();
    this.directory = directory;
    this.httpsAgent = httpsAgent;
    this.records = new Map();
    this.devices = new Map();
    this.deviceTrust = new Map();
    this.sockets = new Set();
    this.state = { running: false, paused: false, port: 8080, host };
    this.busy = false;
    this.notices = new Set();
    this.breakpointRules = new Set();
    this.pendingBreakpoints = new Map();
    this.doNotInspect = normalizeDoNotInspectRules(doNotInspect);
  }
  summary(record) {
    const { requestBody, responseBody, requestHeaders, responseHeaders, ...summary } = record;
    let query = '';
    try { query = new URL(record.url).searchParams.toString(); } catch {}
    return {
      ...summary,
      filterData: {
        query,
        requestHeaders: requestHeaders || {},
        responseHeaders: responseHeaders || {},
        requestBody: requestBody?.encoding === 'base64' ? '' : requestBody?.text || '',
        responseBody: responseBody?.encoding === 'base64' ? '' : responseBody?.text || '',
        requestContentType: String(requestHeaders?.['content-type'] || ''),
        responseContentType: String(responseHeaders?.['content-type'] || record.contentType || '')
      }
    };
  }
  list() { return [...this.records.values()].map(record => this.summary(record)); }
  detail(id) { return this.records.get(id) || null; }
  deviceList() { return [...this.devices.values()]; }
  clear() { this.records.clear(); this.emit('cleared'); }
  breakpointList() { return [...this.breakpointRules]; }
  setDoNotInspect(rules) {
    this.doNotInspect = normalizeDoNotInspectRules(rules);
    if (this.proxy) this.proxy.doNotInspect = this.doNotInspect;
    return [...this.doNotInspect];
  }
  setBreakpoint(host, side, enabled) {
    if (typeof host !== 'string' || !host || host.length > 255 || !['request', 'response'].includes(side) || typeof enabled !== 'boolean') throw new Error('Invalid breakpoint rule.');
    const key = side + ':' + host.toLowerCase();
    if (enabled) this.breakpointRules.add(key); else this.breakpointRules.delete(key);
    this.emit('breakpoint-rules', this.breakpointList());
    return this.breakpointList();
  }
  hasBreakpoint(host, side) { return this.breakpointRules.has(side + ':' + host.toLowerCase()); }
  waitAtBreakpoint(side, record, original) {
    const id = randomUUID();
    return new Promise(resolve => {
      const timer = setTimeout(() => this.resolveBreakpoint(id, { action: 'continue' }), 120000);
      timer.unref?.();
      this.pendingBreakpoints.set(id, { resolve, timer, original });
      this.emit('breakpoint', { id, side, recordId: record.id, method: record.method, url: record.url, body: original.toString('utf8') });
    });
  }
  resolveBreakpoint(id, decision = {}) {
    const pending = this.pendingBreakpoints.get(id);
    if (!pending) return false;
    if (decision.action !== 'continue' && decision.action !== 'edit') throw new Error('Invalid breakpoint action.');
    let body = pending.original;
    if (decision.action === 'edit') {
      if (typeof decision.body !== 'string' || Buffer.byteLength(decision.body) > EDIT_LIMIT) throw new Error('Edited body must be text under 1 MiB.');
      body = Buffer.from(decision.body);
    }
    clearTimeout(pending.timer);
    this.pendingBreakpoints.delete(id);
    pending.resolve(body);
    this.emit('breakpoint-resolved', id);
    return true;
  }
  releaseBreakpoints() {
    for (const id of this.pendingBreakpoints.keys()) this.resolveBreakpoint(id, { action: 'continue' });
  }
  replay(id, draft) { return replay(this, id, draft); }
  async prepareCertificate() {
    this.certificatePath = await ensureCertificate(this.directory);
    await refreshLeafCertificateCache(this.directory);
    return this.certificatePath;
  }
  touchDevice(address, userAgent = '', trusted = false) {
    const normalized = normalizeClientAddress(address);
    if (!normalized) return null;
    if (trusted && !this.deviceTrust.has(normalized)) this.deviceTrust.set(normalized, new Date().toISOString());
    const remote = remoteDeviceAddress(normalized, this.state.host);
    if (!remote) return null;
    const previous = this.devices.get(remote);
    const platform = inferDevicePlatform(userAgent);
    const next = {
      address: remote,
      platform: platform === 'Unknown device' ? previous?.platform || platform : platform,
      trustedAt: this.deviceTrust.get(normalized) || previous?.trustedAt || null,
      lastSeen: new Date().toISOString()
    };
    this.devices.set(remote, next);
    if (!previous || previous.platform !== next.platform || previous.trustedAt !== next.trustedAt) this.emit('device', next);
    return next;
  }
  observeClientRequest(address, userAgent = '', secure = false) {
    const remote = remoteDeviceAddress(address, this.state.host);
    if (remote) this.touchDevice(remote, userAgent, secure);
    return remote;
  }
  setupStatus(address, userAgent = '') {
    const normalized = normalizeClientAddress(address);
    const device = this.touchDevice(normalized, userAgent);
    return {
      address: device?.address || normalized || 'Unknown',
      platform: device?.platform || inferDevicePlatform(userAgent),
      trusted: this.deviceTrust.has(normalized),
      trustedAt: this.deviceTrust.get(normalized) || null
    };
  }
  setupUrl() { return `http://${this.state.host}:${this.state.port}/setup`; }
  respondSetup(ctx, status, contentType, body, extraHeaders = {}) {
    const request = ctx.clientToProxyRequest;
    const payload = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
    ctx.proxyToClientResponse.writeHead(status, {
      'content-type': contentType,
      'content-length': payload.length,
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self' https://proxyking.test; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
      ...extraHeaders
    });
    ctx.proxyToClientResponse.end(request.method === 'HEAD' ? undefined : payload);
  }
  serveSetup(ctx, url, clientAddress) {
    const request = ctx.clientToProxyRequest;
    const methodAllowed = request.method === 'GET' || request.method === 'HEAD';
    const userAgent = request.headers['user-agent'] || '';
    if (ctx.isSSL && url.hostname === SETUP_VERIFY_HOST && url.pathname === '/verify') {
      if (!methodAllowed) { this.respondSetup(ctx, 405, 'text/plain; charset=utf-8', 'Method not allowed', { allow: 'GET, HEAD' }); return true; }
      const normalized = normalizeClientAddress(clientAddress);
      this.deviceTrust.set(normalized, new Date().toISOString());
      this.touchDevice(normalized, userAgent, true);
      this.respondSetup(ctx, 200, 'text/html; charset=utf-8', renderVerifiedPage(this.setupUrl()));
      return true;
    }
    const localHost = ['127.0.0.1', 'localhost', '[::1]', this.state.host].includes(url.hostname);
    const localPort = Number(url.port || (ctx.isSSL ? 443 : 80)) === this.state.port;
    if (!localHost || !localPort || !url.pathname.startsWith('/setup')) return false;
    if (!methodAllowed) { this.respondSetup(ctx, 405, 'text/plain; charset=utf-8', 'Method not allowed', { allow: 'GET, HEAD' }); return true; }
    const status = this.setupStatus(clientAddress, userAgent);
    if (url.pathname === '/setup' || url.pathname === '/setup/') {
      this.respondSetup(ctx, 200, 'text/html; charset=utf-8', renderSetupPage({ host: this.state.host, port: this.state.port, ...status }));
    } else if (url.pathname === '/setup/app.js') {
      this.respondSetup(ctx, 200, 'text/javascript; charset=utf-8', setupScript);
    } else if (url.pathname === '/setup/api/status') {
      this.respondSetup(ctx, 200, 'application/json; charset=utf-8', JSON.stringify(status));
    } else if (url.pathname === '/setup/ca.crt') {
      this.respondSetup(ctx, 200, 'application/x-x509-ca-cert', this.caCertificate, { 'content-disposition': 'attachment; filename="Proxyking-CA.crt"' });
    } else {
      this.respondSetup(ctx, 404, 'text/plain; charset=utf-8', 'Setup resource not found');
    }
    return true;
  }
  publish(record) {
    if (this.records.has(record.id)) this.emit('record', this.summary(record));
  }
  async start(port = 8080, host = this.state.host) {
    if (this.busy) throw new Error('The proxy is changing state. Please try again.');
    if (this.state.running) return this.state;
    if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('Port must be between 1 and 65535.');
    if (require('node:net').isIP(host) !== 4) throw new Error('A valid IPv4 listening address is required.');
    this.busy = true;
    try {
      await this.prepareCertificate();
      this.caCertificate = await fs.readFile(this.certificatePath);
      const proxy = new InspectionProxy({ onPassthrough: connection => this.addPassthrough(connection), doNotInspect: this.doNotInspect });
      this.proxy = proxy;
      let startupReject;
      proxy.onError((ctx, error, kind) => {
        if (startupReject) { startupReject(error); return; }
        if (ctx?._record) {
          ctx._record.error = error.message;
          ctx._record.state = 'failed';
          ctx._record.duration = Date.now() - ctx._record.startedAt;
          this.publish(ctx._record);
        }
        if (QUIET_TLS_ERRORS.has(error.code)) return;
        const message = `${kind}: ${error.message}`;
        if (!this.notices.has(message)) { this.notices.add(message); this.emit('notice', message); }
      });
      proxy.onRequest((ctx, callback) => {
        const req = ctx.clientToProxyRequest;
        const clientAddress = normalizeClientAddress(ctx.connectRequest?.socket?.remoteAddress || req.socket?.remoteAddress);
        let url;
        try { url = new URL(req.url, `${ctx.isSSL ? 'https' : 'http'}://${req.headers.host}`); }
        catch { return callback(new Error('Invalid request URL')); }
        if (this.serveSetup(ctx, url, clientAddress)) return;
        // Reject loops into our own listener before forwarding.
        if (['127.0.0.1', 'localhost', '[::1]', this.state.host].includes(url.hostname) && Number(url.port || (ctx.isSSL ? 443 : 80)) === this.state.port) {
          ctx.proxyToClientResponse.writeHead(508); ctx.proxyToClientResponse.end('Proxy loop blocked'); return;
        }
        if (this.state.paused) return callback();
        const remoteDevice = this.observeClientRequest(clientAddress, req.headers['user-agent'], ctx.isSSL);
        const record = {
          id: randomUUID(), startedAt: Date.now(), method: req.method, url: url.href,
          host: url.host, domain: mainDomain(url.hostname), path: url.pathname + url.search, secure: ctx.isSSL,
          httpVersion: req.httpVersionMajor === 2 ? 'HTTP/2' : `HTTP/${req.httpVersion || '1.1'}`,
          application: inferApplication(req.headers), remoteDevice,
          status: null, state: 'pending', duration: null, size: 0,
          requestSize: 0,
          requestHeaders: { ...req.headers }, responseHeaders: {},
          requestBody: { text: '', size: 0 }, responseBody: { text: '', size: 0 }
        };
        ctx._record = record;
        // Proxy credentials belong only to this hop.
        delete ctx.proxyToServerRequestOptions.headers['proxy-authorization'];
        delete ctx.proxyToServerRequestOptions.headers['proxy-connection'];
        ctx.proxyToServerRequestOptions.maxHeaderSize = UPSTREAM_HEADER_LIMIT;
        this.records.set(record.id, record);
        this.publish(record);
        if (this.hasBreakpoint(url.host, 'request') && editableBody(record.requestHeaders)) {
          delete ctx.proxyToServerRequestOptions.headers['content-length'];
          delete ctx.proxyToServerRequestOptions.headers.expect;
          ctx.proxyToServerRequestOptions.headers['transfer-encoding'] = 'chunked';
          record.requestHeaders = { ...ctx.proxyToServerRequestOptions.headers };
          ctx.requestFilters.push(new BreakpointFilter(body => this.waitAtBreakpoint('request', record, body)));
        }
        const request = bodyCollector();
        const response = bodyCollector();
        ctx.onRequestData((_ctx, chunk, done) => { if (this.records.has(record.id)) request.add(chunk); done(null, chunk); });
        ctx.onRequestEnd((_ctx, done) => { record.requestBody = request.read(record.requestHeaders); record.requestSize = record.requestBody.size; this.publish(record); done(); });
        ctx.onResponse((_ctx, done) => {
          record.status = ctx.serverToProxyResponse.statusCode;
          record.responseHeaders = { ...ctx.serverToProxyResponse.headers };
          record.contentType = String(record.responseHeaders['content-type'] || '');
          if (this.hasBreakpoint(url.host, 'response') && editableBody(record.responseHeaders) &&
              req.method !== 'HEAD' && ![204, 304].includes(record.status)) {
            ctx.responseContentPotentiallyModified = true;
            ctx.responseFilters.push(new BreakpointFilter(body => this.waitAtBreakpoint('response', record, body)));
          }
          this.publish(record); done();
        });
        ctx.onResponseData((_ctx, chunk, done) => { record.size += chunk.length; if (this.records.has(record.id)) response.add(chunk); done(null, chunk); });
        ctx.onResponseEnd((_ctx, done) => {
          record.responseBody = response.read(record.responseHeaders);
          record.duration = Date.now() - record.startedAt;
          record.state = 'complete'; this.publish(record); done();
        });
        ctx.proxyToClientResponse.on('close', () => {
          if (record.state === 'pending') {
            record.state = 'failed'; record.error = 'Connection closed before the response completed.';
            record.duration = Date.now() - record.startedAt; this.publish(record);
          }
        });
        callback();
      });
      await new Promise((resolve, reject) => {
        startupReject = reject;
        proxy.listen({ port, host, sslCaDir: this.directory, timeout: 30000, httpsAgent: this.httpsAgent }, error => {
          if (error) return reject(error);
          startupReject = null;
          proxy.httpServer.on('connection', socket => {
            this.sockets.add(socket); socket.on('close', () => this.sockets.delete(socket));
          });
          resolve();
        });
      });
      this.state = { running: true, paused: false, host, port: proxy.httpPort };
      this.emit('state', this.state);
      return this.state;
    } catch (error) {
      if (this.proxy?.httpServer) this.proxy.close();
      this.proxy = null;
      throw error;
    } finally { this.busy = false; }
  }
  addPassthrough({ host, port, protocols, reason, clientAddress }) {
    if (this.state.paused) return;
    const remoteDevice = remoteDeviceAddress(clientAddress, this.state.host);
    if (remoteDevice) this.touchDevice(remoteDevice);
    const certificateRejected = reason === 'certificate-rejected';
    const startedAt = Date.now();
    const record = {
      id: randomUUID(), startedAt, method: 'TUNNEL', url: `tls://${host}:${port}`,
      host: `${host}:${port}`, domain: mainDomain(host), path: 'Encrypted pass-through', secure: true, tunneled: true,
      application: 'Unknown app', remoteDevice,
      status: 200, state: 'complete', duration: 0, size: 0,
      requestSize: 0,
      contentType: '', requestHeaders: { 'tls-alpn': protocols.join(', ') }, responseHeaders: {},
      requestBody: { text: '', size: 0 }, responseBody: { text: '', size: 0, note: reason === 'do-not-inspect' ? 'This host matches a Do Not Inspect rule, so Proxyking passed the encrypted connection through unchanged.' : certificateRejected ? 'The client rejected Proxyking’s generated certificate, so later connections to this host are passed through encrypted for the rest of this capture session.' : 'This TLS protocol is not supported by the HTTP inspector, so Proxyking passed the encrypted connection through unchanged.' }
    };
    this.records.set(record.id, record);
    this.publish(record);
  }
  async stop() {
    if (this.busy) throw new Error('The proxy is changing state. Please try again.');
    if (!this.proxy) return this.state;
    this.releaseBreakpoints();
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
    this.proxy.httpAgent?.destroy();
    this.proxy.httpsAgent?.destroy();
    this.proxy.close(); this.proxy = null;
    this.state = { ...this.state, running: false, paused: false };
    for (const record of this.records.values()) {
      if (record.state === 'pending') {
        record.state = 'failed'; record.error = 'Capture stopped';
        record.duration = Date.now() - record.startedAt; this.publish(record);
      }
    }
    this.emit('state', this.state); return this.state;
  }
  pause() {
    if (this.state.running && !this.state.paused) {
      this.state = { ...this.state, paused: true };
      this.emit('state', this.state);
    }
    return this.state;
  }
  resume() {
    if (this.state.running && this.state.paused) {
      this.state = { ...this.state, paused: false };
      this.emit('state', this.state);
    }
    return this.state;
  }
  exportHar(records = this.records.values()) {
    const headers = object => Object.entries(object).map(([name, value]) => ({ name, value: Array.isArray(value) ? value.join('\n') : String(value) }));
    return { log: { version: '1.2', creator: { name: 'Proxyking', version }, entries: [...records].map(r => ({
      startedDateTime: new Date(r.startedAt).toISOString(), time: r.duration || 0,
      request: { method: r.method, url: r.url, httpVersion: r.httpVersion || 'HTTP/1.1', cookies: [], headers: headers(r.requestHeaders), queryString: [...new URL(r.url).searchParams].map(([name, value]) => ({ name, value })), headersSize: -1, bodySize: r.requestBody.size, postData: { mimeType: String(r.requestHeaders['content-type'] || ''), text: r.requestBody.text }, _bodyEncoding: r.requestBody.encoding, _truncated: !!r.requestBody.truncated },
      response: { status: r.status || 0, statusText: '', httpVersion: 'HTTP/1.1', cookies: [], headers: headers(r.responseHeaders), content: { size: r.size, mimeType: String(r.responseHeaders['content-type'] || ''), text: r.responseBody.text, ...(r.responseBody.encoding === 'base64' ? { encoding: 'base64' } : {}), _truncated: !!r.responseBody.truncated, _note: r.responseBody.note }, redirectURL: String(r.responseHeaders.location || ''), headersSize: -1, bodySize: r.size },
      cache: {}, timings: { send: 0, wait: r.duration || 0, receive: 0 }, _error: r.error
    })) } };
  }
}
module.exports = { CaptureEngine, bodyCollector, inferApplication, mainDomain, normalizeClientAddress, remoteDeviceAddress, BODY_LIMIT };
