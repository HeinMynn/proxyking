const net = require('node:net');
const https = require('node:https');
const http2 = require('node:http2');
const { Proxy } = require('http-mitm-proxy');
const { readAlpnProtocols, requiresPassthrough } = require('./tls-client-hello');

const expectedClientErrors = new Set([
  'ERR_SSL_NO_APPLICATION_PROTOCOL',
  'ERR_SSL_UNSUPPORTED_PROTOCOL',
  'ERR_SSL_SSLV3_ALERT_CERTIFICATE_UNKNOWN',
  'ERR_SSL_TLSV1_ALERT_UNKNOWN_CA',
  'ECONNRESET',
  'EPIPE'
]);

const certificateRejectionErrors = new Set([
  'ERR_SSL_SSLV3_ALERT_CERTIFICATE_UNKNOWN',
  'ERR_SSL_TLSV1_ALERT_UNKNOWN_CA'
]);
const incompatibleTlsErrors = new Set(['ERR_SSL_UNSUPPORTED_PROTOCOL']);

function isCertificateRejection(error) {
  return certificateRejectionErrors.has(error?.code);
}

function isIncompatibleTls(error) {
  return incompatibleTlsErrors.has(error?.code);
}

function isExpectedSocketClosure(error) {
  return error?.code === 'ECONNRESET' || error?.code === 'EPIPE';
}

function parseConnectTarget(authority) {
  if (typeof authority !== 'string' || !authority || authority.length > 2048 || authority.trim() !== authority || /[\s/?#@]/.test(authority)) return null;
  try {
    const target = new URL(`https://${authority}`);
    const hostname = target.hostname.replace(/^\[|\]$/g, '');
    const port = Number(target.port || 443);
    if (!hostname || !Number.isInteger(port) || port < 1 || port > 65535 || target.pathname !== '/' || target.search || target.hash || target.username || target.password) return null;
    return { hostname, port };
  } catch {
    return null;
  }
}

class InspectionProxy extends Proxy {
  constructor({ onPassthrough } = {}) {
    super();
    this.onPassthrough = onPassthrough;
    this.rejectedHosts = new Set();
    this.incompatibleHosts = new Set();
  }

  _createHttpsServer(options, callback) {
    const hosts = [...(options.hosts || [])];
    // http-mitm-proxy constructs an HTTPS/1 server internally. Substitute
    // Node's HTTP/2 compatibility server during that synchronous construction
    // so h2 clients can be decoded while existing HTTP/1 and WebSocket behavior
    // remains available through allowHTTP1.
    const createServer = https.createServer;
    https.createServer = serverOptions => http2.createSecureServer({ ...serverOptions, allowHTTP1: true });
    try {
      return super._createHttpsServer(options, (port, server, wsServer) => {
        server.on('clientError', error => {
          // Only explicit TLS certificate alerts prove that the generated
          // certificate was rejected. Browsers and media players routinely reset
          // speculative or cancelled connections, so ECONNRESET must not disable
          // inspection for every later connection to the host.
          if (isCertificateRejection(error)) {
            for (const host of hosts) this.rejectedHosts.add(host);
          }
          if (isIncompatibleTls(error)) {
            for (const host of hosts) this.incompatibleHosts.add(host);
          }
        });
        callback(port, server, wsServer);
      });
    } finally {
      https.createServer = createServer;
    }
  }

  _onHttpServerRequest(isSSL, request, response) {
    if (request.httpVersionMajor === 2) {
      const originalHeaders = request.headers;
      const authority = originalHeaders[':authority'];
      const requestPath = originalHeaders[':path'];
      const headers = Object.fromEntries(Object.entries(originalHeaders).filter(([name]) => !name.startsWith(':')));
      if (authority && !headers.host) headers.host = authority;
      Object.defineProperty(request, 'headers', { configurable: true, value: headers });
      if (requestPath) request.url = requestPath;

      // HTTP/2 forbids connection-specific response headers that the underlying
      // HTTP/1 proxy adds. Keep all end-to-end headers and remove only hop-by-hop
      // fields at the protocol boundary.
      const writeHead = response.writeHead.bind(response);
      response.writeHead = (status, statusMessage, headers) => {
        if (typeof statusMessage === 'object') { headers = statusMessage; statusMessage = undefined; }
        const cleaned = { ...(headers || {}) };
        for (const name of ['connection', 'proxy-connection', 'keep-alive', 'transfer-encoding', 'upgrade']) delete cleaned[name];
        return statusMessage === undefined ? writeHead(status, cleaned) : writeHead(status, statusMessage, cleaned);
      };
    }
    return super._onHttpServerRequest(isSSL, request, response);
  }

  _onHttpServerConnectData(req, socket, head) {
    const target = parseConnectTarget(req.url);
    if (!target) {
      const error = new Error('Invalid CONNECT target.');
      error.code = 'ERR_INVALID_CONNECT_TARGET';
      this._onError('INVALID_CONNECT_TARGET', null, error);
      socket.destroy();
      return;
    }
    const { hostname, port } = target;
    const rejectedCertificate = this.rejectedHosts.has(hostname);
    const incompatibleTls = this.incompatibleHosts.has(hostname);
    if (!rejectedCertificate && !incompatibleTls && !requiresPassthrough(head)) return super._onHttpServerConnectData(req, socket, head);
    if (['127.0.0.1', 'localhost', '::1', this.httpHost].includes(hostname) && port === this.httpPort) {
      this._onError('PROXY_LOOP_ERROR', null, new Error('TLS pass-through loop blocked'));
      socket.destroy();
      return;
    }
    socket.pause();
    const upstream = net.connect({ host: hostname, port, allowHalfOpen: true }, () => {
      this.onPassthrough?.({ host: hostname, port, protocols: readAlpnProtocols(head) || [], reason: rejectedCertificate ? 'certificate-rejected' : incompatibleTls ? 'unsupported-tls' : 'unsupported-alpn', clientAddress: socket.remoteAddress });
      socket.pipe(upstream);
      upstream.pipe(socket);
      upstream.write(head);
      socket.resume();
    });
    const close = () => { if (!socket.destroyed) socket.destroy(); if (!upstream.destroyed) upstream.destroy(); };
    upstream.on('error', error => { this._onError('TLS_PASSTHROUGH_ERROR', null, error); close(); });
    upstream.on('close', () => { if (!socket.destroyed) socket.destroy(); });
    socket.on('close', () => { if (!upstream.destroyed) upstream.destroy(); });
  }

  _onSocketError(socketDescription, error) {
    if (isExpectedSocketClosure(error)) return;
    return super._onSocketError(socketDescription, error);
  }

  _onError(kind, ctx, error) {
    if (!expectedClientErrors.has(error?.code)) return super._onError(kind, ctx, error);
    this.onErrorHandlers.forEach(handler => handler(ctx, error, kind));
    if (ctx) {
      ctx.onErrorHandlers.forEach(handler => handler(ctx, error, kind));
      if (ctx.proxyToClientResponse && !ctx.proxyToClientResponse.headersSent) ctx.proxyToClientResponse.writeHead(504, 'Proxy Error');
      if (ctx.proxyToClientResponse && !ctx.proxyToClientResponse.finished) ctx.proxyToClientResponse.end(`${kind}: ${error}`, 'utf8');
    }
  }
}

module.exports = { InspectionProxy, expectedClientErrors, isCertificateRejection, isIncompatibleTls, isExpectedSocketClosure, parseConnectTarget };
