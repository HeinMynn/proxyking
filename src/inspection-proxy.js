const net = require('node:net');
const { Proxy } = require('http-mitm-proxy');
const { readAlpnProtocols, requiresPassthrough } = require('./tls-client-hello');

const expectedClientErrors = new Set([
  'ERR_SSL_NO_APPLICATION_PROTOCOL',
  'ERR_SSL_SSLV3_ALERT_CERTIFICATE_UNKNOWN',
  'ERR_SSL_TLSV1_ALERT_UNKNOWN_CA',
  'ECONNRESET'
]);

class InspectionProxy extends Proxy {
  constructor({ onPassthrough } = {}) {
    super();
    this.onPassthrough = onPassthrough;
    this.rejectedHosts = new Set();
  }

  _createHttpsServer(options, callback) {
    const hosts = [...(options.hosts || [])];
    return super._createHttpsServer(options, (port, server, wsServer) => {
      server.on('clientError', error => {
        // Some TLS stacks send an explicit unknown-CA alert; Node clients may
        // simply reset the socket after certificate verification fails.
        if (['ERR_SSL_SSLV3_ALERT_CERTIFICATE_UNKNOWN', 'ERR_SSL_TLSV1_ALERT_UNKNOWN_CA', 'ECONNRESET'].includes(error?.code)) {
          for (const host of hosts) this.rejectedHosts.add(host);
        }
      });
      callback(port, server, wsServer);
    });
  }

  _onHttpServerConnectData(req, socket, head) {
    const target = new URL(`tls://${req.url}`);
    const port = Number(target.port || 443);
    const rejectedCertificate = this.rejectedHosts.has(target.hostname);
    if (!rejectedCertificate && !requiresPassthrough(head)) return super._onHttpServerConnectData(req, socket, head);
    if (['127.0.0.1', 'localhost', '::1', this.httpHost].includes(target.hostname) && port === this.httpPort) {
      this._onError('PROXY_LOOP_ERROR', null, new Error('TLS pass-through loop blocked'));
      socket.destroy();
      return;
    }
    socket.pause();
    const upstream = net.connect({ host: target.hostname, port, allowHalfOpen: true }, () => {
      this.onPassthrough?.({ host: target.hostname, port, protocols: readAlpnProtocols(head) || [], reason: rejectedCertificate ? 'certificate-rejected' : 'unsupported-alpn' });
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

module.exports = { InspectionProxy, expectedClientErrors };
