const http = require('node:http');
const https = require('node:https');
const { randomUUID } = require('node:crypto');
const zlib = require('node:zlib');
const { EDIT_LIMIT } = require('./traffic-tools');
const { getDomain } = require('tldts');

async function replay(engine, id, draft = {}) {
  const source = engine.detail(id);
  if (!source || source.tunneled || source.state !== 'complete') throw new Error('Select a completed inspected HTTP request to replay.');
  if (source.requestBody?.truncated || source.requestBody?.encoding === 'base64' || !['', 'identity'].includes(String(source.requestHeaders?.['content-encoding'] || '').toLowerCase())) throw new Error('This request body cannot be replayed safely from its preview.');
  const method = String(draft.method || source.method).toUpperCase();
  if (!/^[A-Z]+$/.test(method) || ['CONNECT', 'TRACE'].includes(method)) throw new Error('Invalid replay method.');
  const target = new URL(String(draft.url || source.url));
  if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password) throw new Error('Replay requires an HTTP or HTTPS URL without embedded credentials.');
  if (['127.0.0.1', 'localhost', '[::1]', engine.state.host].includes(target.hostname) &&
    Number(target.port || (target.protocol === 'https:' ? 443 : 80)) === engine.state.port && engine.state.running) throw new Error('Replay cannot target Proxyking itself.');
  const headers = draft.headers === undefined ? source.requestHeaders : draft.headers;
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) throw new Error('Headers must be a JSON object.');
  const cleanHeaders = {};
  for (const [name, value] of Object.entries(headers)) {
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || typeof value !== 'string' && !Array.isArray(value)) throw new Error('Invalid replay header.');
    if (/^(proxy-|connection$|transfer-encoding$|content-length$|host$|expect$)/i.test(name)) continue;
    cleanHeaders[name] = value;
  }
  cleanHeaders.host = target.host;
  const body = Buffer.from(draft.body === undefined ? source.requestBody?.text || '' : String(draft.body));
  if (body.length > EDIT_LIMIT) throw new Error('Replay body must be under 1 MiB.');
  if (body.length) cleanHeaders['content-length'] = String(body.length);
  const record = {
    id: randomUUID(), startedAt: Date.now(), method, url: target.href, host: target.host,
    domain: getDomain(target.hostname) || target.hostname, path: target.pathname + target.search,
    secure: target.protocol === 'https:', httpVersion: 'HTTP/1.1', application: 'Proxyking Replay',
    remoteDevice: '', status: null, state: 'pending', duration: null, size: 0, requestSize: body.length,
    requestHeaders: cleanHeaders, responseHeaders: {},
    requestBody: { text: body.toString('utf8'), encoding: 'utf8', size: body.length },
    responseBody: { text: '', size: 0 }, replayOf: id
  };
  engine.records.set(record.id, record);
  engine.publish(record);
  const chunks = [];
  let captured = 0;
  return new Promise((resolve, reject) => {
    const transport = target.protocol === 'https:' ? https : http;
    const request = transport.request(target, {
      method, headers: cleanHeaders,
      agent: target.protocol === 'https:' ? engine.httpsAgent || engine.proxy?.httpsAgent : engine.proxy?.httpAgent,
      timeout: 30000, maxHeaderSize: 128 * 1024
    }, response => {
      record.status = response.statusCode;
      record.responseHeaders = { ...response.headers };
      record.contentType = String(response.headers['content-type'] || '');
      engine.publish(record);
      response.on('data', chunk => {
        record.size += chunk.length;
        if (captured < 128 * 1024) {
          const part = Buffer.from(chunk.subarray(0, 128 * 1024 - captured));
          chunks.push(part); captured += part.length;
        }
      });
      response.on('end', () => {
        let preview = Buffer.concat(chunks);
        let note = '';
        const encoding = String(record.responseHeaders['content-encoding'] || '').toLowerCase();
        if (record.size === captured) {
          try {
            if (encoding === 'gzip') preview = zlib.gunzipSync(preview, { maxOutputLength: 128 * 1024 });
            else if (encoding === 'br') preview = zlib.brotliDecompressSync(preview, { maxOutputLength: 128 * 1024 });
            else if (encoding === 'deflate') preview = zlib.inflateSync(preview, { maxOutputLength: 128 * 1024 });
            else if (encoding && encoding !== 'identity') note = 'Encoded response shown as base64.';
          } catch { note = 'Compressed response shown as base64.'; }
        }
        const binary = !!note || preview.includes(0) || record.contentType && !/text|json|xml|javascript|form-urlencoded|graphql|svg/i.test(record.contentType);
        record.responseBody = {
          text: preview.toString(binary ? 'base64' : 'utf8'),
          encoding: binary ? 'base64' : 'utf8',
          size: record.size, truncated: record.size > captured, note
        };
        record.duration = Date.now() - record.startedAt;
        record.state = 'complete'; engine.publish(record); resolve(record);
      });
      response.on('error', fail);
    });
    function fail(error) {
      if (record.state !== 'pending') return;
      record.error = error.message; record.state = 'failed';
      record.duration = Date.now() - record.startedAt; engine.publish(record); reject(error);
    }
    request.on('timeout', () => request.destroy(new Error('Replay timed out.')));
    request.on('error', fail);
    request.end(body);
  });
}
module.exports = { replay };
