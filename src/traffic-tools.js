const { Transform } = require('node:stream');

const EDIT_LIMIT = 1024 * 1024;
function editableBody(headers = {}) {
  const encoding = String(headers['content-encoding'] || 'identity').toLowerCase();
  const type = String(headers['content-type'] || '').toLowerCase();
  return (encoding === 'identity' || !encoding) &&
    (!type || /text|json|xml|javascript|form-urlencoded|graphql|svg/.test(type));
}

class BreakpointFilter extends Transform {
  constructor(onBody, limit = EDIT_LIMIT) {
    super();
    this.onBody = onBody;
    this.limit = limit;
    this.chunks = [];
    this.size = 0;
    this.bypassed = false;
  }
  _transform(chunk, _encoding, callback) {
    if (this.bypassed) { this.push(chunk); return callback(); }
    this.size += chunk.length;
    if (this.size > this.limit) {
      this.bypassed = true;
      for (const part of this.chunks) this.push(part);
      this.chunks = [];
      this.push(chunk);
      return callback();
    }
    this.chunks.push(Buffer.from(chunk));
    callback();
  }
  _flush(callback) {
    if (this.bypassed) return callback();
    const original = Buffer.concat(this.chunks);
    this.chunks = [];
    Promise.resolve(this.onBody(original)).then(body => {
      this.push(Buffer.isBuffer(body) ? body : original);
      callback();
    }, () => { this.push(original); callback(); });
  }
}

module.exports = { BreakpointFilter, EDIT_LIMIT, editableBody };
