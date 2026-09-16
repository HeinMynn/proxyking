const fs = require('node:fs/promises');
const path = require('node:path');
const { randomUUID } = require('node:crypto');

class SystemProxyManager {
  constructor({ directory, adapter }) {
    this.file = path.join(directory, 'system-proxy-recovery.json');
    this.adapter = adapter;
    this.pending = false;
    this.active = false;
  }
  async journal() {
    try {
      const text = await fs.readFile(this.file, 'utf8');
      this.pending = true;
      const record = JSON.parse(text);
      if (record.version !== 1 || record.platform !== this.adapter.platform || !this.adapter.validate(record.plan)) throw new Error('Invalid or incompatible proxy recovery record.');
      return record;
    } catch (error) {
      if (error.code === 'ENOENT') return null;
      throw new Error(`Cannot read saved proxy settings: ${error.message} Recovery file: ${this.file}`);
    }
  }
  async enable(port, host = '127.0.0.1') {
    if (await this.journal()) throw new Error('Previous proxy settings still need recovery. Use Restore proxy settings first.');
    const plan = await this.adapter.plan(port, host);
    if (!this.adapter.validate(plan)) throw new Error('Cannot save an invalid proxy configuration.');
    await fs.mkdir(path.dirname(this.file), { recursive: true, mode: 0o700 });
    // A complete file is synced before any OS mutation. Write a temporary
    // file first so a crash during serialization cannot corrupt recovery.
    const temporary = `${this.file}.${randomUUID()}.tmp`;
    const handle = await fs.open(temporary, 'wx', 0o600);
    try { await handle.writeFile(JSON.stringify({ version: 1, platform: this.adapter.platform, plan })); await handle.sync(); }
    finally { await handle.close(); }
    await fs.rename(temporary, this.file);
    this.pending = true;
    // On failure the caller invokes restore while the listener is still up.
    await this.adapter.apply(plan);
    this.active = true;
  }
  async restore() {
    const record = await this.journal();
    if (!record) { this.pending = false; this.active = false; return { recovered: false, notices: [] }; }
    const notices = await this.adapter.restore(record.plan);
    // Keep the snapshot if any write or verification fails.
    await fs.unlink(this.file);
    this.pending = false; this.active = false;
    return { recovered: true, notices };
  }
}
module.exports = { SystemProxyManager };
