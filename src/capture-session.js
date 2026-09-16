const { EventEmitter } = require('node:events');

class CaptureSession extends EventEmitter {
  constructor(engine, systemProxy) {
    super(); this.engine = engine; this.systemProxy = systemProxy;
    this.queue = Promise.resolve(); this.busy = false; this.mode = 'automatic'; this.notice = '';
  }
  get state() {
    return { ...this.engine.state, busy: this.busy, mode: this.mode, systemProxy: this.systemProxy.active, recoveryPending: this.systemProxy.pending };
  }
  tell(message) { this.notice = message; this.emit('notice', message); }
  enqueue(action) {
    const operation = this.queue.then(async () => {
      this.busy = true; this.emit('state', this.state);
      try { return await action(); }
      finally { this.busy = false; this.emit('state', this.state); }
    });
    this.queue = operation.catch(() => {});
    return operation.then(() => this.state);
  }
  async restore() {
    const result = await this.systemProxy.restore();
    if (result.recovered) this.tell(['Previous system proxy settings restored.', ...result.notices].join(' '));
  }
  recover() { return this.enqueue(() => this.restore()); }
  start(port, automatic = true, host = '127.0.0.1') {
    return this.enqueue(async () => {
      if (this.engine.state.running) return;
      await this.restore();
      this.mode = automatic ? 'automatic' : 'manual';
      await this.engine.start(port, host);
      try {
        if (automatic) await this.systemProxy.enable(this.engine.state.port, this.engine.state.host);
        this.tell(automatic ? 'System proxy enabled. Browse normally to capture traffic. HTTPS requires trusting the Proxyking CA.' : 'Manual mode: configure your app to use the local proxy.');
      } catch (error) {
        try { await this.restore(); }
        catch (restoreError) {
          throw new Error(`Proxy setup failed: ${error.message} Restoration also failed: ${restoreError.message} The listener is still running. Retry Stop capture to restore your settings.`);
        }
        await this.engine.stop();
        throw new Error(`Could not enable the system proxy: ${error.message} Previous settings were preserved.`);
      }
    });
  }
  stop() {
    return this.enqueue(async () => {
      // Never shut down the listener while OS settings may still point at it.
      await this.restore();
      await this.engine.stop();
    });
  }
}
module.exports = { CaptureSession };
