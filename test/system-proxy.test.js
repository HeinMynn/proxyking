const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { WindowsProxy, MacProxy, parseProxy, parseEnabled, macScript } = require('../src/system-proxy/adapters');
const { SystemProxyManager } = require('../src/system-proxy/manager');
const { CaptureSession } = require('../src/capture-session');

const original = () => ({ flags: 13, server: 'http=company.example:3128', bypass: '<local>;*.internal', autoConfigUrl: 'https://company.example/proxy.pac' });

class FakeWindows extends WindowsProxy {
  constructor() { super(); this.current = original(); this.writes = []; }
  async read() { return structuredClone(this.current); }
  async write(settings) { this.writes.push(structuredClone(settings)); this.current = structuredClone(settings); }
}
async function setup(t, adapter = new FakeWindows()) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'proxyking-settings-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const manager = new SystemProxyManager({ directory, adapter });
  return { directory, manager, adapter };
}
function fakeEngine(log = []) {
  return {
    state: { running: false, port: 8080, host: '127.0.0.1' },
    async start(port, host = '127.0.0.1') { log.push('listen'); this.state = { ...this.state, running: true, port, host }; },
    async stop() { log.push('close'); this.state.running = false; }
  };
}

test('saves before mutation and restores original proxy, PAC and discovery flags', async t => {
  const { manager, adapter } = await setup(t);
  const write = adapter.write.bind(adapter);
  adapter.write = async settings => {
    const journal = JSON.parse(await fs.readFile(manager.file, 'utf8'));
    assert.deepEqual(journal.plan[0].before, original());
    await write(settings);
  };
  await manager.enable(8088);
  assert.equal(adapter.current.flags, 3);
  assert.equal(adapter.current.server, 'http=127.0.0.1:8088;https=127.0.0.1:8088');
  assert.equal(manager.active, true);
  await manager.restore();
  assert.deepEqual(adapter.current, original());
  await assert.rejects(fs.access(manager.file), { code: 'ENOENT' });
});

test('uses an explicitly selected LAN address in Windows system proxy settings', async t => {
  const { manager, adapter } = await setup(t);
  await manager.enable(8088, '192.168.50.24');
  assert.equal(adapter.current.server, 'http=192.168.50.24:8088;https=192.168.50.24:8088');
  await manager.restore();
});

test('new instance recovers a crash from the durable journal', async t => {
  const { manager, adapter, directory } = await setup(t);
  await manager.enable(8080);
  const recovered = new SystemProxyManager({ directory, adapter });
  assert.equal((await recovered.restore()).recovered, true);
  assert.deepEqual(adapter.current, original());
});

test('restoration preserves a different proxy selected by another app', async t => {
  const { manager, adapter } = await setup(t);
  await manager.enable(8080);
  const changed = { ...adapter.current, server: 'http=new-proxy.example:8888', bypass: 'edited.example' };
  adapter.current = changed;
  const result = await manager.restore();
  assert.deepEqual(adapter.current, changed); assert.equal(result.notices.length, 1);
});

test('restoration preserves PAC URL and bypass edits made during capture', async t => {
  const { manager, adapter } = await setup(t);
  await manager.enable(8080);
  adapter.current.bypass = 'new.example'; adapter.current.autoConfigUrl = 'https://new.example/pac';
  await manager.restore();
  assert.equal(adapter.current.server, original().server);
  assert.equal(adapter.current.flags, original().flags);
  assert.equal(adapter.current.bypass, 'new.example');
  assert.equal(adapter.current.autoConfigUrl, 'https://new.example/pac');
});

test('failed restore retains the recovery file and can be retried', async t => {
  const { manager, adapter } = await setup(t);
  await manager.enable(8080);
  const write = adapter.write.bind(adapter);
  adapter.write = async () => { throw new Error('permission denied'); };
  await assert.rejects(manager.restore(), /permission denied/);
  assert.equal(manager.pending, true); await fs.access(manager.file);
  adapter.write = write;
  await manager.restore(); assert.equal(manager.pending, false);
});

test('invalid journal is not overwritten or applied', async t => {
  const { manager, adapter } = await setup(t);
  await fs.writeFile(manager.file, '{broken');
  await assert.rejects(manager.enable(8080), /Cannot read saved/);
  assert.equal(manager.pending, true); assert.equal(adapter.writes.length, 0);
  assert.equal(await fs.readFile(manager.file, 'utf8'), '{broken');
});

test('session starts listener first and restores settings before stopping it', async t => {
  const { manager, adapter } = await setup(t);
  const log = [];
  const engine = fakeEngine(log);
  const write = adapter.write.bind(adapter);
  adapter.write = async settings => { assert.equal(engine.state.running, true); log.push(settings.server.includes('127.0.0.1') ? 'enable' : 'restore'); await write(settings); };
  const capture = new CaptureSession(engine, manager);
  await capture.start(8080); await capture.stop();
  assert.deepEqual(log, ['listen', 'enable', 'restore', 'close']);
  assert.equal(capture.state.busy, false);
});

test('partial activation failure rolls back before the listener is stopped', async t => {
  const { manager, adapter } = await setup(t);
  const apply = adapter.apply.bind(adapter);
  adapter.apply = async plan => { await apply(plan); throw new Error('notification failed'); };
  const engine = fakeEngine(); const capture = new CaptureSession(engine, manager);
  await assert.rejects(capture.start(8080), /notification failed/);
  assert.deepEqual(adapter.current, original()); assert.equal(engine.state.running, false);
});

test('Windows restores flags if a failed native call changed flags but not the server', async t => {
  const { manager, adapter } = await setup(t);
  adapter.apply = async plan => { adapter.current.flags = plan[0].after.flags; throw new Error('partial native failure'); };
  const capture = new CaptureSession(fakeEngine(), manager);
  await assert.rejects(capture.start(8080), /partial native failure/);
  assert.deepEqual(adapter.current, original());
});

test('listener remains available when rollback fails, and Stop retries restoration', async t => {
  const { manager, adapter } = await setup(t);
  const apply = adapter.apply.bind(adapter);
  const restore = adapter.restore.bind(adapter);
  adapter.apply = async plan => { await apply(plan); throw new Error('partial failure'); };
  adapter.restore = async () => { throw new Error('restore denied'); };
  const engine = fakeEngine(); const capture = new CaptureSession(engine, manager);
  await assert.rejects(capture.start(8080), /listener is still running/);
  assert.equal(engine.state.running, true); assert.equal(manager.pending, true);
  await assert.rejects(capture.stop(), /restore denied/);
  assert.equal(engine.state.running, true);
  adapter.restore = restore;
  await capture.stop(); assert.equal(engine.state.running, false);
});

test('quit/stop queued during startup waits for activation and then restores', async t => {
  const { manager, adapter } = await setup(t);
  const capture = new CaptureSession(fakeEngine(), manager);
  await Promise.all([capture.start(8080), capture.stop()]);
  assert.equal(capture.state.running, false); assert.deepEqual(adapter.current, original());
});

test('manual mode does not mutate system settings', async t => {
  const { manager, adapter } = await setup(t);
  const capture = new CaptureSession(fakeEngine(), manager);
  await capture.start(8080, false); await capture.stop();
  assert.equal(adapter.writes.length, 0); assert.equal(capture.state.mode, 'manual');
});

test('Windows command transport uses stdin for data and detects rejected settings', async () => {
  const proxy = new WindowsProxy(async (executable, args, options) => {
    assert.match(executable, /powershell\.exe$/);
    assert.ok(args.includes('-EncodedCommand'));
    assert.equal(JSON.parse(options.input).action, 'write');
    return JSON.stringify(original());
  });
  await assert.rejects(proxy.write({ ...original(), flags: 3 }), /did not accept/);
});

const macSettings = () => ({
  http: { enabled: false, server: '', port: 0, authenticated: false },
  https: { enabled: true, server: 'corporate.example', port: 8443, authenticated: false },
  pacEnabled: true, discoveryEnabled: true
});
class FakeMac extends MacProxy {
  constructor() { super(); this.current = new Map([['Wi-Fi', macSettings()], ['Ethernet', macSettings()]]); this.writes = []; this.failAt = -1; }
  async services() { return [...this.current.keys()]; }
  async read(id) { if (!this.current.has(id)) throw new Error('service missing'); return structuredClone(this.current.get(id)); }
  async write(commands) {
    for (const args of commands) {
      if (this.writes.length === this.failAt) { this.failAt = -1; throw new Error('networksetup denied'); }
      this.writes.push(args);
      const [option, id, value, port] = args; const state = this.current.get(id);
      if (option === '-setautoproxystate') state.pacEnabled = value === 'on';
      else if (option === '-setproxyautodiscovery') state.discoveryEnabled = value === 'on';
      else {
        const key = option.includes('secure') ? 'https' : 'http';
        if (option.endsWith('state')) state[key].enabled = value === 'on';
        else state[key] = { enabled: true, server: value, port: Number(port), authenticated: false };
      }
    }
  }
}

test('macOS parses native settings and safely quotes service names', () => {
  assert.deepEqual(parseProxy('Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0'), macSettings().http);
  assert.equal(parseEnabled('URL: https://example.com/pac\nEnabled: Yes'), true);
  assert.equal(parseEnabled('Auto Proxy Discovery: Off'), false);
  assert.throws(() => parseProxy('error'), /Could not read/);
  assert.throws(() => parseEnabled('error'), /Could not read/);
  const command = macScript([['-setwebproxy', "Wi-Fi'; touch /tmp/unsafe; echo '", '127.0.0.1', '8080', 'off']]);
  assert.ok(command.includes("'Wi-Fi'\\''; touch /tmp/unsafe; echo '\\'''"));
});

test('macOS restores HTTP, HTTPS and automatic settings across all services', async t => {
  const { manager, adapter } = await setup(t, new FakeMac());
  await manager.enable(8080);
  for (const settings of adapter.current.values()) { assert.equal(settings.http.port, 8080); assert.equal(settings.pacEnabled, false); }
  await manager.restore();
  for (const settings of adapter.current.values()) assert.deepEqual(settings, macSettings());
});

test('macOS partial mutation rolls back even when a service was only partially changed', async t => {
  const { manager, adapter } = await setup(t, new FakeMac());
  adapter.failAt = 7;
  await assert.rejects(manager.enable(8080), /denied/);
  await manager.restore();
  for (const settings of adapter.current.values()) assert.deepEqual(settings, macSettings());
});

test('macOS refuses to overwrite authenticated proxy credentials', async t => {
  const { manager, adapter } = await setup(t, new FakeMac());
  adapter.current.get('Wi-Fi').http.authenticated = true;
  await assert.rejects(manager.enable(8080), /authenticated proxy/);
  assert.equal(adapter.writes.length, 0);
  await assert.rejects(fs.access(manager.file), { code: 'ENOENT' });
});

test('macOS preserves a proxy changed externally while restoring its other protocol', async t => {
  const { manager, adapter } = await setup(t, new FakeMac());
  await manager.enable(8080);
  adapter.current.get('Wi-Fi').http.server = 'new.example';
  await manager.restore();
  assert.equal(adapter.current.get('Wi-Fi').http.server, 'new.example');
  assert.deepEqual(adapter.current.get('Wi-Fi').https, macSettings().https);
});

test('native Windows proxy query is read-only and returns the documented fields', { skip: process.platform !== 'win32' }, async () => {
  const settings = await new WindowsProxy().read();
  assert.ok(Number.isInteger(settings.flags));
  for (const key of ['server', 'bypass', 'autoConfigUrl']) assert.equal(typeof settings[key], 'string');
});
