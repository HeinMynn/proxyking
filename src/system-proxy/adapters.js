const { execFile } = require('node:child_process');
const fs = require('node:fs/promises');
const path = require('node:path');
const { isDeepStrictEqual: equal } = require('node:util');
const net = require('node:net');

function run(file, args, { input, timeout = 30000, ...options } = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(file, args, { windowsHide: true, timeout, maxBuffer: 1024 * 1024, ...options }, (error, stdout, stderr) => {
      // Never include the full command: it may contain a saved PAC URL.
      if (error) return reject(new Error(`${path.basename(file)} failed: ${stderr.trim() || error.code || 'command failed'}`));
      resolve(stdout.trim());
    });
    child.stdin.on('error', () => {});
    child.stdin.end(input || '');
  });
}

function validWindows(value) {
  return value && Number.isInteger(value.flags) && value.flags >= 0 && value.flags <= 15 && ['server', 'bypass', 'autoConfigUrl'].every(key => typeof value[key] === 'string');
}

class WindowsProxy {
  constructor(execute = run) { this.execute = execute; this.platform = 'win32'; }
  async command(request) {
    const script = await fs.readFile(path.join(__dirname, 'windows.ps1'), 'utf8');
    const executable = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    const output = await this.execute(executable, ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], { input: JSON.stringify(request) });
    const result = JSON.parse(output.replace(/^\uFEFF/, ''));
    if (!validWindows(result)) throw new Error('Windows returned invalid proxy settings.');
    return result;
  }
  read() { return this.command({ action: 'read' }); }
  async write(settings) {
    const result = await this.command({ action: 'write', settings });
    if (!equal(result, settings)) throw new Error('Windows did not accept the proxy settings. Check your organization’s proxy policy.');
  }
  async plan(port, host = '127.0.0.1') {
    const before = await this.read();
    return [{ id: 'default', before, after: { ...before, flags: 3, server: `http=${host}:${port};https=${host}:${port}` } }];
  }
  validate(plan) {
    if (!Array.isArray(plan) || plan.length !== 1 || plan[0].id !== 'default' || !validWindows(plan[0].before) || !validWindows(plan[0].after)) return false;
    const match = plan[0].after.server.match(/^http=([^:]+):(\d+);https=([^:]+):(\d+)$/);
    return !!match && match[1] === match[3] && match[2] === match[4] && net.isIP(match[1]) === 4 && Number(match[2]) > 0 && Number(match[2]) <= 65535;
  }
  async apply(plan) {
    if (!equal(await this.read(), plan[0].before)) throw new Error('System proxy settings changed while capture was starting. Please try again.');
    await this.write(plan[0].after);
  }
  async restore(plan) {
    const { before, after } = plan[0];
    const current = await this.read();
    if (equal(current, before)) return [];
    if (current.server !== after.server && current.server !== before.server) return ['System proxy was changed by another app; those settings were kept.'];
    // Only undo fields we changed; preserve edits to bypass rules/PAC URL.
    const restored = { ...current, server: before.server };
    if (current.flags === after.flags) restored.flags = before.flags;
    await this.write(restored);
    return [];
  }
}

function parseProxy(output) {
  const fields = Object.fromEntries(output.split(/\r?\n/).map(line => { const i = line.indexOf(':'); return [line.slice(0, i).trim(), line.slice(i + 1).trim()]; }));
  if (!['Yes', 'No'].includes(fields.Enabled) || !/^\d+$/.test(fields.Port || '') || !['0', '1'].includes(fields['Authenticated Proxy Enabled'])) throw new Error('Could not read macOS proxy configuration.');
  return { enabled: fields.Enabled === 'Yes', server: fields.Server, port: Number(fields.Port), authenticated: fields['Authenticated Proxy Enabled'] === '1' };
}
function parseEnabled(output) {
  const match = output.match(/(?:^|\n)(?:Enabled|Auto Proxy Discovery):\s*(Yes|No|On|Off)\s*$/i);
  if (!match) throw new Error('Could not read macOS automatic proxy configuration.');
  return /yes|on/i.test(match[1]);
}
const quote = value => `'${String(value).replace(/'/g, "'\\''")}'`;
function macScript(commands) {
  // networksetup sometimes prints an error but exits successfully.
  return 'set -e\nrun_networksetup() {\n result=$(/usr/sbin/networksetup "$@" 2>&1) || { printf "%s\\n" "$result" >&2; return 1; }\n case "$result" in *"Error"*|*"error"*) printf "%s\\n" "$result" >&2; return 1;; esac\n}\n' + commands.map(args => `run_networksetup ${args.map(quote).join(' ')}`).join('\n');
}

class MacProxy {
  constructor(execute = run) { this.execute = execute; this.platform = 'darwin'; }
  async readCommand(args) {
    const output = await this.execute('/usr/sbin/networksetup', args, { env: { ...process.env, LC_ALL: 'C', LANG: 'C' } });
    if (/\*\* Error|Error:|requires admin privileges/.test(output)) throw new Error(output);
    return output;
  }
  async services() {
    const output = await this.readCommand(['-listallnetworkservices']);
    return output.split(/\r?\n/).slice(1).map(line => line.trim()).filter(line => line && !line.startsWith('*'));
  }
  async read(service) {
    const [http, https, pac, discovery] = await Promise.all([
      this.readCommand(['-getwebproxy', service]), this.readCommand(['-getsecurewebproxy', service]),
      this.readCommand(['-getautoproxyurl', service]), this.readCommand(['-getproxyautodiscovery', service])
    ]);
    return { http: parseProxy(http), https: parseProxy(https), pacEnabled: parseEnabled(pac), discoveryEnabled: parseEnabled(discovery) };
  }
  async plan(port, host = '127.0.0.1') {
    const services = await this.services();
    if (!services.length) throw new Error('No enabled macOS network services were found.');
    const plan = [];
    for (const service of services) {
      const before = await this.read(service);
      if (before.http.authenticated || before.https.authenticated) throw new Error(`“${service}” has an authenticated proxy. Use manual mode to keep its saved credentials intact.`);
      const proxy = { enabled: true, server: host, port, authenticated: false };
      plan.push({ id: service, before, after: { http: { ...proxy }, https: { ...proxy }, pacEnabled: false, discoveryEnabled: false } });
    }
    return plan;
  }
  validate(plan) {
    const valid = state => state && ['pacEnabled', 'discoveryEnabled'].every(key => typeof state[key] === 'boolean') && ['http', 'https'].every(key => {
      const value = state[key];
      return value && typeof value.enabled === 'boolean' && typeof value.authenticated === 'boolean' && typeof value.server === 'string' && Number.isInteger(value.port) && value.port >= 0 && value.port <= 65535;
    });
    return Array.isArray(plan) && plan.length > 0 && plan.every(item => typeof item.id === 'string' && item.id.length > 0 && valid(item.before) && valid(item.after) && ['http', 'https'].every(key => !item.before[key].authenticated && net.isIP(item.after[key].server) === 4 && item.after[key].port > 0 && !item.after[key].authenticated));
  }
  async write(commands) {
    if (!commands.length) return;
    // Arguments go through explicit POSIX quoting; AppleScript itself is fixed.
    await this.execute('/usr/bin/osascript', ['-e', 'on run argv\n do shell script (item 1 of argv) with administrator privileges\nend run', macScript(commands)], { timeout: 120000 });
  }
  commands(service, before, after) {
    const commands = [];
    for (const key of ['http', 'https']) {
      if (equal(before[key], after[key])) continue;
      const option = key === 'http' ? 'webproxy' : 'securewebproxy';
      const value = after[key];
      if (before[key].server !== value.server || before[key].port !== value.port || before[key].authenticated !== value.authenticated) commands.push([`-set${option}`, service, value.server, String(value.port), 'off']);
      commands.push([`-set${option}state`, service, value.enabled ? 'on' : 'off']);
    }
    if (before.pacEnabled !== after.pacEnabled) commands.push(['-setautoproxystate', service, after.pacEnabled ? 'on' : 'off']);
    if (before.discoveryEnabled !== after.discoveryEnabled) commands.push(['-setproxyautodiscovery', service, after.discoveryEnabled ? 'on' : 'off']);
    return commands;
  }
  async apply(plan) {
    const commands = [];
    for (const item of plan) {
      if (!equal(await this.read(item.id), item.before)) throw new Error('Network proxy settings changed while capture was starting. Please try again.');
      commands.push(...this.commands(item.id, item.before, item.after));
    }
    await this.write(commands);
    for (const item of plan) if (!equal(await this.read(item.id), item.after)) throw new Error(`macOS did not accept proxy settings for “${item.id}”.`);
  }
  async restore(plan) {
    const commands = [], expected = [], notices = [];
    for (const { id, before, after } of plan) {
      // Query saved services even if disabled since capture started. Failure
      // keeps the recovery journal for retry instead of forgetting a service.
      const current = await this.read(id);
      const restored = structuredClone(current);
      let ours = false;
      for (const key of ['http', 'https']) {
        const value = current[key];
        if (value.server === after[key].server && value.port === after[key].port && !value.authenticated) {
          ours = true;
          restored[key] = { ...before[key] };
          if (value.enabled !== after[key].enabled) restored[key].enabled = value.enabled;
        } else if (!equal(value, before[key])) notices.push(`Proxy settings for “${id}” were changed by another app; those changes were kept.`);
      }
      // Handles a crash halfway through applying a multi-service plan.
      if (ours || equal(current.http, before.http) && equal(current.https, before.https)) {
        for (const key of ['pacEnabled', 'discoveryEnabled']) if (current[key] === after[key]) restored[key] = before[key];
      }
      commands.push(...this.commands(id, current, restored)); expected.push({ id, settings: restored });
    }
    await this.write(commands);
    for (const item of expected) if (!equal(await this.read(item.id), item.settings)) throw new Error(`Could not restore proxy settings for “${item.id}”.`);
    return [...new Set(notices)];
  }
}

function createAdapter(platform = process.platform) {
  if (platform === 'win32') return new WindowsProxy();
  if (platform === 'darwin') return new MacProxy();
  throw new Error('Automatic system proxy setup is supported on Windows and macOS.');
}
module.exports = { createAdapter, WindowsProxy, MacProxy, parseProxy, parseEnabled, macScript, run };
