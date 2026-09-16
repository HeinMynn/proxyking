// Loaded only by the desktop test through Playwright's main-process debugger.
// It is not packaged with the application and never edits real OS settings.
const fs = require('node:fs/promises');
const path = require('node:path');

async function install(appPath, file) {
  const { WindowsProxy, MacProxy } = require(path.join(appPath, 'src/system-proxy/adapters.js'));
  const read = async () => JSON.parse(await fs.readFile(file, 'utf8'));
  const write = async value => fs.writeFile(file, JSON.stringify(value));
  if (process.platform === 'win32') {
    const initial = { flags: 9, server: '', bypass: '<local>', autoConfigUrl: '' };
    await write(initial);
    WindowsProxy.prototype.read = read;
    WindowsProxy.prototype.write = write;
    return initial;
  }
  const initial = { http: { enabled: false, server: '', port: 0, authenticated: false }, https: { enabled: false, server: '', port: 0, authenticated: false }, pacEnabled: false, discoveryEnabled: true };
  await write(initial);
  MacProxy.prototype.services = async () => ['Test network'];
  MacProxy.prototype.read = read;
  MacProxy.prototype.write = async commands => {
    const value = await read();
    for (const [option, _service, setting, port] of commands) {
      if (option === '-setautoproxystate') value.pacEnabled = setting === 'on';
      else if (option === '-setproxyautodiscovery') value.discoveryEnabled = setting === 'on';
      else {
        const key = option.includes('secure') ? 'https' : 'http';
        if (option.endsWith('state')) value[key].enabled = setting === 'on';
        else value[key] = { enabled: true, server: setting, port: Number(port), authenticated: false };
      }
    }
    await write(value);
  };
  return initial;
}
module.exports = { install };
