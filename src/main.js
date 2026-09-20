const { app, BrowserWindow, ipcMain, dialog, shell, session, clipboard } = require('electron');
const path = require('node:path');
const fs = require('node:fs/promises');
const { pathToFileURL } = require('node:url');
const QRCode = require('qrcode');
const { CaptureEngine } = require('./engine');
const { createAdapter } = require('./system-proxy/adapters');
const { SystemProxyManager } = require('./system-proxy/manager');
const { CaptureSession } = require('./capture-session');
const { detectLanAddress } = require('./network');
const {
  installMacCertificate, removeMacCertificate, macCertificateTrustStatus,
  installWindowsCertificate, removeWindowsCertificate, windowsCertificateTrustStatus
} = require('./certificate-trust');
const { SettingsStore } = require('./settings');

if (process.platform !== 'win32') process.umask(0o077);

let window;
let engine;
let capture;
let settings;
let allowQuit = false;
let quitInProgress = false;
let localAddress = '127.0.0.1';
const indexPath = path.join(__dirname, 'ui', 'index.html');
const indexUrl = pathToFileURL(indexPath).href;
const iconPath = path.join(__dirname, 'assets', 'icon.png');

function handle(channel, action) {
  ipcMain.handle(channel, async (event, ...args) => {
    if (event.sender !== window?.webContents || event.senderFrame !== window.webContents.mainFrame || event.senderFrame.url !== indexUrl) throw new Error('Untrusted sender');
    return action(...args);
  });
}

function createWindow() {
  window = new BrowserWindow({
    width: 1440, height: 920, minWidth: 1000, minHeight: 680,
    title: 'Proxyking', icon: iconPath, backgroundColor: '#0c1018', autoHideMenuBar: true,
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true }
  });
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  window.webContents.on('will-navigate', event => event.preventDefault());
  window.on('close', event => {
    if (!allowQuit) { event.preventDefault(); app.quit(); }
  });
  window.loadFile(indexPath);
}

// Two instances must never take conflicting snapshots of system settings.
const primary = app.requestSingleInstanceLock();
if (!primary) app.quit();
app.on('second-instance', () => {
  if (window && !window.isDestroyed()) { if (window.isMinimized()) window.restore(); window.focus(); }
});

if (primary) app.whenReady().then(async () => {
  if (process.platform === 'darwin') app.dock.setIcon(iconPath);
  session.defaultSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  localAddress = await detectLanAddress();
  settings = new SettingsStore(app.getPath('userData'));
  const preferences = await settings.load();
  engine = new CaptureEngine({ directory: path.join(app.getPath('userData'), 'certificates'), host: localAddress, doNotInspect: preferences.doNotInspect });
  const systemProxy = new SystemProxyManager({ directory: app.getPath('userData'), adapter: createAdapter() });
  capture = new CaptureSession(engine, systemProxy);
  for (const name of ['record', 'device', 'notice', 'cleared', 'breakpoint', 'breakpoint-rules', 'breakpoint-resolved']) {
    engine.on(name, data => { if (window && !window.isDestroyed()) window.webContents.send(`capture:${name}`, data); });
  }
  for (const name of ['state', 'notice']) capture.on(name, data => {
    if (window && !window.isDestroyed()) window.webContents.send(`capture:${name}`, data);
  });
  handle('capture:snapshot', () => ({ state: capture.state, records: engine.list(), devices: engine.deviceList(), breakpoints: engine.breakpointList(), settings: settings.get(), platform: process.platform, version: app.getVersion(), notice: capture.notice }));
  handle('capture:update-settings', async next => {
    const saved = await settings.update(next);
    engine.setDoNotInspect(saved.doNotInspect);
    return saved;
  });
  handle('capture:start', async (port, automatic = true) => {
    if (quitInProgress) throw new Error('Proxyking is closing.');
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Choose a port from 1 to 65535.');
    if (typeof automatic !== 'boolean') throw new Error('Invalid capture mode.');
    localAddress = await detectLanAddress();
    return capture.start(port, automatic, localAddress);
  });
  handle('capture:pause', () => capture.pause());
  handle('capture:resume', () => capture.resume());
  handle('capture:stop', () => capture.stop());
  handle('capture:recover', () => capture.stop());
  handle('capture:clear', () => engine.clear());
  handle('capture:detail', id => typeof id === 'string' ? engine.detail(id) : null);
  handle('capture:replay', (id, draft) => engine.replay(id, draft));
  handle('capture:set-breakpoint', (host, side, enabled) => engine.setBreakpoint(host, side, enabled));
  handle('capture:resolve-breakpoint', (id, decision) => engine.resolveBreakpoint(id, decision));
  handle('capture:device-setup', async () => {
    const url = engine.setupUrl();
    return {
      available: capture.state.running,
      url,
      endpoint: `${capture.state.host}:${capture.state.port}`,
      qrDataUrl: capture.state.running ? await QRCode.toDataURL(url, { errorCorrectionLevel: 'M', margin: 2, width: 280 }) : null
    };
  });
  handle('capture:copy-text', text => {
    if (typeof text !== 'string' || text.length > 1024 * 1024) throw new Error('Invalid clipboard text.');
    clipboard.writeText(text);
    return true;
  });
  handle('capture:certificate', async () => {
    await engine.prepareCertificate();
    const result = await dialog.showSaveDialog(window, { title: 'Export public certificate', defaultPath: 'Proxyking-CA.crt', filters: [{ name: 'X.509 certificate', extensions: ['crt'] }] });
    if (result.canceled) return false;
    await fs.copyFile(engine.certificatePath, result.filePath);
    shell.showItemInFolder(result.filePath);
    return true;
  });
  handle('capture:trust-certificate', async () => {
    const certificatePath = await engine.prepareCertificate();
    if (process.platform === 'darwin') await installMacCertificate(certificatePath);
    else if (process.platform === 'win32') await installWindowsCertificate(certificatePath);
    else throw new Error('Automatic certificate trust is available only on macOS and Windows.');
    return true;
  });
  handle('capture:certificate-status', async () => {
    const certificatePath = await engine.prepareCertificate();
    if (process.platform === 'darwin') return macCertificateTrustStatus(certificatePath);
    if (process.platform === 'win32') return windowsCertificateTrustStatus(certificatePath);
    return { state: 'unsupported', label: 'Manual setup' };
  });
  handle('capture:remove-certificate', async () => {
    if (!['darwin', 'win32'].includes(process.platform)) throw new Error('Automatic certificate removal is available only on macOS and Windows.');
    const store = process.platform === 'darwin' ? 'login keychain' : 'Windows user Trusted Root store';
    const confirmation = await dialog.showMessageBox(window, {
      type: 'warning', title: 'Revoke Proxyking CA?',
      message: `Remove Proxyking Local CA from your ${store}?`,
      detail: 'Browsers and apps will stop trusting certificates generated by Proxyking. Restart them after removal.',
      buttons: ['Cancel', 'Revoke & Remove'], defaultId: 0, cancelId: 0, noLink: true
    });
    if (confirmation.response !== 1) return { canceled: true };
    const certificatePath = await engine.prepareCertificate();
    return process.platform === 'darwin' ? removeMacCertificate(certificatePath) : removeWindowsCertificate(certificatePath);
  });
  handle('capture:export', async id => {
    const record = id === undefined ? null : typeof id === 'string' ? engine.detail(id) : null;
    if (id !== undefined && !record) throw new Error('The selected request is no longer available.');
    const suffix = record ? `-${record.method}-${record.domain || record.host}`.replace(/[^A-Za-z0-9._-]/g, '-') : '';
    const result = await dialog.showSaveDialog(window, { title: record ? 'Export selected request' : 'Export captured session', defaultPath: `Proxyking${suffix}-${new Date().toISOString().replace(/[:.]/g, '-')}.har`, filters: [{ name: 'HTTP Archive', extensions: ['har'] }] });
    if (result.canceled) return false;
    await fs.writeFile(result.filePath, JSON.stringify(engine.exportHar(record ? [record] : undefined), null, 2));
    return true;
  });
  createWindow();
  await capture.recover().catch(error => capture.tell(`System proxy recovery failed: ${error.message} Use Restore proxy settings to retry before starting capture.`));
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
}).catch(error => {
  dialog.showErrorBox('Proxyking could not start', error.message);
  app.quit();
});
app.on('window-all-closed', () => app.quit());
app.on('before-quit', event => {
  if (allowQuit || !capture) return;
  event.preventDefault();
  if (quitInProgress) return;
  quitInProgress = true;
  capture.stop().then(() => { allowQuit = true; app.quit(); }).catch(error => {
    quitInProgress = false;
    capture.tell(`Could not restore the system proxy: ${error.message} Retry Stop capture or Restore proxy settings.`);
    dialog.showErrorBox('Proxy settings still need restoration', 'Proxyking is staying open to avoid leaving your browser pointed at a stopped proxy.\n\n' + error.message);
  });
});
