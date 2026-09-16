const { _electron: electron, expect } = require('@playwright/test');
const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const assert = require('node:assert/strict');

(async () => {
  const profile = await fs.mkdtemp(path.join(os.tmpdir(), 'proxyking-desktop-'));
  const origin = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ message: 'Hello from Proxyking', captured: true, items: ['Windows', 'macOS'] }));
  });
  await new Promise(resolve => origin.listen(0, '127.0.0.1', resolve));
  const probe = http.createServer();
  await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
  const proxyPort = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  let app;
  try {
    const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
    const packaged = process.argv[2];
    // Chromium switches must precede Electron's app path. Otherwise Electron
    // uses the real default cache/profile and sandboxed test runs can crash.
    app = await electron.launch({ ...(packaged ? { executablePath: path.resolve(packaged) } : {}), args: [`--user-data-dir=${profile}`, ...(packaged ? [] : [path.resolve('.')])], env });
    // Install the fake OS boundary BEFORE clicking Start. Failure aborts the
    // test, so this test can never silently change the host's live settings.
    const simulatedSettings = path.join(profile, 'simulated-os-proxy.json');
    const originalSettings = await app.evaluate(async ({ app }, config) => {
      const load = process.getBuiltinModule('module').createRequire(app.getAppPath() + '/package.json');
      return load(config.helper).install(app.getAppPath(), config.file);
    }, { helper: path.resolve('test/helpers/desktop-proxy-simulation.js'), file: simulatedSettings });
    const userData = await app.evaluate(({ app }) => app.getPath('userData'));
    const page = await app.firstWindow();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await expect(page.locator('.app-identity strong')).toHaveText('Proxyking');
    await expect(page.locator('#appsToggle')).toHaveAttribute('aria-expanded', 'true');
    await expect(page.locator('#apps')).toBeVisible();
    await expect(page.locator('#domainsToggle')).toHaveAttribute('aria-expanded', 'false');
    await expect(page.locator('#hosts')).toBeHidden();
    const appsBounds = await page.locator('#apps').boundingBox();
    const domainsBounds = await page.locator('#domainsToggle').boundingBox();
    assert.ok(appsBounds && domainsBounds && domainsBounds.y - (appsBounds.y + appsBounds.height) < 20, 'Empty Apps section pushed Domains to the bottom of the sidebar');
    await page.locator('#domainsToggle').click();
    await expect(page.locator('#hosts')).toBeVisible();
    await page.locator('#appsToggle').click();
    await expect(page.locator('#apps')).toBeHidden();
    await page.locator('#appsToggle').click();
    const assertFooterAtBottom = async () => {
      const viewportHeight = await page.evaluate(() => window.innerHeight);
      const footer = await page.locator('.network-footer').boundingBox();
      assert.ok(footer && Math.abs(footer.y + footer.height - viewportHeight) < 1, `Footer is not at viewport bottom: ${JSON.stringify({ footer, viewportHeight })}`);
    };
    await assertFooterAtBottom();
    await page.locator('#setupButton').click();
    await page.locator('#port').fill(String(proxyPort));
    await page.locator('#closeSetup').click();
    await page.locator('#captureButton').click();
    await expect(page.locator('#statusText')).toHaveText('Running');
    await expect(page.locator('#routingStatus')).toContainText('System proxy');
    await fs.access(path.join(userData, 'system-proxy-recovery.json'));
    assert.notDeepEqual(JSON.parse(await fs.readFile(simulatedSettings, 'utf8')), originalSettings);
    const target = `127.0.0.1:${origin.address().port}`;
    const proxyHost = (await page.locator('#headerEndpoint').textContent()).split(':')[0];
    await new Promise((resolve, reject) => {
      const req = http.get({ host: proxyHost, port: proxyPort, path: `http://${target}/api/hello?source=desktop`, headers: { host: target, 'user-agent': 'Mozilla/5.0 Chrome/140.0 Safari/537.36' } }, res => { res.resume(); res.on('end', resolve); });
      req.on('error', reject);
    });
    await expect(page.locator('.request-row')).toHaveCount(1);
    await assertFooterAtBottom();
    await expect(page.locator('#apps .app-name')).toHaveText('Google Chrome');
    await page.locator('#apps .host-button').click();
    await expect(page.locator('.request-row')).toHaveCount(1);
    await page.locator('#allTraffic').click();
    await page.locator('.request-row').click();
    const urlFitsSelectionBar = await page.locator('#selectedUrl').evaluate(element => {
      element.textContent = `https://example.test/${'very-long-path/'.repeat(80)}?token=${'x'.repeat(500)}`;
      const urlBox = element.getBoundingClientRect();
      const barBox = element.parentElement.getBoundingClientRect();
      const style = getComputedStyle(element);
      return urlBox.right <= barBox.right && urlBox.left >= barBox.left && element.scrollWidth <= element.clientWidth && urlBox.height > parseFloat(style.lineHeight) && style.whiteSpace === 'normal' && style.textOverflow === 'clip';
    });
    assert.equal(urlFitsSelectionBar, true, 'Selected long URL did not wrap fully inside its detail bar');
    await page.locator('.request-row').click();
    await expect(page.locator('#copyUrl')).toBeEnabled();
    await app.evaluate(({ clipboard }) => {
      global.__proxykingClipboardText = '';
      clipboard.writeText = value => { global.__proxykingClipboardText = value; };
    });
    await page.locator('#copyUrl').click();
    await expect(page.locator('#notice')).toHaveText('Request URL copied.');
    assert.equal(await app.evaluate(() => global.__proxykingClipboardText), `http://${target}/api/hello?source=desktop`);
    const requestPanel = await page.locator('.message-panel').nth(0).boundingBox();
    const responsePanel = await page.locator('.message-panel').nth(1).boundingBox();
    assert.ok(requestPanel && responsePanel && Math.abs(requestPanel.width - responsePanel.width) < 1, `Request and response panels are not equal width: ${JSON.stringify({ requestPanel, responsePanel })}`);
    await expect(page.locator('#requestContent')).toHaveCSS('overflow-x', 'auto');
    await expect(page.locator('#responseContent')).toHaveCSS('overflow-x', 'auto');
    await page.locator('[data-side="response"] [data-view="body"]').click();
    await expect(page.locator('#responseContent pre')).toContainText('Hello from Proxyking');
    await app.evaluate(({ dialog }, savePath) => { dialog.showSaveDialog = async () => ({ canceled: false, filePath: savePath }); }, path.join(profile, 'session.har'));
    await page.locator('#exportButton').click();
    await expect(page.locator('#notice')).toHaveText('Session exported as HAR.');
    await expect(page.locator('#notice')).toBeHidden({ timeout: 7500 });
    const har = JSON.parse(await fs.readFile(path.join(profile, 'session.har'), 'utf8'));
    if (har.log.entries[0].response.status !== 200) throw new Error('HAR export did not contain captured request');
    await page.locator('#typeFilter').selectOption('json');
    await expect(page.locator('.request-row')).toHaveCount(1);
    await page.locator('#search').fill('does-not-exist');
    await expect(page.locator('.request-row')).toHaveCount(0);
    await page.locator('#search').fill('');
    await expect(page.locator('.request-row')).toHaveCount(1);
    await fs.mkdir('artifacts', { recursive: true });
    await page.screenshot({ path: 'artifacts/desktop-capture.png' });
    await page.locator('#setupButton').click();
    await page.screenshot({ path: 'artifacts/desktop-setup.png' });
    await app.evaluate(({ dialog, shell }, savePath) => { dialog.showSaveDialog = async () => ({ canceled: false, filePath: savePath }); shell.showItemInFolder = () => {}; }, path.join(profile, 'export.crt'));
    await page.locator('#exportCertificate').click();
    await expect(page.locator('#notice')).toContainText('Public certificate exported.');
    const certificate = await fs.readFile(path.join(profile, 'export.crt'), 'utf8');
    if (!certificate.includes('BEGIN CERTIFICATE') || certificate.includes('PRIVATE KEY')) throw new Error('Invalid public certificate export');
    await page.locator('#newButton').click();
    await expect(page.locator('#statusText')).toHaveText('Running');
    await expect(page.locator('.request-row')).toHaveCount(0);
    await assertFooterAtBottom();
    await page.locator('#captureButton').click();
    await expect(page.locator('#statusText')).toHaveText('Paused');
    assert.deepEqual(JSON.parse(await fs.readFile(simulatedSettings, 'utf8')), originalSettings);
    await assert.rejects(fs.access(path.join(userData, 'system-proxy-recovery.json')), { code: 'ENOENT' });
    await page.locator('#clearButton').click();
    // Closing the window while capture is active must restore first.
    await page.locator('#captureButton').click();
    await expect(page.locator('#routingStatus')).toContainText('System proxy');
    await app.close(); app = null;
    assert.deepEqual(JSON.parse(await fs.readFile(simulatedSettings, 'utf8')), originalSettings);
    await assert.rejects(fs.access(path.join(userData, 'system-proxy-recovery.json')), { code: 'ENOENT' });
    if (errors.length) throw new Error(errors.join('\n'));
    console.log('Desktop smoke test passed: automatic proxy setup (simulated OS), capture, inspection, exports, filters, restoration on stop and exit. No live system proxy settings changed.');
  } finally {
    if (app) await app.close();
    origin.close();
    await fs.rm(profile, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
