const SETUP_VERIFY_HOST = 'proxyking.test';

function inferDevicePlatform(userAgent = '') {
  const value = String(userAgent);
  if (/\b(?:iPhone|iPad|iPod)\b/i.test(value)) return 'iOS';
  if (/\bAndroid\b/i.test(value)) return 'Android';
  return 'Unknown device';
}

function escapeHtml(value = '') {
  return String(value).replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}

const setupScript = [
  "'use strict';",
  "const buttons = [...document.querySelectorAll('[data-platform]')];",
  "const panels = [...document.querySelectorAll('[data-panel]')];",
  "function selectPlatform(name) {",
  "  buttons.forEach(button => { const selected = button.dataset.platform === name; button.classList.toggle('selected', selected); button.setAttribute('aria-selected', String(selected)); });",
  "  panels.forEach(panel => { panel.hidden = panel.dataset.panel !== name; });",
  "}",
  "buttons.forEach(button => button.addEventListener('click', () => selectPlatform(button.dataset.platform)));",
  "selectPlatform(/Android/i.test(navigator.userAgent) ? 'android' : 'ios');",
  "let verificationPending = false;",
  "async function verifyHttps() {",
  "  if (verificationPending) return;",
  "  verificationPending = true;",
  "  try { await fetch('https://proxyking.test/verify', { mode: 'no-cors', cache: 'no-store' }); } catch {}",
  "  finally { verificationPending = false; }",
  "}",
  "async function refreshStatus() {",
  "  try {",
  "    const response = await fetch('/setup/api/status', { cache: 'no-store' });",
  "    const status = await response.json();",
  "    document.getElementById('deviceAddress').textContent = status.address;",
  "    document.getElementById('devicePlatform').textContent = status.platform;",
  "    const badge = document.getElementById('trustStatus');",
  "    badge.className = status.trusted ? 'status trusted' : 'status pending';",
  "    badge.textContent = status.trusted ? 'HTTPS verified' : 'HTTPS not verified';",
  "    document.getElementById('trustHelp').textContent = status.trusted ? 'This device accepts certificates issued by Proxyking Local CA.' : 'Waiting for certificate trust. Proxyking checks automatically.';",
  "    if (!status.trusted) await verifyHttps();",
  "  } catch { document.getElementById('trustHelp').textContent = 'Proxyking is not reachable. Confirm that both devices remain on the same Wi-Fi network.'; }",
  "}",
  "document.getElementById('refreshStatus').addEventListener('click', () => refreshStatus());",
  "document.getElementById('copyProxy').addEventListener('click', async () => {",
  "  const value = document.getElementById('proxyAddress').textContent;",
  "  try { await navigator.clipboard.writeText(value); document.getElementById('copyProxy').textContent = 'Copied'; } catch { document.getElementById('copyProxy').textContent = value; }",
  "});",
  "refreshStatus(); setInterval(refreshStatus, 2000);"
].join('\n');

const pageStyle = [
  ":root{color-scheme:dark;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#08101a;color:#edf4ff}",
  "*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 10% 0,#173048 0,transparent 36%),#08101a;min-height:100vh}",
  "main{width:min(760px,100%);margin:auto;padding:28px 18px 48px}",
  ".brand{display:flex;align-items:center;gap:12px;margin-bottom:26px}.logo{display:grid;place-items:center;width:42px;height:42px;border-radius:11px;background:#72d994;color:#102619;font-size:23px;font-weight:800}.brand h1{margin:0;font-size:22px}.brand p{margin:3px 0 0;color:#91a4ba;font-size:13px}",
  ".card{margin:14px 0;padding:20px;border:1px solid #29394e;border-radius:14px;background:#101a27;box-shadow:0 16px 50px #0004}.card h2{margin:0 0 8px;font-size:17px}.card p,.card li{color:#a6b5c8;font-size:14px;line-height:1.55}",
  ".device{display:grid;grid-template-columns:1fr auto;gap:12px;align-items:center}.meta{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px;color:#89a0ba;font-size:12px}.meta code,.endpoint{color:#bfe9cc;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}",
  ".status{display:inline-flex;padding:7px 10px;border-radius:999px;font-size:12px;font-weight:700}.status.pending{border:1px solid #765f2d;background:#302817;color:#f0cf73}.status.trusted{border:1px solid #38694b;background:#193728;color:#83e5a1}",
  ".step{display:flex;gap:14px}.number{width:28px;height:28px;flex:0 0 28px;display:grid;place-items:center;border:1px solid #3d7051;border-radius:50%;background:#1b3929;color:#86e3a2;font-weight:700}.step>div:last-child{min-width:0;flex:1}",
  ".endpoint-row{display:flex;gap:8px;align-items:center;margin:13px 0}.endpoint{min-width:0;flex:1;padding:12px;border:1px solid #31445b;border-radius:8px;background:#0a131f;overflow-wrap:anywhere}",
  "button,.button{display:inline-flex;justify-content:center;align-items:center;min-height:42px;padding:0 15px;border:1px solid #3b526d;border-radius:8px;background:#18283a;color:#eaf2fd;font:inherit;text-decoration:none;cursor:pointer}.button.primary{border-color:#46805a;background:#1d4a31;color:#a8f0bd;font-weight:700}",
  ".tabs{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:14px 0}.tabs button.selected{border-color:#4a805c;background:#1b3b2a;color:#9ce9b3}.platform{padding:2px 2px 0}.platform ol{padding-left:22px}.note{padding:10px 12px;border-left:3px solid #d2a84f;background:#2b2417;color:#e1c984!important;border-radius:4px}",
  ".actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:13px}.small{font-size:12px;color:#70869f;text-align:center;margin-top:22px}",
  "@media(max-width:540px){main{padding-top:20px}.card{padding:17px}.device{grid-template-columns:1fr}.step{gap:10px}.endpoint-row{align-items:stretch;flex-direction:column}}"
].join('');

function renderSetupPage({ host, port, address, platform, trusted }) {
  const endpoint = escapeHtml(host + ':' + port);
  const safeAddress = escapeHtml(address);
  const safePlatform = escapeHtml(platform);
  return [
    '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
    '<meta name="color-scheme" content="dark"><title>Set up Proxyking</title><style>', pageStyle, '</style></head><body><main>',
    '<header class="brand"><div class="logo">P</div><div><h1>Connect this device</h1><p>Proxyking mobile traffic setup</p></div></header>',
    '<section class="card device"><div><h2>Device detected</h2><div class="meta"><span id="devicePlatform">', safePlatform, '</span><code id="deviceAddress">', safeAddress, '</code></div><p id="trustHelp">', trusted ? 'This device accepts certificates issued by Proxyking Local CA.' : 'Complete the steps below to verify HTTPS inspection.', '</p></div>',
    '<span id="trustStatus" class="status ', trusted ? 'trusted' : 'pending', '">', trusted ? 'HTTPS verified' : 'HTTPS not verified', '</span></section>',
    '<section class="card step"><div class="number">1</div><div><h2>Configure the Wi-Fi proxy</h2><p>Open the proxy settings for this Wi-Fi network. Select Manual, then enter the server and port shown below.</p>',
    '<div class="endpoint-row"><code id="proxyAddress" class="endpoint">', endpoint, '</code><button id="copyProxy" type="button">Copy</button></div>',
    '<p>Keep this page open. After saving the proxy settings, return here to install the certificate.</p></div></section>',
    '<section class="card step"><div class="number">2</div><div><h2>Install Proxyking Local CA</h2>',
    '<div class="tabs" role="tablist"><button type="button" data-platform="ios" role="tab">iPhone &amp; iPad</button><button type="button" data-platform="android" role="tab">Android</button></div>',
    '<div class="platform" data-panel="ios"><p class="note"><b>Required after installation:</b> iOS does not enable SSL trust automatically. After installing the profile, open Settings → General → About → Certificate Trust Settings and enable full trust for <b>Proxyking Local CA</b>.</p><ol><li>Download the CA certificate below and allow the configuration profile download.</li><li>Open Settings → Profile Downloaded, tap Install, and complete profile installation.</li><li>Then open Settings → General → About → Certificate Trust Settings.</li><li>Under Enable Full Trust for Root Certificates, turn on <b>Proxyking Local CA</b> and confirm Continue.</li></ol></div>',
    '<div class="platform" data-panel="android" hidden><ol><li>Download the CA certificate below.</li><li>Open Settings → Security &amp; privacy → More security settings.</li><li>Select Install a certificate → CA certificate, then choose the downloaded file.</li><li>Confirm the security warning and installation.</li></ol><p class="note">Many Android apps do not trust user-installed CAs unless their developer enables it. Browser traffic can still be verified here.</p></div>',
    '<div class="actions"><a class="button primary" href="/setup/ca.crt" download="Proxyking-CA.crt">Download Proxyking CA</a></div></div></section>',
    '<section class="card step"><div class="number">3</div><div><h2>Verify HTTPS inspection</h2><p>Proxyking checks automatically after you trust the certificate. You can also open the verification page manually if the status does not update.</p>',
    '<div class="actions"><a class="button primary" href="https://', SETUP_VERIFY_HOST, '/verify" target="_blank" rel="noopener">Verify HTTPS</a><button id="refreshStatus" type="button">Refresh status</button></div></div></section>',
    '<p class="small">Keep Proxyking running and keep both devices on the same Wi-Fi network.</p>',
    '<script src="/setup/app.js"></script></main></body></html>'
  ].join('');
}

function renderVerifiedPage(setupUrl) {
  return [
    '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
    '<meta name="color-scheme" content="dark"><title>Proxyking HTTPS verified</title><style>', pageStyle, '</style></head><body><main>',
    '<header class="brand"><div class="logo">P</div><div><h1>HTTPS verified</h1><p>Proxyking mobile traffic setup</p></div></header>',
    '<section class="card"><span class="status trusted">Certificate trusted</span><h2 style="margin-top:16px">This device is ready</h2>',
    '<p>Proxyking successfully decrypted this verification request. Return to the setup page and start browsing to capture traffic.</p>',
    '<div class="actions"><a class="button primary" href="', escapeHtml(setupUrl), '">Return to setup</a></div></section>',
    '</main></body></html>'
  ].join('');
}

module.exports = { SETUP_VERIFY_HOST, inferDevicePlatform, renderSetupPage, renderVerifiedPage, setupScript };
