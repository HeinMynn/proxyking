const api = window.proxyking;
const $ = id => document.getElementById(id);
const records = new Map();
const knownDevices = new Map();
const breakpointRules = new Set();
const pendingBreakpoints = new Map();
let activeBreakpoint = null;
const views = { request: 'headers', response: 'headers' };
let state = { running: false, paused: false, busy: false, host: '127.0.0.1', port: 8080 };
let selectedId = null;
let selectedDomain = null;
let selectedApp = null;
let selectedDevice = null;
let currentRecord = null;
let renderQueued = false;
let detailVersion = 0;
let noticeTimer = null;

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
function bytes(value = 0) { return value < 1024 ? `${value} B` : value < 1048576 ? `${(value / 1024).toFixed(1)} KB` : `${(value / 1048576).toFixed(1)} MB`; }
function colorHue(value) { return [...value].reduce((hash, character) => (hash * 31 + character.charCodeAt(0)) % 360, 0); }
function notify(message) {
  clearTimeout(noticeTimer);
  noticeTimer = null;
  $('notice').textContent = message;
  $('notice').hidden = !message;
  if (message) noticeTimer = setTimeout(() => {
    $('notice').hidden = true;
    $('notice').textContent = '';
    noticeTimer = null;
  }, 6000);
}
async function action(fn) { try { return await fn(); } catch (error) { notify(error.message.replace(/^Error invoking remote method '[^']+': (Error: )?/, '')); return null; } }

function showCertificateStatus(status) {
  if (!status) return;
  const sidebar = $('certificateStatusSidebar');
  const modal = $('certificateStatusModal');
  sidebar.className = `certificate-status-dot ${status.state}`;
  sidebar.title = status.label;
  sidebar.setAttribute('aria-label', `Certificate status: ${status.label}`);
  $('removeCertificate').disabled = !['trusted', 'untrusted'].includes(status.state);
  modal.textContent = status.state === 'trusted' ? '✓ Proxyking CA is installed and trusted for SSL.'
    : status.state === 'untrusted' ? 'Proxyking CA is installed but is not trusted for SSL.'
      : status.state === 'missing' ? 'Proxyking CA is not installed in your user trust store.'
        : 'Certificate trust must be configured manually on this platform.';
  modal.className = `certificate-status-detail ${status.state}`;
}
async function refreshCertificateStatus() {
  const status = await action(() => api.certificateStatus());
  if (status) showCertificateStatus(status);
}

function updateState(next) {
  state = next;
  const mode = state.busy ? 'Updating' : !state.running ? 'Stopped' : state.paused ? 'Paused' : 'Running';
  const className = `status-indicator ${state.busy ? 'busy' : state.running && !state.paused ? '' : 'paused'}`;
  $('statusIndicator').className = className;
  $('footerStatus').className = className;
  $('statusText').textContent = mode;
  $('captureIcon').className = `capture-icon ${state.running && !state.paused ? 'pause' : 'play'}`;
  $('captureButton').title = !state.running ? 'Start capture' : state.paused ? 'Resume capture' : 'Pause capture';
  $('captureButton').setAttribute('aria-label', $('captureButton').title);
  const endpoint = `${state.host || '127.0.0.1'}:${state.port}`;
  $('headerEndpoint').textContent = endpoint;
  $('setupEndpoint').textContent = endpoint;
  $('port').disabled = state.running || state.busy;
  $('automaticProxy').disabled = state.running || state.busy || state.recoveryPending;
  $('captureButton').disabled = state.busy || (!state.running && state.recoveryPending);
  $('stopButton').disabled = state.busy || !state.running;
  $('newButton').disabled = state.busy || state.recoveryPending && !state.systemProxy;
  $('recoverButton').hidden = !state.recoveryPending || state.running;
  $('recoverButton').disabled = state.busy;
  $('routingStatus').textContent = state.busy ? 'Updating system proxy…' : state.recoveryPending && !state.systemProxy ? 'Proxy recovery needed' : state.systemProxy ? `System proxy → ${endpoint}${state.paused ? ' · capture paused' : ''}` : state.running ? `Manual proxy → ${endpoint}${state.paused ? ' · capture paused' : ''}` : 'System proxy restored';
}

function scheduleRender() {
  if (renderQueued) return;
  renderQueued = true;
  setTimeout(() => { renderQueued = false; render(); }, 70);
}

function filteredRecords() {
  const search = $('search').value.toLowerCase();
  const filter = $('typeFilter').value;
  return [...records.values()].filter(record => {
    if (selectedDomain && (record.domain || record.host) !== selectedDomain || selectedApp && record.application !== selectedApp || selectedDevice && record.remoteDevice !== selectedDevice) return false;
    if (!`${record.url} ${record.method} ${record.status || ''}`.toLowerCase().includes(search)) return false;
    return filter === 'all' || filter === 'https' && record.secure || filter === 'errors' && (record.state === 'failed' || record.status >= 400) || filter === 'json' && /json/i.test(record.contentType || '') || filter === 'tunnels' && record.tunneled;
  }).reverse();
}

function render() {
  const all = [...records.values()];
  const visible = filteredRecords();
  const rows = visible.map(record => {
    const row = element('button', `request-row${selectedId === record.id ? ' selected' : ''}`);
    row.setAttribute('aria-label', `${record.method} ${record.url}, status ${record.status || record.state}`);
    const target = element('div', 'request-target');
    target.append(element('div', 'request-host', record.host), element('div', 'request-path', record.path));
    const type = record.tunneled ? 'TUNNEL' : record.secure ? 'HTTPS' : 'HTTP';
    row.append(
      element('span', 'method', record.method), target,
      element('span', record.state === 'failed' || record.status >= 400 ? 'status-bad' : record.status ? 'status-good' : 'status-pending', record.state === 'failed' ? 'Error' : record.status || '…'),
      element('span', 'protocol-badge', type),
      element('span', 'cell-muted', record.duration === null ? '…' : `${record.duration} ms`),
      element('span', 'cell-muted', bytes(record.size))
    );
    row.addEventListener('click', () => { selectedId = record.id; render(); loadDetail(); });
    return row;
  });
  $('requests').replaceChildren(...rows);
  $('empty').hidden = visible.length > 0;
  $('empty').querySelector('h2').textContent = all.length ? 'No matching connections' : state.paused ? 'Capture paused' : state.running ? 'Waiting for traffic' : 'Ready to capture';
  $('empty').querySelector('p').textContent = all.length ? 'Change the domain, search, or filter.' : state.paused ? 'Traffic continues through Proxyking without being recorded.' : state.running ? 'Browse normally to populate this list.' : 'Press Start, then browse normally.';
  $('requestCount').textContent = all.length;
  $('totalBadge').textContent = all.length;
  $('visibleCount').textContent = `${visible.length} of ${all.length} requests`;
  $('requestTraffic').textContent = bytes(all.reduce((total, record) => total + (record.requestSize || 0), 0));
  $('responseTraffic').textContent = bytes(all.reduce((total, record) => total + record.size, 0));
  const hosts = [...new Set(all.map(record => record.domain || record.host))].sort();
  const apps = [...new Set(all.map(record => record.application || 'Unknown app'))].sort();
  const devices = [...new Set([...knownDevices.keys(), ...all.map(record => record.remoteDevice).filter(Boolean)])].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
  $('hostCount').textContent = hosts.length;
  $('footerHosts').textContent = hosts.length;
  $('appCount').textContent = apps.length;
  $('deviceCount').textContent = devices.length;
  $('allTraffic').classList.toggle('active', !selectedDomain && !selectedApp && !selectedDevice);
  $('apps').replaceChildren(...apps.map(app => {
    const button = element('button', `host-button${app === selectedApp ? ' selected' : ''}`);
    const icon = element('span', 'app-icon', app.slice(0, 1).toUpperCase());
    icon.style.setProperty('--icon-hue', colorHue(app));
    button.append(icon, element('span', 'app-name', app));
    button.title = app;
    button.addEventListener('click', () => { selectedApp = app === selectedApp ? null : app; selectedDomain = null; selectedDevice = null; render(); });
    return button;
  }));
  if (!apps.length) $('apps').append(element('p', 'subtle', 'Apps appear as traffic arrives.'));
  $('devices').replaceChildren(...devices.map(device => {
    const info = knownDevices.get(device);
    const button = element('button', `host-button device-button${device === selectedDevice ? ' selected' : ''}`);
    const count = all.filter(record => record.remoteDevice === device).length;
    const identity = element('span', 'device-identity');
    if (info?.platform && info.platform !== 'Unknown device') identity.append(element('span', 'device-platform', info.platform));
    identity.append(element('span', 'device-name', device));
    const trust = element('span', `device-trust${info?.trustedAt ? ' trusted' : ''}`);
    trust.title = info?.trustedAt ? 'HTTPS verified' : 'HTTPS not verified';
    button.append(element('span', 'device-icon', info?.platform === 'Android' ? 'A' : info?.platform === 'iOS' ? 'i' : '◇'), identity, trust, element('span', 'device-traffic-count', String(count)));
    button.title = `${info?.platform || 'Remote device'} · ${device} · ${info?.trustedAt ? 'HTTPS verified' : 'HTTPS not verified'}`;
    button.addEventListener('click', () => { selectedDevice = device === selectedDevice ? null : device; selectedApp = null; selectedDomain = null; render(); });
    return button;
  }));
  if (!devices.length) $('devices').append(element('p', 'subtle', 'Remote devices appear when they use this proxy.'));
  $('hosts').replaceChildren(...hosts.map(domain => {
    const button = element('button', `host-button domain-button${domain === selectedDomain ? ' selected' : ''}`);
    button.append(element('span', 'domain-icon', '◌'), element('span', 'domain-name', domain));
    button.title = domain;
    button.addEventListener('click', () => { selectedDomain = domain === selectedDomain ? null : domain; selectedApp = null; selectedDevice = null; render(); });
    return button;
  }));
  if (!hosts.length) $('hosts').append(element('p', 'subtle', 'Domains appear as traffic arrives.'));
  if (selectedId && !records.has(selectedId)) resetSelection();
}

function resetSelection() {
  selectedId = null; currentRecord = null;
  $('selectedMethod').textContent = '—';
  $('selectedUrl').textContent = 'Select a connection to inspect its URL';
  $('selectedUrl').title = '';
  $('copyUrl').disabled = true;
  $('exportSelected').disabled = true;
  $('replaySelected').disabled = true;
  $('requestBreakpoint').disabled = true;
  $('responseBreakpoint').disabled = true;
  $('requestSummary').textContent = 'No request selected';
  $('responseSummary').textContent = 'No response selected';
  $('requestContent').replaceChildren(element('div', 'placeholder', 'Select a connection above.'));
  $('responseContent').replaceChildren(element('div', 'placeholder', 'Select a connection above.'));
}

async function loadDetail() {
  const version = ++detailVersion;
  const detail = await action(() => api.detail(selectedId));
  if (version !== detailVersion || !detail || detail.id !== selectedId) return;
  currentRecord = detail;
  $('selectedMethod').textContent = detail.method;
  $('selectedUrl').textContent = detail.url;
  $('selectedUrl').title = detail.url;
  $('copyUrl').disabled = false;
  $('exportSelected').disabled = false;
  const replayable = detail.state === 'complete' && !detail.tunneled && !detail.requestBody?.truncated && detail.requestBody?.encoding !== 'base64' && ['', 'identity'].includes(String(detail.requestHeaders?.['content-encoding'] || '').toLowerCase());
  $('replaySelected').disabled = !replayable;
  for (const side of ['request', 'response']) {
    const button = $(side + 'Breakpoint');
    button.disabled = !!detail.tunneled;
    button.classList.toggle('tool-active', breakpointRules.has(side + ':' + detail.host.toLowerCase()));
  }
  $('requestSummary').textContent = `${bytes(detail.requestBody?.size)} · ${Object.keys(detail.requestHeaders || {}).length} headers`;
  $('responseSummary').textContent = `${detail.status || detail.state} · ${bytes(detail.size)} · ${detail.duration ?? '…'} ms`;
  renderMessages();
}

function pairs(values, emptyText) {
  const entries = Object.entries(values || {});
  if (!entries.length) return element('div', 'placeholder', emptyText);
  const fragment = document.createDocumentFragment();
  for (const [key, raw] of entries) {
    const row = element('div', 'kv');
    row.append(element('span', 'key', key), element('span', 'value', Array.isArray(raw) ? raw.join('\n') : String(raw ?? '')));
    fragment.append(row);
  }
  return fragment;
}

function prettyBody(body, pending) {
  const container = document.createDocumentFragment();
  if (body?.note) container.append(element('p', 'body-note', body.note));
  let value = body?.text || (pending ? 'Waiting for body…' : 'No body');
  if (body?.encoding !== 'base64' && !body?.truncated && body?.text) { try { value = JSON.stringify(JSON.parse(body.text), null, 2); } catch {} }
  container.append(element('pre', '', value));
  return container;
}

function rawMessage(side, record) {
  const request = side === 'request';
  const headers = request ? record.requestHeaders : record.responseHeaders;
  const first = request ? `${record.method} ${record.path} ${record.httpVersion || 'HTTP/1.1'}` : `${record.httpVersion || 'HTTP/1.1'} ${record.status || 0}`;
  const lines = Object.entries(headers || {}).map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : value}`);
  const body = request ? record.requestBody : record.responseBody;
  return [first, ...lines, '', body?.text || ''].join('\n');
}

function queryValues(side, record) {
  const source = side === 'request' ? record.url : record.responseHeaders?.location;
  if (!source) return {};
  try { return Object.fromEntries(new URL(source, record.url).searchParams); } catch { return {}; }
}

function renderSide(side) {
  const content = $(`${side}Content`);
  if (!currentRecord) return;
  const view = views[side];
  if (view === 'headers') content.replaceChildren(pairs(currentRecord[`${side}Headers`], `No ${side} headers.`));
  else if (view === 'query') content.replaceChildren(pairs(queryValues(side, currentRecord), side === 'request' ? 'No query parameters.' : 'No redirect query parameters.'));
  else if (view === 'body') content.replaceChildren(prettyBody(currentRecord[`${side}Body`], currentRecord.state === 'pending'));
  else content.replaceChildren(element('pre', '', rawMessage(side, currentRecord)));
}
function renderMessages() { renderSide('request'); renderSide('response'); }

function openSetup() { $('setup').showModal(); refreshCertificateStatus(); }
async function openDeviceSetup() {
  if (!$('deviceSetupDialog').open) $('deviceSetupDialog').showModal();
  const details = await action(() => api.deviceSetup());
  if (!details) return;
  $('deviceSetupUrl').textContent = details.url;
  $('deviceSetupUnavailable').hidden = details.available;
  $('deviceSetupAvailable').hidden = !details.available;
  if (details.available) $('deviceSetupQr').src = details.qrDataUrl;
}
function showNextBreakpoint() {
  if (activeBreakpoint || !pendingBreakpoints.size) return;
  const next = pendingBreakpoints.values().next().value;
  activeBreakpoint = next.id;
  $('breakpointTitle').textContent = next.side === 'request' ? 'Request breakpoint' : 'Response breakpoint';
  $('breakpointTarget').textContent = next.method + ' ' + next.url;
  $('breakpointBody').value = next.body;
  $('breakpointDialog').showModal();
}
async function resolveActiveBreakpoint(actionName) {
  const id = activeBreakpoint;
  if (!id) return;
  const body = $('breakpointBody').value;
  const result = await action(() => api.resolveBreakpoint(id, actionName === 'edit' ? { action: 'edit', body } : { action: 'continue' }));
  if (result === null) return;
}
function openReplay() {
  if (!currentRecord || $('replaySelected').disabled) return;
  $('replayMethod').value = currentRecord.method;
  $('replayUrl').value = currentRecord.url;
  $('replayHeaders').value = JSON.stringify(currentRecord.requestHeaders || {}, null, 2);
  $('replayBody').value = currentRecord.requestBody?.text || '';
  $('replayDialog').showModal();
}
function setupSectionToggle(buttonId, contentId, collapsedClass) {
  const button = $(buttonId);
  const content = $(contentId);
  button.addEventListener('click', () => {
    const expanded = button.getAttribute('aria-expanded') !== 'true';
    button.setAttribute('aria-expanded', String(expanded));
    content.hidden = !expanded;
    document.querySelector('.sidebar').classList.toggle(collapsedClass, !expanded);
  });
}
setupSectionToggle('appsToggle', 'apps', 'apps-collapsed');
setupSectionToggle('devicesToggle', 'devices', 'devices-collapsed');
setupSectionToggle('domainsToggle', 'hosts', 'domains-collapsed');
for (const id of ['setupButton', 'certificateButton', 'emptySetup']) $(id).addEventListener('click', openSetup);
$('deviceSetupButton').addEventListener('click', openDeviceSetup);
$('closeSetup').addEventListener('click', () => $('setup').close());
$('closeDeviceSetup').addEventListener('click', () => $('deviceSetupDialog').close());
$('copyDeviceSetupUrl').addEventListener('click', () => action(async () => { await api.copyText($('deviceSetupUrl').textContent); notify('Mobile setup URL copied.'); }));
$('captureButton').addEventListener('click', async () => {
  notify('');
  const next = await action(() => !state.running ? api.start(Number($('port').value), $('automaticProxy').checked) : state.paused ? api.resume() : api.pause());
  if (next) updateState(next);
});
$('stopButton').addEventListener('click', async () => {
  notify('');
  const next = await action(() => api.stop());
  if (next) updateState(next);
});
$('newButton').addEventListener('click', async () => {
  notify('');
  if (state.running && !await action(() => api.stop())) return;
  await action(() => api.clear());
  const next = await action(() => api.start(Number($('port').value), $('automaticProxy').checked));
  if (next) updateState(next);
});
$('clearButton').addEventListener('click', () => action(() => api.clear()));
$('recoverButton').addEventListener('click', () => action(async () => updateState(await api.recover())));
$('exportButton').addEventListener('click', () => action(async () => { if (await api.export()) notify('Session exported as HAR.'); }));
$('exportSelected').addEventListener('click', () => action(async () => { if (currentRecord && await api.export(currentRecord.id)) notify('Selected request exported as HAR.'); }));
$('exportCertificate').addEventListener('click', () => action(async () => { if (await api.certificate()) { $('setup').close(); notify('Public certificate exported. Install it, then restart the browser.'); } }));
$('trustCertificate').addEventListener('click', () => action(async () => {
  $('trustCertificate').disabled = true;
  try {
    if (await api.trustCertificate()) {
      await refreshCertificateStatus();
      notify('Proxyking CA installed and trusted for this user. Restart browsers and apps to use it.');
    }
  } finally { $('trustCertificate').disabled = false; }
}));
$('removeCertificate').addEventListener('click', () => action(async () => {
  $('removeCertificate').disabled = true;
  try {
    const result = await api.removeCertificate();
    if (!result?.canceled) {
      await refreshCertificateStatus();
      notify(result.systemCopy ? 'Login-keychain CA removed. A matching System-keychain copy remains; remove it with Keychain Access.' : result.removed ? 'Proxyking CA trust revoked and certificate removed. Restart browsers and apps.' : 'Proxyking CA was not present in the login keychain.');
    }
  } finally { await refreshCertificateStatus(); }
}));
$('copyUrl').addEventListener('click', () => action(async () => { await api.copyText(currentRecord.url); notify('Request URL copied.'); }));
$('replaySelected').addEventListener('click', openReplay);
$('closeReplay').addEventListener('click', () => $('replayDialog').close());
$('sendReplay').addEventListener('click', async () => {
  let headers;
  try { headers = JSON.parse($('replayHeaders').value); } catch { notify('Headers must be valid JSON.'); return; }
  $('sendReplay').disabled = true;
  try {
    const result = await action(() => api.replay(currentRecord.id, {
      method: $('replayMethod').value, url: $('replayUrl').value, headers, body: $('replayBody').value
    }));
    if (result) {
      $('replayDialog').close();
      selectedDomain = selectedApp = selectedDevice = null;
      selectedId = result.id;
      render(); loadDetail();
      notify('Replay completed.');
    }
  } finally { $('sendReplay').disabled = false; }
});
for (const side of ['request', 'response']) $(side + 'Breakpoint').addEventListener('click', async () => {
  if (!currentRecord || currentRecord.tunneled) return;
  const host = currentRecord.host;
  const key = side + ':' + host.toLowerCase();
  const rules = await action(() => api.setBreakpoint(host, side, !breakpointRules.has(key)));
  if (rules) {
    breakpointRules.clear(); rules.forEach(rule => breakpointRules.add(rule));
    loadDetail();
    notify((breakpointRules.has(key) ? 'Enabled' : 'Disabled') + ' ' + side + ' breakpoint for ' + host + '.');
  }
});
$('continueBreakpoint').addEventListener('click', () => resolveActiveBreakpoint('continue'));
$('sendBreakpoint').addEventListener('click', () => resolveActiveBreakpoint('edit'));
$('breakpointDialog').addEventListener('cancel', event => { event.preventDefault(); resolveActiveBreakpoint('continue'); });

$('allTraffic').addEventListener('click', () => { selectedDomain = null; selectedApp = null; selectedDevice = null; render(); });
$('search').addEventListener('input', scheduleRender);
$('typeFilter').addEventListener('change', render);
$('port').addEventListener('input', () => { if (!state.running) updateState({ ...state, port: Number($('port').value) }); });
$('automaticProxy').addEventListener('change', render);
document.querySelectorAll('.data-tabs').forEach(nav => nav.querySelectorAll('button').forEach(button => button.addEventListener('click', () => {
  const side = nav.dataset.side; views[side] = button.dataset.view;
  nav.querySelectorAll('button').forEach(item => item.classList.toggle('selected', item === button));
  renderSide(side);
})));
document.addEventListener('keydown', event => { if (event.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName) && !document.querySelector('dialog[open]')) { event.preventDefault(); $('search').focus(); } });

api.on('record', record => {
  records.set(record.id, record);
  scheduleRender();
  if (selectedId === record.id) loadDetail();
});
api.on('device', device => { knownDevices.set(device.address, device); render(); });
api.on('state', next => { updateState(next); if ($('deviceSetupDialog').open) openDeviceSetup(); });
api.on('notice', notify);
api.on('breakpoint', item => { pendingBreakpoints.set(item.id, item); showNextBreakpoint(); });
api.on('breakpoint-rules', rules => { breakpointRules.clear(); rules.forEach(rule => breakpointRules.add(rule)); if (currentRecord) loadDetail(); });
api.on('breakpoint-resolved', id => {
  pendingBreakpoints.delete(id);
  if (activeBreakpoint === id) { activeBreakpoint = null; $('breakpointDialog').close(); }
  showNextBreakpoint();
});

api.on('cleared', () => { records.clear(); selectedDomain = null; selectedApp = null; resetSelection(); render(); });

action(async () => {
  const snapshot = await api.snapshot();
  $('footerVersion').textContent = `v${snapshot.version}`;
  snapshot.records.forEach(record => records.set(record.id, record));
  (snapshot.devices || []).forEach(device => knownDevices.set(device.address, device));
  (snapshot.breakpoints || []).forEach(rule => breakpointRules.add(rule));
  updateState(snapshot.state);
  if (snapshot.notice) notify(snapshot.notice);
  if (snapshot.state.running) $('automaticProxy').checked = snapshot.state.mode === 'automatic';
  const mac = snapshot.platform === 'darwin';
  const windows = snapshot.platform === 'win32';
  const automaticCertificateTrust = mac || windows;
  $('trustCertificate').hidden = !automaticCertificateTrust;
  $('removeCertificate').hidden = !automaticCertificateTrust;
  $('systemGuide').textContent = mac ? 'macOS may ask for administrator permission. Existing proxy settings are restored on Stop.' : 'Windows user proxy settings are updated automatically and restored on Stop.';
  $('trustGuide').textContent = mac ? 'Install & Trust adds the CA to your login keychain with SSL trust. System-wide automatic installation requires a signed privileged helper.' : windows ? 'Install & Trust adds the CA to your Current User Trusted Root Certification Authorities store. Windows may show a security confirmation.' : 'Install the exported CA in your system or browser trust store, then restart the browser.';
  await refreshCertificateStatus();
  render();
});
