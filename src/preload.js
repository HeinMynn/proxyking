const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('proxyking', {
  snapshot: () => ipcRenderer.invoke('capture:snapshot'),
  start: (port, automatic = true) => ipcRenderer.invoke('capture:start', port, automatic),
  pause: () => ipcRenderer.invoke('capture:pause'),
  resume: () => ipcRenderer.invoke('capture:resume'),
  stop: () => ipcRenderer.invoke('capture:stop'),
  recover: () => ipcRenderer.invoke('capture:recover'),
  clear: () => ipcRenderer.invoke('capture:clear'),
  detail: id => ipcRenderer.invoke('capture:detail', id),
  replay: (id, draft) => ipcRenderer.invoke('capture:replay', id, draft),
  setBreakpoint: (host, side, enabled) => ipcRenderer.invoke('capture:set-breakpoint', host, side, enabled),
  resolveBreakpoint: (id, decision) => ipcRenderer.invoke('capture:resolve-breakpoint', id, decision),
  copyText: text => ipcRenderer.invoke('capture:copy-text', text),
  deviceSetup: () => ipcRenderer.invoke('capture:device-setup'),
  certificate: () => ipcRenderer.invoke('capture:certificate'),
  trustCertificate: () => ipcRenderer.invoke('capture:trust-certificate'),
  certificateStatus: () => ipcRenderer.invoke('capture:certificate-status'),
  removeCertificate: () => ipcRenderer.invoke('capture:remove-certificate'),
  export: id => ipcRenderer.invoke('capture:export', id),
  on: (name, callback) => {
    if (!['record', 'device', 'state', 'notice', 'cleared', 'breakpoint', 'breakpoint-rules', 'breakpoint-resolved'].includes(name)) return;
    const listener = (_event, value) => callback(value);
    ipcRenderer.on(`capture:${name}`, listener);
    return () => ipcRenderer.removeListener(`capture:${name}`, listener);
  }
});
