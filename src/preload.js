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
  copyText: text => ipcRenderer.invoke('capture:copy-text', text),
  certificate: () => ipcRenderer.invoke('capture:certificate'),
  trustCertificate: () => ipcRenderer.invoke('capture:trust-certificate'),
  certificateStatus: () => ipcRenderer.invoke('capture:certificate-status'),
  removeCertificate: () => ipcRenderer.invoke('capture:remove-certificate'),
  export: id => ipcRenderer.invoke('capture:export', id),
  on: (name, callback) => {
    if (!['record', 'state', 'notice', 'cleared'].includes(name)) return;
    const listener = (_event, value) => callback(value);
    ipcRenderer.on(`capture:${name}`, listener);
    return () => ipcRenderer.removeListener(`capture:${name}`, listener);
  }
});
