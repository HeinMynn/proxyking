const fs = require('node:fs/promises');
const path = require('node:path');
const { normalizeDoNotInspectRules, normalizeHostRules, normalizeAppRules } = require('./do-not-inspect');

const defaults = Object.freeze({ doNotInspect: [], excludeInspectApps: [], excludeCaptureHosts: [], excludeCaptureApps: [] });

function normalizeSettings(value = {}) {
  return {
    doNotInspect: normalizeDoNotInspectRules(value.doNotInspect),
    excludeInspectApps: normalizeAppRules(value.excludeInspectApps),
    excludeCaptureHosts: normalizeHostRules(value.excludeCaptureHosts, 'Capture exclusions'),
    excludeCaptureApps: normalizeAppRules(value.excludeCaptureApps)
  };
}

class SettingsStore {
  constructor(directory) {
    this.file = path.join(directory, 'settings.json');
    this.value = { ...defaults };
  }

  async load() {
    try {
      const saved = JSON.parse(await fs.readFile(this.file, 'utf8'));
      this.value = normalizeSettings(saved);
    } catch (error) {
      if (error.code !== 'ENOENT' && !(error instanceof SyntaxError)) throw error;
    }
    return this.get();
  }

  get() {
    return {
      doNotInspect: [...this.value.doNotInspect],
      excludeInspectApps: [...this.value.excludeInspectApps],
      excludeCaptureHosts: [...this.value.excludeCaptureHosts],
      excludeCaptureApps: [...this.value.excludeCaptureApps]
    };
  }

  async update(next) {
    if (!next || typeof next !== 'object' || !Array.isArray(next.doNotInspect) || !Array.isArray(next.excludeInspectApps) || !Array.isArray(next.excludeCaptureHosts) || !Array.isArray(next.excludeCaptureApps)) throw new Error('Invalid settings.');
    this.value = normalizeSettings(next);
    await fs.mkdir(path.dirname(this.file), { recursive: true });
    const temporary = `${this.file}.tmp`;
    await fs.writeFile(temporary, JSON.stringify(this.value, null, 2), { mode: 0o600 });
    await fs.rename(temporary, this.file);
    return this.get();
  }
}

module.exports = { SettingsStore };
