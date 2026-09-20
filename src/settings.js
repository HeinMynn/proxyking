const fs = require('node:fs/promises');
const path = require('node:path');
const { normalizeDoNotInspectRules } = require('./do-not-inspect');

const defaults = Object.freeze({ doNotInspect: [] });

class SettingsStore {
  constructor(directory) {
    this.file = path.join(directory, 'settings.json');
    this.value = { ...defaults };
  }

  async load() {
    try {
      const saved = JSON.parse(await fs.readFile(this.file, 'utf8'));
      this.value = { doNotInspect: normalizeDoNotInspectRules(saved.doNotInspect) };
    } catch (error) {
      if (error.code !== 'ENOENT' && !(error instanceof SyntaxError)) throw error;
    }
    return this.get();
  }

  get() { return { doNotInspect: [...this.value.doNotInspect] }; }

  async update(next) {
    if (!next || typeof next !== 'object' || !Array.isArray(next.doNotInspect)) throw new Error('Invalid settings.');
    this.value = { doNotInspect: normalizeDoNotInspectRules(next.doNotInspect) };
    await fs.mkdir(path.dirname(this.file), { recursive: true });
    const temporary = `${this.file}.tmp`;
    await fs.writeFile(temporary, JSON.stringify(this.value, null, 2), { mode: 0o600 });
    await fs.rename(temporary, this.file);
    return this.get();
  }
}

module.exports = { SettingsStore };
