const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { SettingsStore } = require('../src/settings');

test('settings persist normalized Do Not Inspect rules', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'proxyking-settings-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const store = new SettingsStore(directory);
  assert.deepEqual(await store.load(), { doNotInspect: [] });
  assert.deepEqual(await store.update({ doNotInspect: [' *.Telegram.org ', 'api.telegram.org', '*.telegram.org'] }), {
    doNotInspect: ['*.telegram.org', 'api.telegram.org']
  });
  const reloaded = new SettingsStore(directory);
  assert.deepEqual(await reloaded.load(), { doNotInspect: ['*.telegram.org', 'api.telegram.org'] });
});

test('settings reject URLs instead of broadening an exclusion accidentally', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'proxyking-settings-invalid-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const store = new SettingsStore(directory);
  await assert.rejects(store.update({ doNotInspect: ['https://example.com/path'] }), /Invalid Do Not Inspect host/);
});
