const test = require('node:test');
const assert = require('node:assert/strict');
const filters = require('../src/ui/advanced-filter');

const record = {
  url: 'https://api.example.com/v2/users?role=admin',
  domain: 'example.com',
  host: 'api.example.com',
  path: '/v2/users?role=admin',
  method: 'POST',
  secure: true,
  state: 'complete',
  status: 201,
  duration: 145,
  requestSize: 42,
  size: 120,
  application: 'Chrome',
  remoteDevice: 'iPhone',
  filterData: {
    query: 'role=admin',
    requestHeaders: { 'content-type': 'application/json', authorization: 'Bearer token' },
    requestBody: '{"name":"Ada"}',
    requestContentType: 'application/json',
    responseHeaders: { 'content-type': 'application/json' },
    responseBody: '{"id":7,"name":"Ada"}',
    responseContentType: 'application/json'
  }
};

const condition = (key, operator, value = '') => ({ key, operator, value });

test('advanced filters use AND within groups and OR between groups', () => {
  const groups = [
    [condition('method', 'equals', 'GET'), condition('status', 'equals', '200')],
    [condition('domain', 'equals', 'example.com'), condition('status', 'greaterEqual', '200')]
  ];
  assert.equal(filters.matches(record, groups), true);
  groups[1][1].value = '400';
  assert.equal(filters.matches(record, groups), false);
});

test('advanced filters support bodies, headers, regex, numbers, and existence', () => {
  assert.equal(filters.matches(record, [[condition('requestBody', 'contains', 'Ada')]]), true);
  assert.equal(filters.matches(record, [[condition('requestHeaders', 'contains', 'Bearer token')]]), true);
  assert.equal(filters.matches(record, [[condition('responseBody', 'regex', '"id"\\s*:\\s*7')]]), true);
  assert.equal(filters.matches(record, [[condition('duration', 'less', '150')]]), true);
  assert.equal(filters.matches(record, [[condition('device', 'exists')]]), true);
  assert.equal(filters.matches(record, [[condition('replayed', 'equals', 'false')]]), true);
});

test('invalid and unfinished conditions do not hide traffic', () => {
  assert.equal(filters.matches(record, [[condition('url', 'contains', '')]]), true);
  assert.equal(filters.matches(record, [[condition('responseBody', 'regex', '[')]]), true);
  assert.equal(filters.validate(condition('responseBody', 'regex', '[')), 'Invalid regular expression.');
});

test('normalization enforces ten conditions across all groups', () => {
  const groups = [
    Array.from({ length: 7 }, () => condition('url', 'contains', 'a')),
    Array.from({ length: 7 }, () => condition('status', 'equals', '200'))
  ];
  const normalized = filters.normalizeGroups(groups);
  assert.equal(normalized.flat().length, filters.MAX_ROWS);
});

test('highlight matchers only include positive conditions for the active view', () => {
  const groups = [[
    condition('responseBody', 'contains', 'Ada'),
    condition('responseHeaders', 'notContains', 'private'),
    condition('status', 'equals', '201')
  ]];
  assert.deepEqual(filters.highlightMatchers(groups, 'response', 'body'), ['Ada']);
  assert.deepEqual(filters.highlightMatchers(groups, 'request', 'body'), []);
});
