(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.ProxykingFilters = api;
})(typeof window !== 'undefined' ? window : globalThis, function () {
  'use strict';

  const MAX_ROWS = 10;
  const FIELD_DEFINITIONS = [
    { group: 'Connection', key: 'url', label: 'URL', type: 'text' },
    { group: 'Connection', key: 'domain', label: 'Domain', type: 'text' },
    { group: 'Connection', key: 'host', label: 'Host', type: 'text' },
    { group: 'Connection', key: 'path', label: 'Path', type: 'text' },
    { group: 'Connection', key: 'protocol', label: 'Protocol', type: 'protocol' },
    { group: 'Connection', key: 'state', label: 'State', type: 'state' },
    { group: 'Connection', key: 'duration', label: 'Duration (ms)', type: 'number' },
    { group: 'Connection', key: 'totalSize', label: 'Total size (bytes)', type: 'number' },
    { group: 'Source', key: 'application', label: 'Application', type: 'text' },
    { group: 'Source', key: 'device', label: 'Remote device', type: 'text' },
    { group: 'Source', key: 'replayed', label: 'Replayed request', type: 'boolean' },
    { group: 'Request', key: 'method', label: 'Method', type: 'method' },
    { group: 'Request', key: 'query', label: 'Query', type: 'text' },
    { group: 'Request', key: 'requestHeaders', label: 'Request headers', type: 'text' },
    { group: 'Request', key: 'requestBody', label: 'Request body', type: 'text' },
    { group: 'Request', key: 'requestContentType', label: 'Request content type', type: 'text' },
    { group: 'Request', key: 'requestSize', label: 'Request size (bytes)', type: 'number' },
    { group: 'Response', key: 'status', label: 'Status', type: 'number' },
    { group: 'Response', key: 'responseHeaders', label: 'Response headers', type: 'text' },
    { group: 'Response', key: 'responseBody', label: 'Response body', type: 'text' },
    { group: 'Response', key: 'responseContentType', label: 'Response content type', type: 'text' },
    { group: 'Response', key: 'responseSize', label: 'Response size (bytes)', type: 'number' }
  ];

  const OPERATORS = {
    text: [
      ['contains', 'Contains'], ['notContains', 'Does not contain'], ['equals', 'Is exactly'],
      ['notEquals', 'Is not'], ['startsWith', 'Starts with'], ['endsWith', 'Ends with'],
      ['regex', 'Matches regex'], ['exists', 'Exists'], ['notExists', 'Does not exist']
    ],
    number: [
      ['equals', 'Is'], ['notEquals', 'Is not'], ['greater', 'Greater than'],
      ['greaterEqual', 'At least'], ['less', 'Less than'], ['lessEqual', 'At most'],
      ['exists', 'Exists'], ['notExists', 'Does not exist']
    ],
    choice: [['equals', 'Is'], ['notEquals', 'Is not']],
    boolean: [['equals', 'Is'], ['notEquals', 'Is not']]
  };

  const CHOICES = {
    method: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'],
    protocol: ['HTTP', 'HTTPS', 'TUNNEL'],
    state: ['pending', 'complete', 'failed'],
    boolean: ['true', 'false']
  };

  const fieldMap = new Map(FIELD_DEFINITIONS.map(field => [field.key, field]));

  function operatorsFor(key) {
    const type = fieldMap.get(key)?.type || 'text';
    return OPERATORS[type === 'number' ? 'number' : type === 'text' ? 'text' : type === 'boolean' ? 'boolean' : 'choice'];
  }

  function choicesFor(key) {
    const type = fieldMap.get(key)?.type;
    return CHOICES[type] || null;
  }

  function headerText(value) {
    if (typeof value === 'string') return value;
    if (!value || typeof value !== 'object') return '';
    return Object.entries(value).map(([name, raw]) => `${name}: ${Array.isArray(raw) ? raw.join(', ') : raw}`).join('\n');
  }

  function fieldValue(record, key) {
    const data = record.filterData || {};
    switch (key) {
      case 'url': return record.url || '';
      case 'domain': return record.domain || '';
      case 'host': return record.host || '';
      case 'path': return record.path || '';
      case 'protocol': return record.tunneled ? 'TUNNEL' : record.secure ? 'HTTPS' : 'HTTP';
      case 'state': return record.state || '';
      case 'duration': return record.duration;
      case 'totalSize': return Number(record.requestSize || 0) + Number(record.size || 0);
      case 'application': return record.application || '';
      case 'device': return record.remoteDevice || '';
      case 'replayed': return !!record.replayOf;
      case 'method': return record.method || '';
      case 'query': return data.query || '';
      case 'requestHeaders': return headerText(data.requestHeaders);
      case 'requestBody': return data.requestBody || '';
      case 'requestContentType': return data.requestContentType || '';
      case 'requestSize': return record.requestSize;
      case 'status': return record.status;
      case 'responseHeaders': return headerText(data.responseHeaders);
      case 'responseBody': return data.responseBody || '';
      case 'responseContentType': return data.responseContentType || record.contentType || '';
      case 'responseSize': return record.size;
      default: return '';
    }
  }

  function isComplete(condition) {
    if (!condition || !fieldMap.has(condition.key)) return false;
    const validOperator = operatorsFor(condition.key).some(([value]) => value === condition.operator);
    if (!validOperator) return false;
    return ['exists', 'notExists'].includes(condition.operator) || String(condition.value ?? '').length > 0;
  }

  function validate(condition) {
    if (!condition?.key) return '';
    if (!isComplete(condition)) return ['exists', 'notExists'].includes(condition.operator) ? '' : 'Enter a value.';
    const field = fieldMap.get(condition.key);
    if (field.type === 'number' && !Number.isFinite(Number(condition.value))) return 'Enter a valid number.';
    if (condition.operator === 'regex') {
      try { new RegExp(condition.value, 'i'); } catch { return 'Invalid regular expression.'; }
    }
    return '';
  }

  function testCondition(record, condition) {
    if (!isComplete(condition) || validate(condition)) return null;
    const field = fieldMap.get(condition.key);
    const actual = fieldValue(record, condition.key);
    const exists = actual !== null && actual !== undefined && String(actual).length > 0;
    if (condition.operator === 'exists') return exists;
    if (condition.operator === 'notExists') return !exists;
    if (field.type === 'number') {
      const left = Number(actual); const right = Number(condition.value);
      if (!Number.isFinite(left) || !Number.isFinite(right)) return false;
      if (condition.operator === 'equals') return left === right;
      if (condition.operator === 'notEquals') return left !== right;
      if (condition.operator === 'greater') return left > right;
      if (condition.operator === 'greaterEqual') return left >= right;
      if (condition.operator === 'less') return left < right;
      if (condition.operator === 'lessEqual') return left <= right;
      return false;
    }
    const left = String(actual).toLowerCase();
    const right = String(condition.value).toLowerCase();
    if (condition.operator === 'contains') return left.includes(right);
    if (condition.operator === 'notContains') return !left.includes(right);
    if (condition.operator === 'equals') return left === right;
    if (condition.operator === 'notEquals') return left !== right;
    if (condition.operator === 'startsWith') return left.startsWith(right);
    if (condition.operator === 'endsWith') return left.endsWith(right);
    if (condition.operator === 'regex') return new RegExp(condition.value, 'i').test(String(actual));
    return false;
  }

  function activeGroups(groups) {
    return (groups || []).map(group => (group || []).filter(condition => isComplete(condition) && !validate(condition))).filter(group => group.length);
  }

  function matches(record, groups) {
    const active = activeGroups(groups);
    if (!active.length) return true;
    return active.some(group => group.every(condition => testCondition(record, condition)));
  }

  function highlightMatchers(groups, side, view) {
    const keys = view === 'body' ? [`${side}Body`] : view === 'headers' ? [`${side}Headers`, `${side}ContentType`] : view === 'query' ? ['query'] : [`${side}Body`, `${side}Headers`, `${side}ContentType`, ...(side === 'request' ? ['query', 'url', 'path'] : [])];
    return activeGroups(groups).flat().filter(condition => keys.includes(condition.key) && !['notContains', 'notEquals', 'notExists', 'exists'].includes(condition.operator)).map(condition => {
      if (condition.operator === 'regex') { try { return new RegExp(condition.value, 'gi'); } catch { return null; } }
      return String(condition.value || '');
    }).filter(Boolean);
  }

  function normalizeGroups(groups) {
    const normalized = [];
    for (const group of Array.isArray(groups) ? groups : []) {
      const rows = [];
      for (const condition of Array.isArray(group) ? group : []) {
        if (normalized.flat().length + rows.length >= MAX_ROWS) break;
        const key = fieldMap.has(condition?.key) ? condition.key : 'url';
        const options = operatorsFor(key);
        const operator = options.some(([value]) => value === condition?.operator) ? condition.operator : options[0][0];
        rows.push({ key, operator, value: String(condition?.value ?? '') });
      }
      if (rows.length) normalized.push(rows);
      if (normalized.flat().length >= MAX_ROWS) break;
    }
    return normalized.length ? normalized : [[{ key: 'url', operator: 'contains', value: '' }]];
  }

  return { MAX_ROWS, FIELD_DEFINITIONS, operatorsFor, choicesFor, fieldValue, isComplete, validate, matches, highlightMatchers, normalizeGroups };
});
