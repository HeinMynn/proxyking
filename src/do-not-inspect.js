const net = require('node:net');

const MAX_RULES = 500;

function normalizeHostRules(input, label = 'Host exclusions') {
  const values = Array.isArray(input) ? input : String(input || '').split(/\r?\n/);
  if (values.length > MAX_RULES) throw new Error(`${label} supports up to ${MAX_RULES} rules.`);
  const rules = [];
  for (const value of values) {
    const rule = String(value).trim().toLowerCase().replace(/\.$/, '');
    if (!rule || rule.startsWith('#')) continue;
    const wildcard = rule.startsWith('*.');
    let hostname = wildcard ? rule.slice(2) : rule;
    if (hostname.startsWith('[') || hostname.endsWith(']')) {
      if (wildcard || !hostname.startsWith('[') || !hostname.endsWith(']')) throw new Error(`Invalid ${label} host: ${value}`);
      hostname = hostname.slice(1, -1);
    }
    const ipVersion = net.isIP(hostname);
    if (!hostname || hostname.length > 253 || wildcard && ipVersion ||
        (!ipVersion && (/[^a-z0-9.-]/.test(hostname) || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(hostname)))) {
      throw new Error(`Invalid ${label} host: ${value}`);
    }
    const normalized = wildcard ? `*.${hostname}` : hostname;
    if (!rules.includes(normalized)) rules.push(normalized);
  }
  return rules;
}

function normalizeDoNotInspectRules(input) { return normalizeHostRules(input, 'Exclude'); }

function normalizeAppRules(input) {
  const values = Array.isArray(input) ? input : String(input || '').split(/\r?\n/);
  if (values.length > MAX_RULES) throw new Error(`App exclusions support up to ${MAX_RULES} rules.`);
  const rules = [];
  for (const value of values) {
    const rule = String(value).trim();
    if (!rule || rule.startsWith('#')) continue;
    if (rule.length > 80 || /[\r\n]/.test(rule)) throw new Error(`Invalid excluded app name: ${value}`);
    if (!rules.some(existing => existing.toLowerCase() === rule.toLowerCase())) rules.push(rule);
  }
  return rules;
}

function matchesDoNotInspect(hostname, rules) {
  const host = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  return rules.some(rule => rule.startsWith('*.')
    ? host === rule.slice(2) || host.endsWith(`.${rule.slice(2)}`)
    : host === rule);
}

module.exports = { normalizeHostRules, normalizeDoNotInspectRules, normalizeAppRules, matchesDoNotInspect, MAX_RULES };
