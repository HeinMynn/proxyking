const fs = require('node:fs');
const path = require('node:path');

const files = [
  path.join(__dirname, '..', 'node_modules', 'http-mitm-proxy', 'dist', 'lib', 'proxy.js'),
  path.join(__dirname, '..', 'node_modules', 'http-mitm-proxy', 'lib', 'proxy.ts')
];

for (const file of files) {
  if (!fs.existsSync(file)) throw new Error(`http-mitm-proxy file is missing: ${file}`);
  const source = fs.readFileSync(file, 'utf8');
  const indent = file.endsWith('.ts') ? '          ' : '                ';
  const original = `${indent}host: "0.0.0.0",\n${indent}allowHalfOpen: true,`;
  const replacement = `${indent}host: self.httpHost === "0.0.0.0" ? "127.0.0.1" : self.httpHost,\n${indent}allowHalfOpen: true,`;
  if (source.includes(replacement)) continue;
  if (!source.includes(original)) throw new Error(`Expected HTTPS tunnel code was not found in ${file}`);
  fs.writeFileSync(file, source.replace(original, replacement));
}

console.log('Patched http-mitm-proxy internal HTTPS connection address.');
