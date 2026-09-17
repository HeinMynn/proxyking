const fs = require('node:fs');
const path = require('node:path');

const files = [
  path.join(__dirname, '..', 'node_modules', 'http-mitm-proxy', 'dist', 'lib', 'proxy.js'),
  path.join(__dirname, '..', 'node_modules', 'http-mitm-proxy', 'lib', 'proxy.ts')
];

let patchedFiles = 0;
for (const file of files) {
  if (!fs.existsSync(file)) throw new Error(`http-mitm-proxy file is missing: ${file}`);
  let source = fs.readFileSync(file, 'utf8');
  let changed = false;
  const indent = file.endsWith('.ts') ? '          ' : '                ';
  const original = `${indent}host: "0.0.0.0",\n${indent}allowHalfOpen: true,`;
  const replacement = `${indent}host: self.httpHost === "0.0.0.0" ? "127.0.0.1" : self.httpHost,\n${indent}allowHalfOpen: true,`;
  if (!source.includes(replacement)) {
    if (!source.includes(original)) throw new Error(`Expected HTTPS tunnel code was not found in ${file}`);
    source = source.replace(original, replacement); changed = true;
  }
  const noisy = file.endsWith('.ts')
    ? `          socket.on("error", (err) => {\n            console.error("Socket error:");\n            console.error(err);\n          });`
    : `                socket.on("error", (err) => {\n                    console.error("Socket error:");\n                    console.error(err);\n                });`;
  const quiet = file.endsWith('.ts')
    ? `          socket.on("error", self._onSocketError.bind(self, "CLIENT_TO_PROXY_SOCKET"));`
    : `                socket.on("error", self._onSocketError.bind(self, "CLIENT_TO_PROXY_SOCKET"));`;
  if (!source.includes(quiet)) {
    if (!source.includes(noisy)) throw new Error(`Expected client socket error handler was not found in ${file}`);
    source = source.replace(noisy, quiet); changed = true;
  }
  const noisyConnection = file.endsWith('.ts')
    ? `          conn.on("error", (err) => {\n            console.error("Connection error:");\n            console.error(err);\n            conn.destroy();\n          });`
    : `                conn.on("error", (err) => {\n                    console.error("Connection error:");\n                    console.error(err);\n                    conn.destroy();\n                });`;
  const quietConnection = file.endsWith('.ts')
    ? `          conn.on("error", () => conn.destroy());`
    : `                conn.on("error", () => conn.destroy());`;
  if (!source.includes(quietConnection)) {
    if (!source.includes(noisyConnection)) throw new Error(`Expected internal connection error handler was not found in ${file}`);
    source = source.replace(noisyConnection, quietConnection); changed = true;
  }
  if (changed) {
    fs.writeFileSync(file, source);
    patchedFiles++;
  }
}

console.log(patchedFiles ? `Patched http-mitm-proxy in ${patchedFiles} file(s).` : 'http-mitm-proxy patches already applied.');
