# Proxyking

A Windows and macOS desktop HTTP/HTTPS capture app built with Electron. The current milestone includes a real local interception proxy, live traffic inspection, remote-device setup for Android and iOS, certificate trust management, and full-session or individual-request HAR export.

## Run

Install Node.js 22 or newer, then:

```sh
npm ci
npm start
```

1. Click **Start** in the header. Proxyking detects the private IPv4 address on the active network route (for example, `192.168.1.42`) and uses port `8080` by default. The port is configurable in **Connection setup**.
2. Browse normally in a browser that uses your system proxy, such as Chrome or Edge. On macOS, approve the OS administrator prompt when asked. The listener binds to the private network address shown in the header.
3. For HTTPS, export **Proxyking CA** and install/trust it as described below.
4. Send requests from the configured app. Select a request to view its headers and body.
5. Click **Stop capture** or close Proxyking. Your previous system proxy settings are restored before the listener shuts down.

### Automatic setup and recovery

- Windows uses the current user's default/LAN connection settings through WinINet. It saves and restores proxy and automatic-discovery flags, while keeping your bypass rules and PAC URL. WinHTTP services and separate VPN/dial-up proxy configurations are not changed.
- macOS configures HTTP and HTTPS proxies for enabled network services and temporarily disables their PAC/discovery settings. macOS may request administrator authorization both when starting and when restoring. Authenticated HTTP/HTTPS proxies require manual mode because their saved passwords cannot be safely reconstructed with `networksetup`.
- Before changing anything, Proxyking saves a recovery record in its user-data directory. After a crash or forced termination, **reopen Proxyking** to restore previous settings. Recovery does not run while the app is closed. A **Restore proxy settings** button appears if startup recovery needs to be retried.
- If restoration fails, Proxyking keeps the listener and window open and retains the recovery record. Retry stopping capture after resolving the permission or policy issue.
- A proxy endpoint selected by another app during capture is preserved instead of blindly overwritten. Corporate upstream proxy chaining is not implemented; use manual mode when your app requires an existing upstream proxy.
- Turn off **Configure system proxy automatically** in Connection setup to use manual mode. Then set your app's HTTP/HTTPS proxy to the exact address shown in the header, such as `192.168.1.42:8080`, and remove that configuration when finished. Apps with independent proxy settings, such as Firefox configurations, may need to select **Use system proxy settings**.
- The header Start/Pause button controls recording without discarding the list. Pause keeps the listener and system proxy active so traffic continues to flow without being recorded. Stop restores the previous proxy settings and shuts down the listener. Clear removes captured entries. New restores the current proxy settings, clears the list, detects the active LAN address again, and starts a fresh session.
- The sidebar groups traffic by app, remote device, and registrable domain. Remote devices are identified by client IP when they connect through Proxyking; traffic from the computer running Proxyking remains under **All connections**. Subdomains such as `docs.google.com` and `drive.google.com` are grouped under `google.com`. App names are inferred from HTTP client headers (for example Edge, Chrome, Firefox, Postman, curl, and common SDKs); clients without an identifying header appear under **Unknown app**.
- The separate **Settings** page provides persistent **Do Not Inspect** rules. Enter exact hostnames, wildcard domains such as `*.telegram.org`, or IP addresses. Matching HTTPS connections skip interception immediately, remain encrypted, and appear as `TUNNEL` records.
- Proxyking binds only to the selected private interface address, rather than every adapter. Other devices on that LAN may still be able to reach it while capture runs if the operating-system firewall permits the connection.

For a quick HTTP check on Windows (use `curl` on macOS):

```powershell
curl.exe --proxy http://192.168.1.42:8080 http://example.com
```

For HTTPS without installing the CA system-wide, export it and pass its location explicitly:

```powershell
curl.exe --proxy http://192.168.1.42:8080 --cacert Proxyking-CA.crt https://example.com
```

## Advanced filters

Open **Filters** above the connection list to filter or highlight traffic as it arrives. Conditions can inspect connection metadata, app or remote-device identity, request method/query/headers/body, and response status/headers/body. Text operators include contains, exact matching, prefixes, suffixes, existence checks, and regular expressions; sizes, durations, and status codes support numeric comparisons.

**AND** adds a required condition to the current group. **OR** starts an alternative group, so the editor can express rules such as `(method is POST AND status is 201) OR (domain is example.com AND response body contains success)`. A filter may contain up to ten conditions. Incomplete or invalid rows are ignored while you edit, and results update immediately without an Apply button.

Choose **Filter + highlight**, **Filter only**, or **Highlight only**. Positive text matches are marked in the selected connection's headers, query, body, and raw views. Named filter presets are saved locally in the desktop app.

## Replay and breakpoints

Select a completed inspected request and click **Replay** to edit its method, URL, headers, or text body and send it again from the desktop. The replay appears as a new connection. Replaying a state-changing request can repeat a real action; inspect the URL and body before sending. Truncated, binary, or compressed request bodies are not offered for replay.

Select a connection and enable **Request BP** or **Response BP** to pause future traffic for that exact host. When a text body is intercepted, Proxyking opens an editor. **Continue original** sends the unmodified body; **Send edited body** substitutes your text. Breakpoints are limited to 1 MiB and automatically continue unchanged after two minutes or when capture stops. Compressed and non-text bodies pass through without a breakpoint. Rules last until the app exits.

## Android and iOS setup

Start Proxyking, then select **Mobile setup** in the sidebar. Scan the QR code from a phone or tablet on the same Wi-Fi network. The local setup page at `http://<proxy-ip>:<port>/setup` provides:

- the Wi-Fi proxy server and port;
- platform-specific Android and iOS instructions;
- a download of the public **Proxyking Local CA**;
- an automatic local HTTPS verification at `https://proxyking.test/verify` while the setup page is open, with a manual fallback button.

Proxyking also marks a device verified when it successfully inspects that device's first HTTPS request. A successful verification means that the device accepted a certificate issued by Proxyking Local CA. The Remote Devices sidebar then shows a green trust indicator for that client IP. Setup and verification requests are handled locally and are not added to the capture list.

Proxy and CA installation still require confirmation in Android or iOS settings. Many Android applications do not trust user-installed CAs unless their developer opts in through Network Security Configuration. Certificate-pinned applications can still reject interception.

## Certificate setup

Each installation generates its own **Proxyking Local CA**, valid for one year. Only the public certificate is exported. The private key stays in the Electron user-data directory (`%APPDATA%/Proxyking/certificates` on Windows, `~/Library/Application Support/Proxyking/certificates` on macOS; actual directory casing follows Electron's app name).

**Windows:** Click **Install & Trust CA** to add the public CA to the current user's Trusted Root Certification Authorities store; Windows may show a security confirmation. Use **Revoke & Remove CA** to delete the exact matching certificate. Alternatively, export the `.crt` and install it manually for Current User. Automatic mode handles your proxy settings; manual settings are in Settings → Network & internet → Proxy → Manual proxy setup.

**macOS:** Click **Install & Trust CA** to add the public CA to your login keychain with SSL trust. Use **Revoke & Remove CA** to remove the exact matching CA and its user trust settings. Alternatively, export the `.crt`, import it with Keychain Access, open **Proxyking Local CA**, expand Trust, and set Secure Sockets Layer (SSL) to Always Trust. System-wide one-click installation or removal requires a separately signed privileged helper and is not part of the current development build. Automatic mode handles Web Proxy (HTTP) and Secure Web Proxy (HTTPS); manual settings are in System Settings → Network → your connection → Details → Proxies.

Some browsers and runtimes use separate trust stores. Certificate-pinned apps need an appropriate debug configuration; installing a root certificate does not universally bypass pinning. Upstream TLS certificates remain validated.

Restart browsers and other apps after trusting the CA. If iOS shows **This Connection Is Not Private** for `proxyking.test`, first confirm that **Proxyking Local CA** is enabled under Settings → General → About → Certificate Trust Settings, then restart Proxyking so cached host certificates are regenerated. `SSLV3_ALERT_CERTIFICATE_UNKNOWN` means that client rejected Proxyking's generated site certificate: its process may not have reloaded the trust store, may use its own trust store, or may pin the server certificate.
After such a rejection, Proxyking learns that host for the current capture session and passes later connections through encrypted. The first attempt can fail before the client retries; pass-through entries are labeled `TUNNEL`. Restart capture after fixing certificate trust to try inspection again.

## Scope and limits

- HTTP/1.1 and HTTP/2 capture with HTTPS interception through an explicit proxy. Intercepted HTTP/2 requests are translated through the current HTTP/1.1 upstream pipeline. Apps that ignore the proxy and HTTP/3/QUIC traffic are not captured.
- TLS clients that offer only a private or unsupported ALPN protocol are passed through encrypted so the application keeps working. They appear as `TUNNEL` entries and their contents cannot be inspected.
- Requests remain in memory until Clear, New, or application exit. Up to 128 KiB is retained per request/response body preview; the full payload is forwarded. Compressed previews are decoded within the same bound; binary bodies use base64.
- Sessions are not persisted unless exported. HAR files contain captured headers, cookies, and payloads, including any credentials in them. Truncation is marked with custom HAR fields. Timing is total elapsed time, not a DNS/TLS phase breakdown.
- WebSocket frame inspection, native mobile apps, and pinning bypass are not implemented. Android and iOS devices can use the desktop proxy through the local setup assistant.
- Certificate trust can be installed and removed automatically for the current user on Windows and macOS. Linux remains manual. Do not share the private CA key. Certificates are not automatically renewed; remove the trusted CA and regenerate local certificate data when it expires.
- Closing the app restores settings changed by automatic mode before stopping its listener. Restore manually configured app proxy settings yourself.

## Test and package

```sh
npm test
npm run test:desktop
npm run pack
npm run dist:win
```

Build the macOS artifact **on a Mac**:

```sh
npm ci
npm test
npm run dist:mac
```

The desktop smoke test launches a real Electron window with an isolated temporary profile and a local fixture server. It replaces the OS adapter with a simulation through the test debugger before capture starts, verifies restoration on stop and exit, and does not change system trust or live proxy settings. Unit tests cover journal recovery, partial failures, concurrent settings changes, Windows/macOS adapters with simulated writes, and a read-only native Windows query. Screenshots are saved to `artifacts/`.

The macOS adapter still requires verification on macOS hardware. The current development environment is Windows; native proxy writes are not exercised by the automated suite on this host.

Outputs go to `release/`. Local packages are unsigned development builds. Public distribution requires platform signing identities and macOS notarization. The included manual GitHub Actions workflow builds Windows and macOS artifacts without publishing them.

## Layout

- `src/engine.js`: reusable capture engine and HAR export.
- `src/network.js`: active-route private IPv4 detection.
- `src/certificate.js`: local CA generation.
- `src/device-setup.js`: local Android/iOS onboarding page and HTTPS trust verification.
- `src/system-proxy/`: Windows/macOS proxy adapters and durable restoration journal.
- `src/capture-session.js`: serialized start/stop and proxy restoration lifecycle.
- `src/main.js`, `src/preload.js`: Electron lifecycle and restricted IPC bridge.
- `src/ui/`: local interface; captured content is rendered as text, never HTML.
- `test/`: local HTTP/TLS integration tests.

The renderer runs sandboxed, without Node access, with a restrictive content security policy. The proxy binds to the selected private IPv4 interface and requires explicit certificate trust for HTTPS inspection.
