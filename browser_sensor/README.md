# Endpoint Browser Sensor source

One Manifest V3 source tree serves Google Chrome and Yandex Browser. The worker sends bounded metadata only to the fixed local Native Messaging host `ru.sosnadmin.endpoint.browser`; it has no Endpoint server credential or network client.

Run `npm test --prefix browser_sensor` from the repository root. The tests require Node.js and no package installation.

Version 0.1 observes active HTTP(S) origin/domain, file-input selection metadata, and paste MIME categories. It does not read file names, clipboard values, page text, titles, cookies or browser history. File-input selection does not cover every upload mechanism, including drag/drop and custom JavaScript transfers.

The worker asks `chrome.management.getSelf()` for its own `installType` and sends only that bounded value in heartbeat. [Chrome documents](https://developer.chrome.com/docs/extensions/reference/api/management) that `getSelf()` needs no `management` manifest permission; the manifest keeps that broad permission absent. If the API is unavailable, rejects, or returns a different extension ID, the Agent reports `unknown`. Server compliance requires `admin` for a live managed Browser Sensor. This is browser-side evidence of administrative installation, not proof of the exact policy source or update URL; inspect each browser's effective policy page during Windows acceptance. Yandex support for this signal still requires installed-browser verification.

The public extension ID is pinned in `extension-id.txt`. The signing key is kept in protected operator storage outside Git. Losing or changing that key changes the extension ID and breaks the installed release lineage.

On a clean committed source tree, build a signed CRX with Chrome's packer:

```powershell
$KeyPath = 'C:\protected-location\signing-key.pem'
$OutputDir = 'C:\release-output\browser-sensor'
python -m pip install -r requirements/browser-sensor-release.txt
python -m browser_sensor.tools.build_release `
  --key-path $KeyPath `
  --chrome-path 'C:\Program Files\Google\Chrome\Application\chrome.exe' `
  --output-dir $OutputDir `
  --minimum-agent-version 3.2.68
```

The builder verifies the key against the pinned ID, packages only the four extension source files, adds the approved HTTPS `update_url`, invokes Chrome, verifies the CRX3 signature and ZIP payload, and writes `sensor.crx`, `update.xml`, and `release.json` into an immutable version directory. It rejects dirty Browser Sensor source and an existing version directory. The URL in `update.xml` matches the Endpoint HTTPS artifact route; this build step alone does not publish the release or establish browser installation. Select `--minimum-agent-version` from the verified Agent release, rather than relying on the example value above.

After the server migration and deployment, follow `docs/runbooks/browser-sensor-release.md` to validate and register the candidate without copying the signing key to the server. Registration makes the fixed HTTPS update/CRX/metadata routes available; managed-browser installation remains a separate acceptance gate.

Chrome's [current CRX creator](https://chromium.googlesource.com/chromium/src/+/lkgr/components/crx_file/crx_creator.cc) and [verifier](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/crx_file/crx_verifier.cc) use RSA PKCS#1 SHA-256 for this proof. The release verifier follows that implementation and checks the actual package produced by installed Chrome.
