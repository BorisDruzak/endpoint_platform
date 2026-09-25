# Browser Sensor: Yandex Browser managed installation

Yandex Browser uses the same signed Browser Sensor release as Chrome. The
extension ID is `kkkoaifoohdbdaccmnnoagedifflbide`; its update URL is
`https://endpoint.sosnadmin.local/api/v1/browser-sensor/update.xml`.

## Agent-managed policy

The MSI-owned `EndpointBrowserPolicy` service writes a JSON LIST file at
`C:\Program Files\Endpoint Platform\Agent\yandex-forcelist.json`:

```json
["kkkoaifoohdbdaccmnnoagedifflbide;https://endpoint.sosnadmin.local/api/v1/browser-sensor/update.xml"]
```

The root `REG_SZ` value
`HKLM\SOFTWARE\Policies\YandexBrowser\ExtensionInstallForcelist` points to it:

```json
[{"_FILE_":{"name":"C:/Program Files/Endpoint Platform/Agent/yandex-forcelist.json"}}]
```

The file inherits the Program Files ACL, allowing browser users to read it.
The helper owns only its exact pointer, file, and marker. It migrates a sole
legacy Agent-owned numbered entry. Foreign numbered entries or an unowned root
policy cause `POLICY_CONFLICT`: Yandex Browser blocks a combined root file
pointer and numbered entry. Relinquish removes only the owned values.

The file reference is documented by [Yandex's policy-in-file
guide](https://browser.yandex.ru/support/browser-corporate/ru/settings/policy-in-file-config).
On Windows, Yandex says [ExtensionInstallForcelist works only inside a domain
or through the management
console](https://browser.yandex.ru/support/browser-corporate/ru/policy/extension-install-forcelist).
On the WORKGROUP test VM with Yandex Browser 26.8.0.1774 corp, the file policy
showed `OK` and downloaded Sensor 0.1.0, but the extension remained **off**.
The bridge and heartbeat were not observed. A correct registry policy and an
installed CRX do not prove an active Sensor on that machine.

## External-managed deployment

GPO, Ansible, or another corporate owner supplies the same ID and update URL.
The Agent checks the Bridge and accepts heartbeat. The MSI registers the host at
`HKLM\Software\Chromium\NativeMessagingHosts\ru.sosnadmin.endpoint.browser`,
pointing to a fixed-origin manifest beside `EndpointBrowserBridge.exe`. The
installed Yandex binary contains this lookup path, but a live Native Messaging
handshake remains required evidence.

## Verification

1. Record existing Yandex policies and native hosts on the test device.
2. Confirm the browser's domain or management-console state before assigning
   `agent_managed`.
3. Check the exact file pointer and LIST content, then reload `browser://policy`.
   Require mandatory machine scope, `OK`, and no competing numbered value.
4. Use a fresh browser profile to check the XML/CRX requests, installed version,
   **enabled** state, Native Messaging launch, Agent receipt, and heartbeat.
5. Reapply, restart, upgrade, and relinquish the policy. Confirm that foreign
   policy, the native host, and other extensions remain intact.

The [test VM diagnostic](../verification/yandex-browser-sensor-diagnostics-2026-09-25.md)
records the observed limitation. Treat `browser://policy` status and filesystem
installation as intermediate checks; the enabled state and heartbeat are the
acceptance gate.
