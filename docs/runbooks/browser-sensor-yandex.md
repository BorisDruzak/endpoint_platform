# Browser Sensor: Yandex Browser managed installation

Yandex Browser uses the same signed Browser Sensor source, public extension ID
and native messaging protocol as Chrome. The approved ID is
`kkkoaifoohdbdaccmnnoagedifflbide`; the update endpoint is
`https://endpoint.sosnadmin.local/api/v1/browser-sensor/update.xml`.

## Agent-managed pilot

The MSI-owned `EndpointBrowserPolicy` service adds one numbered REG_SZ value
under HKLM `SOFTWARE\Policies\YandexBrowser\ExtensionInstallForcelist`:

```text
1 = kkkoaifoohdbdaccmnnoagedifflbide;https://endpoint.sosnadmin.local/api/v1/browser-sensor/update.xml
```

It chooses the first free numbered slot, preserving foreign entries. The
number shown above is an example, not a reserved slot. It records ownership
outside the browser policy key and rejects a pre-existing unowned Endpoint ID,
malformed values, a conflicting root `ExtensionInstallForcelist` or
`ExtensionSettings` value, and a changed owned slot. Reapplication is a no-op.
On `external_managed` hand-off, it deletes only its exact owned slot and
marker. Existing corporate entries remain in place.

Yandex documents both [numbered Windows registry list
values](https://browser.yandex.ru/support/browser-corporate/ru/deployment/windows/setting-policy)
and [the `extension_id;update_url` force-install
format](https://browser.yandex.ru/support/browser-corporate/ru/policy/extension-install-forcelist).
The force-install policy has domain/management-console conditions on Windows;
verify it is effective on the actual managed browser. A registry write by
itself is not acceptance.

## External-managed deployment

GPO, Ansible or another corporate owner supplies the same ID and update URL.
The Agent only checks the Bridge, accepts heartbeat and reports the observed
state. The MSI must register its own native host for Yandex without changing
unrelated hosts. Foundation v1 must not set a global
`NativeMessagingBlocklist = *` automatically; the Yandex native-host
registration path and effective browser handshake remain a live gate.

## Verification

1. Record existing Yandex policies and native hosts on the test Device.
2. Begin with the Endpoint extension absent; assign `agent_managed`.
3. Open `browser://policy`, reload policies and verify the exact Endpoint ID,
   update URL, source and absence of policy errors.
4. Restart Yandex Browser; confirm it downloads the same signed CRX, connects
   to EndpointBrowserBridge, reaches the Agent and appears ACTIVE in Console.
5. Reapply policy, restart Browser and Agent, upgrade Agent, then switch to
   `external_managed`. Confirm no foreign policy/native host is removed.

The [Yandex policy documentation](https://browser.yandex.ru/support/browser-corporate/ru/policy/extension-install-forcelist)
is the mechanism reference. The installed browser's effective policy and
end-to-end heartbeat are the acceptance evidence.
