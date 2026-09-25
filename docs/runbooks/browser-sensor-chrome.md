# Browser Sensor: Chrome managed installation

The Endpoint Browser Sensor uses the public extension ID in
`browser_sensor/extension-id.txt` and the fixed update endpoint
`https://endpoint.sosnadmin.local/api/v1/browser-sensor/update.xml`. The
signing private key is never installed on an endpoint.

## Agent-managed pilot

For `browser_sensor.deployment_mode = agent_managed`, the LocalService Agent
sends a typed request to the MSI-owned `EndpointBrowserPolicy` LocalSystem
service. The helper checks the Agent service SID for every request. It writes
only the Endpoint entry in HKLM
`SOFTWARE\Policies\Google\Chrome\ExtensionSettings` and its own ownership
marker under `SOFTWARE\Endpoint Platform\Agent\BrowserPolicy`. The entry is:

```json
{
  "kkkoaifoohdbdaccmnnoagedifflbide": {
    "installation_mode": "force_installed",
    "update_url": "https://endpoint.sosnadmin.local/api/v1/browser-sensor/update.xml"
  }
}
```

The helper does not replace an existing unowned `ExtensionSettings` value. It
reports `POLICY_CONFLICT` so the existing GPO/cloud owner can be identified.
If it owns the entry, reapplying the same policy performs no write. On a switch
to `external_managed`, it removes only its exact, unchanged entry and marker;
it preserves other extension settings. A changed Endpoint entry remains in
place and is reported as a conflict for operator review.

## External-managed deployment

GPO or another enterprise manager owns the force-install value. The Agent
does not write installation policy after safe hand-off. Use the same extension
ID and HTTPS update URL. Register the MSI-owned native host
`ru.sosnadmin.endpoint.browser` with the manifest that allows only this
extension origin. Do not set a global `NativeMessagingBlocklist = *` during
Foundation v1; preserve other corporate hosts.

## Verification

1. Confirm the endpoint CA and DNS resolve the HTTPS update endpoint with
   normal certificate validation.
2. Record existing Chrome policies and native hosts before assigning the pilot
   policy.
3. Start with the extension absent. Assign `agent_managed` to one test Device.
4. Open `chrome://policy`, reload policies and confirm the Endpoint ID has
   `force_installed` and the approved update URL. Check any policy errors.
5. Restart Chrome and inspect `chrome://extensions` for the same ID. Confirm
   Bridge handshake, Agent heartbeat and Console status separately; a registry
   value alone is not installation proof.
6. Reapply the policy and restart Agent, then switch to `external_managed`.
   Compare foreign extension and native-host entries before and after.

Chrome's [ExtensionSettings policy](https://support.google.com/chrome/a/answer/9867568?hl=en)
documents `force_installed` and `update_url`. The browser's effective policy
page, not the registry alone, is the live acceptance source.
