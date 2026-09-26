# Opera runtime architecture decision — 2026-09-26

Decision: STOP at the architecture gate. NO-GO FOR SUBMISSION.

Operator-confirmed starting revision: `552783744f3476e3f16a9d2d44abf20bc86a69f0`, clean `codex/yandex-browser-sensor-diagnostics`. Opera work branches from this revision, preserving five commits ahead of the local `origin/main` reference `26e1383ff294197bf6d0265d2e9f84e220dcce20`. The initial workspace was a different branch (`codex/endpoint-capability-platform-v2`, `959ba1ca7a5dc6182c9585c90b918c78e11f57f9`) without Browser Sensor. No remote refresh or history rewrite was performed.

GitNexus repository discovery and BrowserHelloV1 context preceded source investigation. The index is at `26e1383`, so it does not represent subsequent local Yandex commits. Its interface/dynamic-dispatch warning makes the graph a lower bound; source confirms the following boundaries.

## Architecture

`browser_sensor/protocol.js` rejects `OPR/` rather than labeling it Chrome. `background.js` therefore does not open the native port or send telemetry in Opera. The content script still observes file selection/paste categories and messages the worker; it has no user authorization gate.

Intended path: extension → `ru.sosnadmin.endpoint.browser` → `pc_agent/platform/windows/browser_bridge.py` → `LocalBrowserEnvelopeV1` → Windows sensor/activity aggregation → Activity/SecurityEvent Agent transport → server ingestion → Console/compliance.

| Boundary | Verified restriction / consequence |
|---|---|
| `pc_agent/browser_protocol.py` | `Family = Literal["chrome", "yandex"]`; Opera hello/context/events fail validation |
| `local_sensor_protocol.py` | Embeds BrowserMessageV1; cannot carry genuine Opera observations |
| `endpoint_contracts/activity.py` | BrowserFamilyV1 rejects Opera; origin validation is shared with native events |
| `endpoint_contracts/security_events.py` | Browser upload/paste family rejects Opera |
| `endpoint_contracts/browser_status.py` | Exactly two status entries, one Chrome and one Yandex |
| `endpoint_server/policy/browser_status.py` | Ingestion/projection assumes those two families |
| `endpoint_server/policy/models.py` and migration `0033_browser_status.py` | Database CHECK restricts browser family to Chrome/Yandex |
| `endpoint_server/policy/compliance.py`, `admin_routes.py` | Family DTOs/compliance and Console projection need deliberate expansion |
| `contracts/jsonschema/*`, canonical OpenAPI | Published schema artifacts need regeneration and compatibility review |

## Options

**A — genuine Opera family support:** add Opera truthfully across extension, native protocol, IPC, activity, events, status discovery, server ingestion/compliance and published schemas. Supporting managed status requires a database migration and policy/Console design. This is a broad Foundation expansion and is outside this task's architecture gate. Do not implement here.

**B — bounded local-only compatibility:** recognizing Opera for a status popup without forwarding telemetry could truthfully report unsupported/unavailable. It cannot satisfy the declared purpose of sending security telemetry to the Agent. A separate local observation sink would change the product and leave ingestion unsupported. Not a submission solution.

**C — current architecture cannot support an honest submission:** selected. Preserve the exclusion and identity; stop candidate implementation. No alias to Chrome, no schema/database changes, no fabricated successful runtime evidence.

## Identity dependencies

Pinned ID: `kkkoaifoohdbdaccmnnoagedifflbide`. Release builder reads `browser_sensor/extension-id.txt`, derives identity from signing key and renders update.xml; registrar verifies this lineage. Windows native manifest allows only this origin. Bridge entry and policy service entry read the same packaged ID; PyInstaller core/bridge/policy specs include it. BrowserProtocolSession verifies hello identity and fixed family; browser policy/status depend on approved release identity. Changing the ID is a separate migration, never a packaging assumption.

## Resumption gate

Before implementation: approve a separate genuine-family contract/migration design, settle user authorization for all deployed browsers, and resolve cross-platform acceptance with Opera. Then tests-first implementation, version 0.2.0 (subject to current history), icons/status UI, deterministic candidate and actual Opera session may proceed. Store identity remains unknown until submission.
