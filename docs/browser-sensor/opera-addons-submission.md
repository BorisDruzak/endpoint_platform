# Opera Add-ons metadata — blocked draft

Status: NO-GO. Do not upload this description against current 0.1.0 source: its intended Opera function is not implemented. Proposed version 0.2.0 is reserved in this plan only; source/package versions remain 0.1.0 because the architecture STOP gate fired.

Name: Endpoint Browser Sensor

Summary: Enterprise browser security sensor that sends bounded activity metadata to a locally installed Endpoint Agent.

Description (for a future verified candidate):

Endpoint Browser Sensor is intended for organization-managed Windows endpoints with a supported local Endpoint Agent. It observes active HTTP(S) domain/origin, file-input selection count, total size and coarse file type categories, and paste type categories. In the background it sends bounded metadata and heartbeat messages through Native Messaging to the local Endpoint Agent. File selection does not establish that an upload completed, and custom upload mechanisms are not all covered.

The planned toolbar status panel shows browser family, extension version and verified local Agent availability, together with the collection boundaries. It has no administration controls. The status panel is not present in current 0.1.0 and must be implemented and tested before using this text.

The sensor does not collect page contents, URL paths/query/fragments, filenames/file contents, clipboard contents, passwords or screenshots. It has no direct extension-to-cloud client. The local Agent can forward observations to the organization's Endpoint server; consult the organization's privacy/retention policy. Authorization must be resolved before collection is offered for store distribution.

Category: Productivity — closest factual category from Opera's published list; no Security category was listed.

License: OPERATOR DECISION REQUIRED. No root LICENSE was found in the reviewed file inventory. Opera's publishing guidelines describe a default CC BY-NC-ND 4.0 distribution license when no separate EULA is included; this task does not accept it or the terms on the operator's behalf.

Support page content:

- Intended use: organization-managed endpoint telemetry with the local companion.
- Agent unavailable: ask the organization's Endpoint administrator to verify approved Agent installation, native-host registration and sensor policy. Do not change browser/domain policy to bypass restrictions.
- Unsupported platform: no macOS/Linux companion support is claimed.
- Privacy: disclose origin/domain and bounded action metadata; refer to privacy.md and deployed organization policy.
- Contact and public support/privacy URLs: OPERATOR INPUT / DEPLOYMENT REQUIRED.

Upload package format: OPERATOR VERIFICATION REQUIRED in the authenticated developer portal. Documentation contains historical pack instructions and does not prove today's upload validator. After gates are resolved, build a deterministic source ZIP plus inventory/hash and document Opera Pack Extension locally. Never label a build as acceptance proof.

Post-submission identity gate: record store-assigned ID; compare with `kkkoaifoohdbdaccmnnoagedifflbide`. If identical, continue verified distribution checks. If different, STOP for a separate migration design. Do not alter update.xml, native allowed_origins, bridge verification, policy or Agent status before that decision. Store trust/verified_contents suitability for Yandex is a separate unverified outcome; Opera publication alone would not prove it.
