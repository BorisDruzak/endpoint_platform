# Endpoint Policy & DLP Foundation v1

Repository: `BorisDruzak/endpoint_platform`

Baseline at task creation:

```text
main:
8044ff1ee993754a295f10f47672ce9402e6f10b

Agent:
3.2.67

Alembic:
0028_capability_platform_v2
```

Codex MUST verify these values against current `main` before implementation.

---

# SPEC

## 1. Goal

Implement **Endpoint Policy & DLP Foundation v1** as a native subsystem of Endpoint Platform.

The goal is to add:

1. server-owned Endpoint Policy;
2. policy delivery and acknowledgement through the existing Agent control plane;
3. user Activity Context;
4. one shared Chromium Browser Sensor for Chrome and Yandex Browser;
5. secure local Browser → Agent communication;
6. audit-only DLP sensors;
7. typed Security Events;
8. bounded offline event buffering;
9. policy/compliance state;
10. Console integration showing whether Policy, Activity Sensor, Browser Sensor and DLP are actually active.

This subsystem must NOT be implemented as Module recipes.

Target architecture:

```text
                       ENDPOINT PLATFORM
                              │
                       Endpoint Policy
                              │
                     existing Gateway WSS
                              │
                              ▼
                       Endpoint Agent
                              │
               ┌──────────────┴──────────────┐
               │                             │
        system/session                 user session
          sensors                         sensor
               │                             │
               │                      idle / foreground
               │                             │
               │                      Browser Bridge
               │                             │
               │                       Native Messaging
               │                             │
               │                  Endpoint Browser Sensor
               │                    Chrome + Yandex
               │
               ├──────── Activity Context
               │
               └──────── Security Events
                              │
                              ▼
                    Context / Security storage
                              │
                              ▼
                       Endpoint Console
```

---

# 2. Fundamental boundary

Keep the following distinction explicit:

```text
Module Platform
=
request → typed operation → result → terminal state

Policy / DLP
=
continuously active Agent subsystem
→ state
→ observations
→ events
```

DLP sensors MUST NOT appear as ordinary Module capabilities such as:

```text
dlp.usb.observe
dlp.browser.observe
```

inside the recipe catalog.

They belong to Policy/Sensor runtime.

---

# 3. Mandatory repository discovery

Before implementation:

1. read `AGENTS.md`;
2. read current `PLANS.md`;
3. inspect current branch and `main`;
4. record starting SHA;
5. determine current `AGENT_VERSION`;
6. determine current Alembic head;
7. inspect:

   * Gateway WSS contracts;
   * Gateway hello/heartbeat;
   * Device sessions;
   * Device Context;
   * Retention v2;
   * DeviceEvent;
   * OperationEvidence;
   * Capability Platform v2;
   * Windows tray/session-launch infrastructure;
   * Windows packaging/MSI/Setup;
   * ALT packaging;
   * Console admin APIs;
   * Console frontend;
   * update/release lifecycle.
8. identify existing user-session companion processes and startup mechanisms;
9. identify safest existing local IPC pattern;
10. inspect existing artifact serving and immutable release metadata patterns.

Also verify current enterprise browser requirements against official Chrome Enterprise and Yandex Browser for Organizations documentation before selecting the exact policy/packaging mechanism.

Do not start implementation before producing a repo-grounded implementation plan.

---

# 4. Agent release boundary

Policy/DLP introduces new Agent runtime behavior and therefore requires a new Agent release.

Codex MUST determine the correct next version from current repository/release state.

Do not assume a specific version from this specification.

Use the existing:

```text
immutable runtime
update ZIP
canary
rollback
WSS startup proof
```

release pipeline.

Do not create a dynamic plugin loader.

---

# 5. Privacy boundary

Foundation v1 explicitly MUST NOT implement:

```text
keylogging
keyboard text capture
clipboard contents
document contents
file contents
browser DOM capture
browser form values
browser search text
browser query strings
browser page contents
screenshots
webcam
microphone
password capture
token capture
cookies
browser history dump
process command lines
```

The platform needs operational/security context, not content surveillance.

---

# 6. Activity Context

Add a new bounded state profile, preferably:

```text
activity_v1
```

unless repository discovery proves another integration is cleaner.

Activity answers:

> Is an interactive user currently using the workstation and what application context is active?

Minimum schema:

```text
activity_v1

user_login:
    string | null

session_state:
    active
    idle
    locked
    disconnected
    unknown

idle_seconds:
    integer | null

foreground:
    process_name
    application_category

browser:
    browser_family
    origin
    domain
    sensor_state
    extension_version
    last_seen_at
```

All fields bounded.

---

# 7. Activity states

Canonical server/UI states:

```text
ACTIVE
IDLE
LOCKED
DISCONNECTED
UNKNOWN
```

Offline remains server-derived from WSS/presence and is not an Agent-reported activity state.

Example:

```text
Device:
PC-KDN-07

User:
ivanova.aa

Presence:
Online

Activity:
ACTIVE

Idle:
48 sec

Foreground:
browser

Browser:
Yandex Browser

Domain:
zakupki.gov.ru
```

---

# 8. Idle detection

Determine activity through OS last-input/session APIs.

Do not capture which key or button was pressed.

Only expose:

```text
idle_seconds
```

Server-owned policy defines threshold for:

```text
ACTIVE → IDLE
```

Suggested initial bounded range:

```text
60..3600 seconds
```

Default may be 600 seconds if no stronger project convention exists.

---

# 9. Foreground application

Collect only bounded application identity.

Allowed:

```text
process_name
application_category
```

Example categories:

```text
browser
office
business_app
system
remote_access
other
```

Do not collect window title by default.

Do not collect document name.

Do not collect executable arguments.

---

# 10. User-session sensor

The Agent service runs outside the interactive desktop and must not obtain user-session information through unsafe hacks.

Introduce a minimal per-interactive-session companion, conceptually:

```text
EndpointUserSensor.exe
```

Exact naming/implementation should be repo-grounded.

Responsibilities:

```text
interactive session state
idle time
foreground process
Browser Sensor local state
```

It must run unprivileged as the interactive user.

Reuse existing tray/session startup architecture where appropriate rather than inventing a conflicting second mechanism.

Do not move Agent credentials into the user process.

---

# 11. Browser Sensor overview

Create one source project:

```text
browser_sensor/
```

or repository-consistent equivalent.

It is a Chromium Manifest V3 extension.

**One source codebase** must support:

```text
Google Chrome
Yandex Browser
```

Do not create:

```text
browser_sensor_chrome/
browser_sensor_yandex/
```

with duplicated business logic.

Browser-specific code may exist only behind a minimal adapter/detection layer.

---

# 12. Browser Sensor responsibilities

Browser Sensor v1 may observe:

```text
browser startup/connection
active tab change
navigation
active domain/origin
file upload action
paste action
```

It must never collect page contents.

---

# 13. Browser context normalization

Browser Sensor sends only:

```text
browser_family

scheme
origin
domain

tab_active
observed_at
```

For:

```text
https://zakupki.gov.ru/epz/order/extendedsearch/results.html?searchString=...
```

store/report:

```text
scheme = https
origin = https://zakupki.gov.ru
domain = zakupki.gov.ru
```

Do NOT send:

```text
path
query
fragment
page title
```

---

# 14. Supported schemes

Only process:

```text
http
https
```

Do not report:

```text
file:
chrome:
browser:
extension:
data:
javascript:
```

unless a later approved design explicitly requires one.

---

# 15. Extension permissions

Use the minimum Manifest V3 permissions necessary.

Expected candidates:

```text
tabs
nativeMessaging
```

and narrowly justified navigation/content-script permissions.

The implementation MUST NOT request unless technically proven necessary:

```text
clipboardRead
clipboardWrite
cookies
history
bookmarks
debugger
webRequestBlocking
management
downloads
```

Add a regression test over `manifest.json` forbidding dangerous unused permissions.

---

# 16. Browser upload sensor

Browser DLP v1 should observe a user selecting files for upload.

Allowed metadata:

```text
event_type = BROWSER_UPLOAD

destination_domain
destination_origin

file_count
total_bytes

mime_categories
browser_family
user_login
```

Do NOT send:

```text
filename
full local path
file contents
file hashes in v1
```

Example:

```text
event:
BROWSER_UPLOAD

domain:
mail.ru

file_count:
3

total_bytes:
8244412

categories:
spreadsheet
document
```

---

# 17. Browser upload limitations

Document explicitly that v1 detects approved browser-visible upload mechanisms such as file-input selection.

Do not claim complete detection of every possible JavaScript/custom upload implementation unless testing proves it.

Drag/drop and alternative browser APIs may be added only if they can preserve the same privacy boundary.

---

# 18. Browser paste sensor

Detect the event:

```text
BROWSER_PASTE
```

Allowed:

```text
destination_domain
destination_origin
browser_family
clipboard_types
```

Do NOT read:

```text
clipboard text
HTML
image bytes
file names
```

Do not call APIs whose purpose is retrieving clipboard contents.

---

# 19. Browser Sensor heartbeat

The extension must periodically prove that it is alive while the browser is running.

Example:

```text
browser_sensor_heartbeat_v1

extension_version
protocol_version
browser_family
observed_at
```

Suggested heartbeat:

```text
60 seconds
```

Choose actual value after resource testing.

Do not create a server request every heartbeat.

Heartbeat goes through local bridge → Agent, and Agent batches/reports state through existing control plane.

---

# 20. Native Messaging architecture

Browser Sensor must NOT connect directly to Endpoint Platform.

Required architecture:

```text
Browser Extension
       │
       ▼
Native Messaging
       │
       ▼
EndpointBrowserBridge
       │
       ▼
local IPC
       │
       ▼
Endpoint Agent
       │
       ▼
existing WSS
```

No Endpoint server bearer/token/certificate is exposed to the browser extension.

---

# 21. EndpointBrowserBridge

Create a minimal native messaging host, conceptually:

```text
EndpointBrowserBridge.exe
```

Responsibilities:

* parse Chromium Native Messaging framing;
* validate exact typed messages;
* enforce size limits;
* reject unknown fields/types;
* forward safe events to local Endpoint session sensor/Agent;
* return bounded acknowledgements.

It MUST NOT:

* have Endpoint server credentials;
* open outbound Internet connections;
* execute commands;
* read browser profile files;
* read cookies/history/passwords.

---

# 22. Local IPC

Browser Bridge and user-session components communicate with Endpoint Agent through a bounded local IPC mechanism.

On Windows prefer existing architecture or:

```text
Named Pipe
```

with strict ACL.

Security requirements:

* SYSTEM/Agent service owns server side;
* only expected interactive SID/session may connect;
* validate session identity;
* the Bridge verifies the server process has the EndpointAgent service SID and
  LocalService identity before sending a frame, including when a different
  process creates the pipe name first;
* Agent impersonates the writer after reading each frame and verifies its
  interactive user SID, logon SID and active Windows session;
* bounded message size;
* typed protocol;
* no arbitrary JSON passthrough;
* no executable/path parameters.

Do not expose a localhost TCP listener unless repository constraints make it necessary.

---

# 23. Native Messaging host identity

Use one stable native host name, e.g. conceptually:

```text
ru.sosnadmin.endpoint.browser
```

Final value must follow repository/product naming conventions.

Native messaging manifest must allow only the Endpoint Browser Sensor extension origin.

No wildcard extension origins.

---

# 24. Stable Extension ID

Browser Sensor must have one stable Extension ID.

The ID is part of:

```text
Chrome policy
Yandex policy
Native Messaging allowed_origins
release metadata
Console status
```

Signing key/private key:

* MUST NOT be committed to Git;
* MUST NOT be embedded in documentation;
* should be supplied to release tooling from a protected external location.

Loss/change of signing identity must be treated as a release-breaking event.

---

# 25. Browser Sensor build

Provide deterministic/reproducible-enough build tooling.

Release metadata should contain:

```text
schema_version
extension_version
extension_id
protocol_version
source_revision

artifact filename
artifact SHA-256

manifest SHA-256
update manifest SHA-256

minimum_agent_version
created_at
```

Do not put the private signing key into release metadata.

---

# 26. Chrome deployment

Support enterprise force-install in both `agent_managed` and `external_managed` ownership modes. In `agent_managed`, Endpoint Agent applies only its own machine-level enterprise policy; in `external_managed`, the external administrator supplies that policy and Agent only observes its result.

Provide managed-policy deployment artifact/template for:

```text
ExtensionSettings
```

with:

```text
installation_mode = force_installed
update_url = internal Endpoint URL
```

Do not require Chrome Web Store.

Production target is a domain-managed workstation.

The Agent MUST NOT copy the extension into a browser profile, edit `User Data/Extensions` or browser databases, use developer mode or unsupported sideloading, or store the extension signing key. It must preserve other extensions' settings. If an existing policy cannot be safely merged or its ownership cannot be established, report a policy conflict and do not overwrite it.

---

# 27. Yandex Browser deployment

Support Yandex Browser for Organizations using the same Browser Sensor source and protocol.

Provide deployment template for:

```text
ExtensionInstallForcelist
```

or `ExtensionSettings` where better supported by the current corporate browser.

Use internal update URL. In `agent_managed`, apply only the Endpoint extension's machine-level force-install setting; in `external_managed`, leave installation policy to GPO/Ansible or another external owner.

Register and, where an existing allowlist requires it, allow only the Endpoint native host without deleting or overwriting other hosts. Foundation v1 MUST NOT automatically set a global `NativeMessagingBlocklist = *`; existing corporate hosts such as CryptoPro must keep working.

Do not fork extension functionality for Yandex.

---

# 28. One codebase / packaging exception

Preferred:

```text
one source
one manifest
one signed CRX
Chrome + Yandex
```

If actual browser acceptance demonstrates that one physical CRX cannot be deployed correctly in both products:

allowed fallback:

```text
one source tree
one protocol
one extension behavior

→ Chrome package
→ Yandex package
```

No duplicated implementation.

This fallback must be documented with actual technical evidence.

---

# 29. Self-hosted update location

Serve extension artifacts from existing trusted Endpoint HTTPS infrastructure.

Conceptually:

```text
https://endpoint.sosnadmin.local/browser-sensor/
```

Exact route should reuse current artifact infrastructure.

Serve:

```text
CRX/package
update manifest
release metadata
```

No directory listing.

No private signing material.

---

# 30. Browser release registry

Reuse an existing immutable release-registry pattern where possible.

If no suitable model exists, create a minimal BrowserSensorRelease metadata model.

Console should know:

```text
current published extension version
extension ID
protocol version
artifact digest
minimum Agent version
```

Do not store CRX bytes in PostgreSQL.

---

# 31. Windows Agent packaging

The new Agent release should install:

```text
EndpointUserSensor
EndpointBrowserBridge
native messaging manifest(s)
required registry registration
the narrowly privileged Browser Integration Policy Applicator needed for agent_managed
```

Use existing MSI/Setup ownership and upgrade rules.

Do not require a second manual installer.

The current Windows Agent service runs as `LocalService`, so it must not silently gain broad administrator rights. `agent_managed` policy writes require a fixed, narrowly privileged component installed by the signed MSI/Setup and controlled by Agent through a typed local contract. It may write only the approved Endpoint extension's machine-level browser policy and its ownership marker; no arbitrary registry path/value API is allowed.

---

# 32. Upgrade behavior

Agent upgrade must:

* preserve Device identity;
* preserve credentials;
* preserve Policy cache;
* register/update Browser Bridge;
* preserve existing Tray;
* not launch Browser Sensor itself;
* not install Chrome/Yandex if absent.

In `agent_managed`, Agent drives installation through official machine-level enterprise policy and the browser fetches the signed extension from Endpoint HTTPS. In `external_managed`, Agent does not change browser installation policy. Agent never installs the CRX directly into a browser profile.

---

# 33. ALT packaging

Prepare equivalent architecture for ALT Linux where practical:

```text
user-session sensor
native messaging host
Chrome managed policy
Yandex managed policy
```

Use repository/Ansible conventions.

If live ALT remains unavailable:

* implement code/tests where support is claimed;
* do not claim live ALT acceptance.

---

# 34. Endpoint Policy contract

Create strict typed contract:

```text
EndpointPolicyV1
```

Conceptual structure:

```text
schema_version

policy_id
policy_version

activity:
    enabled
    idle_threshold_seconds
    foreground_application
    browser_context

dlp:
    usb_device_events
    removable_write_events
    print_events
    browser_upload_events
    browser_paste_events

browser_sensor:
    required
    deployment_mode: agent_managed | external_managed

event_retention:
    security_event_days
```

All fields strict and bounded.

`deployment_mode` is a strict enum, not a free string. It determines who owns the browser installation policy; it does not change the Browser Sensor source or protocol.

---

# 35. DLP modes v1

Only support:

```text
disabled
audit
```

Do NOT implement:

```text
warn
block
block_with_override
delete
quarantine
```

in Foundation v1.

This rollout is observational.

---

# 36. Policy versioning

Policies are immutable by version.

Do not mutate an already-applied policy version.

Concept:

```text
Policy:
Municipal Default

Version:
1
2
3
```

New configuration creates a new version.

---

# 37. Policy assignment

Support:

1. server default policy;
2. explicit per-device override.

Do not implement AD group synchronization in v1.

Future group/OU mapping must be possible without changing policy contract semantics.

---

# 38. Policy delivery

Use the existing authenticated Agent connection.

No second WebSocket.

Policy should be delivered/synchronized through:

```text
/agent/v1/connect
```

using a dedicated typed policy message/envelope.

Do not implement policy as a Module Operation.

---

# 39. Policy acknowledgement

Agent reports:

```text
policy_id
policy_version
policy_digest

received_at
applied_at

status
error_code
```

Server must know whether the policy was actually applied.

Possible states:

```text
PENDING
APPLIED
STALE
UNSUPPORTED
ERROR
```

---

# 40. Policy cache

Agent stores last successfully applied policy in protected Agent data storage.

Requirements:

* SYSTEM-controlled ACL;
* no secrets;
* schema validation on load;
* digest;
* atomic replacement;
* survives reboot/offline operation.

If server is temporarily unavailable, last applied policy remains active.

---

# 41. Old Agent behavior

Agents without Policy v1 support must:

* continue working normally;
* not receive incompatible policy frames;
* display in Console:

```text
Политика не поддерживается
Требуется обновление Agent
```

No connection failure.

---

# 42. Policy compliance

Server derives device compliance.

Minimum states:

```text
COMPLIANT
PARTIAL
NON_COMPLIANT
STALE
UNSUPPORTED
```

Examples of non-compliance:

```text
policy not acknowledged
activity sensor missing
Browser Sensor required but never seen
Browser Bridge unavailable
sensor stale
required DLP sensor unavailable
```

Do not let Agent self-declare overall compliance.

---

# 43. Browser Sensor compliance

Distinguish:

```text
browser installed
deployment ownership: agent_managed or external_managed
Endpoint managed installation policy applied
native host registered
managed extension last seen
browser currently running
policy conflict
```

Do not say:

```text
Extension missing
```

merely because browser is currently closed.

Recommended states:

```text
NOT_APPLICABLE
NEVER_SEEN
ACTIVE
STALE
ERROR
```

with `last_seen_at`.

Server and Console must distinguish browser detected, externally managed, policy applied, never seen, active, stale, browser closed and conflict. In `agent_managed`, failure to apply the policy is separate from failure of the browser to download the extension. In `external_managed`, Agent must not claim it applied installation policy.

---

# 44. SecurityEvent

Now introduce the previously deferred separate model:

```text
SecurityEvent
```

It MUST NOT be a ContextSnapshot, ModuleOperation or AuditEvent.

Minimum fields:

```text
id
event_identifier
device_id

event_type
channel
severity

occurred_at
received_at

user_login

policy_id
policy_version

safe_metadata

created_at
expires_at
```

---

# 45. Security Event types v1

Required first set:

```text
USB_DEVICE_CONNECTED
USB_DEVICE_DISCONNECTED

PRINT_JOB

BROWSER_UPLOAD
BROWSER_PASTE
```

Optional only if a bounded reliable implementation is proven:

```text
REMOVABLE_WRITE
```

Do not fake support if OS-level monitoring is incomplete.

---

# 46. Deferred DLP channels

Explicitly defer:

```text
general clipboard monitoring
network share copy monitoring
email content inspection
screen capture
generic filesystem monitoring
browser page inspection
```

until separately designed.

---

# 47. USB sensor

Observe removable device lifecycle.

Allowed metadata:

```text
vendor
product
device_class
removable
serial_hash
```

Prefer hashing stable serial identity before transmission where appropriate.

Do not transmit arbitrary device descriptor blobs.

---

# 48. Removable write sensor

If implemented in v1, it remains audit-only and best-effort.

Allowed aggregate metadata:

```text
volume identity
file_count
total_bytes
extension categories
```

Do NOT transmit:

```text
file names
full paths
contents
```

If reliable detection requires a filesystem minifilter/kernel driver, defer it rather than introducing such a driver in Foundation v1.

---

# 49. Print sensor

Observe print activity.

Allowed:

```text
printer identity
page count if available
copies if available
size if safely available
timestamp
user_login
```

Explicitly exclude:

```text
document name
document contents
spool file
print preview
```

---

# 50. Browser Security Events

Browser extension is authoritative only for browser-observed actions, not for overall user intent.

`BROWSER_UPLOAD`:

```text
domain
origin
file_count
total_bytes
mime_categories
browser_family
```

`BROWSER_PASTE`:

```text
domain
origin
clipboard_types
browser_family
```

No content.

---

# 51. Event transport

Continuous sensor events MUST NOT create Module Operations.

Use a dedicated typed WSS event channel/envelope.

Concept:

```text
AgentSecurityEventBatchV1
```

Bound:

```text
max events per batch
max message bytes
max metadata bytes/event
```

Suggested:

```text
<= 50 events/batch
<= 64 KiB total
```

Adjust only with tests.

---

# 52. Event idempotency

Every event has stable:

```text
event_identifier
```

Server must reject/replay idempotently.

WSS retry must not create duplicate SecurityEvent rows.

Unique constraint should cover appropriate device/event identity.

---

# 53. Event acknowledgement

Server acknowledges persisted event batches.

Agent removes events from local spool only after valid ACK.

Do not implement fire-and-forget for security events.

---

# 54. Offline event spool

Agent requires a bounded durable event spool.

Requirements:

```text
survive Agent restart
survive network outage
bounded disk usage
idempotent replay
```

Use protected Agent data storage.

SQLite is acceptable if consistent with repository constraints.

Suggested bounds:

```text
max 1000 events
max 5 MiB
max event age 24 hours
```

Choose actual constants after testing.

---

# 55. Spool overflow

Never grow without bounds.

When full:

* discard according to deterministic documented policy;
* increment drop counter;
* surface degradation in Agent health/compliance.

Do not silently drop without state.

---

# 56. SecurityEvent retention

For Foundation v1:

```text
default retention = 30 days
```

Server-owned and bounded.

Allow validated future configuration range, e.g.:

```text
7..365 days
```

Do not retain raw sensor transport beyond validation.

Do not mix SecurityEvent retention with 24h Context hot-history retention.

---

# 57. Activity retention

`activity_v1` belongs to Context/Retention v2.

Recommended:

```text
Current:
always retained

Hot history:
24 hours

semantic dedup:
yes for unchanged activity state
```

`last_observed_at` must advance even if semantic state is unchanged.

---

# 58. Activity semantic identity

Ignore:

```text
collection timestamp
heartbeat timestamp
```

Material fields include:

```text
session state
user login
foreground process/category
browser family/domain/origin
```

Do not create snapshot churn solely because idle seconds increased slightly.

Normalize idle into state rather than hash exact `idle_seconds`.

---

# 59. SecurityEvent vs DeviceEvent

Keep boundaries:

```text
DeviceEvent
=
durable device/context state change

SecurityEvent
=
policy/security activity event
```

Example:

```text
NETWORK_CHANGED
→ DeviceEvent

BROWSER_UPLOAD
→ SecurityEvent
```

---

# 60. SecurityEvent vs AuditEvent

Keep boundaries:

```text
AuditEvent
=
administrator/system control-plane action

SecurityEvent
=
endpoint-observed security event
```

Do not write one AuditEvent for every DLP observation.

---

# 61. Console navigation

Add a dedicated section:

```text
Политики и DLP
```

Suggested route:

```text
/admin/security
```

or repo-consistent equivalent.

Do not redesign full Dashboard yet.

---

# 62. Console — Policy page

Show:

```text
Активная политика

Название
Версия
Создана
Состояние
```

Policy sections:

```text
Активность
Browser Sensor
DLP
Retention
```

Actions:

```text
Создать новую версию
Назначить устройству
Сделать политикой по умолчанию
```

All mutations audited.

---

# 63. Console — Policy state

Fleet table:

```text
Устройство
Agent
Policy
Applied version
Compliance
Last policy acknowledgement

Activity Sensor
Browser Sensor
DLP
```

Filters:

```text
Compliant
Partial
Non-compliant
Stale
Unsupported
```

---

# 64. Console — Browser Sensor status

For each browser:

```text
Chrome

Browser installed:
Да

Management:
Endpoint Agent | external policy

Installation policy:
applied | conflict | external | not applied

Native Host:
Готов

Extension:
ACTIVE

Version:
1.0.0

Last seen:
1 минуту назад
```

Same for:

```text
Yandex Browser
```

Do not show `Extension missing` merely because browser is closed.

Use Russian labels for each state. If Agent applied policy but the browser has not run since then, show that as the reason for `NEVER_SEEN`. Show Chrome and Yandex separately, including browser detection, policy owner, native host, extension version and last seen time.

---

# 65. Console — Device activity

Device detail should gain:

```text
Активность
```

Either new tab or clearly separated section.

Show:

```text
Пользователь

ACTIVE / IDLE / LOCKED

Неактивность

Активное приложение

Browser

Domain

Последнее наблюдение
```

No window titles.

---

# 66. Console — Security Events

Add bounded paginated list:

```text
Время
Устройство
Пользователь
Канал
Событие
Назначение
Policy
```

Filters:

```text
period
device
user
channel
event type
severity
domain
```

No unbounded query.

---

# 67. Console — Event detail

Display safe metadata only.

Examples:

### Browser upload

```text
Передача файла через браузер

Пользователь:
ivanova.aa

Браузер:
Yandex

Назначение:
mail.ru

Файлов:
3

Размер:
8.2 MB

Категории:
Документ
Таблица

Режим:
Аудит
```

### Print

```text
Печать

Printer:
Kyocera ...

Pages:
12
```

No document title.

---

# 68. Console — Browser release

If Browser Sensor release registry is implemented, show:

```text
Browser Sensor

Current release:
1.0.0

Extension ID:
...

Protocol:
1

SHA-256:
...

Minimum Agent:
...
```

Provide deployment references/templates but do not expose signing key.

---

# 69. Console status metrics

Foundation v1 may add small counters to existing dashboard:

```text
Policy compliant
Policy problems
Browser Sensor active
Browser Sensor stale
Security Events 24h
```

Do not build the full observability dashboard requested for the later phase.

That is a separate milestone.

---

# 70. Admin APIs

Add session-authenticated, typed, bounded routes as required.

Conceptually:

```text
GET  /api/admin/security/policies
POST /api/admin/security/policies/versions

GET  /api/admin/security/compliance

GET  /api/admin/security/events

GET  /api/admin/console/devices/{id}/activity
GET  /api/admin/console/devices/{id}/browser-sensors
```

Exact namespace must follow existing Console conventions.

---

# 71. Future service API

Do NOT implement broad Helpdesk/public service API in this task.

Design internal DTOs so a later safe service projection can expose:

```text
activity state
policy compliance
browser sensor health
selected security event summaries
```

without exposing raw internal data.

Helpdesk API integration is the next stage.

---

# 72. Feature flags

New functionality defaults disabled.

Suggested grouping:

```text
ENDPOINT_POLICY_ENABLED
ENDPOINT_ACTIVITY_SENSOR_ENABLED
ENDPOINT_BROWSER_SENSOR_ENABLED
ENDPOINT_DLP_AUDIT_ENABLED
```

Avoid dozens of individual environment flags.

Policy determines individual sensor modes after subsystem enablement.

---

# 73. Browser extension feature rollout

Browser Sensor rollout is independent from Agent rollout.

Possible states:

```text
Agent supports Browser Sensor
but extension not deployed
```

must be valid and visible as non-compliance/partial state, not Agent failure.

## Browser Sensor installation ownership

`browser_sensor.deployment_mode` is either `agent_managed` or `external_managed`.

In `agent_managed`, Endpoint Agent owns a Browser Integration Policy Applicator. It uses official machine-level Chrome and Yandex enterprise policies to force-install the approved extension ID from the Endpoint HTTPS update URL. The applicator is idempotent, narrowly scoped, merge-safe and restart-safe. It must preserve other extension entries and native hosts. It must determine policy ownership before modifying an existing value and fail closed with a reported `POLICY_CONFLICT` when it cannot safely merge. Reapplying the same policy must perform no write. When switching away, it may remove only its own exact, unchanged extension entry and ownership marker; it must never delete a foreign entry or another owner's policy value. If ownership is uncertain, it leaves the value and reports conflict.

In `external_managed`, GPO, Ansible or another enterprise system owns force-install. After any safe hand-off cleanup, Agent does not change browser installation policy; it verifies Browser Bridge registration, accepts extension heartbeat and reports observed state. This mode remains compatible with a later fleet rollout.

In either mode the browser itself fetches the signed CRX from the approved Endpoint HTTPS artifact source. Agent never edits browser profiles, uses developer mode, performs unsupported sideloading or stores the extension private key. Agent does not set a global Native Messaging blocklist. Existing corporate Native Messaging hosts must remain usable.

---

# 74. Deployment templates

Prepare deployment artifacts/documentation for future fleet rollout.

## Windows / AD

Document/configure:

```text
Chrome ExtensionSettings
Yandex ExtensionInstallForcelist / ExtensionSettings
NativeMessaging policies
```

Do not automatically modify domain GPO from development code.

Provide tested policy values/templates.

`agent_managed` may write only its own local machine-level browser policy on selected pilot devices. That is distinct from modifying domain GPO or bulk-deploying policies. Include ownership-marker, merge/conflict and removal-on-mode-switch procedures in the runbook.

## ALT / Ansible

Provide repo-consistent templates for managed browser policies and native messaging manifests.

Do not bulk-deploy to production fleet in this task.

---

# 75. Extension update independence

Browser Sensor extension should have its own version:

```text
Browser Sensor 1.0.0
```

It need not equal:

```text
Agent 3.x.x
```

Compatibility is through:

```text
browser protocol version
minimum Agent version
```

---

# 76. Protocol compatibility

Browser Bridge must validate:

```text
extension protocol version
```

Unknown/newer protocol:

```text
reject safely
report sensor incompatibility
```

No best-effort arbitrary JSON compatibility.

---

# 77. Browser sensor messages

Define strict DTOs such as:

```text
BrowserHelloV1
BrowserHeartbeatV1
BrowserContextV1
BrowserUploadEventV1
BrowserPasteEventV1
```

All:

```text
extra=forbid
bounded strings
bounded lists
strict enum
```

---

# 78. Local browser message size

Set small explicit bounds.

A browser message must never become a path for megabytes of page/file content into Agent.

Example:

```text
max message <= 16 KiB
```

Choose actual constant through implementation/testing.

---

# 79. Browser Sensor fail-safe

If BrowserBridge/Agent unavailable:

* extension continues normal browser operation;
* do not block navigation;
* do not block upload/paste;
* retain only small bounded local health state if necessary;
* report recovery after reconnect.

Foundation v1 is audit-only.

---

# 80. No blocking

Foundation v1 MUST NOT interfere with:

```text
upload
paste
print
USB usage
browser navigation
```

Any future preventive action requires:

```text
Policy & DLP Enforcement v2
```

with separate risk analysis.

---

# 81. Packaging security

Browser Bridge and User Sensor binaries included in Windows release must use the existing signed Agent/MSI/Setup pipeline.

Browser extension package must have verified artifact digest and stable signing identity.

No unsigned production artifact should be marked production-ready.

---

# 82. Agent tray

Do not overload Tray with detailed DLP UI.

At most add bounded status:

```text
Политика: применена
Browser Sensor: подключён
```

only if consistent with current Tray UX.

Console remains administrative surface.

---

# 83. Tests — Browser extension

Required automated tests:

```text
domain normalization
query/path stripping
unsupported scheme rejection
upload metadata
paste event without contents
message bounds
manifest permission guard
native messaging protocol
heartbeat
browser family detection
```

Add an explicit test proving test fixtures containing clipboard/page text do not appear in emitted messages.

---

# 84. Tests — local bridge

Required:

```text
Native Messaging frame parsing
oversized frame rejection
unknown schema rejection
wrong extension/protocol rejection
IPC ACL/identity behavior where testable
no outbound network path
reconnect
```

---

# 85. Tests — Activity

Required:

```text
ACTIVE
IDLE
LOCKED
DISCONNECTED

idle threshold
foreground normalization
browser context
semantic dedup
last_observed_at
24h retention
```

---

# 86. Tests — Policy

Required:

```text
immutable version
default assignment
device override
delivery
acknowledgement
old Agent unsupported
cache reload
policy digest
stale state
compliance derivation
```

---

# 87. Tests — Security Events

Required:

```text
typed ingestion
idempotency
batch ACK
offline spool replay
spool bounds
TTL cleanup
privacy field rejection
pagination
```

---

# 88. Security regression guards

Add guards preventing:

```text
key logging
clipboard content access
page DOM serialization
browser title collection
URL query persistence
arbitrary filesystem path
arbitrary script
browser direct Endpoint auth
```

Search/architecture tests are acceptable where appropriate, but functional tests should prove critical boundaries.

---

# 89. Browser acceptance

On a Windows lab workstation with Chrome and/or Yandex:

1. install new Agent;
2. verify User Sensor;
3. verify Native Messaging host registration;
4. install Browser Sensor using managed policy where possible;
   for `agent_managed`, start with the extension absent and verify that Agent applies only its own machine-level policy and the browser downloads the signed extension;
5. verify extension handshake;
6. open approved test domains;
7. verify only origin/domain arrive;
8. test upload with disposable test files;
9. verify file names/content do not arrive;
10. test paste with synthetic secret text;
11. verify secret text never reaches Agent/server/log;
12. close browser and verify status semantics;
13. restart browser and verify reconnect.

Repeat the `agent_managed` install path for Chrome and Yandex where installed. Verify idempotent reapplication, browser restart, Agent restart and Agent upgrade. Switch to `external_managed` and prove that Agent stops policy writes without removing another owner's configuration. Inspect both browsers' effective policy pages and unrelated corporate extension/native-host entries before and after.

---

# 90. Dual-browser acceptance

Required before claiming one-package support:

```text
same source
same protocol

Chrome:
PASS

Yandex:
PASS
```

If same CRX works:

record it.

If separate package artifacts are required:

record why, but source remains shared.

---

# 91. DLP live acceptance

Generate safe synthetic events:

```text
USB connect
test print
browser upload
browser paste
```

Verify:

```text
Agent
→ WSS
→ SecurityEvent
→ Console
```

No actual sensitive document is necessary.

Use synthetic disposable data.

---

# 92. Policy live acceptance

Create:

```text
Municipal Default v1
```

with:

```text
activity enabled
browser sensor required
browser sensor deployment_mode = agent_managed
USB audit
print audit
browser upload audit
browser paste audit
```

Assign to one test Device.

Verify:

```text
PENDING
→ APPLIED
→ COMPLIANT
```

and Console status.

---

# 93. Browser missing acceptance

Remove/disable extension in a lab scenario only where enterprise policy allows controlled testing.

Verify server distinguishes:

```text
browser closed
```

from:

```text
sensor never seen/stale
```

Do not produce false critical alerts simply because Chrome/Yandex is not running.

---

# 94. Agent update acceptance

Use existing process:

```text
current stable
→ new Policy/DLP Agent canary
→ WSS
→ Context
→ capabilities
→ Policy
→ Activity
→ Browser Sensor
→ Security Event
```

Then rollback to previous verified Agent.

Confirm:

* normal Context still works;
* Module Platform still works;
* old Agent safely reports Policy unsupported;
* Browser extension does not break when Agent has been rolled back.

Then reapply the new Agent.

---

# 95. Initial rollout

Do not bulk-deploy.

Sequence:

```text
local development workstation
        ↓
IT canary
        ↓
1–3 pilot workstations
```

Observe stability before AD/Ansible fleet rollout.

---

# 96. ALT live acceptance

If dedicated ALT test host is still unavailable:

* automated ALT tests may pass;
* do not claim live ALT acceptance;
* explicitly record gap.

Do not delay Windows Foundation acceptance solely because the existing ALT host is unreachable.

---

# 97. Non-goals

Do NOT implement:

```text
keylogger
screenshots
DOM collection
page contents
clipboard contents
email contents
file contents
file names in DLP events
document titles in print events

DLP blocking
quarantine
delete
service restart
process kill

network share DLP unless separately proven
general clipboard monitoring

Helpdesk integration
public service API v2
full Console analytics dashboard
fleet-wide GPO rollout
fleet-wide Ansible rollout
```

---

# 98. Documentation

Add architecture document:

```text
docs/architecture/endpoint-policy-dlp-foundation-v1.md
```

It must clearly describe:

```text
Policy
Activity Context
User Sensor
Browser Sensor
Browser Bridge
Native Messaging
SecurityEvent
retention
privacy boundaries
deployment
```

Add deployment runbooks:

```text
Chrome managed deployment
Yandex managed deployment
ALT/Ansible deployment
Browser Sensor release
```

---

# EXECUTION

## 99. Phase 0 — Discovery and design

Before implementation answer:

1. How will policy travel over existing WSS?
2. How will old Agents remain compatible?
3. What existing user-session startup mechanism can User Sensor reuse?
4. What exact IPC implementation is safest?
5. Can one signed CRX be used by both installed Chrome/Yandex versions?
6. How is Extension ID stabilized?
7. What current artifact infrastructure should host Browser Sensor?
8. What exact Windows APIs will provide idle/foreground state?
9. What exact APIs will provide USB and print events?
10. Which DLP sensors can be reliably implemented without kernel drivers?

Produce implementation plan from actual repository.

---

# 100. Phase 1 — Policy contracts and persistence

Implement:

```text
EndpointPolicyV1
PolicyDefinition
PolicyVersion
PolicyAssignment
PolicyDeviceState
```

Add migration.

Add admin API.

No Agent sensors yet.

---

# 101. Phase 2 — Policy WSS synchronization

Extend existing WSS contracts with typed:

```text
policy delivery
policy acknowledgement
```

Backward compatible.

Add Agent cache.

Prove old Agent compatibility.

---

# 102. Phase 3 — User Activity Sensor

Implement user-session component.

Add:

```text
idle
session state
foreground process/category
```

Integrate `activity_v1` into Context + Retention v2.

Do not involve Browser Sensor yet.

---

# 103. Phase 4 — Browser Sensor source project

Create shared MV3 extension.

Implement:

```text
hello
heartbeat
active origin/domain
upload metadata
paste occurrence
```

No server connectivity.

Add extension tests.

---

# 104. Phase 5 — Browser Bridge

Implement native messaging host.

Integrate with secure local IPC.

Register for Chrome/Yandex.

Package with Agent.

---

# 105. Phase 6 — Browser release/deployment

Create release tooling:

```text
stable Extension ID
signed package
update manifest
SHA-256 metadata
self-host
```

Prepare Chrome/Yandex managed-policy templates.

Perform local managed-browser acceptance.

Implement the narrowly privileged, typed Browser Integration Policy Applicator for `agent_managed`; test merge-safe ownership and `external_managed` no-write behavior before live acceptance. Do not apply a global Native Messaging blocklist.

---

# 106. Phase 7 — SecurityEvent pipeline

Add:

```text
SecurityEvent
typed WSS batches
ACK
idempotency
bounded spool
30-day retention
```

No blocking.

---

# 107. Phase 8 — OS DLP sensors

Implement approved bounded sensors:

```text
USB device lifecycle
Print
```

Implement removable-write sensor only if it can meet v1 boundaries without kernel-level scope expansion.

---

# 108. Phase 9 — Console integration

Add:

```text
Политики и DLP

Policy editor/version
Compliance
Browser Sensor status
Security Events

Device → Активность
Device → Policy/DLP status
```

Russian UI mandatory.

---

# 109. Phase 10 — Packaging and Agent release

Build new signed Windows Agent release containing:

```text
User Sensor
Browser Bridge
Policy runtime
DLP audit runtime
```

Use immutable runtime/update pipeline.

Do not modify Browser Sensor version merely to match Agent version.

---

# 110. Phase 11 — Live acceptance

Test:

```text
Policy applied
Activity
Chrome Sensor
Yandex Sensor
USB
Print
Browser Upload
Browser Paste
Security Events
Console
```

with synthetic data.

Then Agent rollback/reapply.

---

# 111. Phase 12 — Limited pilot

Deploy to:

```text
local
IT
1–3 normal workstations
```

Do not perform general AD/Ansible rollout yet.

Record stability evidence.

---

# 112. Verification gates

At minimum:

```text
full Python tests
contracts generation
Alembic tests
Gateway tests
Agent tests
Windows tests
browser extension unit tests
native bridge tests
Console tests
Playwright
production frontend build
packaging tests
git diff --check
provider-release-gate
```

---

# 113. Required privacy acceptance

Use synthetic secret marker:

```text
ENDPOINT_DLP_SECRET_MUST_NOT_LEAK_...
```

Place it in:

* clipboard paste test;
* browser page body;
* test filename/path where safe.

After test, search:

```text
Agent logs
server DB
SecurityEvent
Audit
Context
Browser Sensor output
```

The marker MUST NOT appear.

This is a release gate.

---

# 114. Required final report

Return:

## Repository

```text
starting SHA
ending SHA
branch
remote SHA
working tree
```

## Agent

```text
previous version
new version
source revision
artifact SHA
rollback artifact
```

## Browser Sensor

```text
version
extension ID
protocol version
source revision
artifact SHA

Chrome result
Yandex result

single CRX or dual packaging
```

## Policy

```text
policy versions
assignment model
WSS sync
cache
compliance
```

## Activity

```text
session
idle
foreground
browser context
retention
```

## DLP

List every actually implemented sensor and explicit limitations.

Do not report deferred sensors as implemented.

## Privacy

Report negative leakage tests.

## Console

Report pages/statuses.

## Tests

Exact commands/results.

## Production

If deployed:

```text
backup
migration
server release
Agent canary
rollback
reapply
Browser Sensor deployment
Policy acceptance
event acceptance
```

## Remaining gaps

Especially:

```text
ALT live acceptance
fleet deployment
Helpdesk API
full dashboards
DLP enforcement/blocking
network share monitoring
```

---

# 115. Definition of Done

Foundation v1 is complete when one managed Windows endpoint can demonstrate:

```text
Endpoint Console
       │
       ▼
Municipal Default Policy
       │
       ▼
Agent acknowledges/applies policy
       │
       ├── Activity Sensor ACTIVE
       │
       ├── Browser Sensor ACTIVE
       │     ├── Chrome
       │     └── Yandex
       │
       ├── USB DLP audit
       ├── Print DLP audit
       ├── Browser Upload audit
       └── Browser Paste audit
              │
              ▼
       Security Events
              │
              ▼
       Endpoint Console
```

and the same acceptance proves that:

```text
no keylogging
no browser contents
no clipboard contents
no document contents
no arbitrary file contents
no browser-to-server credential
no DLP blocking
```

has been introduced.

---

# 116. Architectural invariant

The final architecture must preserve:

> **Endpoint Policy determines which continuous sensors are active. Activity Context describes current user/device activity. Browser Sensor contributes only bounded browser context and action metadata. SecurityEvent records meaningful security events. Module Platform remains the on-demand diagnostic automation system. None of these subsystems may become a generic surveillance or remote-code-execution surface.**
