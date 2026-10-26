# WorkTime notification companion

The existing Windows User Sensor and ALT KDE User Sensor poll through the same
mutually authenticated local sensor IPC they already use. The new closed
`endpoint.worktime-companion.v1` poll and action contracts are separate from
legacy Activity/Browser envelopes. Existing peers keep their original framing
and acknowledgements. No extra WSS hello field or generic command is introduced.
An old Core rejects the unfamiliar local record safely; an old server's 404
produces an empty capability reply and leaves ordinary agent operation intact.

Core derives the login from the authenticated Windows token SID/logon/session or
Linux kernel peer UID and current logind graphical session. User-supplied login,
person, URL and command fields are forbidden in local interaction records. Core
alone calls the TLS-verified, non-redirecting POST routes
`/agent/v1/gateway/worktime/next` and `/agent/v1/gateway/worktime/ack` with its
existing device credential. Per-account polls are limited to one per 30 seconds.
The routes are installed only when `ENDPOINT_WORKTIME_ENABLED` is enabled; no
new collection policy or fleet monitoring is activated.
Optional HTTPS client construction/context-entry failure leaves the technical
WSS agent running. The companion retries after 5 seconds with exponential
backoff capped at 300 seconds, propagates cancellation, closes its own connector
and reports only a safe error type without exception text or credentials.

The server normalizes the OS account exactly as Activity does, including device
scope for unqualified local accounts. It requires one unambiguous, explicitly
verified temporal ActivityBinding for the authenticated device/account, both now
and over the complete request interval. It never guesses a person from a login.
Each poll and action also requires an active, non-revoked ConfirmedIdentity and a
fresh successful resolution through the configured Helpdesk identity authority.
Missing authority, errors or a changed person binding fail closed. Polling and
fresh presentation require the current effective working schedule, including
the previous day's overnight shift and its own effective assignment/overrides.
Only server-generated durable explanation requests qualify. Explanation coverage
uses the union of saved intervals, including explanations saved while the agent
was offline. Linked completed explanations also suppress delivery.

Migration `0042_worktime_companion`, after `0041_worktime`, adds the personnel
delivery table. A unique request constraint and the existing per-person WorkState
row lock serialize claims across devices, with the same preceding confirmed
identity lock as personnel mutations. At most two pages of 500 pending rows are
examined per poll. Requests closed by the union of explanations receive durable
`covered` delivery markers, so a large historical prefix cannot starve later
requests or restart from the same prefix on every call. Coverage calculation
fails closed above its bounded 20,000-explanation projection limit.

A 90-second lease recovers an interrupted claim on either the original device or
another currently verified device/account mapped to the same person over the
complete request interval. Each assignment rotates a UUID lease fence. Every
local action and Core/server action echoes that fence. Before starting native UI,
the user process must obtain a fresh `present` acceptance; stale/expired/reassigned
leases cannot present or acknowledge. Accepted `presented` ownership is never
automatically reassigned, preventing duplicate notices after a slow UI or lost
reply. A known native startup failure uses a fenced `failed` action to release
the claim for retry. Displayed/reason/later acknowledgement suppresses future
delivery through restart or reconnect. A reason action rechecks the same device/account mapping
and explanation state immediately before returning a URL. The URL contains only
`/employee?day=YYYY-MM-DD&request_id=UUID`; the browser portal independently
reauthorizes the employee and owns all explanation mutations.

The user process keeps a bounded UUID-only durable receipt before invoking a
native notice, so a process restart cannot repeat a displayed notice if its ACK
was interrupted. A known native startup failure releases that local receipt and
permits server lease retry. There is an unavoidable at-most-once presentation
window if the process terminates after server presentation acceptance and before
showing the native surface: the durable request remains visible in the employee portal,
but the notice itself may not have appeared. No explanation is lost or fabricated.

Windows calls the native TaskDialog API in an unprivileged interactive user
session, with explicit reason/later buttons and a Session 0 refusal. ALT calls
`/usr/bin/notify-send` with native freedesktop DBus actions in the KDE X11 or
Wayland session; libnotify belongs to the optional user-sensor RPM. A dedicated
daemon thread owns the notice and bounded IPC calls, while the existing sampler
continues. Missing native APIs or notification-service failure cannot terminate
Core or sampling. The user process never receives device credentials, passwords,
browser cookies or SSO tokens.

Qualification requires installed Windows and ALT native UI/action evidence,
shared-account/session checks, and offline/reconnect/update acceptance. Unit
tests validate both typed boundaries, OS-peer authorization gates, durable claim
and ACK behavior, explanation suppression and per-user restart receipts. They do
not establish installed native notification or signed artifact acceptance.
