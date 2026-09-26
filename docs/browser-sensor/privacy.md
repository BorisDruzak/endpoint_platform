# Endpoint Browser Sensor privacy — factual draft

Purpose: enterprise endpoint browser security telemetry for a locally installed Endpoint Agent. Current supported families are Chrome and Yandex; Opera is excluded and submission is blocked.

| Collected field | Classification and timing |
|---|---|
| Browser family, extension ID/version, timestamp, heartbeat, bounded install type | Operational identity/status metadata; worker start and periodic heartbeat |
| Active HTTP(S) origin/domain | Browsing metadata, potentially private; active tab/startup/heartbeat and upload/paste destination |
| File count, total bytes, coarse MIME categories | Potentially private action metadata; trusted file-input selection, maximum 64 files; not proof upload completed |
| Clipboard type categories | Potentially private action metadata; trusted paste event, no value read |

Collection listeners start automatically at document_start. Worker starts automatically when loaded, including startup/installed callbacks. There is no demonstrated user authorization mechanism. Organization-managed installation does not itself prove that Opera's user-authorization requirement is met.

The extension excludes page text/DOM contents, titles, URL path/query/fragment/credentials, filenames/paths/contents, clipboard values, typed text, keystrokes, passwords, cookies, history and screenshots. Reading input kind/files size/type and clipboard types to classify actions does not read their contents.

Transport is fixed local Native Messaging → EndpointBrowserBridge → local Agent IPC. The extension contains no direct cloud HTTP/WebSocket client and no Endpoint credentials. The Agent may forward validated observations/events to the organization's Endpoint server. Activity dispatch and durable SecurityEvent replay are implemented; server security ingestion persists safe_metadata and expiry based on policy.event_retention.security_event_days. Actual retention depends on deployed policy and cleanup execution; no universal deletion period or non-retention promise is made here. The browser queue is memory-only, limited to 64 messages, with reconnect backoff up to 60 seconds and 16 KiB message bound.

Support/contact: OPERATOR INPUT REQUIRED. Public privacy URL: OPERATOR DEPLOYMENT REQUIRED. This document does not assert legal compliance or consent.
