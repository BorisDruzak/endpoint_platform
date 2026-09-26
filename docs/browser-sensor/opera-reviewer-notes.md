# Opera reviewer notes — preparation only

NO-GO; not instructions for a submitted working Opera candidate. Current OPR detection is intentionally unsupported and downstream family validation is closed to Chrome/Yandex. A supported Opera-with-Agent test path does not currently exist.

After resolving architecture/authorization/platform gates:

1. Use an isolated ordinary Opera test installation; record exact version and Windows version. Open opera:extensions, enable the documented Developer Mode, Load Unpacked, and record the observed development ID. Never assume it is the store ID.
2. Without Agent, inspect service worker errors and planned popup. Expected future status: Endpoint Agent unavailable; no Connected without accepted Agent ACK, no noisy repeated UI, no crash. Verify queue never exceeds 64, message size 16 KiB, and reconnect delay bounded to 60 seconds.
3. With Agent, use a dedicated non-production Windows test device and approved package registering only ru.sosnadmin.endpoint.browser. Preserve fixed allowed_origins and identity validation. If the unpacked ID differs, stop; do not loosen identity to make the test pass. Genuine Opera contracts and a compatible test Agent are prerequisites.
4. Inspect handshake/accepted ACK, heartbeat, active origin/domain and bounded file-input/paste events using a public or synthetic local HTTP(S) test page. Never use private browsing pages or production credentials. Verify Agent receipt and downstream typed acceptance separately.
5. Inspect readable background.js/content.js/protocol.js. No fetch/XHR/WebSocket or remote JS exists. Only local Native Messaging transport is intended; Agent forwarding remains disclosed.
6. Confirm exclusions: page/title/text, path/query, filenames/file paths/contents, clipboard values, typed text/passwords and screenshots. Test secret markers across those inputs, not only happy-path metadata.
7. On Mac/Linux, test no-companion behavior and resource bounds, but do not claim core Agent telemetry support. Seek a valid platform acceptance resolution before submission.

No production credentials or production test changes are supplied. Current source has no popup and no authorization gate; these must not be concealed from reviewers.
