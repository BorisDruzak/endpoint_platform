# Browser Sensor permissions

Source version 0.1.0, discovery only. No permissions changed.

| Permission/scope | Exact usage | Required behavior / narrower alternative | Opera / warning evidence |
|---|---|---|---|
| tabs | tabs.query/get, onActivated/onUpdated, tab.url and sender.tab.url | Normalize active HTTP(S) origin and event destination. activeTab would need an explicit user gesture and would not cover automatic active-domain observation | Documented by Opera; actual warning wording/runtime untested; potentially sensitive tab access |
| nativeMessaging | runtime.connectNative to fixed host | Only Agent transport; removal prevents companion communication | Documented by Opera; actual native-app warning/runtime untested |
| alarms | alarms.create/onAlarm, one-minute heartbeat | MV3 worker wake/reconnect/context refresh; ordinary timers do not provide equivalent wake behavior | Current Opera runtime/API support and warning untested |
| http://*/*, https://*/* content scripts | protocol.js/content.js at document_start, top frame only, trusted change/paste listeners | Observe bounded file-input/paste categories across arbitrary enterprise HTTP(S) pages; fixed domains would remove that declared coverage | Opera documents match-pattern permissions; actual all-site warning untested |

No management, storage, clipboardRead/Write, history, cookies, host_permissions or external messaging permission. management.getSelf is attempted only if present and leaves install type unknown on rejection/mismatch. Do not add management to resolve an untested Opera API assumption. No API-dependent changes implemented, so Context7 implementation gate was not entered.
