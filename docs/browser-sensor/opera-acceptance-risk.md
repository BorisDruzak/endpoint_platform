# Opera acceptance risk — 2026-09-26

NO-GO FOR SUBMISSION. This is a source-grounded discovery result, not a compliant candidate.

Authoritative current inputs: [Acceptance criteria](https://help.opera.com/en/extensions/acceptance-criteria/), [Publishing guidelines](https://help.opera.com/en/extensions/publishing-guidelines/), [Manifest](https://help.opera.com/en/extensions/manifest/), [Permissions](https://help.opera.com/en/extensions/declare-permissions/), [Native Messaging](https://help.opera.com/en/extensions/message-passing/), [Testing/debugging](https://help.opera.com/en/extensions/testing/). Read on 2026-09-26. The manifest help contains legacy MV2 examples; these do not establish current MV3 runtime or authenticated upload acceptance.

| Criterion | Status | Evidence / remaining gate |
|---|---|---|
| Single purpose | PASS | Enterprise endpoint browser security telemetry for a locally installed Endpoint Agent; no unrelated features |
| Accurate name and background disclosure | RISK | Proposed metadata discloses observations; cannot claim Opera telemetry works |
| Performs as described | BLOCKER | OPR returns null; native and downstream contracts reject Opera |
| User authorization for private information | BLOCKER | Automatic startup/listeners; no demonstrated authorization step or record. Administrative deployment is not evidence of individual authorization |
| No private data to external store | RISK | Extension has only local Native Messaging; Agent can forward activity/events to Endpoint server and persist them. Local transport alone does not settle Opera's criterion |
| All-platform function/testing | BLOCKER | Core companion path is Windows-specific; no demonstrated Mac/Linux companion. Graceful failure cannot establish core function on all platforms |
| Local readable JavaScript / no remote JS | PASS | Three readable scripts, fixed local importScripts, no fetch/XHR/WebSocket/eval/Function in reviewed source |
| No unused packaged files | RISK | Existing release allow-list has four source files; Opera candidate not built |
| No redundant permissions/manifest values | RISK | Three permissions have source uses; actual Opera warnings/API behavior unverified |
| Valid current manifest | RISK | MV3 source; actual Opera load not executed |
| Icons and screenshots | BLOCKER | No required candidate icons or actual acceptance screenshots |
| Popup quality/usefulness | RISK | Current extension has no popup; status surface deferred by STOP gate |
| No third-party branding/artwork | PASS | Source name has no Opera branding; no new artwork added |
| No ads/referral interference/gambling/start-page override | PASS | No such source behavior |
| Reviewable code / third-party dependencies | PASS | First-party readable source; no extension JS dependencies |
| Terms/license | RISK | Operator must settle terms and distribution license; no default accepted |
| Support page | RISK | Draft content prepared; public URL/contact unresolved |
| Upload format | RISK | Authenticated portal format unverified; operator verification required |
| ID continuity | RISK | Unpacked ID is not store ID; store assignment unknown |

PASS refers to reviewed source only, not store approval. STOP conditions preclude runtime/candidate implementation. No legal conclusion is asserted.
