# Independent Windows support access: live verification

Windows primary remains **3.2.172** and ALT remains **3.2.156**. Neither diagnostic173 nor174 was published to enrollment/AUTO. Fleet policy9 is paused after the first174 wave exposed an unsupported bootstrap assumption. The source fix is intended for a distinct signed175; this receipt does not claim175 build or acceptance.

## Independent access on test120

Target: DESKTOP-9ST5HO2,192.168.101.120, UUID943c87ef-f121-40b9-a31f-003e9459e292. Existing local administrator: test_agent_win. The selected existing administrator for other Windows devices is admin-2; no account or password is created/distributed.

Actual strict host-key-verified SSH through the independent gateway passed with Core and updater stopped and the scheduled observer disabled. Initial access survived166seconds of policy renewal without Core. A reboot at12:44:17Z was followed by reserve SSH at12:45:11Z before interactive Windows login. After login, repeated stopped-Core tests passed. Explicit key reset, old-pin rejection, wrong operator/device keys, unused port, disable,80-second expiry, token revocation, service stop and a scoped Support-only HTTPS outage were exercised. Normal restart, reenable and network restoration recovered access. The owned temporary firewall rule was removed.

The live wrong-forward-binding probe was rejected by automatic approval review with reason blocked by policy and was not executed. Read-only actual daemon/key configuration and negative broker tests verify the restricted loopback-forwarding policy; they are separate evidence, not a passed live probe.

After ordinary174 acceptance, the NEW signed Support executable was reached by SSH at15:28:47Z. Its host key matched the original approved pin. With Core/updater stopped and observer disabled, actual SSH challenges at15:32:57Z and15:34:46Z passed108.833542seconds apart, using the same Support PID9860 and exact new payload. CoreRunning, updaterStopped/Manual and observerEnabled/running were restored. Fresh WSS, observer174/174 and user telemetry returned.

All four Agent private-file hashes/SDDL, existing direct sshd configuration and firewall rule were unchanged. The reserve daemon listened only at127.0.0.1:22222. Support was Auto/LocalSystem, timestamped Valid publisher4D4C23389F5FF77BC4EB32044761019EAE8FB776; only its current executable remained in its payload directory.

## Native failure and ordinary174 update

Diagnostic173 assignment3d74b5ab-ca2b-4b41-80f6-bfecba560e6f deliberately stopped Core once during a fresh authenticated trial. Native rollback restored172;74strict SSH commands succeeded with zero errors, including Core/selector absence. Independent Support PID7020/bytes remained unchanged. A historical172 restoration continuation remained reserved. No MSI was replayed, and no selector/grant/private file was rewritten. Newly signed174 SYSTEM recovery proved the exact completed restoration and published a new derived receipt before retiring only its hold. Console settled the original173 result ROLLED_BACK/native67/pendingfalse at15:13:08Z. Its original history is preserved.

The174 controlled rollback assignment3cd5c791-8342-4e38-951e-511ce9c1a6ae then passed **automatically**, without another repair: one Core stop, exact172 restoration, parent-authenticated derived finalization, no pending native/continuation hold and normal Core restart. Console settled ROLLED_BACK/native67 at15:21:25Z.64strict SSH commands succeeded with zero errors and unchanged Support PID7020.

Ordinary174 assignmentf9c1d078-986f-458a-b49f-246906f7abff was APPLIED at15:32:04Z: native0, exact174 Core/Foundation/source/MSI, private four preserved,185.281seconds/six stable samples, one fresh UserSensor and connected WSS. Qualification909d671d-6f25-45df-b0d0-96d48ea81367 covers exact174 bytes from Foundation172 until2026-12-06T15:36:28Z. Restored observer/WSS/user freshness was required; a stale-observer qualification attempt correctly returned409 before fresh confirmation.

## Immutable174 artifact

Runtime source87e27008d070599711ed30b0418ed36090d8079e; packaging bindingb122c2d9ee0d3cb7678a13353169049d4ec961f3. Producer:C:/endpoint-platform-wix-build/setup174-restoration-87e2700. Runtime119files/tree4aa7bd7b9130b13a9510fa43b1273b9a00384daa14ca255157dc782f170b3600;291committed inputs; componentA91DC9A0-EB69-4E59-BFFA-1B1E67214AFC; epoch1793976898.

| Artifact | SHA256 | Bytes |
|---|---|---:|
| EndpointAgentSetup-3.2.174-x64.exe |28c2f4c35a45a16ffca47e8d0d91d836ecb07202dc9ca8d8d3d36de7ee7db41d|166112040|
| EndpointAgent-3.2.174-x64.msi |5711f7714072d63fd7bdf1cef243f92d77d94b51f9989342b0d0bd2429e8dfa4|124506112|
| EndpointSupportAccess.exe |8ea64e764a51ff1007b94c1abd2132bf6b082e5680d93c7cd4555f02c769f007|10089768|

All three signatures are Valid/timestamped from the existing publisher. Canonical validation against172 and all committed input hashes passed. Actual schema3 MSI/CAB, staged helper, Foundation pin and embedded removal helper agree. MSI controls only the original three Agent services; active Support is outside native ownership. Frozen Support excludes Core/updater/observer/build tooling. Frozen recovery helper, Setup CLI and wrapper match reviewed source. Native helper reuse was disabled; exact signed observer1.0.7 was retained.

Separate diagnostic FullSetup release993b6b7f-678a-4ba3-88ee-020296b20610 is not an enrollment/primary publication.

## First fleet wave and175 correction

After qualification, policy8 enabled all-active/max2. Preview: five eligible172 devices, test120 already current, six offline172 devices, one offline historical79, nine unknown historical platforms and one ALT device outside scope. Only two new assignments started.

| Host |174 assignment | Native acceptance | Support |
|---|---|---|---|
| A2-MUNSLU-N /101.27 |1fd492d4-a889-435a-9a89-881dcd26ce61|APPLIED/native0,181.909s,six samples,one sensor,private preserved|Not registered|
| A2-IAO /101.22 |1bda1d02-9d84-4881-a380-17c562b2a987|APPLIED/native0,182.687s,six samples,one sensor,private preserved|Not registered|

Root paused new assignments as policy9 at15:41:53Z; both existing chains completed normally, with maximum concurrency two. ADMIN-2, DESKTOP-2EVR855 and MUNSLU-S2 were not assigned174. Native success was not treated as Support success. Windows primary172 and all ten AUTO versions remained unchanged.

Read-only SMB with the operator's existing domain identity confirmed both machines had no optional Agent/endpoint-origin; other required private files/ACLs were present. No Support roots existed and the separate installation receipts said unavailable. Canonical Core already permits this absent override and uses its compiled HTTPS origin. Support incorrectly required the file before any dependency provisioning or registration.

Fix6b1bb2cc75f44b2b583d51d27756b596fe303efe permits only proven absence of that optional leaf and uses the identical compiled origin. Existing malformed/unreadable/reparse/unsafe overrides and the other three missing inputs remain rejected. No Agent file is fabricated and the isolated service imports no Core module. Bounded allowlisted installation error codes now survive into the separate local diagnostic receipt; arbitrary exceptions/stderr/tokens are discarded. Root185focused tests passed; independent review found no P1/P2. NEW175 signed media and actual missing-origin bootstrap remain required before resuming delivery.

Inventory also found differing OpenSSH installations. Absence of the OS server is an installer dependency condition, not proof of failure: the reviewed installer may add the Microsoft capability. UNC signature metadata cannot substitute for local catalog verification. No OS capability, SSH service/configuration, GPO or firewall was changed during inventory. Actual175 dependency provisioning and local signature checks remain live gates.

## Verification and production boundary

Fresh full project command: C:/Users/admin-2/Documents/endpoint/.venv-device-binding/Scripts/python.exe -m pytest -q —6500passed,454skipped,5warnings,874.59seconds at8488fefe6548cad99da2ade725d107e26430284a. The prior single failure was a native ChangeTime fixture race; the test now establishes an observable descriptor change before requiring the unchanged production guard to reject it. Related52tests and100fixed repetitions passed. Real PostgreSQL Support integration:2passed. Frontend:88tests/build passed. Contract generation check and final branch diff check passed. New175 changes require their own verification.

Provider438f8903f11454e2d5abc5a60d25308a88f51d10 runs on192.168.100.19 with additive migration0046_support_access and independently supervised gateway2222/exporter/broker. Existing administrator SSH22 is preserved. Per-device keys, independent bearer, strict host pins, fresh policies, expiry/revocation and audit do not depend on Core/WSS health. New policies are disabled and access requires an explicit lease of at most8hours. All TLS uses the existing CA and endpoint.sosnadmin.local.

GitNexus was unavailable after retries; source/tests verified the architecture without inferring absence of cross-repository dependencies. No Helpdesk code was modified. Linux primary156 is unchanged. Private backups, source/artifact reports, task proof, SSH challenge logs and original failure/rollback histories are retained outside Git; no credential/private key is included here.
