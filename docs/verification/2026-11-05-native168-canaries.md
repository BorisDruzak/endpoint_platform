# Native168 canaries and observer directory failure

## Result

146 completed165-to168 through Console with no workstation preparation for this
transition. Both native/Core168 and active-user telemetry were accepted.
27 exposed a separate cold observer-provisioning defect on158-to168 with the old
1.0.5 caller. Do not promote or fleet-enable168. Original167/120 and168/27
exit21 jobs and native recovery ownership are preserved. Policy remains disabled,
revision3/all_active/max_parallel2, with both slots occupied by those holds.

The original146165 recovery used the earlier explicitly authorized administrative
exception. It is separate from the subsequent clean delivery of168; it does not
prove that every historically broken165 source can self-repair.

## Immutable build and distribution

Runtime source8c110e8d9b5ec9c002c4e7084eefd4bba8a8d6b3;
Windows packaging53a7cc4ae344ed1411fa616f6d83f0b6b7074f0c.
Producer `C:\endpoint-platform-wix-build\setup168-8c110e8`.
All280 committed source bindings and119 frozen payload files verified.
All native helpers rebuilt; no helper reuse. Core and native helper archives
contain the canonical selector call; the continuation grant reader is unchanged.

| Artifact | SHA256 | Bytes |
| --- | --- | --- |
| EndpointAgentSetup-3.2.168-x64.exe | bb48b95a10dbae2f054686b5660a2e293ad96ffec84856cb2ece042d76b66ca6 | 146248016 |
| EndpointAgent-3.2.168-x64.msi | cb7b8dafc404b665405f589926ff536abf6ddfcf4dac12d9539dd4d4ab394c2a | 104435712 |

Both Authenticode signatures Valid and timestamped, publisher
4D4C23389F5FF77BC4EB32044761019EAE8FB776. Native helper SHA256
6679742c57db6df1c2513578119d738fc116622001f0e41b0bd35c62e8d2f231,
438 modules/112 members, build tools absent. Packaged observer remains the
immutable signed1.0.6/f6359376cac7f5a5de6476ed9c41ea652fb95fe7e64c285d1ff2eaa8f6b0b069.
Root-owned server artifact copies were atomically published without overwriting
historical versions and rehashed before canonical registration.

Full-Setup release6e9b355c-15cd-4756-973a-70cef6a80b04. Enrollment registry/default
download165 and default AUTO campaign were unchanged; this is an update candidate,
not a new enrollment-primary declaration. Fresh standalone native enrollment168,
Core166 absent-observer preparation and general fleet acceptance are unverified.
The separately designed outgoing support tunnel is not included or installed.

## Server policy retry

Server75adbf4b414fb5e9d65622a5b0b32a6f6f1c7dc4 deployed at
`/opt/endpoint-platform/releases/endpoint-platform-75adbf4b414f`.
Archive94dd94282e3f3c05578b22373cf06dc7bcff08c3f0d8aa1fe50b19b24f7e3b4e.
Existing exact dependency constraints preserved; pip check, configured import
and Alembic current passed. Schema0045 unchanged. API/worker active; canonical
DNS/CA/hostname TLS health200/databaseok. Previous773f2dbeeee5 retained for rollback.

Repeated ERROR/BROWSER_POLICY_HELPER_UNAVAILABLE reports at13:12:59 and13:13:59
proved bounded delivery was functioning, but the existing146 helper still failed.
Full Setup168 subsequently restarted/replaced native services and the unchanged
telemetry policy was genuinely APPLIED at13:26:30.790688Z. The server retry alone
is not credited with restoring the old helper. No telemetry policy was disabled.

## Accepted146 transition

- Device00aa5779-d229-4dce-a28c-1e668819eed2 / A2-MUNSLU-S1.
- Exact target/device values checked in Console before assignment.
- Job113c1719-def9-41ee-8960-e7037d44fac4, attempt
  034099c3-d0c8-40f8-8281-c7b5cfe93179; assigned13:24:19.494112Z.
- Source Core/Foundation165, caller1.0.6; no SSH/manual preparation for168.
- APPLIED13:30:50.426427Z, `setup_post_restart_confirmed`, native accepted/0.
- Native/Core/provenance/services verified; pendingfalse; companions restored.
- Four private credential/identity/origin/CA records preserved.
- 181.509 seconds/six samples/one UserSensor/max sensor CPU0.0043%; stable
  services, companions and endpoint connection.
- Fresh client1.0.6 reporting168/168, fresh UserSensor and Activity intervals.
- Console-qualified Foundation165 source at13:31:17.480947Z, qualification
  f9f2ffb1-7b9a-4a05-bac1-8c89db4b68ce, expiry2026-12-05.

Screenshot: operator evidence `C:\Temp\endpoint-setup165-20261105\setup168-146-accepted.jpg`.
No Yandex extension heartbeat or physical USB/print event is claimed; those
checks are separate from Activity and source-ready health indicators.

## Failed27 transition and actual cause

- Device13f38b93-cc73-4130-b58c-41f534b1893e / A2-MUNSLU-N.
- Jobe41d9fe1-628c-4279-b224-b7a4f55e7b99, attempt
  91899f50-0c7b-439b-a741-ddb8d2329aa4, assigned13:31:43.340898Z through Console.
- Source Core164/Foundation158/caller1.0.5; no SSH/manual update preparation.
- Native operation1eeb0682-f3ac-4b79-8edf-eafdd5df8d83 reached accepted, but
  original exit21 at13:35:19.5132259Z; recovery_required/native_exit_requires_recovery.
- Core/Foundation168 and policy APPLIED, but no new1.0.6 directory and no fresh
  UserSensor/Activity after native switch. This is not a passing update.

Read-only SMB verified enrollment identity, protected existing observer roots,
private grant selection and exact cached Setup/MSI/script digests. Candidate
selector7e07a3b9fd3429598df39c6b9db7ec01b1dfad709e41903acd66b9d4a73fce4e
and previous7e67a54eda493308256cb844c39ead5f5146c574584305482ccfe910b377d79c
exactly match the immutable grant; normalized candidate tree is
3b32a57eb9ae7e4e05e2ee297023d0aaad477f31e00883e977868c45ca3e4c21.
The selector fix worked. Native continuation recovery and staged-owner adoption
also succeeded; companion restoration failed again.

New EventLog RPC/DCOM was unavailable and the live EVTX was locked. Read-only
legacy `win32evtlog.OpenEventLog` through the existing domain SMB channel obtained
Application event1001, source `Endpoint Platform Installer`. Its sanitized
frames identify FileNotFoundError/winerror2:

`provision_packaged_observer:187 -> _administrative_directory:74 ->
assert_namespace_security:154 -> reject_reparse_ancestors:158`.

The old helper validates the missing version directory before mkdir. Existing
1.0.6 on146 hid this cold provisioning defect. The future-source fix validates
the existing parent with include_self=True first, then retains the exact child
protection/namespace checks after creation. Shared fence/reparse semantics,
grant/capture/MSI authority, existing root ACLs and old1.0.5 bytes are unchanged.
No GPO cause is supported by this exception.

## Changes and verification

| Commit | Message | Files / checks |
| --- | --- | --- |
| 436f8a1959f2574faa8fefbfaae2f04e22c63add | fix(policy): retry transient browser helper unavailability | delivery.py + policy delivery tests;86 focused canonical Python3.12 tests, contract generator check |
| f5e6f33c94798296cbe6f0ddcdd1831987946d27 | fix(windows): preserve native selector bytes through staged trial | staged_trial_proof.py + native continuation tests;219 Windows tests; independent review |
| 75adbf4b414fb5e9d65622a5b0b32a6f6f1c7dc4 | docs(updates): record repaired146 and failed167 canary | AGENTS, canonical/165/167 records, plan and verification checkpoint; JSON/diff checks; server npm ci/typecheck/build passed |
| 8c110e8d9b5ec9c002c4e7084eefd4bba8a8d6b3 | build(agent): stage full Setup3.2.168 selector correction | version.py;50 focused packaging tests |
| 53a7cc4ae344ed1411fa616f6d83f0b6b7074f0c | build(windows): bind Setup168 to canonical selector runtime | immutable168 binding, candidate/canonical records and AGENTS;280 source bindings/119 payload files,40 packaging tests |
| d7304706263f1427b6ed267e66661a3989ecf8d6 | fix(windows): create missing native observer version directory | native_setup_observer.py + native continuation tests;178 Windows tests; independent review |

The missing-child regression reproduced the exact live FileNotFoundError before
the fix. Seven added cases cover live mutation scope, unsafe parent, file,
ordinary/broken reparse points, protected existing roots and complete105-to106
provisioning. Authenticode/Scheduler boundaries are mocked in the provisioning
test; signature bytes and real native acceptance remain separate gates.
`git diff --check` passed before each commit. No push or PR was performed.

## Outstanding recovery boundary

Source fixes do not mutate already-signed167/168 helpers. Narrow administrative
recovery for27/120 is being prepared for review; no such exception has been
authorized or applied on these two hosts. It must preserve original grants,
captures, native exit21 and job history, and use only original cached native
recovery rather than replaying MSI. A truthful mechanism to reconcile an accepted
target after recovered continuation is also required before releasing server
ownership; an observed version or manually written APPLIED/native0 is forbidden.
