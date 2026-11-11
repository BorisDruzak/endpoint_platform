# Repository scope

- The primary repository for this workspace is [`BorisDruzak/endpoint_platform`](https://github.com/BorisDruzak/endpoint_platform). Treat it as the default repository for all implementation, Git, and remote operations.
- [`BorisDruzak/helpdesk`](https://github.com/BorisDruzak/helpdesk) is a secondary, read-only data source. Do not edit it, push to it, or add it as a working repository from this workspace. Its data may be consulted in a future, explicitly requested task.
- The approved local Helpdesk server-code source is `C:\Users\admin-2\CodexProjects\pc_client\server`. Use it solely to check and analyze Helpdesk code from this workspace. Changes there are prohibited: do not edit, commit, push, or create worktrees in that directory.
- The shallow, sparse, read-only snapshot at `C:\Users\admin-2\Documents\endpoint-helpdesk-agent-source`, from branch `codex/helpdesk-process-model` at commit `8be364000089d70bac3ccf9aaef4f84397ca21a7`, remains an approved limited agent-contract reference. It intentionally contains only `pc_agent/`, `shared/tool_contracts.py`, `shared/builtin_tool_descriptors.py`, `shared/redaction.py`, `pytest.ini`, `requirements-ci.txt`, and the agent capability document. Do not expand it without a demonstrated runtime or test dependency.

- On 2026-11-09 the user explicitly authorized one scoped exception: transfer
  only SSO/Worktime from Helpdesk staging to production. The accepted backport is
  `1dc2be0d358dec13b12c4861d4f43419c70672d8`, branch
  `codex/worktime-production-sso`, isolated checkout
  `C:/Users/admin-2/CodexProjects/pc_client/.worktrees/production-6cca48e5`.
  The main approved read-only server directory above remains unchanged. This
  exception does not authorize wholesale staging promotion or unrelated Helpdesk work.

# Current Worktime server deployment

- At 2026-11-09T21:06:44Z production and staging Endpoint API/worker run the same
  runtime `24461a70286ec1b70c8c08369c1ac0787aeb3087`, schema
  `0051_staging_linux_worktime`. This supersedes the provider revisions recorded
  at the historical agent-release acceptance checkpoints below; immutable
  Windows177/Linux183 artifacts and their qualifications are unchanged. The narrow
  signed108 source-recovery contract is included; no schema/configuration or
  Helpdesk deployment was performed for the186 candidate. See the
  [186 receipt](docs/verification/2026-11-10-test120-windows186-inbox-openssh.md).
- Production Helpdesk runs the scoped backport `1dc2be0d358dec13b12c4861d4f43419c70672d8`,
  schema153, with Worktime handoff enabled to the fixed production employee
  portal. Endpoint SSO/Worktime/Helpdesk login are enabled. After the user's
  missing-AD-entry report, production Helpdesk AD login was enabled and verified
  at 2026-11-09T16:59Z; its existing confidential `helpdesk-web` client uses the
  same password-level assurance as staging. Normal password login and local
  Endpoint administrators remain available. See the [AD correction receipt](docs/verification/2026-11-09-helpdesk-production-ad-entry.md).
  Confirmed Helpdesk identity bindings are still empty: the visible AD entry and
  valid provider redirect do not establish a successful employee login. Use the
  canonical authenticated administrator propose/confirm workflow and independently
  verified existing person/account/AD ownership; do not fabricate bindings.
- Main Helpdesk staging independently advanced to
  `b9361e0f04c1738b09536dcf832e201a8f5cb04f`, schema158. Its unrelated features
  were preserved. Do not describe the complete Helpdesk repositories as identical.
- No production person/binding/schedule/category or attendance facts were invented.
  Genuine production employee handoff and live native Worktime prompts remain
  distinct acceptance gates. See the [deployment receipt](docs/verification/2026-11-09-worktime-production-parity.md)
  for actual CI, database preservation, fresh accepted agent telemetry and limits.

# Canonical agent release

- Current Windows rollout checkpoint, 2026-11-11T10:52Z: policy17 is enabled
  on signed189/all_active/max2. Exact source Foundation187 is qualified through
  2026-12-11T10:27Z. Test120 applied187 to189 with native0, 185.769 seconds and
  one UserSensor. Support1.1.4 had already passed missing OpenSSH Server
  installation and the verified stock port22 rule disable on this host. The
  Windows CIM inventory probe exceeded five seconds as LocalService. Test120
  applied the signed Core190 inventory fix using temporary scoped OTA directory
  repair, with original owner and DACL restored. Core190/Foundation189 then
  reported complete x86_64 inventory and UserSensor. Actual pinned Support SSH
  passed with Core/updater stopped and observer disabled. The original service
  states were restored. Two source187 fleet chains reached native switching. The
  Core190 fix is assigned only to test120. Windows primary177/Linux183 remain
  current. See the
  [189 receipt](docs/verification/2026-11-11-test120-windows189-openssh.md).

- Historical Windows rollout checkpoint, 2026-11-10T00:09Z: policy16 remains paused
  on hidden187/all_active/max2.188/Support1.1.3 fixed the PS5.1 binding and its
  ADMIN-2 native canary accepted0/191.404seconds/sensor1, but the540second timeout
  killed the servicing witness. CBS later finalized exact Server session
  31289507_3567631198 S_OK/no reboot/no repair after about15minutes; old Support101
  remains active and original v1 receipt12f0efdddccd426f822bd3900495bbec stays
  servicing. Windows replaced the disabled nonce reservation with its standard
  Domain allow rule; global sshd remains Stopped/Manual0. Do not infer boundary
  proof from installed files, remove an unowned rule or replay Add/MSI.188 is not
  qualified/promoted.189 durable completion work is separate; missing-FoD and
  native-forward source gates remain. Do not manually prepare OS components to
  manufacture an unattended canary. Windows primary177/Linux183 remain unchanged.
  See [188 receipt](docs/verification/2026-11-10-windows188-fleet-auto.md).

- Historical fleet186 checkpoint, 2026-11-09T22:41Z: policy13 briefly enabled186/all_active/max2.
  Four fleet jobs accepted native0 and genuine telemetry, but27/22/ADMIN-2 retained
  Support1.0.1. Independent SSH on27 proved optional `endpoint-origin` absent;
  lifecycle sender incorrectly required it and retained genuine177/186 facts.
  Policy14 is now paused, running chains completed without cancellation. Do not
  promote186 or manufacture the missing file. Distinct187 must qualify actual
  affected186 and untouched177 with ordered facts, new Support and actual SSH
  before delivery resumes. Public Windows177/Linux183 remain unchanged. See
  [fleet receipt](docs/verification/2026-11-10-windows186-fleet-auto.md).

- The primary published Windows agent is **3.2.177**; the primary native ALT Linux kit is **3.2.183**. Read [`docs/releases/current-agent-release.json`](docs/releases/current-agent-release.json), [`docs/releases/linux-3.2.183-native.json`](docs/releases/linux-3.2.183-native.json) and [`docs/releases/windows-3.2.177-setup.json`](docs/releases/windows-3.2.177-setup.json) for exact bytes, sources and qualification limits. The Console Windows download serves177 and the single Windows AUTO campaign accepts fifteen immutable installer versions. Policy12 is enabled/all_active/max2 with dynamic future admission. All6 initially available Windows PCs accepted177: test120 by verified clean Setup0, the other five by APPLIED/native0 with fresh independent Support1.0.1. Six offline172 PCs await fresh reconnect; legacy79 and other unqualified/unknown sources remain unsupported. Two removed test identities remain visible and receive no new work. Preserve all historical installer bytes and prior failure receipts.
- The primary Windows installer is `C:\endpoint-platform-wix-build\setup177-lifecycle-25f2ad8\native-setup-build\releases\EndpointAgentSetup-3.2.177-x64.exe`, bound by `packaging/windows/initial-runtime-3.2.177.json`. Runtime source `25f2ad8a5e13991e4e76260da939d29aafba8674`, native packaging `d21bc3bba119a178607de6f64f620fb53eeadf01`; actual served SHA `9d06a8339c2ed3b2c563f2b5258ad9fdbef0962b6d85f79e6e88490ca7f426fc`, timestamped Valid publisher4D. Exact-source qualifications cover Foundation172 and176/client107. Provider-only parent digest fix `266e38e5c2ead35f95978da1b95cc7a4fadb2a82` compares original enrollment requests through the consumed claim; it changes no signed177 bytes. Signed Support1.0.1 remains independent of Core/observer; portable Microsoft10.4.0.0p1-Preview remains unchanged and its upstream non-production-ready limit stays explicit. This Windows177 artifact is unchanged; the separately published native Linux183 kit is described below.
- Native Linux183 is published at `/srv/endpoint-platform-distribution/alt/endpoint-alt-pilot-3.2.183-1/`, operator kit `C:/endpoint-platform-wix-build/linux178-native/kit183/endpoint-alt-pilot-3.2.183-1.tar.gz`, source `21fc543af8d4b8b24df83f29a27e4e2eeb86c268`, actual archive SHA `c5b552afa4aa27e4df73af0ce68be4ecc88729f30baf3a70e6f9d4c8c709a3f3`. Production provider `fd196e78b2c5cef00c86de79ca359147676f8b2f` uses additive49/50 only; staging `0b8ea9138011c1a4512737629d5a12b0269e4e7d` separately preserves Worktime51. Actual VM107 acceptance covers native0, same-card history/private4, modern full-wipe parent link, genuine user telemetry, expiry/revoke, manual disable through mixed online/offline rebind and root SSH with Core/updater/path stopped108.613629715seconds. See [receipt](docs/verification/2026-11-09-linux183-native-canary.md). Linux fleet rollout was not started, no global Linux enrollment campaign/network authority was created, the initial VM receipt alone does not qualify production Linux SSH; the subsequent explicit physical cohort below supplies separate acceptance. Use the native RPM coordinator, not Core-only OTA, to install privileged Support/helpers. Subsequent explicitly authorized physical105/190/210 acceptance is recorded in `docs/verification/2026-11-09-linux183-physical-cohort.md`: actual production root SSH with Core/updater stopped on each, accepted domain-user telemetry and preserved identity/domain state. The210 historical158 path required archival of an exact redundant production drop-in after canonical not-started recovery; do not generalize that administratively prepared continuation to unattended historical sources or arbitrary drop-ins. No automatic Linux fleet rollout is enabled. The historical156 kit, signatures and Core-only OTA remain immutable; the exact signed156 pair is separately registered for rollback. Historical178-182 candidates remain unqualified.
- Core **3.2.163**, source `b23857849ad5b877e67d0de3c28d297f9ae5d507`, is the current Windows preparation bridge with signed client1.0.5. Its artifact is `C:\endpoint-platform-wix-build\setup-client-3.2.163-b238578\EndpointCore-3.2.163-b238578.zip`; see [`docs/releases/core-3.2.163-setup-client.json`](docs/releases/core-3.2.163-setup-client.json). It is not a primary installer or Linux release. Historical Core162/client1.0.4 artifacts and reports remain immutable. Foundation156 uses the exact compatible Core155 return, identifier `endpoint-windows-core-3.2.155-setup-source-725739f`, before full Setup158; other qualified profiles retain Core157. Never weaken Core157's Foundation157 minimum. Preserve all failed attempt receipts.
- Windows power-context patch Core **3.2.164**, source `1c2e54a06d1a7dfb6c2c2e0d2ef2cde2d0fe9896`, requires Foundation **3.2.158**. Immutable artifact: `C:\endpoint-platform-wix-build\core164-power-1c2e54a\EndpointCore-3.2.164-1c2e54a.zip`. See [`docs/releases/core-3.2.164-power-context.json`](docs/releases/core-3.2.164-power-context.json) for actual Endpoint cohort acceptance and limits. This patch does not promote a primary installer, change Foundation158 or replace the compatible163 bridge for Foundation156. Future full Setup media must include the corrected runtime in a new, separately qualified native version; historical installer bytes remain unchanged. Explicit Core cohort assignments do not enable the disabled full-Setup fleet policy or create persistent automatic assignment for future/offline agents.
- The tested automatic Setup revision is `C:\endpoint-platform-wix-build\setup158-r3-5cb267d\releases\EndpointAgentSetup-3.2.158-r3-x64.exe`. Its wrapper source is `5cb267d3440511a62e466f49e6cc4ce80c3897a8`; native MSI/Core remain source `9423d9c27ea6b2d6c544c1bcdc1edb7cc9d15421`, bound by `packaging/windows/initial-runtime-3.2.158.json`. Exact original MSI and Core ZIP bytes are preserved. Clean Core/Foundation156 to full158 passed on test120 without workstation preparation after baseline acceptance; see [`docs/verification/2026-11-04-test120-clean156-full158.md`](docs/verification/2026-11-04-test120-clean156-full158.md). The earlier Foundation158/Core157 result remains historical. That earlier clean156 proof had no active user sensor and did not qualify its CPU/user telemetry; no Windows158 Core-only release or primary download promotion is implied.
- Unknown native outcomes keep exclusive recovery ownership; do not cancel, delete journals/cache, or replay installation. A known exit21 may settle as failed only after exact unchanged-source/private/session/180-second proof and the completed recovery return. Historical158-source preparation on test120 needed an explicitly approved owner exception; the04.11 clean156-source test required no exception or updater preparation after baseline acceptance.
- The second clean156 test with client1.0.5 automatically started UserSensor/Tray and applied full158 with native0 and183.636 seconds of stable observation, sensor_count1. Normal RDP reconnection on05.11 confirmed fresh accepted UserSensor samples and activity without a companion restart. Exact158-r3/source156 qualification872a53bc-17f3-48ac-a481-dfeaaac2f961 expires2026-12-05T04:07:57.728041Z; other source profiles are not inferred. Yandex26.10 browser telemetry remains a known issue explicitly deferred by the user, not a passed browser test. See [`docs/verification/2026-11-04-test120-usersensor156-full158.md`](docs/verification/2026-11-04-test120-usersensor156-full158.md). Fleet policy is deployed but disabled, max_parallel1. Use [`docs/runbooks/FULL_SETUP_FLEET_POLICY.md`](docs/runbooks/FULL_SETUP_FLEET_POLICY.md) for bounded waves.
- Every subsequent agent release must update this section's version/paths and the canonical record together with runtime version, Windows source binding and Linux kit metadata. Verify actual published bytes/signatures before declaring a new primary. Keep native source qualification, public enrollment, scoped bootstrap and fleet acceptance distinct.
- Existing156 on A2-INFAN-N/101.29 initially failed to bootstrap163: an Administrators-owned updates root denied LocalService the WRITE_DAC required by frozen156 before download. After explicit user authorization, a one-time owner-only repair changed that root to LocalService while preserving its exact DACL/group and private files. The same Endpoint bridge163/return155/full158 chain then applied05.11 at05:25:49Z, native0,181.622 seconds stable, fresh UserSensor/activity and completed health/inventory. This administratively prepared continuation does not qualify unattended historical156 delivery or replace the clean120 evidence; fleet remains disabled. Do not generalize version eligibility to historical ACL readiness or apply this repair elsewhere without authorization. See [`docs/verification/2026-11-05-test29-endpoint-full158.md`](docs/verification/2026-11-05-test29-endpoint-full158.md).

- The Windows enrollment download remains **3.2.165**, signed EXE `C:\endpoint-platform-wix-build\setup165-final-ed7f77a\native-setup-build\releases\EndpointAgentSetup-3.2.165-x64.exe`, source binding `packaging/windows/initial-runtime-3.2.165.json`. Its exact Foundation158-source canary120 is qualified. The original first-wave146 failure was later recovered under explicit authorization and its165 job is APPLIED; do not treat that administrative continuation as unattended source qualification.144 applied165 without an active user sensor and is currently unavailable. Fleet revision3 remains **paused**, all-active/max2 retained; current169 canary evidence is described below. This is not general fleet acceptance or a new stable-primary declaration. See [`docs/releases/windows-3.2.165-setup.json`](docs/releases/windows-3.2.165-setup.json) and [`docs/verification/2026-11-05-native-canary-recovery-execution.md`](docs/verification/2026-11-05-native-canary-recovery-execution.md). Historical disabled/max1 statements describe earlier checkpoints; Linux primary156 remains unchanged.
- Full-Setup candidate **3.2.167** failed its Console canary on101.120 after native acceptance, at companion restoration: native/staged writers serialized the same selector differently. Its signed EXE `C:\endpoint-platform-wix-build\setup167-ab31322\native-setup-build\releases\EndpointAgentSetup-3.2.167-x64.exe` and binding `packaging/windows/initial-runtime-3.2.167.json` remain immutable; see [`docs/releases/windows-3.2.167-setup.json`](docs/releases/windows-3.2.167-setup.json). Do not qualify, promote or fleet-assign167. Preserve the original120 failure history: the approved one-off continuation finished and its server job is FAILED/native21 with target recovered; no active120 native hold remains. The current165 enrollment download is unchanged. Core166 remains a distinct upward preparation candidate, not a full installer or primary release: [`docs/releases/core-3.2.166-observer-bootstrap.json`](docs/releases/core-3.2.166-observer-bootstrap.json). The original146 job completed after the explicitly authorized one-off repair; this is not unattended source qualification. Keep the fleet policy paused; a signed build/registry row is not fleet acceptance.
- Full Setup **3.2.168** fixes the selector producer and passed165-to168 on101.146 (native0,181.509 seconds, fresh UserSensor/Activity). The158-to168 canary101.27 failed before creation of the missing observer1.0.6 directory. The approved one-off recoveries on120 and27 have finished; both original jobs retain FAILED/native21 target-recovered history and no active native hold. **Do not fleet-enable or promote168.** Runtime source is `8c110e8d9b5ec9c002c4e7084eefd4bba8a8d6b3`, binding `packaging/windows/initial-runtime-3.2.168.json`, signed EXE `C:\endpoint-platform-wix-build\setup168-8c110e8\native-setup-build\releases\EndpointAgentSetup-3.2.168-x64.exe`; see [`docs/releases/windows-3.2.168-setup.json`](docs/releases/windows-3.2.168-setup.json). The future-source missing-directory fix is `d7304706263f1427b6ed267e66661a3989ecf8d6`; existing signed167/168 helpers cannot receive it implicitly. The operator explicitly authorized and completed the narrowly scoped27/120 recovery; see `docs/verification/2026-11-05-native-canary-recovery-execution.md`. Preserve grants, captures, private identity and original native21 history.
- Signed, registered update candidate **3.2.169** includes both selector and missing-observer-directory fixes. Source `4525435f1345e0d44253948f2867a0a099475f6b`, binding `packaging/windows/initial-runtime-3.2.169.json`, EXE `C:\endpoint-platform-wix-build\setup169-4525435\native-setup-build\releases\EndpointAgentSetup-3.2.169-x64.exe`; see [`docs/releases/windows-3.2.169-setup.json`](docs/releases/windows-3.2.169-setup.json). Console canary168-to169 on101.146 is APPLIED/native0 with181.528seconds and fresh user telemetry. The158/client1.0.5-to169 canary101.187 originally held recovery despite observed169/observer1.0.6 and fresh telemetry. Authorized read-only SSH diagnosis found an unresolved Foundation invariant failure and a confirmed Tray parent/child counting bug; source fix `888af5a7559af4b3e208509384eb8143ee4b6f29` addresses only the latter and is built into170; immutable169 does not contain it. **Do not fleet-enable or enrollment-promote169.** No server qualification was created. Preserve original187 native failure evidence: its local exit21 is confirmed, native continuation finished automatically after power return and the later explicit client-only107 exception closed its original job FAILED/native21 target-recovered. No active187 hold remains. Original27/120 holds are already resolved as FAILED/target-recovered. See `docs/verification/2026-11-06-setup169-187-readonly.md` and the107 recovery proposal. Broader native repair, service restart or configuration changes are not authorized by the client-only exception.

# Canonical Windows update workflow

- Hidden signed186/Support1.1.1 uses only Windows-serviced OpenSSH and observer108.
  Actual test120177/client107-to186 repeat is APPLIED/native0/185.119seconds,
  private4 and genuine user telemetry, without workstation repair for that job.
  Qualification53c243c3-c346-4000-a16e-f1dd0777b0af covers only exact186/source177,
  evidence1c0176f2-02e4-4e09-978f-c59bd14c3eeb, through2026-12-09T22:04:33.615258Z.
  Real domain SSH passed with Core/updater stopped and observer disabled, after
  owned tunnel/service crashes, bounded HTTPS authority loss and normal reboot;
  post-boot UserSensor is accepted. Keys/private4/original grant expiry survived;
  foreign global SSH/configuration/firewall are unchanged. Only120 is updated:
  download/fleet12 remain177, Linux183 unchanged. Missing-FoD provisioning and a
  real bundled-Preview migration are not live-qualified on this provisioned PC.
  Preserve the first prepared177/client108 result separately, without inferring
  unattended source qualification from it. See the [186 record](docs/releases/windows-3.2.186-setup.json)
  and [acceptance receipt](docs/verification/2026-11-10-test120-windows186-inbox-openssh.md).
- Hidden candidate184/Support1.1.0 is retained without qualification or promotion.
  Its177-to184 test120 job accepted native0/185.318seconds/private4/sensor1, but
  first Support activation compensated to1.0.1. The first-publish readiness race
  is corrected in185; later manual canonical1.1.0
  activation does not qualify unattended migration. Preserve all184 bytes and
  receipts. See docs/releases/windows-3.2.184-setup.json and
  docs/verification/2026-11-10-test120-windows184-support-first-start.md.
- Hidden185 contains that readiness fix but its real177 canary failed before MSI
  on retained-storage recapture after ordinary reinstall. Its original job is
  FAILED21/native_failed_source_restored after actual signed108/185.12seconds
  source proof; retain exact media/history. Source177 was canonically
  rolled-back/preparation_cancelled, with no MSI replay or journal/selector repair.
  New186 journals recapture before creating payload and signed108 adds read-only
  source recovery attestation. Server settlement must retain FAILED21, original
  attempt, trusted exact177 catalog, fresh108/WSS/real active-user proof; unknown
  outcomes remain held. Neither184 nor185 is qualified or promoted. See
  docs/releases/windows-3.2.185-setup.json and its verification receipt.

- Historical Full Setup **3.2.172** was built, signed, registered, source-qualified and enrollment-promoted with Foundation execution fix `d5cfb0daa61aff14f4cd4e9685c716a78300e1c3` and Power stream anchor fix `d4774f78b3a5e1ea356936171bbc46fbcb5fadc4`. Console canaries27/source170/client107 and local/source158/Core164/client105 accepted native0 without workstation preparation for these assignments.27 Power is freshREADY with durable reset8689 stable and36 original facts; counters/history were preserved. Fleet policy7 was enabled/all_active/max2 at that checkpoint; current177 policy12 above supersedes that checkpoint. Source167 was also qualified by Console canary101.120 after an ordinary user login: native0, fresh telemetry, no workstation preparation for that assignment. Total172 acceptance is12devices; known legacy101.69/source79 remains unsupported. See `docs/verification/2026-11-06-setup172-120.md`. Other exact sources require their own qualified canaries. See `docs/verification/2026-11-06-setup172-web-fleet.md` and the172 release record for its historical rollout, evidence and unresolved gates. Signed observer107, private identities and all prior native21 failure histories remain intact.

- Full Setup **3.2.171** is signed and registered as an installer candidate with Foundation execution fix `d5cfb0daa61aff14f4cd4e9685c716a78300e1c3`: accepted-native companion launch binds actual retained-handle security/attributes, identities and bytes; default reads retain strict ChangeTime guards. Signed observer107 is unchanged. The fix passed308direct Windows tests and338integration tests with1skip and independent review. Runtime `3f71f5fca8c74eefab52aacc9c1a1c4cdb6a72dd`, binding `packaging/windows/initial-runtime-3.2.171.json`, native packaging `b0d7cdb09cb34e6de3dc2f1869a85ec6ffe16ce4`; signed EXE `C:\endpoint-platform-wix-build\setup171-3f71f5f\native-setup-build\releases\EndpointAgentSetup-3.2.171-x64.exe`, record `docs/releases/windows-3.2.171-setup.json`. Console canary187 from170/client107 is APPLIED/native0 with183.381seconds, private4 preserved and fresh UserSensor/Activity; no new manual preparation or native21.171 is not enrollment-promoted, server-qualified or fleet-enabled. The independent27 Power stream anchor repair will go into a distinct full172 before mass rollout; do not overwrite171 bytes/binding. Preserve immutable170 and all prior failure histories.

- Full Setup **3.2.170** is signed and registered as an update candidate with the Tray fix, Foundation diagnostic detail and signed observer1.0.7. Runtime `bd2d736f33de5422902adca0f9d07aee40bf2ec7`, binding `packaging/windows/initial-runtime-3.2.170.json`, native packaging `800f9151ea9cff3344b2069474897425c56d0460`; signed EXE `C:\endpoint-platform-wix-build\setup170-bd2d736\native-setup-build\releases\EndpointAgentSetup-3.2.170-x64.exe`, record `docs/releases/windows-3.2.170-setup.json`. Console canary27/source168/client106 is APPLIED/native0 with181.989seconds and fresh telemetry.187/source169/client107 failed native21/change_time for Tray, then recovered automatically with183.629seconds and fresh telemetry; original failure history remains. No new workstation preparation or administrative repair was used for these170 jobs; active chains0. See `docs/superpowers/plans/2026-11-06-foundation-execution-pins.md` for the narrow follow-up using existing Core execution security/attribute proof. It is not qualified, enrollment-promoted or fleet-enabled; Windows enrollment remains165 and Linux primary156. Observer107 source `411b19625e97fd196d84bd1f4cdda28a16c0b614`, signed SHA `8a1a30e7d208fbb431e2f715967d8a21eb82eac43edbfb4e97433a83049a6247`; see `docs/releases/windows-setup-client-1.0.7.json`. Server `ce46fd47a3a929a2fe104f01fac2bc8cc619559d` accepts qualified107 with the unchanged recovered-target native21 gates.187's original native continuation completed automatically after power return; authorized107 replacement then closed its original job FAILED/native21 target-recovered with183.588seconds of fresh proof and no active chain. Do not use a Core bridge or fake pending record to change its MSI169 selection.

- Foundation diagnostic improvement `9aade90a33217c483dc11a9c051ae5dacc333d43` distinguishes path/descriptor identity and native ChangeTime failures while retaining the original strict rejection. The122 public Foundation files on187 matched the actual signed169 MSI at2026-11-06T05:16Z; this does not explain the historical metadata failure or authorize recovery. The operator reports a later power outage;187 is QEMU/SeaBIOS by saved inventory and reconnected after the reported power outage. This improvement and Tray fix888af5a are now built into the distinct170 candidate; do not imply169 contains them. See `docs/verification/2026-11-06-setup169-187-readonly.md`.

- Use one process for every new Windows full release: immutable signed build,
  candidate publication, Console canary, server qualification, coverage preview,
  persistent fleet policy, observed acceptance and primary-download promotion.
  Follow [`docs/runbooks/FULL_SETUP_FLEET_POLICY.md`](docs/runbooks/FULL_SETUP_FLEET_POLICY.md).
- Author the runtime compatibility contract before freezing initial runtime
  bytes. Bind its complete tree, reviewed source files, exact Git revision,
  toolchain and a new component GUID/version. Verify signed MSI and EXE bytes
  with the existing trusted publisher and timestamp. Never replace old packages.
- In **Releases and updates -> Full Setup**, use the single exact target through
  all numbered steps. Select the canary by computer hostname; duplicate enrollment
  campaign names are not sufficient device identity. A canary draft pins its target.
- Qualification comes only from a real accepted assignment for that EXE/source:
  native0, exact Core/Foundation/source/MSI, preserved private identity, stable
  services/companions, fresh WSS and active-user telemetry, at least180 seconds
  observed. The Console qualification action never enables the policy itself.
- After qualification, preview **all active Windows**, select **two concurrent
  chains**, enable and save. This is a persistent dynamic scope with no frozen
  UUID list: later registrations and reconnections are evaluated automatically.
  Include every trusted new installer in the single default AUTO enrollment
  campaign through the canonical transactional publisher; preserve its authority.
- Fresh WSS and Setup hello must agree before automatic native admission. Missing,
  stale or busy modern observers and discordant versions wait for confirmation;
  they must not trigger a legacy bridge, poison a device or pause the whole fleet.
  Preserve the existing controlled legacy preparation/return path.
- After a three-minute WSS grace, an absent/stale observer on Core163–165 and
  Foundation158–165 may use only registered upward Core166, then a distinct full
  Setup newer than166. Require applied child, fresh matching observer1.0.6 and
  WSS, and recheck exact EXE/source qualification before automatic handoff. Do
  not replace a recently busy observer or reuse the same staged version slot.
- Enter a bounded public reason using ordinary letters, numbers and simple punctuation. The existing prose validator rejects slashes and diagnostic-shaped text before creating an assignment; correct the description rather than changing workstation state.
- Keep exact-source qualification and its expiry visible. Unsupported sources
  remain blocked with a reason. Global slots include manual/recovery chains;
  real failure pauses new work. Never replay MSI or clear an unknown native outcome.
- Verify actual assignments and fresh telemetry after update; heartbeat/version
  alone is not acceptance. Promote the Windows download only after native canary
  acceptance and verified served bytes. Keep Linux release/version separate.
- Independent diagnostic access introduced by Setup176 is retained in signed177/Support1.0.1
  through a separate outbound SSH tunnel, per-device keys, strict host verification,
  temporary policy, expiry/revocation and audit. Active Support/runtime/state are
  outside MSI/Core/observer ownership. See the [support spec](docs/superpowers/specs/2026-11-05-pilot-support-tunnel.md)
  and [live receipt](docs/verification/2026-11-06-independent-support-access.md).
  Installation defaults may authorize a new/pristine installation automatically
  after a successful running Support1.0.1 report, using the explicitly configured
  existing administrator and approved operator keys for at most8hours. Manual
  disable/revoke/reset and existing per-device policies take precedence; retries
  never renew an expired or consumed initial grant. Historical176 SSH passed on five devices.
  Current177 actual SSH is verified on120 with Core/updater/observer stopped;
  fresh component status on other updated devices is not an administrator SSH proof.
  Never infer working administrator access from agent version or tunnel alone.


# Confirmed removal and retained installation identity

- Setup177 records native installed/removed facts only after known native0 through
  the authenticated protected owner. Notifications run after owner/mutex cleanup
  in a bounded notification-only child. Keep native result, cleanup result and
  server delivery separate; no background sender remains after uninstall.
- Ordinary uninstall retains the four private identity files and does not retire
  the Device or revoke its credential. Reinstall uses the same UUID/card/history.
  A confirmed removed card remains visible, blocks new work and is not resurrected
  by heartbeat. Offline removal is pending until delivered; future Setup flushes
  removed before installed. Never invent a removal from missing heartbeat.
- Native uninstall must release exact owned browser values before deleting their
  ownership markers. Preserve foreign values and unknown-native recovery evidence.
  The earlier manual purge caused UserSensor rejection; current177 clean install
  and post-Core-restart genuine samples are verified in
  docs/verification/2026-11-07-test120-installation-lifecycle177.md.
- Full wipe is separately authorized: require known native0, complete owned
  cleanup and server-received removal before archiving/purging active roots.
  Preserve old history and revoke the lost credential with audit. Keep the removed
  historical parent nonretired. Canonical approval of the fresh request may link
  previous_device_id only through its consumed claim and matching original
  enrollment request; compare request-domain fingerprints, never Claim/Request
  digests from different HMAC contexts. No credential/history merge or fingerprint
  bypass is permitted. Missing prior request or mismatched identity fails closed.
- Reinstall Support key rebind is one-use, tied to the exact native sequence and
  unchanged source credential/policy revision/generation. Manual disable/revoke/
  reset wins. Automatic access is bounded and is never renewed by replay/polling.
  A changed SSH host key must still fail strict checking until the authorized
  reinstall and new authenticated binding are verified; archive the old public
  pin and change only that UUID's pin. Do not use scans or disable host checking.
- Candidate-only Windows publication keeps primary download visibility separate
  from trusted native proof/default AUTO eligibility. Normal canonical same-row
  promotion is one-way and audited; preserve immutable metadata, campaign authority
  and source qualification. After a hidden candidate exists, rollback must retain
  the visibility filter or explicitly retire it; do not revert to exposing it.

# Reserve connection during agent or updater incidents

- Corrected clean176 acceptance on120 passed native0, advancing genuine user
  samples and actual domain SSH with Core/updater/observer stopped; see
  [cause and repeat receipt](docs/verification/2026-11-07-test120-usersensor-cause-clean176.md).
  The earlier manual purge removed browser-policy ownership markers while leaving
  their owned values, causing POLICY_CONFLICT and rejected sensor samples.
  Never recursively purge product ownership metadata before exact owned-policy
  cleanup. Preserve foreign values and native recovery evidence; a running sensor
  or READY listener alone does not prove accepted telemetry.

- When authorized Endpoint diagnosis/update work cannot be completed using
  available telemetry, server logs or update receipts, use the independent
  support channel to inspect the affected Windows PC. Do not stop at an absent
  heartbeat or treat a stopped Core/updater as proof the PC is unreachable.
- This diagnostic connection, and bounded policy enable/renewal using the existing
  approved operator key and verified Windows administrator, are authorized within
  the user's requested incident scope. Do not ask the user to repeat that
  authorization solely because Core or the update observer is unavailable.
- Full Setup must install/start EndpointSupportAccess as an independent Auto
  LocalSystem service. Production installation defaults authorize first access
  after a healthy Support1.0.1 report; use existing SOSNADM\admin-2 for domain
  PCs and preserve existing explicit local-account policies. The historical
  test120/test_agent_win registration was retired during the authorized clean
  reinstall; current120 uses SOSNADM\admin-2 and Devicec87eaa22-4fd1-4830-bc11-88142afda87e.
  No guessed account, password creation, permanent grant or automatic lease
  renewal is implied. Initial grants are at most8hours; subsequent diagnostic
  access can be enabled centrally without a working Core/updater.
- Open the exact Device UUID card in Endpoint -> Devices -> Support access,
  including when ordinary agent state is offline. Check independent installed
  state, report time, expiry and current approved key/account. If necessary,
  enable/renew a temporary policy with a diagnosis reason using existing admin
  scope; do not override an explicit manual refusal/revocation without authority.
- Read Device UUID, remote loopback port and host public key together from that
  authenticated card/API. Verify strict gateway and UUID-bound workstation SSH
  host keys. Use tools/support/Connect-EndpointSupport.ps1; never accept a scan
  or silently replace a changed host key. The operator uses the gateway's normal
  existing SSH alias, not the device's outbound2222 tunnel identity.
- Begin with read-only evidence: hostname/administrator identity, relevant
  services/tasks/processes and bounded logs. Perform only repairs already within
  the requested scope, retain before/after proof and restore task-related state.
  Reserve access does not authorize replaying MSI, clearing unknown native
  journals/recovery ownership, replacing private identities/keys or rewriting
  grants/selectors as an access workaround.
- Registration, a connected tunnel and an actual successful administrator command
  are separate states. Record the last as an operator attestation only after a
  real command. If the independent service, Windows/network or gateway is itself
  unavailable, report that specific blocker rather than claiming access works.
- Follow docs/runbooks/INDEPENDENT_SUPPORT_ACCESS.md for Console controls,
  automatic-install bounds, strict SSH commands, expiry and cleanup. Keep secrets
  out of source/logs/reports; never upload operator/device private keys.

- Apply the same diagnostic escalation to native Linux183 when telemetry/logs/receipts
  cannot resolve the authorized incident: use independent `endpoint-support-access.service`
  even with Core/updater stopped. Production first-install defaults explicitly bind
  existing `root`/UID0 and the approved operator key for at most8hours after a healthy
  Support1.0.0 report; later bounded diagnostic enable/renew is centrally authorized
  within the requested incident. Existing manual policies/revoke/reset win; do not
  create accounts, passwords, sudoers changes, permanent grants or automatic renewals.
  Read Linux Device UUID, loopback port, administrator name/UID and public host key
  together from the authenticated card. Follow the strict ordinary-gateway SSH
  command in [Linux native Setup](docs/runbooks/LINUX_NATIVE_SETUP.md); the Windows
  connection helper retains its Windows-only contract. A real root command is
  proven on Stage VM107 and explicitly selected physical105/190/210 only; do not infer acceptance on other devices.
- Preserve explicit disabled-policy provenance across online/offline Linux native
  reinstall. Only exact one-use native tickets and authenticated audited authority
  may rebind keys. Unmarked/missing history, intervening policy/revoke/reset or
  credential/revision/generation mismatch fails closed. Never backfill causal
  events, edit fingerprints or change private keys as a diagnostic shortcut.

# Production host

- Historical first clean176/automatic Support evidence is preserved in
  `docs/verification/2026-11-07-test120-clean176-support.md`; its UserSensor failure
  was not a passed user-telemetry test. Later cause proof identified the manual
  ownership-marker purge and repeated clean176 successfully; see the corrected
  cause receipt. Current177 clean/native0, genuine before/after Core-stop samples,
  automatic eight-hour grant and actual independent domain SSH for96.908636seconds
  are accepted in `docs/verification/2026-11-07-test120-installation-lifecycle177.md`.
  Keep historical failed evidence, exact-source qualifications and Linux156 separate.

- Publish every new trusted Windows agent/installer release into the single active default Windows auto-enrollment campaign by default. Use the canonical publisher's transactional campaign inclusion; preserve its CIDRs, expiry, quota and usage. Any explicit diagnostic exclusion must be documented. Never create a separate version-specific campaign or expand network authority merely to publish a version. Historical expired/revoked campaigns retain their audit history. Linux native sources use the separate platform-bound native registry and separately approved Linux campaign authority; never insert a Linux source into a Windows policy or create/expand a campaign merely to publish a kit.

- `osn_admin@192.168.100.19` (SSH host alias: `endpoint-platform-server`) is the production machine for the Endpoint Platform service.
- Use this host for live testing and verification when that is necessary to complete the task. Treat changes, deployments, service restarts, configuration changes, and data changes as production operations.
- The `endpoint.sosnadmin.local` DNS record is configured. The Endpoint Platform CA certificate is available on the operator workstation at `C:\Users\admin-2\Desktop\РќРѕРІР°СЏ РїР°РїРєР° (2)\С‚РµС…\СЃРµСЂС‚РёС„РёРєР°С‚\sosnadmin-local-ca.crt`; treat it as deployment input and do not commit it. Do not work around DNS/TLS with an IP address or by disabling TLS verification.
- PostgreSQL and Nginx installation and configuration on this host are part of the Endpoint Platform deployment work. Perform them when the deployment assets are ready, rather than before the application is ready to deploy.
- Disk resize is cancelled. Re-check actual available capacity at the deployment gate and proceed only if it is sufficient for the verified deployment footprint; do not schedule or wait for a resize.
- `openvpm@192.168.100.30` (SSH host alias: `ui-vpn-deploy`) is the production host for the network web panel. Use it for necessary live testing and verification; treat changes, deployments, service restarts, configuration changes, and data changes as production operations.

# Related production repositories

- [`BorisDruzak/web_ovpn`](https://github.com/BorisDruzak/web_ovpn) is the repository for the network web panel hosted on `192.168.100.30`.
- [`BorisDruzak/network_configuration`](https://github.com/BorisDruzak/network_configuration) contains the network configuration associated with that panel.

# Test host

- The current dedicated Linux canary is pve1/VM107 `test-agent-lin`, hardware UUID
  `db12fb5c-3732-487f-911f-80e31f79b29b`, hostname `alt-a2-pc86.sosnadmin.local`,
  DHCP IPv4 `192.168.101.191`. Historical162 aliases are stale until freshly checked.
  Its ordinary `osn-admin` has no sudo; do not add it. Existing root is explicitly
  approved through the independently pinned support channel; the trusted hypervisor
  guest agent remains a separate administrative recovery path.
- VM107 stays enrolled on staging. Current Device
  `5c51cb65-4ccd-4f19-87bc-b06c088d1e1a`/generation
  `48238935-7663-4ac3-8102-fe978093d0e6` has native183 sequence11/ACK11 and genuine
  active-user telemetry. Modern previous-card link points to
  `ebd42535-32e7-4443-95a4-20da3cb0b157`; legacy29a8 history remains separate after
  canonical fingerprint refusal. Preserve all historical private archives/receipts.
  Dedicated native tests/restarts are authorized when required; preserve AD, CUPS,
  user applications and the active KDE session. No reboot/logout/input injection
  or unrelated production-workstation changes are implied.
