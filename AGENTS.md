# Repository scope

- The primary repository for this workspace is [`BorisDruzak/endpoint_platform`](https://github.com/BorisDruzak/endpoint_platform). Treat it as the default repository for all implementation, Git, and remote operations.
- [`BorisDruzak/helpdesk`](https://github.com/BorisDruzak/helpdesk) is a secondary, read-only data source. Do not edit it, push to it, or add it as a working repository from this workspace. Its data may be consulted in a future, explicitly requested task.
- The approved local Helpdesk server-code source is `C:\Users\admin-2\CodexProjects\pc_client\server`. Use it solely to check and analyze Helpdesk code from this workspace. Changes there are prohibited: do not edit, commit, push, or create worktrees in that directory.
- The shallow, sparse, read-only snapshot at `C:\Users\admin-2\Documents\endpoint-helpdesk-agent-source`, from branch `codex/helpdesk-process-model` at commit `8be364000089d70bac3ccf9aaef4f84397ca21a7`, remains an approved limited agent-contract reference. It intentionally contains only `pc_agent/`, `shared/tool_contracts.py`, `shared/builtin_tool_descriptors.py`, `shared/redaction.py`, `pytest.ini`, `requirements-ci.txt`, and the agent capability document. Do not expand it without a demonstrated runtime or test dependency.

# Canonical agent release

- The primary published Windows agent is **3.2.176**; ALT Linux remains **3.2.156**. Read [`docs/releases/current-agent-release.json`](docs/releases/current-agent-release.json) and [`docs/releases/windows-3.2.176-setup.json`](docs/releases/windows-3.2.176-setup.json) for exact bytes, sources and qualification limits. The Console download serves176 and the single Windows AUTO campaign accepts eleven immutable installer versions. Policy10 is enabled/all_active/max2 with dynamic future admission. All six currently online Windows devices accepted native0 and healthy independent Support1.0.1; six offline172 devices await fresh reconnect. Legacy79 and unqualified sources remain unsupported. Historical173/174/175 diagnostics were not enrollment/AUTO promoted; all prior artifacts and failures remain.
- The primary Windows installer is `C:\endpoint-platform-wix-build\setup176-bundled-03143de\native-setup-build\releases\EndpointAgentSetup-3.2.176-x64.exe`, bound by `packaging/windows/initial-runtime-3.2.176.json`. Runtime source `03143de5005201837c58a2f0955d714e7026a2eb`, native packaging `be3ea71493af47229320c8f4ee5206b33631ce39`; actual served download SHA `e0e3289fbdda59a368d01931518a38c6e1003a0be74002cf9e7313491101f6f8`, timestamped Valid publisher4D. Exact-source qualifications cover Foundation175 and172 only. Signed Support1.0.1 is independent of Core/observer; missing OS SSH uses the pinned Microsoft10.4.0.0p1-Preview private runtime. The upstream Preview/non-production-ready limit is explicit. Linux kit/source/metadata remain156 unchanged.
- The primary Linux kit remains `C:\endpoint-platform-wix-build\unified-3.2.156\linux-kit\endpoint-alt-pilot-3.2.156-1.tar.gz`, published under `/srv/endpoint-platform-distribution/alt/endpoint-alt-pilot-3.2.156-1/`. Historical158 ALT singleton/kit evidence remains in the separate158 record; this Windows auto-update task publishes no new Linux release.
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

- Historical Full Setup **3.2.172** was built, signed, registered, source-qualified and enrollment-promoted with Foundation execution fix `d5cfb0daa61aff14f4cd4e9685c716a78300e1c3` and Power stream anchor fix `d4774f78b3a5e1ea356936171bbc46fbcb5fadc4`. Console canaries27/source170/client107 and local/source158/Core164/client105 accepted native0 without workstation preparation for these assignments.27 Power is freshREADY with durable reset8689 stable and36 original facts; counters/history were preserved. Fleet policy7 was enabled/all_active/max2 at that checkpoint; current176 policy10 above replaces it. Source167 was also qualified by Console canary101.120 after an ordinary user login: native0, fresh telemetry, no workstation preparation for that assignment. Total172 acceptance is12devices; known legacy101.69/source79 remains unsupported. See `docs/verification/2026-11-06-setup172-120.md`. Other exact sources require their own qualified canaries. See `docs/verification/2026-11-06-setup172-web-fleet.md` and the172 release record for its historical rollout, evidence and unresolved gates. Signed observer107, private identities and all prior native21 failure histories remain intact.

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
- Independent diagnostic access is implemented in signed Setup176/Support1.0.1
  through a separate outbound SSH tunnel, per-device keys, strict host verification,
  temporary policy, expiry/revocation and audit. Active Support/runtime/state are
  outside MSI/Core/observer ownership. See the [support spec](docs/superpowers/specs/2026-11-05-pilot-support-tunnel.md)
  and [live receipt](docs/verification/2026-11-06-independent-support-access.md).
  Installation defaults may authorize a new/pristine installation automatically
  after a successful running Support1.0.1 report, using the explicitly configured
  existing administrator and approved operator keys for at most8hours. Manual
  disable/revoke/reset and existing per-device policies take precedence; retries
  never renew an expired or consumed initial grant. Actual SSH passed on five devices,
  including120 with Core/updater stopped; VM registration is not an SSH proof.
  Never infer working administrator access from agent version or tunnel alone.


# Reserve connection during agent or updater incidents

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
  reinstall; current120 uses SOSNADM\admin-2 and Device06143264-1b7b-42e7-990f-7f8e1292491b.
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

# Production host

- Clean176/automatic Support acceptance on120 is recorded in
  `docs/verification/2026-11-07-test120-clean176-support.md`: native0, new identity
  and keys, automatic eight-hour grant and real domain SSH with Core/updater
  stopped for96seconds. UserSensor samples were not accepted after the controlled
  Core restart despite an active session and READY listener; a bounded sensor
  restart did not resolve it. Do not call complete user telemetry qualified or
  attribute its cause to initial installation without further evidence. Existing
  signed176/source172/175 update qualification and Linux156 remain separate.

- Publish every new trusted agent/installer release into the single active default auto-enrollment campaign by default. Use the canonical publisher's transactional campaign inclusion; preserve its CIDRs, expiry, quota and usage. Any explicit diagnostic exclusion must be documented. Never create a separate version-specific campaign or expand network authority merely to publish a version. Historical expired/revoked campaigns retain their audit history.

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

- `test-agent-lin@192.168.101.162` (SSH aliases: `test-agent` and `test-agent-lin`) is a dedicated non-production test machine for installing, reinstalling, and validating the Endpoint Platform agent and related functionality.
- Use this host proactively for agent and integration tests. Changes, service restarts, and test data on this machine are permitted when they are needed for the task. SSH key authentication and passwordless `sudo` are configured for `test-agent-lin`.
