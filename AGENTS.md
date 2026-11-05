# Repository scope

- The primary repository for this workspace is [`BorisDruzak/endpoint_platform`](https://github.com/BorisDruzak/endpoint_platform). Treat it as the default repository for all implementation, Git, and remote operations.
- [`BorisDruzak/helpdesk`](https://github.com/BorisDruzak/helpdesk) is a secondary, read-only data source. Do not edit it, push to it, or add it as a working repository from this workspace. Its data may be consulted in a future, explicitly requested task.
- The approved local Helpdesk server-code source is `C:\Users\admin-2\CodexProjects\pc_client\server`. Use it solely to check and analyze Helpdesk code from this workspace. Changes there are prohibited: do not edit, commit, push, or create worktrees in that directory.
- The shallow, sparse, read-only snapshot at `C:\Users\admin-2\Documents\endpoint-helpdesk-agent-source`, from branch `codex/helpdesk-process-model` at commit `8be364000089d70bac3ccf9aaef4f84397ca21a7`, remains an approved limited agent-contract reference. It intentionally contains only `pc_agent/`, `shared/tool_contracts.py`, `shared/builtin_tool_descriptors.py`, `shared/redaction.py`, `pytest.ini`, `requirements-ci.txt`, and the agent capability document. Do not expand it without a demonstrated runtime or test dependency.

# Canonical agent release

- The primary published agent version remains **3.2.156** for Windows and ALT Linux. Read [`docs/releases/current-agent-release.json`](docs/releases/current-agent-release.json) for exact publication source, signed artifacts and compatibility limits.158 qualification is preserved separately in [`docs/releases/agent-3.2.158.json`](docs/releases/agent-3.2.158.json). That156 primary checkpoint is historical. The current enrollment download is candidate165 and the single Windows AUTO campaign accepts nine immutable installer releases. Fleet is paused after the first165 wave; see the current165 record below.
- The primary Windows installer is `C:\endpoint-platform-wix-build\staged-3.2.156-6ed41cd\native-setup-build\releases\EndpointAgentSetup-3.2.156-x64.exe`, bound by `packaging/windows/initial-runtime-3.2.156.json`. This is the historical156 primary artifact; the enrollment page now serves published candidate165, whose fleet acceptance is incomplete. Foundations older than156 require full signed Setup before Core-only156.
- The primary Linux kit remains `C:\endpoint-platform-wix-build\unified-3.2.156\linux-kit\endpoint-alt-pilot-3.2.156-1.tar.gz`, published under `/srv/endpoint-platform-distribution/alt/endpoint-alt-pilot-3.2.156-1/`. Historical158 ALT singleton/kit evidence remains in the separate158 record; this Windows auto-update task publishes no new Linux release.
- Core **3.2.163**, source `b23857849ad5b877e67d0de3c28d297f9ae5d507`, is the current Windows preparation bridge with signed client1.0.5. Its artifact is `C:\endpoint-platform-wix-build\setup-client-3.2.163-b238578\EndpointCore-3.2.163-b238578.zip`; see [`docs/releases/core-3.2.163-setup-client.json`](docs/releases/core-3.2.163-setup-client.json). It is not a primary installer or Linux release. Historical Core162/client1.0.4 artifacts and reports remain immutable. Foundation156 uses the exact compatible Core155 return, identifier `endpoint-windows-core-3.2.155-setup-source-725739f`, before full Setup158; other qualified profiles retain Core157. Never weaken Core157's Foundation157 minimum. Preserve all failed attempt receipts.
- Windows power-context patch Core **3.2.164**, source `1c2e54a06d1a7dfb6c2c2e0d2ef2cde2d0fe9896`, requires Foundation **3.2.158**. Immutable artifact: `C:\endpoint-platform-wix-build\core164-power-1c2e54a\EndpointCore-3.2.164-1c2e54a.zip`. See [`docs/releases/core-3.2.164-power-context.json`](docs/releases/core-3.2.164-power-context.json) for actual Endpoint cohort acceptance and limits. This patch does not promote a primary installer, change Foundation158 or replace the compatible163 bridge for Foundation156. Future full Setup media must include the corrected runtime in a new, separately qualified native version; historical installer bytes remain unchanged. Explicit Core cohort assignments do not enable the disabled full-Setup fleet policy or create persistent automatic assignment for future/offline agents.
- The tested automatic Setup revision is `C:\endpoint-platform-wix-build\setup158-r3-5cb267d\releases\EndpointAgentSetup-3.2.158-r3-x64.exe`. Its wrapper source is `5cb267d3440511a62e466f49e6cc4ce80c3897a8`; native MSI/Core remain source `9423d9c27ea6b2d6c544c1bcdc1edb7cc9d15421`, bound by `packaging/windows/initial-runtime-3.2.158.json`. Exact original MSI and Core ZIP bytes are preserved. Clean Core/Foundation156 to full158 passed on test120 without workstation preparation after baseline acceptance; see [`docs/verification/2026-11-04-test120-clean156-full158.md`](docs/verification/2026-11-04-test120-clean156-full158.md). The earlier Foundation158/Core157 result remains historical. That earlier clean156 proof had no active user sensor and did not qualify its CPU/user telemetry; no Windows158 Core-only release or primary download promotion is implied.
- Unknown native outcomes keep exclusive recovery ownership; do not cancel, delete journals/cache, or replay installation. A known exit21 may settle as failed only after exact unchanged-source/private/session/180-second proof and the completed recovery return. Historical158-source preparation on test120 needed an explicitly approved owner exception; the04.11 clean156-source test required no exception or updater preparation after baseline acceptance.
- The second clean156 test with client1.0.5 automatically started UserSensor/Tray and applied full158 with native0 and183.636 seconds of stable observation, sensor_count1. Normal RDP reconnection on05.11 confirmed fresh accepted UserSensor samples and activity without a companion restart. Exact158-r3/source156 qualification872a53bc-17f3-48ac-a481-dfeaaac2f961 expires2026-12-05T04:07:57.728041Z; other source profiles are not inferred. Yandex26.10 browser telemetry remains a known issue explicitly deferred by the user, not a passed browser test. See [`docs/verification/2026-11-04-test120-usersensor156-full158.md`](docs/verification/2026-11-04-test120-usersensor156-full158.md). Fleet policy is deployed but disabled, max_parallel1. Use [`docs/runbooks/FULL_SETUP_FLEET_POLICY.md`](docs/runbooks/FULL_SETUP_FLEET_POLICY.md) for bounded waves.
- Every subsequent agent release must update this section's version/paths and the canonical record together with runtime version, Windows source binding and Linux kit metadata. Verify actual published bytes/signatures before declaring a new primary. Keep native source qualification, public enrollment, scoped bootstrap and fleet acceptance distinct.
- Existing156 on A2-INFAN-N/101.29 initially failed to bootstrap163: an Administrators-owned updates root denied LocalService the WRITE_DAC required by frozen156 before download. After explicit user authorization, a one-time owner-only repair changed that root to LocalService while preserving its exact DACL/group and private files. The same Endpoint bridge163/return155/full158 chain then applied05.11 at05:25:49Z, native0,181.622 seconds stable, fresh UserSensor/activity and completed health/inventory. This administratively prepared continuation does not qualify unattended historical156 delivery or replace the clean120 evidence; fleet remains disabled. Do not generalize version eligibility to historical ACL readiness or apply this repair elsewhere without authorization. See [`docs/verification/2026-11-05-test29-endpoint-full158.md`](docs/verification/2026-11-05-test29-endpoint-full158.md).

- Current Windows full Setup candidate is **3.2.165**, signed EXE `C:\endpoint-platform-wix-build\setup165-final-ed7f77a\native-setup-build\releases\EndpointAgentSetup-3.2.165-x64.exe`, source binding `packaging/windows/initial-runtime-3.2.165.json`. Its enrollment download is published and the exact Foundation158-source canary120 is qualified, but the first automatic wave stopped on101.146 with `native_observation_unavailable` and stale UserSensor. Policy revision3 is **paused**, all-active/max2 retained;144 applied successfully. Preserve146 recovery ownership and do not replay or resume before diagnosis. This is not general fleet acceptance or a new stable-primary declaration. See [`docs/releases/windows-3.2.165-setup.json`](docs/releases/windows-3.2.165-setup.json) and [`docs/verification/2026-11-05-setup165-web-fleet.md`](docs/verification/2026-11-05-setup165-web-fleet.md). Historical disabled/max1 statements above describe their earlier checkpoints; Linux primary156 remains unchanged.
- Full-Setup candidate **3.2.167** failed its Console canary on101.120 after native acceptance, at companion restoration: native/staged writers serialized the same selector differently. Its signed EXE `C:\endpoint-platform-wix-build\setup167-ab31322\native-setup-build\releases\EndpointAgentSetup-3.2.167-x64.exe` and binding `packaging/windows/initial-runtime-3.2.167.json` remain immutable; see [`docs/releases/windows-3.2.167-setup.json`](docs/releases/windows-3.2.167-setup.json). Do not qualify, promote or fleet-assign167. Preserve the original120 job/native hold. The current165 enrollment download is unchanged. Core166 remains a distinct upward preparation candidate, not a full installer or primary release: [`docs/releases/core-3.2.166-observer-bootstrap.json`](docs/releases/core-3.2.166-observer-bootstrap.json). The original146 job completed after the explicitly authorized one-off repair; this is not unattended source qualification. Keep the fleet policy paused; a signed build/registry row is not fleet acceptance.

# Canonical Windows update workflow

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
- Keep exact-source qualification and its expiry visible. Unsupported sources
  remain blocked with a reason. Global slots include manual/recovery chains;
  real failure pauses new work. Never replay MSI or clear an unknown native outcome.
- Verify actual assignments and fresh telemetry after update; heartbeat/version
  alone is not acceptance. Promote the Windows download only after native canary
  acceptance and verified served bytes. Keep Linux release/version separate.
- The selected pilot diagnostic-access design is a separate Foundation component
  using an outbound SSH tunnel through Endpoint, independent of Core/observer,
  with per-device keys, strict host verification, expiry/revocation and audit.
  See [`support access spec`](docs/superpowers/specs/2026-11-05-pilot-support-tunnel.md).
  This channel is not implemented or included in Setup167; never claim that a
  workstation has service access merely because it runs that agent version.

# Production host

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
