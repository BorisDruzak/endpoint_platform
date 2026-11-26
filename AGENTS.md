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

# Worktime and Helpdesk identity

- Confirm existing person, account and AD ownership through the canonical
  authenticated propose/confirm flow. A visible AD login or provider redirect
  is separate from a genuine employee Worktime handoff. Keep native prompt
  acceptance separate. See the [Worktime deployment receipt](docs/verification/2026-11-09-worktime-production-parity.md).

# Canonical agent release

- Default to **DEVELOP**. Implement, run risk-based checks and integrate through
  normal CI. Keep AGENT_VERSION and native package versions at their existing
  baseline. Use the Git SHA for isolated development builds. A change merged
  into main alone does not authorize signing, publication or assignments.
- Use **QUALIFY** for a new distributable candidate and exact-artifact Lab
  evidence. Use **RELEASE** to publish and promote the qualified bytes within the
  authorized scope. **HOTFIX** starts from the affected deployed source and
  uses the same applicable qualification and release gates. See the
  [agent release workflow](pc_agent/docs/AGENT_UPDATE_WORKFLOW.md).
- Choose the affected release cycle independently for agent Core, native
  Setup/RPM/DEB, Support/Observer, Browser Sensor or provider/Console. Apply
  existing runtime compatibility, source binding, signatures, TLS/WSS, ACL,
  enrollment, identity and rollback requirements. Preserve normal CI and
  the applicable native and release gates.
- Read platform-specific pointers from
  [current-agent-release.json](docs/releases/current-agent-release.json) and
  verify the owning catalog before release. The root version field preserves a
  historical checkpoint. Update platform records when their releases change.
  Earlier release and provider facts live in the
  [checkpoint archive](docs/releases/2026-11-25-historical-checkpoints.md).
- A candidate confined to Lab creates no mandatory future upgrade source after
  a verified complete reset. Keep operational pilots, offline or pending
  assignments, interrupted transactions and uncertain exposure in scope until
  their state is verified. Retain failed-attempt evidence and recovery ownership.

# Canonical Windows update workflow

- Follow the [Full Setup fleet policy](docs/runbooks/FULL_SETUP_FLEET_POLICY.md).
  Bind the runtime contract, complete source tree, reviewed files, Git SHA,
  toolchain and component GUID/version before freezing bytes. Verify signed MSI
  and EXE bytes, trusted publisher and timestamp. Historical artifacts and
  their source bindings remain immutable.
- Use the same exact EXE through candidate registration, Console canary,
  qualification, coverage preview, approved bounded delivery and same-row
  promotion. Identify the canary by hostname and confirmed device card.
  Qualification uses an accepted native0 assignment, exact Core/Foundation/MSI
  source, preserved private identity, stable services and companions, fresh
  WSS and active-user telemetry, and at least 180 seconds of observation.
  Qualification and preview leave fleet policy unchanged.
- Choose scope and concurrency for each authorized wave using the Console
  preview. All-active scope dynamically includes future registrations and
  reconnections. Keep exact source qualification, expiry, and blocked
  reasons visible. Manual and recovery chains count toward shared slots.
- Require matching fresh WSS and Setup hello for direct native admission.
  Missing, stale, busy or discordant modern observations wait for confirmation.
  Use only the approved legacy preparation/return route where applicable.
  For eligible Core163–165/Foundation158–165, after the three-minute WSS grace,
  use only the registered upward Core166 bridge and a distinct Setup newer than
  166. Require applied child, matching fresh observer1.0.6 and WSS and renewed
  exact EXE/source admission checks. Preserve busy observers and staged slots.
  For the historical Foundation156 preparation route use only the documented
  exact compatible Core155 return before full Setup158. Keep Core157's
  Foundation157 minimum. See the [bridge record](docs/releases/core-3.2.163-setup-client.json).
- Use a bounded public reason accepted by the Console validator. Native failure
  pauses new work, and unknown native outcomes retain exclusive recovery
  ownership. Preserve journals and cache and avoid cancellation or MSI replay
  while the outcome is unknown. Settle a known source-restored exit21 only
  with exact unchanged-source, private identity and session proof, at least
  180 seconds of verification, and completed recovery return.
- Administrative repairs need scoped authority. Treat prepared continuations
  as evidence for the actual prepared profile. The
  [historical ACL recovery](docs/verification/2026-11-05-test29-endpoint-full158.md)
  used a one-time owner-only repair while preserving the exact DACL, group and
  private files.
- Verify served bytes and native acceptance before primary promotion. Trusted
  released Windows installers use the canonical publisher's transactional
  inclusion in the single default AUTO campaign. Preserve CIDRs, expiry, quota,
  usage and campaign history. Document any explicit diagnostic exclusion. Keep
  primary visibility, enrollment, scoped bootstrap and existing-device policy
  separate. Linux native enrollment uses its own platform-bound registry and
  separately authorized campaign.

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

- `osn_admin@192.168.100.19` (SSH host alias: `endpoint-platform-server`) is the production machine for the Endpoint Platform service.
- Use this host for live testing and verification when that is necessary to complete the task. Treat changes, deployments, service restarts, configuration changes, and data changes as production operations.
- The `endpoint.sosnadmin.local` DNS record is configured. The Endpoint Platform CA certificate is available on the operator workstation at `C:\Users\admin-2\Desktop\РќРѕРІР°СЏ РїР°РїРєР° (2)\С‚РµС…\СЃРµСЂС‚РёС„РёРєР°С‚\sosnadmin-local-ca.crt`; treat it as deployment input and do not commit it. Do not work around DNS/TLS with an IP address or by disabling TLS verification.
- PostgreSQL and Nginx installation and configuration on this host are part of the Endpoint Platform deployment work. Perform them when the deployment assets are ready, rather than before the application is ready to deploy.
- Disk resize is cancelled. Re-check actual available capacity at the deployment gate and proceed only if it is sufficient for the verified deployment footprint; do not schedule or wait for a resize.
- `openvpm@192.168.100.30` (SSH host alias: `ui-vpn-deploy`) is the production host for the network web panel. Use it for necessary live testing and verification; treat changes, deployments, service restarts, configuration changes, and data changes as production operations.

# Related production repositories

- [`BorisDruzak/web_ovpn`](https://github.com/BorisDruzak/web_ovpn) is the repository for the network web panel hosted on `192.168.100.30`.
- [`BorisDruzak/network_configuration`](https://github.com/BorisDruzak/network_configuration) contains the network configuration associated with that panel.

# Endpoint release laboratory

Use the existing `pve1` guests for Windows and ALT release tests. Check the
current node, VMID, Proxmox name, DMI UUID, guest OS edition/build, and snapshot
before using one. A hostname can be shared by full clones. Reuse these guests
and their matching snapshots before allocating another VM.

| Guest | Default use and starting point |
| --- | --- |
| VM226 `endpoint-stab15-win10-205-262` | Windows 10 Enterprise Evaluation 19045 offline upgrade, repair, and preflight. For Core/Foundation 3.2.205 use `primary205-accepted-offline`. The guest's current disk can hold a later version. |
| VM484 `endpoint-win11-9457-lab` and VM485 `endpoint-win11-9457-provider` | Windows 11 LTSC Evaluation 26100.9457. Use `clean-9457-fod-trusted205` for factory setup or `primary205-ack1-before276` with its matching private PostgreSQL checkpoint for a network upgrade. Verify the paired provider and bridge `vmbr484`. |
| VM486 `endpoint-alt-native-dev486` | ALT 11.4 RPM build worker with the pinned stock OpenSSL/Qt inputs. Use it for DEVELOP builds without enrollment. |
| VM487 `endpoint-alt-native-stock487` | Stock ALT 11.4 offline native install, RPM dependency check, and KDE acceptance. Start from `before-alt274-factory-verifier` and restore it after collecting evidence. |
| VM107 `test-agent-lin` | Persistent staging canary. Follow the separate staging rules below. |

- Keep `EnterpriseS` and `EnterpriseSEval` distinct. Use official, licensed
  media with verified provenance for a missing edition or ALT release. Reuse
  an existing VM with a verified baseline or repurpose an available lab slot
  after preserving its prior evidence. Windows 11 `EnterpriseS` and ALT
  11.2/11.5 need their own acceptance profiles.
- VM482/483 are the retained Windows 11 Evaluation 26100.1742 pair. VM259/260
  are the retained paired ALT 11.4 network upgrade and recovery history.
  Reuse them only for their matching profile when needed. Preserve historical
  guests with active staging duties, linked disks, or unresolved transactions.
  In particular, VM480/481 are offline MSI holds. Leave their guests,
  identities, snapshots, and recovery ownership intact.
- Use a private bridge with verified guest membership, no physical uplink or
  default routes, and a dedicated Lab provider and database for network trials.
  An offline trial uses a disconnected or detached adapter. Restore an enrolled
  client only with its matching provider checkpoint. Keep a snapshot before
  enrollment or installation whenever a clean baseline is needed.
- Allocate a temporary clone only when an existing guest cannot cover the exact
  profile or a destructive fault trial needs an independent copy. Record its
  purpose, parent snapshot, paired provider, and disposal condition before
  creating it. Save the evidence, shut down idle Lab guests, and remove temporary
  guests after confirming that recovery holds, linked disks, and owned data are
  accounted for. Verify that the guest is absent from Proxmox after removal.

# Persistent staging test host

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
