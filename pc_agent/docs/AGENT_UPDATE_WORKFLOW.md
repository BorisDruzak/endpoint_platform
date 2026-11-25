# Endpoint Agent release workflow

## Choose the mode

| Mode | Work and exit criteria |
| --- | --- |
| **DEVELOP** (default) | Implement, verify and integrate ordinary changes through the usual review and CI. Keep `AGENT_VERSION` and product/package versions at the released baseline. Identify any local or CI development build by its Git SHA, isolate its runtime and state, and keep it outside production signing, catalogs, enrollment and assignments. |
| **QUALIFY** | Pin a clean source revision and select the delivery path. Reserve a unique version when a new distributable build needs one. Build and sign with the existing platform tools and approved signing environment. Record exact digest, artifact identity, source binding and relevant profiles. Exercise required installation, upgrade and recovery scenarios in Lab. Bind any acceptance to the exact artifact and environment. |
| **RELEASE** | Within the authorized scope, validate the same digest, signature, source binding and still-valid evidence. Use existing publisher and server-side gates for candidate registration, canary, qualification, bounded delivery and any primary promotion. Record the published bytes and the observed outcome. |
| **HOTFIX** | Start from the applicable deployed source and limit the change to the incident. Qualify and release the resulting artifact through the same applicable gates. |

A sent assignment, version report or process start alone does not prove
acceptance. Confirm the installed artifact, preserved identity, healthy services
and companions, fresh Gateway telemetry, and any required rollback evidence.

For a Windows or ALT native candidate, use the
[shared reservation workflow](../../tools/release/CODEMAP.md#reserve-and-bind-a-windows-or-alt-version).
Reserve the number before editing the version. Bind the reviewed build commit
before producing distributable bytes.

## Choose the release cycle

- **Windows Core OTA.** Use [the Windows packaging tools](../../packaging/windows/README.md)
  for a compatible runtime payload. Verify minimum Foundation/launcher, signed
  payload and exact source constraints. For example, the
  [Core164 fix](../../docs/releases/core-3.2.164-power-context.json) used the
  existing Foundation158.
- **Windows native Setup/Foundation.** Use the [Windows packaging tools](../../packaging/windows/README.md)
  and [Full Setup fleet policy](../../docs/runbooks/FULL_SETUP_FLEET_POLICY.md)
  for MSI, services, ACLs, or other native installation changes. The canonical
  publisher's `--candidate-only` hides the primary download. Use
  `--without-auto-enrollment` for a permitted diagnostic registration that
  must stay outside AUTO enrollment. Keep Lab candidates in Lab and use
  same-row promotion once the actual release gates pass. Check Support and the
  Setup observer against their own compatibility and acceptance requirements.
- **ALT Core OTA and native RPM.** Follow [ALT installation and update](../../docs/runbooks/ALT_AGENT_INSTALL.md)
  and [Linux native Setup](../../docs/runbooks/LINUX_NATIVE_SETUP.md). Use the
  native path for privileged services or helpers. Keep native enrollment
  platform-bound and separately authorized.
- **Ubuntu and Debian native packages.** Follow the
  [DEB/APT runbook](../../docs/runbooks/UBUNTU_SERVER_AGENT.md) and
  [Debian release evidence](../../docs/verification/2026-11-12-proxmox-debian-rollout.md).
  Verify the suite-specific package, signed indexes, trust and expiry.
- **Provider and Console or Browser Sensor.** Follow the separate
  [provider](../../deploy/server/PRODUCTION_RUNBOOK.md) or
  [Browser Sensor](../../docs/runbooks/browser-sensor-release.md) process.
  Check compatibility with deployed peers when contracts change. Server-only
  work does not require an agent package.

## Choose checks from the affected behavior

- Local functional change. Run targeted checks and the existing integration CI.
  CUPS development can integrate its relevant provider and agent tests
  without promoting the runtime or building a signed package.
- Runtime or contract change. Check both producer and consumer, supported
  versions, startup, transport and recovery as applicable.
- Updater, identity, service, migration, privilege or native installation change.
  Exercise the affected lifecycle on exact source profiles and verify identity,
  ACLs, retained state, interruption and compensation paths as applicable.
  Keep all existing required CI and release gates.

Select upgrade sources by actual exposure and installed profile. A rejected
candidate can be excluded as a mandatory predecessor only if it was confined
to Lab and the test state was fully reset. Keep exposed pilots, offline
devices, pending installs, recovery holds and unknown outcomes in the analysis.
Preserve receipts and distinguish an administrative recovery from an unattended
successful transition.

## Read the current release pointers

Start with [the checked-in release record](../../docs/releases/current-agent-release.json).
Read `primary_windows_release` and `current_windows_rollout` for separate
Windows pointers, `record_role` and the linked
[ALT native record](../../docs/releases/linux-3.2.183-native.json) for the
recorded ALT primary, `ubuntu_servers_197` and `proxmox_debian` for the
recorded APT entries, and `current_provider` for the provider. Top-level
`version` is the historical 3.2.192 checkpoint. Before a release, verify
these pointers against the owning live catalogs and a fresh device snapshot.
Keep the release records and applicable source bindings in sync with each
actual publication.
