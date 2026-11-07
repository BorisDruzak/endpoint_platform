# ALT Linux client: independent support and installation lifecycle

Status: independent builder check passed; pending user approval. No implementation or new
publication is authorized by this document alone. The user's requested scope is
confirmed: include independent support and removal/reinstallation behavior.

## Intent and existing evidence

After Windows177 acceptance, update the existing ALT11 x86_64 client with current
shared fixes, independent administrator support and native installation facts.
Ordinary reinstall must retain the device card and history. Full wipe creates a
new credential/card with an explicitly verified historical parent.

The current Linux primary is156, with signed Core and UserSensor RPMs. Windows
primary177, immutable bytes, source qualifications, grants and policy12/max2
remain unchanged. The preliminary Linux checks passed137/skipped29 on Windows;
these do not qualify native Linux operation. See the Linux baseline receipt.

The operator reported powering on the dedicated test PC162. Strict SSH still
timed out on the first two subsequent probes; controller TCP returned no route.
Do not replace the test machine with a production workstation without an
explicit target. Preserve existing AD/SSSD, user sessions and system SSH.

## Approach

Use the existing Endpoint support gateway, authenticated HTTPS, audit and Console
with a separate Linux systemd service. Its own root-owned code, configuration,
credential and SSH children must not depend on the selected Core runtime or
updater. This is the recommended continuation of the Windows design.

Running the channel inside Core fails the required stopped-Core test. Enabling
direct inbound workstation SSH requires unrelated network exposure and supplies
no centralized lease/revocation. Neither alternative is selected.

Builder decisions below are proposals, not additional user requirements.

## Native delivery and independent component

- Build a new immutable Linux release, provisionally3.2.178, from a committed
  source. Do not overwrite156/157/158 or rebuild Windows177. Assign a separately
  recorded Linux Support component version and exact source/payload digest.
- Ship support code/unit and native lifecycle helper with the signed Core RPM,
  with ownership separate from `/opt/endpoint-agent/current.json` and Core update
  paths. Core-only OTA must never replace package-owned privileged code.
- Enable the support service on normal installation and boot. Install/start it
  only after configured origin, CA and permanent device identity are verified.
  An unconfigured RPM remains safely unconfigured; it must not guess credentials.
- Use ALT's authenticated native OpenSSH package, not the Windows portable
  Preview archive. Validate the actual target RPM/tool versions and documented
  supported options before freezing a build. Missing dependencies are an explicit
  readiness failure, not permission to download an unreviewed executable.
- Run a private `sshd` listening only on127.0.0.1:22222 with its own host keys and
  authorized-key file. Reverse forwarding uses the existing strict gateway host
  pin and unique per-device tunnel key. Do not modify system sshd configuration,
  its port22 keys, users' authorized_keys or firewall profiles.
- The service may use root for private sshd/ownership/child supervision. Its
  isolated frozen module closure must exclude Core, updater and arbitrary command
  execution APIs. Preserve service-account, PAM and operating-system boundaries.
  Actual administrator commands run only through explicitly granted SSH.

## Administrator and lease authority

- Select an existing exact Linux account. Verify NSS resolution to the expected
  numeric UID and noninteractive administrative capability before a grant is
  usable. No accounts, passwords, sudoers entries or AD joins are created.
- On162 the proposed canary account is the already configured `test-agent-lin`,
  conditional on its fresh successful identity and `sudo -n` checks. The operator
  key must be the existing approved support key, not a generated substitute.
- Linux has its own explicitly configured administrator defaults. Never reuse
  `SOSNADM\\admin-2` automatically or distribute the canary login as a fleet
  default. Unknown/missing defaults leave access unavailable with a visible reason.
- Healthy new installation may receive one automatic initial8-hour grant for
  this exact identity/key configuration. Explicit disable/revoke/reset wins;
  polls/retries/heartbeat never renew a grant. Renewal is an audited Console
  action and works while Core/updater are stopped.
- Enforce expiry locally, including policy-server failure and wall-clock change,
  with an independently bounded monotonic deadline. Expiry/revocation stops both
  SSH children and active support sessions. Gateway expiry remains a second gate.
- New host keys remain strict identity changes. Rebind only through the exact
  authenticated native remove/install sequence and an unchanged administrative
  revision/generation. Never scan-and-trust or weaken host verification.

## Backward-compatible provider contracts

- Reuse the existing support ownership, key-conflict locks, gateway lease/export,
  quotas, audit and authenticated device boundaries. Linux must not masquerade
  as Windows through `windows_admin_username` or fake a Windows MSI ProductCode.
- Add Linux-specific strict request/response DTOs and routes alongside the
  unchanged Windows routes. Delegate to shared authority/service functions.
  This is an HTTPS platform adapter, not another Agent WSS/control transport.
  Legacy Windows DTOs retain exactly their existing serialized shapes.
- Add an explicit platform and Linux principal binding to support persistence,
  defaulting historical rows to Windows only. Require server-known matching
  device platform before Linux registration and every authority change.
  Shared Console actions choose the adapter from verified platform, never from
  an unchecked username or client-provided platform alone.
- Introduce a Linux-native source registry binding exact signed RPM identities,
  Core/UserSensor digests, signer fingerprint, frozen manifest and source revision.
  Compute archive digests after signing and register them externally; do not
  embed a package's own final archive hash inside that same package. The native
  coordinator verifies exact signed input bytes and records the operation input
  digest in its protected receipt before executing RPM.
  Windows continues to validate against WindowsSetupRelease with no loosening.
- Linux installation events extend the same causal per-device projection and
  append-only history through a strict RPM proof variant. Device credential,
  source CIDR/revocation, exact package source and causal predecessor are checked
  transactionally. Existing Windows event JSON and acknowledgements remain valid.
- Publish provider routes/DTOs in canonical OpenAPI/JSON Schema. Use an additive
  migration after0048; preserve legacy rows and migration round-trip tests.
  Deploy the compatible provider before any new client. Group consumers are not
  modified; unavailable GitNexus requires explicit source/test impact checks.

## RPM settlement, cleanup and reinstall

- Provide a canonical signed native setup/remove coordinator around RPM. It
  records the exact reviewed package inputs, owns one operation lock and obtains
  the actual native process result. Record installation/removal only after a
  known successful native transaction plus verified resulting package state.
- RPM `%preun`/`%postun` alone do not prove the eventual RPM process exit code.
  Hooks may stage protected intent and perform owned cleanup; they must not
  fabricate native0. A direct unmanaged RPM transaction without a coordinator
  receipt remains pending/unknown until explicitly reconciled by the same helper
  using sufficient durable native proof. Absence alone is not native0 and does
  not authorize replay. Document this boundary in the shipped uninstall command.
- Capture only an exact signed installed source. Keep the settlement/notification
  helper available outside the code being removed until its bounded owner exits.
  Do not leave a background notification daemon after uninstall.
- Preserve package-manager locking and reject unknown, interrupted or concurrent
  native outcomes. Never replay RPM, clear journals or replace identity to make
  an uncertain operation appear successful. Failed attempts retain their receipts.
- Relinquish only Endpoint-owned browser values before ownership markers;
  preserve foreign corporate policy. Remove the independent support unit/children,
  active keys and code on final removal. Cleanup failures and native result are
  separately reported. Upgrading packages is not a device removal.
- The bounded authenticated HTTPS notifier runs after native owner/lock cleanup.
  It uses the existing trusted CA/FQDN, no redirects and no raw bearer in durable
  queue records. A protected ordered queue retains unsent events for next Setup.
  Offline uninstall success is independent of delivery; server state changes only
  when the authenticated event is received. Deliver removed before installed.
- Ordinary uninstall preserves Linux's existing configuration, CA, permanent
  credential, canonical enrollment identity, telemetry and protected event queue.
  Reinstall retains UUID/card/history and respects manual access decisions.
- Full wipe is a separately targeted destructive operation after known native
  settlement and confirmed cleanup/removal. Preserve historical card/audit,
  archive evidence, revoke the lost credential and use canonical enrollment
  approval with the existing consumed-request fingerprint parent verification.
  No credential/history merge and no fingerprint bypass.

## Release and acceptance gates

1. Establish actual162 OS, RPM/OpenSSH/systemd/Python/toolchain, storage,
   domain/session, installed package/source, device credential identity and
   service baseline without printing secrets. Verify CA/DNS and trusted host keys.
2. TDD for Linux DTOs/platform enforcement and backward-compatible Windows wire
   shapes; PG locks/races/migration/native-source validation; native coordinator,
   owned cleanup, causal offline queue, strict paths/permissions/symlinks and
   service child lifetime/expiry. No tests may modify the operator's real state.
3. Commit reviewed runtime source, bind a new immutable signed Core/UserSensor
   RPM pair and signed distribution kit. Verify actual frozen code closure,
   publisher signatures, files/modes and dependency requirements on native ALT.
   Keep signing private material off build worker and out of Git/logs.
4. Back up provider/database and preserved per-device policies. Deploy additive
   provider with strict HTTPS readiness and real existing-Windows compatibility
   probes, keeping gateway and active support sessions alive.
5. On162 qualify retained156-to-new upgrade, native rollback to156 and forward,
   ordinary uninstall/reinstall, and a targeted archival full clean install.
   Compare UUID/credential/config/CA hashes and retained history. Preserve user
   session/AD state; no reboot/logout, input injection or real print jobs.
6. Capture genuinely accepted fresh UserSensor/activity before and after Core
   stop/restart. Stop Core and updater, disable its update watcher, then perform
   two actual strict administrator SSH commands at least90seconds apart through
   Support. Verify same independent PID, exact signed bytes and fresh status.
   Restore original services/watchers and prove fresh accepted samples again.
7. Verify initial automatic grant exactly once, manual disable across reinstall,
   expiry/revocation, offline removed-before-installed delivery and real Console
   history/parent/access on desktop/mobile/reload. Include a bare RPM operation's
   truthful pending/unknown boundary; never count it as known native0.
8. Observe at least180seconds of stable canary runtime and perform a longer quiet
   stability check where feasible. Publish only after actual signed native and
   live gates; verify real served bytes/signatures. Update only the Linux section
   of canonical records and document qualification limits. Fleet admission needs
   explicit source compatibility and fresh device evidence, not version alone.

## Open facts to resolve before implementation/deployment

The requested feature scope is settled. Remaining facts are test162 reachability
and its actual native versions, existing administrative identity and signing/build
environment. These must be measured, not guessed. If162 cannot be reached, source
design/tests may progress but live acceptance/publication remains incomplete.

The detailed implementation plan follows approval of this design. The builder
may choose module names, strict filesystem adapters and exact test partitioning
without changing the authority, compatibility or native-outcome boundaries.

Independent builder check returned `nothing important left`. Native RPM manual
consulted through Context7 confirms preun/postun are package-removal hooks and
posttrans follows package installation transactions, not the final CLI exit.
The v249 systemd documentation is a conservative reference for separate service
ownership; the actual target versions and supported options still need probing.

References: [RPM scriptlet tags](https://github.com/rpm-software-management/rpm/blob/master/docs/manual/tags.md),
[systemd service ownership](https://github.com/systemd/systemd/blob/v249/docs/ROOT_STORAGE_DAEMONS.md).
