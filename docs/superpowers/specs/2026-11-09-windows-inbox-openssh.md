# Windows native OpenSSH and forward update resilience

## User-approved scope

The user selected Microsoft's in-box Windows OpenSSH and the existing independent
outbound tunnel, then explicitly requested implementation and test120 acceptance:
upgrade from177, recovery after failures, and real administrator access with Core
and updater stopped. Do not add qualification for older source versions. Preserve
all historical media, receipts, private identities, explicit access refusals and
unrelated server/Helpdesk/Linux state. Reuse the existing isolated worktree.

## Decision

Build a distinct Windows184 candidate and Support1.1.0. Use only the operating
system OpenSSH Client/Server Feature on Demand, verified Microsoft signatures and
canonical System32 paths. Retain the separate EndpointSupportAccess service,
loopback listener22222, outbound gateway2222, exact device/gateway pins, existing
administrator and bounded policy. No new Endpoint inbound LAN listener or permanent
access. Test120's existing global sshd/configuration/firewall are preserved.

Alternatives considered: retain the pinned Preview bundle (predictable offline
bytes, but vendor Preview limit remains), or migrate to WinRM HTTPS (additional
certificate/transport integration). The user selected in-box OpenSSH. Provision
missing FoD components through Windows servicing; never copy binaries between OS
builds, disable TLS/signature validation, change WSUS/GPO or invoke an unapproved
third-party download. An unavailable source or reboot-required result is explicit
and must leave the existing working Support unchanged.

## Dependency lifecycle

- Installer preparation verifies the existing177 Support and identity first.
  FoD servicing and signature/config validation precede stopping that service.
  Preserve existing global sshd configuration/service state and foreign firewall
  rules. If the vendor default rule name is absent, reserve it disabled BEFORE
  servicing with this durable operation's nonce. Only that unchanged owned
  reservation (full rule/filter fingerprint) may be removed. Preserve foreign
  replacements and refuse the migration instead of inferring creation ownership.
- Add a versioned `windows-openssh-fod-v1` dependency profile. New media contain
  historical bundle metadata only for exact owned cleanup/compensation, not the
  Preview ZIP/executables. Keep the existing177 bundle inert until migration and
  recovery acceptance; never erase its immutable recovery input as preparation.
- Signature validation uses fixed system PowerShell with fixed encoded source
  and canonical paths; no policy/request-supplied executable, command or script.
  Normal tunnel launch performs fast path/hash/security checks. Refresh after
  Windows servicing runs in the independent policy worker, outside the lease
  cutoff loop; a blocked validator cannot extend access. This narrowly extends
  the historical installer-only signature-query rule so OS updates can recover
  without Core, updater or an operator-only reinstall.
- After changed OS bytes, stop using the old dependency selection, validate the
  complete selected set and persist the authenticated new snapshot under the
  existing protected activation lock. Partial, invalid, foreign/writable/reparse
  inputs fail closed, report dependency_unavailable and retry with bounded delay.
  Known completed FoD followed by signature failure is installed_unverified:
  retry read-only verification, never replay servicing or invent an unknown MSI.
  Do not silently fall back to Preview. Keys, credential, policy revision and
  deadline are not changed by dependency revalidation.
- Preserve the previous private configuration across payload activation failure;
  compensate exact image/SCM/configuration as one bounded operation. Following an
  authenticated reset, preserve NEW keys/credential fields and compensate only the
  old image's compatible dependency selection. Never restore revoked authority.
  Existing unknown-payload
  ownership remains a hold, never a guessed file replacement.

## Forward update and qualification

Keep canonical signed full Setup/native owner, immutable source binding, canary,
qualification and transactional candidate publisher. Author the184 runtime
contract before freezing bytes. Support remains outside MSI/Core ownership and
is activated only after known accepted native success. A failed/unknown native
result cannot remove or replace the active channel; never repeat MSI on timeout.
Qualify only exact Foundation177/client107 to184 in this task. Candidate exposure
and trusted default AUTO campaign inclusion remain separate from primary/fleet
promotion. This task is limited to120; do not expand fleet177 policy or Linux.

## Acceptance

1. Fresh baseline identifies current120 UUID,177, private4, Support1.0.1, account,
   pins, OS build, FoD/service/firewall state and accepted active-user telemetry.
2. RED/GREEN tests cover FoD absent/failure/reboot/concurrent changes; migration
   and compensation; trusted OS replacement versus tamper; validator blocking
   beyond lease expiry; unchanged credentials/manual revoke; source/native holds.
3. Inspect signed184 EXE/MSI/Core/Support source/bytes/toolchain and ensure no new
   Preview payload. Existing signed177/observer107 and Linux183 remain immutable.
4. Actual canonical177→184 assignment accepts native0, retained private identity,
   stable services, fresh WSS and genuine accepted user telemetry for at least
   180 seconds. Longer observation and normal reboot/session restoration are
   separate acceptance facts, not inferred from version/heartbeat.
5. Real strict-pinned administrator commands prove in-box sshd and tunnel access
   while Core/updater/observer are stopped. Restore task-related state afterward.
6. Safely exercise service-child crash, updater interruption outside an uncertain
   native transaction, bounded transport failure and reboot. Retain failed probes,
   observe bounded reconnection/lease expiry and prove fresh telemetry afterward.
   Unit/native harnesses cover unsafe crash points without inventing product
   recovery records or killing MSI to manufacture an unknown outcome.
7. Record source/dependency/OS/build-specific limits. No arbitrary future Windows
   build or update-path qualification follows from one PC. Retain protected
   evidence, remove only owned scratch resources, update rules/runbooks/releases.
