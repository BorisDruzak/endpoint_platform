# UserSensor unattended startup implementation plan

> Execute inline with superpowers:executing-plans; fleet policy is a separate
> parallel task under the approved server auto-update design.

**Goal:** Genuine156 to full158 through Endpoint must start both fixed installed
user companions in ordinary logged-in sessions even when neither ran in source.
**Architecture:** Signed observer1.0.5 discovers WTS sessions, revalidates SID and
fixed target hashes, and uses existing limited interactive-token task launch. Its
accepted-job maintenance also covers later logons, without replaying native Setup.
Ship a new immutable Core163 bootstrap; retain exact native158 MSI/Setup bytes.
**Tech stack:** Existing PowerShell5.1/WTS/TaskScheduler, frozen Python3.12 build,
canonical Core/Setup services and real Windows/server acceptance.

- [ ] Write failing PowerShell tests for absent source companions, duplicate
  processes, invalid/reused session identity, late logon and busy/native-failure
  maintenance refusal. Preserve existing rollback/source/private guarantees.
- [ ] Implement bounded WTS session discovery and exact-path per-session launch.
  Persist the planned companion set before native execution; verify target hashes
  and native bindings before adding post-install sessions. Add logon trigger and
  periodic repair using only an accepted exact native target and no pending work.
- [ ] Qualify1.0.5 for new preparations via Core163; retain1.0.4 compatibility
  for historical in-flight operation reporting. Tests before changing controller.
- [ ] Independent security review, focused tests, commit, signed immutable build
  from exact source and original158 native artifacts. Never replace older ZIPs.
- [ ] User-authorized full removal on101.120 and original signed156 installation.
  Preserve domain/user/GPO and old server receipts; retire only exact removed
  registration. Accept pristine156 with no observer/ACL intervention or manually
  launched user companions, then remove baseline administration tasks.
- [ ] Assign only through Endpoint, observe163 to compatible155 to full158.
  Require actual native0, private bytes/metadata continuity, correct services,
  fresh WSS, stable nonzero UserSensor and fresh activity/policy/sensor health.
- [ ] Deploy fleet UI/control after checks, leave policy disabled for the user's
  launch. Record exact release qualification only after successful combined test.

No GPO changes, no workstation SSH, no post-baseline ACL repair, no native replay
for unknown outcomes, and no fleet enablement are part of this implementation.
