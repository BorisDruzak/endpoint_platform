# Full Setup165 and persistent Console rollout

Status at 2026-11-05 09:21 UTC: **fleet paused after a real recovery hold**.
This report does not claim fleet acceptance or complete UserSensor coverage.

## Immutable artifacts and deployment

- Core source: `ed7f77a559e19500df75b9ec169c5336e308b304`.
- Native wrapper/source binding: `0080690784ff4efa8cecd014d0e38afbc02bc1d5`.
- Running Console/server: `366133981f4b45b132e3cc6839707f74728d0d28`;
  `/opt/endpoint-platform/releases/endpoint-platform-366133981f4b`.
- EXE SHA256: `c71cfffca525f8370b22a9f96155176464566739c675f9325596fd2d045f159a`;
  145978968 bytes. MSI SHA256:
  `831ed1996daae0bf68a046828ff0e8f3775b879e14bf05e9a086304672cee5a9`.
- Both Authenticode signatures are Valid with timestamp, publisher thumbprint
  `4D4C23389F5FF77BC4EB32044761019EAE8FB776`. The runtime contains119
  individually verified files, including its compatibility contract.
- Full Setup registry ID: `b9734c6c-7152-44d6-99c3-58cde589d720`.
  No separate Core165 OTA release was registered. Observer remains signed1.0.5.
- Native publication ID: `e1ae6965-f135-43e8-9c7e-0d55a2dbe983`.
  The real authenticated enrollment download was saved and independently checked
  against the EXE size, SHA256, publisher and timestamp above.
- Default AUTO campaign `09e62472-a6ae-49ab-aaaa-6613836b4423` now includes165
  among9 installer releases. Its CIDRs, authority, expiry, quota and usage were
  preserved by the canonical transactional publisher. Linux publication unchanged.
- Existing schema0045 and dependency pins were preserved; API/database health200
  and worker active. HTTPS hostname and CA were verified without disabling TLS.

Operator evidence is under `C:\Temp\endpoint-setup165-20261105`, protected for
the operator, SYSTEM and Administrators. Private snapshots are not committed.

## Actual Console and native acceptance

The user authenticated the in-chat browser as the existing Console administrator.
The separately unauthenticated Playwright profile was not used for production
mutations. All canary, qualification and policy actions below used the actual UI.

| Machine | Assignment | Result |
| --- | --- | --- |
|101.120 / DESKTOP-9ST5HO2|`9255096a-d178-46d2-a0c5-e46ee44a3891`|APPLIED08:57:15.077908Z, native0, Core/Foundation165|
|101.144 / A1-OHTRUD-S1W|`bade87b9-26f5-4d77-91c3-b1c252738b00`|APPLIED09:09:33.796238Z, native0, Core/Foundation165|
|101.146 / A2-MUNSLU-S1|`6bc214b4-50b3-4fe0-91b4-0732b8dea2e6`|RECOVERY_REQUIRED, `native_observation_unavailable`; native exit/proof unavailable|

All three originated from Core164/Foundation158/client1.0.5. No workstation
preparation, manual installer launch, reboot or GPO change was used for these
updates. This is not a new clean156 test or evidence for historical156 ACLs.

120 passed183.731 seconds/six samples: stable services, companions, advancing
connection, sensor_count1 and maximum sensor CPU0.0065 percent. Fresh UserSensor,
activity and power READY continued. All four private files retained bytes and
owner/SDDL, and all119 installed runtime files matched the exact signed payload.
Actual first qualification was created through the Console at09:00:20.002499Z:
`ffbc8451-8a2c-4689-b586-b3151d1baed0`, Foundation158/exact EXE, expires
2026-12-05T09:00:20.002499Z. Qualification alone did not enable fleet policy.

144 passed181.014 seconds/six samples with stable services/connection, all119
runtime file hashes, and preserved private-file presence, bytes and owner/SDDL.
Its sensor_count0 and absent UserSensor existed before update; no fresh active
user telemetry is claimed for this PC.

## Persistent policy and automatic safety stop

Preview showed23 records:11 eligible,1 already current,10 blocked/unknown
platform and1 other platform. At09:00:56.465493Z the UI saved revision2:
enabled, exact165 target, `scope=all_active`, `device_ids=[]`, `max_parallel=2`.
Reload confirmed these persisted fields. Later registrations/reconnections use
the same dynamic scheduler and source qualification gates, not a frozen list.

The scheduler automatically assigned144 and146 at09:01:49Z, occupying exactly
two native chains. At09:06:53.917645Z the real failure circuit saved revision3,
disabled, `fleet_failure_requires_review`, retaining target, all-active scope and
max_parallel2. The UI visibly displayed the pause. After144 completed, only146
retained recovery ownership; no further165 assignments were issued.

146 still has fresh Core/Foundation165 presence and power READY, but its last
UserSensor was09:03:42.942789Z and native proof is null. Version/presence are not
accepted as native completion. The generic error does not establish a domain
policy, installer, or companion-restoration cause. Preserve its original attempt
`43731f03-f211-465d-8cf2-f8dd1f8fc5fa`, journals/cache and exclusive hold. Do not
cancel, replay MSI, clear ownership or manufacture an acceptance result.

Read-only diagnosis could not reach146 using SSH, SMB, WinRM or RDP from the
operator; the server's corresponding probes also failed. RPC endpoint135 was
reachable but DCOM/WMI timed out. Current Endpoint primitives cannot read the
protected observer status file. Requested only local status fields
`safe_code,stage,line,utc`; no credential or complete job file was requested.
The root cause and recovery remain outstanding. Keep automatic policy paused.
The165 enrollment download is published; this is explicitly not general fleet
acceptance or an unqualified stable-primary declaration.

## Verification and review

- Python3.12:24 power/context and14 initial-runtime-contract tests passed.
- Focused server policy/preparation/service/API:60 passed.
- Real isolated PostgreSQL suite:18 passed, including version-agreement across
  separate scheduler ticks, late hello, role/CSRF/revocation/rollback and slot races.
  Temporary databases, role and SSH tunnel were removed; production DB not used
  as a test fixture.
- Web:83 tests passed; typecheck/build and generated-contract check passed.
- Browser fixture workflows:2 passed at1440 and390 pixels, including persistent
  max2 enable/reload/pause, overflow and console checks. These are UI tests, not
  native fleet proof.
- Independent review found source disagreement admission, premature reconnect
  bridge selection, and a target change during canary editing. All reproduced
  RED and fixed GREEN. A qualification first-insert unit-fixture gap remains;
  the actual fresh165 qualification above provides live first-insert evidence.
- Canonical server archive SHA256:
  `3db1ebf8e3cebe34f64a46ba8e52a72549b33bc56037f29c5473f88405b61e34`.
- Yandex browser telemetry remains explicitly user-deferred. Full repository
  baseline failures were not relabelled as passing; no broad all-green claim.

The common operator process is in
[`FULL_SETUP_FLEET_POLICY.md`](../runbooks/FULL_SETUP_FLEET_POLICY.md), with
mandatory future-release rules in [`AGENTS.md`](../../AGENTS.md).
