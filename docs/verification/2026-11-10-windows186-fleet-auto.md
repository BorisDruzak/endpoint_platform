# Windows186 automatic fleet rollout

The user explicitly authorized enabling186 after the accepted test120 canary,
and asked whether powered-off agents join automatically when they reconnect.
This receipt records the persistent production policy, separate from the
[test120 acceptance](2026-11-10-test120-windows186-inbox-openssh.md).

## Saved policy and scope

The authenticated Console preview checked27 registrations: six eligible,
one already current, six waiting for reconnect; removed identities, unknown
platforms and Linux were not admitted. Five waiting devices last reported177:
101.146,101.144,101.170,101.207 and101.138. Legacy101.69 last reported79 and is
outside the qualified177-to186 source profile; reconnect alone does not qualify it.

At2026-11-09T22:20:38.309937Z (10November03:20 local), Console saved policy13:

- policy UUID `0ab7e6f8-7f3b-42b4-9b62-e0718dd6a3fc`;
- enabled; `all_active`; empty device-ID list; max_parallel2;
- release `a4615295-d023-457e-84b6-cb0cf87617f4`, signed Setup3.2.186;
- EXE SHA256 `67fd0d7ded0eed838491f4f3c056da15567d768f9d71c78f22937013ea0e4115`;
- source177 qualification `53c243c3-c346-4000-a16e-f1dd0777b0af`, backed only by
  nominal177/client107 assignment`1c0176f2-02e4-4e09-978f-c59bd14c3eeb`;
- qualification expires2026-12-09T22:04:33.615258Z (10December03:04 local).

Reloading Console restored the selected186, enabled all-active scope and limit2.
Two real chains were then present. This is a saved dynamic policy, not a frozen
list of machines that happened to be online. The worker reevaluates a returning
or newly registered Windows device after fresh matching authenticated WSS/Setup
hello. Exact qualified source, readiness, expiry, native ownership, competing
work and capacity are checked again. Unsupported source, stale/busy observer,
removed device and unknown native outcome are not bypassed.

Existing automatic pausing on real failures/recovery holds remains enabled.
No source qualifications below177, new bridge, repeated MSI, journal cleanup,
network authority or separate enrollment campaign were introduced.

## Observed delivery

The worker automatically assigned the first wave to devices reporting gateway
source addresses192.168.101.27 and192.168.101.22:

- assignment `158acc12-61de-4bb5-b5b7-155f4960bba0`;
- assignment `d9ed9cff-a08d-4cbc-99a0-97c0ffe1f84f`.

Both frozen sources are177/client107. At22:25:05Z both were verifying, four
other eligible devices waited on capacity, the six disconnected devices retained
waiting_reconnect and policy13 stayed enabled. Acceptance is being observed;
observed versions, native_trial and Support component status alone are not
recorded as complete update/administrator SSH acceptance.

## Capacity, preservation and evidence

Before enabling, both immutable177/186 server files matched their catalog hashes
and sizes, qualification was current, no native hold occupied a slot, and root
free space636465152bytes exceeded two simultaneous EXE response buffers plus the
110MiB reserve. The default AUTO campaign retained CIDRs, expiry, quota, usage
and15 trusted immutable installer versions. Historical media/failures/private
identities and explicit Support policy decisions remain intact. Linux183 and
Helpdesk were not changed. Production/staging runtime remains24461a70286e,
schema0051_staging_linux_worktime.

The enabled-policy screenshot and bounded read-only DB snapshots are retained at
`C:/endpoint-platform-wix-build/windows184-inbox-20261109`, under
`windows186-fleet13-enabled.jpg` and `fleet186-*.json`.

## Fleet follow-up: optional-origin notification failure

Both first-wave assignments above completed APPLIED/native0 (181.932 and182.963
seconds; sensor_count1 and fresh genuine telemetry). They retained Support1.0.1,
so native acceptance alone did not establish the intended reserve-channel upgrade.
Read-only strict domain SSH on device27 (`13f38b93-cc73-4130-b58c-41f534b1893e`)
proved the existing Agent directory had no optional `endpoint-origin`. Support's
own enrollment reader already accepted that valid state, but the lifecycle sender
required the leaf. Genuine native0 facts177 and186 remained pending, preventing
Support activation. Private identities, retained facts and native receipts were
preserved; no origin file was manufactured.

At22:29:48.348739Z canonical policy14 paused new assignments, retaining target186,
all_active andmax2. In-flight work was not cancelled. Four fleet assignments
ultimately accepted native0 with fresh user telemetry:27,22,ADMIN-2 and187.
Three retained oldSupport;187 reported1.1.1. This is not fleet Support acceptance
or promotion of186. Public Windows download remains177, Linux183 unchanged.

A distinct187 will correct only the optional-origin sender boundary. It must
retain exact canonical destination/private-CA/credential checks, deliver original
pending facts in sequence, and prove actual updated Support/SSH on an affected186
and an untouched177 source before automatic delivery resumes. Existing186 bytes
and successful native/failure evidence remain immutable. The currently paused
policy means offline PCs are not receiving a new release yet.
