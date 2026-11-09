# Agent 3.2.156 fleet update observations

User scope: start updates for all registered agents and independently verify
actual installation. Server assignment, a completed rollout containing a failed
target, a preflight result and a test-VM installation are separate observations.

## Linux OTA

- The original stable-channel canary was rejected by the existing privileged
  ALT installer, which requires `canary`. Its actual native rejection and
  failed target were retained; it does not satisfy the bulk success gate.
- Registered `agent-linux-unified32156-6ed41cd-canary` through the canonical
  build service, preserving the stable registration and immutable archive.
  Both registrations use SHA256
  `c2fb732693884e7779a95cf9fbbc931d5fd7253435ecb7483c5e722162981370`.
- The corrected production canary upgraded selected runtime 3.2.127 to
  3.2.156 automatically. The agent reported
  `applied / post_restart_handshake_confirmed`; all 98 installed runtime files
  matched the archive manifest and source
  `6ed41cd01d494e46111a452c2ae3a844f723175b`.
- Core and the user sensor execute from the selected 3.2.156 directory.
  Native core/sensor RPM metadata remains 3.2.127-alt5; an OTA runtime update
  does not establish an RPM package upgrade.
- Four private input hashes, owners and modes were unchanged. CUPS and SSSD
  retained their original processes. One authenticated session advanced for
  more than 420 seconds; Core had zero service restarts, policy was `APPLIED`,
  Activity/USB/Print/security spool and power source were `READY`, and power
  loss count was zero.
- Created an explicit five-record offline bulk assignment only after checking
  the same build's actual applied canary and fresh policy/health again.
  Exact-version historical source parsers for 3.1.93, 3.2.21, 3.2.40 and
  3.2.121 accept the published manifest. Source also packages the privileged
  update helper/path and uses the compatible channel. These are compatibility
  observations, not per-host native readiness or installation acceptance.
  All five targets remain assigned while the devices are offline.

## Windows delivery and compatibility

- Core-only ZIP requires Foundation 3.2.156. Older Foundations require the
  full signed Setup, delivered through the existing administrative/domain
  mechanism. Lowering the immutable ZIP's Foundation requirement is invalid.
- Three accessible 3.2.149 devices returned `READY_FOR_SETUP_UPGRADE` from
  the actual signed 3.2.156 Setup. This does not prove installation.
- Another healthy current 3.2.149 device was blocked by its protected
  historical previous 3.2.79. `inspect_installed_core` validates both current
  and previous against destination Foundation 3.2.156; the retained legacy
  previous fails that compatibility check. The actual current 3.2.149 native
  owner verifies. Existing equal-version 3.2.149 Setup preserves the previous
  selector; no supported repair flag rotates it. History was not cleared.
- A separate 3.2.81 source also failed provenance admission. No unsupported
  legacy route or broad compatibility exemption was substituted.
- Read-only checks of both domain controllers found identical task bytes
  and permissions. The existing five-device pilot has one SYSTEM task with
  highest privileges, seven-hour repetition, `IgnoreNew` and no execution
  time limit. Its task/share scope and the separate one-device legacy bridge
  remain preserved during preparation.
- Four historical device identities belong to earlier snapshots of the same
  Windows qualification VM. They must not be counted as four additional
  physical installations or receive duplicate physical deployment attempts.

## Windows 3.2.149 qualification

- Genuine Foundation/Core 3.2.149 with compatible previous 3.2.121 and
  legitimately absent origin upgraded using the immutable production Setup.
  Exit 0, `UPDATED / SERVICE_RUNNING`, actual authenticated heartbeat and
  matching `APPLIED` policy were verified. Elapsed time was 285.185 seconds.
- A second trial blocked only the exact candidate Core's network access.
  No candidate proof was fabricated. Original Setup returned 67,
  `ROLLED_BACK / CANDIDATE_ROLLED_BACK`, in 504.829 seconds. Native 3.2.149
  MSI/source/Core bytes and both original selector byte sequences were
  restored; original 3.2.149 reconnected and freshly applied its policy.
- Private input content, owner, group, full SDDL and NTFS identity matched
  the captured baseline; legitimate origin absence remained unchanged. No
  installer fences or recovery tasks remained. Historical failures were
  preserved, and positive/negative snapshots were retained independently.
- Reverse MSI recreated NTFS identities for 118 old Core files, while all
  118 hashes and sizes matched. Core file-identity preservation across reverse
  MSI is not claimed. The native rollback contract checks original Core
  selector/source/tree bytes; private-file identities remain mandatory and
  passed.
- Admission is restricted to genuine 3.2.149/Core 3.2.149, absent origin with
  compiled default, compatible previous runtime and actual signed156
  preflight readiness. The three ready production devices were independently
  checked to have this origin state. Protected origin overrides and
  incompatible legacy history remain outside this qualification.
- A normal retry on the actual clean-compensated 3.2.149 disks subsequently
  completed with the same published Setup, exit 0 / `UPDATED`, in 281.247
  seconds. No snapshot restore or manual journal change supplied this result.
  Exact native/Core/private identity checks passed; the VM remains on 3.2.156.
  One unchanged service-bound Core and WSS session advanced for 182.831
  seconds. Initial global process-count assertions were retained as harness
  failures: frozen 3.2.156 legitimately starts bounded read-only
  `--windows-power-read` children. A live child flag and the source dispatch
  were verified; the main service-bound process remained unchanged.

## Production Windows acceptance

Three matching production devices completed the central administrative
dispatcher with the original signed full Setup, exit 0. Independent receipt
comparison verified exact Native/Core 3.2.156 source/MSI, unchanged private
content/file IDs/owner/group/full SDDL and preserved origin absence.

Fresh server verification at 2026-10-26T21:02:59Z confirmed one new authenticated
3.2.156 session per device, matching fresh `APPLIED`, all four sensor sources
`READY`, power source `READY` and zero power-event loss. Minimum advancing
heartbeat duration was 180.076 seconds; the first production canary was
separately accepted after 240.164 seconds before the other two were admitted.
The previously recovered original affected PC is a separate earlier
acceptance, not one of these three new installations.

Windows user-sensor processes were created after the candidate native install;
their backing-file SHA256 matches the signed 3.2.156 MSI catalogue. They did
not require application restart, logout or reboot. An absent PE version field
was not interpreted as evidence of an old runtime.

Four offline Windows records and the two observed online legacy-conflict
states are not verified installed by this rollout. No fleet-wide acceptance
is claimed here.

## Deferred Windows delivery

Published a separate seven-computer policy and versioned signed delivery
assets. Independent readback of both controllers verified AD/GPT version 1,
the exact seven apply SIDs, authenticated users with read-only access, the
enabled non-enforced lowest-precedence link, and identical task/script bytes.
The original eight Endpoint policies, four distribution shares and existing
link order were independently compared and preserved.

Four historical deferred permits expire at
2026-10-28T21:22:41.826181Z. They assert registered/AD identity only, not fresh
offline authentication or successful installation. Actual execution requires
protected local identity, exact AD SID/object GUID, the qualified MSI-origin
149 profile with both original package digests, and a fresh authenticated
204 response over normal OS-validated HTTPS. Redirects, proxies and certificate
validation overrides are disabled. The existing bearer is used only in memory;
the probe does not persist it or read a response body. Actual native trial and
separate subsequent server acceptance remain required.

One real SYSTEM probe returned 204. The published task was then retrieved by
an actual incremental computer GPO refresh, with no forced refresh, logout,
reboot or manual task registration. Client RSoP contained the new policy and
the registered task's action matched the published bytes. Starting that actual
delivered task produced a fresh signed-bootstrap verified156 no-op and task
result 0, with no installation or HTTP probe. Already-current verification
precedes expired authorization handling; newer installations are not downgraded.

An initial verifier stopped on the localized SYSTEM account name. Resolving
the actual principal to SID S-1-5-18 corrected the verifier; no published policy
or product bytes were changed. A broad readback's UNC-context failure remains
recorded separately; independent narrow AD/ACL/link and fresh direct both-DC
GPT/task/script reads supplied the required proof.

## Final observation and parallel pilot

At 2026-10-26T21:47:43Z, all three newly updated production Windows devices
and the Linux canary still reported156, fresh `APPLIED`/`READY` and zero power
loss. API/worker had been separately deployed to a SSO/WorkTime pilot provider
at 21:19:15Z; clients established new sessions at 21:19:19Z. Earlier single-WSS
acceptance windows remain bounded observations, not an assertion that clients
never reconnected. The separate pilot is preparing newer157/158 packages;
its deployment and machines were not rolled back or overwritten here.

Five Linux assignments and four deferred Windows installations remain
unverified while offline. Historical Windows VM snapshot identities were
not treated as additional physical deployments. The actual qualification VM
was separately left healthy on156 after a genuine retry.

Final private-file and service checks remained unchanged after the GPP no-op.
All transient administrative helper services were verified absent; no Agent
service or delivered task was stopped or deleted.

Private operational evidence is retained outside Git under
`C:/Temp/endpoint156-fleet-rollout-20261027`,
`C:/endpoint-platform-wix-build/fleet156-windows149-20261027` and
`C:/endpoint-platform-wix-build/fleet156-domain-prepare-20261027`.
