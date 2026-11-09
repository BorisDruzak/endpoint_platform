# Windows187 optional-origin correction and automatic delivery

The user authorized automatic Windows updates, including devices currently
offline. The [186 fleet receipt](2026-11-10-windows186-fleet-auto.md) preserves
the initial rollout and its safe pause: native acceptance did not establish
successful Support migration on enrollments missing optional `endpoint-origin`.

## Correction and immutable media

Lifecycle delivery now accepts only a proven missing optional leaf beneath an
existing, non-reparse directory and uses the existing fixed production origin.
Existing overrides still require protected ACLs, an ordinary single-link ASCII
file and exact canonical origin. Credentials/private CA remain mandatory. The
HTTPS client still pins the private CA, destination and route, rejects redirects
and uses its existing bounded foreground process. No origin file, identity,
native fact or acknowledgement was manufactured; no native replay occurred.

Runtime source `785337b190114df212b0755a78f778783d716223`, packaging
`019d5cd4c09656a4ec487b0f03b7d5590a599bad`; see the
[release record](../releases/windows-3.2.187-setup.json). Setup187, its MSI and
Support1.1.2 have valid timestamped signatures from the existing publisher4D.
Frozen installer/Support modules were compared semantically with frozen source;
MSI-bound Support bytes matched the staged signed image. The exact observer108
remains unchanged. No Preview executable/archive is bundled.

The canonical publisher added the trusted candidate to the existing default
AUTO campaign without changing its CIDRs, expiry, quota or usage. Candidate
publication did not promote the primary download or enable the paused policy.
Public RAM staging was hash-checked and unmounted; operator originals and live
EXE remain. Root468049920bytes exceeded two166974248byte response buffers plus
110MiB reserve before canary assignment. No disk resize or history purge.

## Qualification runs

The real authenticated Console created these assignments on2026-11-09:

| PC | UUID | Source | Assignment |
| --- | --- | --- | --- |
| A2-MUNSLU-N /101.27 |13f38b93-cc73-4130-b58c-41f534b1893e|186/client108, origin absent|f93f5201-3046-4074-8b4a-0cd4ae578898|
| A2-INFAN-N /101.29 |dd5ebcfc-2e47-4d2b-ab29-85c689028b24|177/client107, origin present|bb971272-57c2-45d7-92cf-095ec784b2bf|

Read-only administrator SSH captured original private-file digests, existing
Support/global SSH states and outbox facts before both updates. Device27 had
genuine pending177 and186 installed facts, sequence1/2, no ACK. Device29 already
had a delivered177 fact. Both retained the existing domain administrator/key.
Bounded diagnostic leases were explicit manual renewals of expired existing
policies, not replayed installation grants or permanent/automatic renewal.

Both accepted APPLIED/native0 with preserved private4, exact source/MSI,
restored companions, fresh WSS and genuine user telemetry:27 at22:59:14.171102Z
after181.963seconds;29 at22:59:19.819497Z after181.428seconds, sensor_count1 each.
Actual domain administrator SSH then verified deployed Support1.1.2 hash,
timestamped Valid signature and `windows-openssh-fod-v1` on both PCs. Global
sshd state/startup/PID remained unchanged:27 Stopped/Manual/0;29 Running/Auto/4368.

Device27 automatically delivered177/186/187 facts in sequence1/2/3 at
22:55:57.668594/.746210/.802042Z. Existing event IDs, facts, generation anchor
and private bytes were unchanged; every fact has its canonical ACK. The missing
origin remained missing. Device29 preserved its delivered177 fact and added187
as sequence2. Neither manual diagnostic lease's expiry/revision/generation changed.

On27 the new Support PID10148 carried a fresh actual administrator SSH command
with Core/updater/global sshd Stopped and observer Disabled,27.03seconds after the
stop record. Core and observer were restored; Support never restarted. A unique
three-minute SYSTEM restoration task was registered before stopping Core, then
its exact action/principal and XML were checked and archived before removal.
It did not need to execute (last result267011, not claimed as a passed task).
The first oversized operator command was rejected before PowerShell ran;
read-only proof confirmed no task/directory/service change, then the same
strictly pinned SSH used stdin. No product/native state was repaired.
Fresh genuine UserSensor health23:03:51 and advancing activity after Core restart
confirmed recovery without restarting the sensor or the user's session.

The authenticated Console qualified both actual canaries:

- 177: `f9639599-1e90-4f62-bb01-3d36fae993e1`, expiry2026-12-09T23:01:10.556341Z;
- 186: `202cda3a-63b2-4ff9-9ed1-d4ed88d05095`, expiry2026-12-09T23:01:40.488492Z.

At2026-11-09T23:03:26.519916Z Console saved policy15, enabled target187,
`all_active`, empty UUID list and max_parallel2. Reload restored all values.
Preview checked27 registrations:5eligible,2alreadycurrent,6waiting,11blocked,
3otherplatforms. Five waiting PCs last reported177; legacy101.69/source79 remains
unsupported. Returning devices are reevaluated after fresh matching WSS/observer
and exact-source qualification; this is a dynamic persistent scope. Qualification
expiry, removed identities, unknown native ownership and readiness gates remain.
The available fleet's automatic assignments were observed separately. Device22
accepted native0/182.841seconds and Support1.1.2. ADMIN-2 accepted Core/native0
and189.72seconds but retained old Support1.0.1: its Windows Server FoD was absent
and the preparation script failed before DISM. At23:12:32.312817Z canonical
policy16 paused new187 assignments without cancelling the running120 chain.
That120 chain accepted native0/185.409seconds with Support1.1.2 at23:25:03.380863Z.
All five187 jobs are terminal; no native hold remains. New automatic delivery is
currently paused and Windows primary download remains177.

Actual local ADMIN-2 (`c450fc70-63e6-4c2b-baf6-7de79820d63f`) runs Windows11 IoT
LTSC build26100.9711 and still uses the bundled Preview runtime. Its protected
`os-servicing.json` contains known `failed`, not an unknown servicing operation.
The actual System32 Windows PowerShell5.1 returns a nested Object[] from
`@($json | ConvertFrom-Json)`. A single capability fails `[string]Name` parameter
binding; two capabilities fail the existing name guard. No Add-Capability call
appeared in DISM. The exact production-script regression reproduces this with
all native mutators isolated. Distinct188/Support1.1.3 will use direct assignment
and must qualify this real missing-FoD/Preview migration before new fleet work.
Do not promote187, backfill an origin, clear servicing/native receipts, or prepare
the missing capability manually to make the next canary pass.

## Verification and remaining limits

- Regression RED reproduced missing-origin delivery failure while the existing
  canonical-origin control passed. The first fixture ACL issue was corrected
  before the meaningful RED; production code was unchanged during that step.
- Targeted lifecycle/Support tests:121passed. Complete Windows suite after the
  golden-version fixture correction:2605passed,4skipped. Additional real-TLS
  invalid-protected-CA regression and origin suite:20passed; invalid CA cannot
  reach a connection or acknowledge a retained fact.
- Server/shared suite:4227passed,441skipped. Source/design review: no blockers.
- Native runtime119files/tree
  `01fcde976f0bac6c4d76c6c99cb95dca9fc406c8685c9c87f3b409d0dcb2a92c`;
 321bound source files, exact qualified toolchain and signed108 verified.

Support dependency/service/child/network/reboot fault behavior was actually
qualified on120 with186;187 changes the notification bootstrap boundary and
component version. A machine needing fresh FoD download or migration from an
actively bundled Preview installation is not live-qualified by these existing
OS OpenSSH tests. Native acceptance, independent component reports and a real
administrator command remain separate evidence. Linux183/Helpdesk and provider
runtime24461a70/schema51 are unchanged by this installer-only correction.

Operator evidence: `C:/endpoint-platform-wix-build/windows184-inbox-20261109`,
`artifact187-qualified.json`, `fleet187-*.json`, `read27_before187.stdout`,
`read29_before187.stdout`, `tests187-*.txt` and immutable native-build inputs.
