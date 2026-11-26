# Server release tools

- `build_console_server_archive.ps1`: clean committed server source + local Console
  bundle, using actual native tar staging and Python3.12 safe-header finalization.
- `normalize_server_archive.py`: server-only archive writer; validates one regular
  source tree, preserves payload bytes, emits deterministic root0:0/0644/0755
  headers and refuses existing output. It never extracts or edits deployed files.
- `apply_query_safe_nginx.py`, `verify_query_safe_nginx.py`: independent reviewed
  configuration-only callback logging repair and isolated sentinel verification.
- `tests/deploy/test_server_archive_permissions.py`: actual Windows PowerShell/
  native-tar header, byte-preservation/reproducibility and unsafe-input regressions.
- `deploy/server/PRODUCTION_RUNBOOK.md`: immutable archive identity, protected
  root extraction and complete physical/mode/digest closure before venv/imports.
- `inventory_deployments.py`: read-only release-volume inventory with current,
  rollback, staged commit, explicit pins, observed Linux process references,
  and transitive protection through links between release directories.
  `--check-release-space` checks the 10 GiB deployment threshold on the
  release volume and works before the initial selector is created. The
  worker uses the same check when running from a versioned release.
- `inventory_storage.py`: read-only artifact-volume inventory against the four
  release catalog owners. Both inventory modules ship in the server archive.
- `verify_server_release_payload.py`: operator-side, read-only comparison of a
  server archive's source payload with a deployed tree. Reports archive SHA-256,
  missing or different members and extra deployment paths.
- `prepare_endpoint_apt_windows.ps1`: verifies live APT trees on the Linux
  repository host and prepares date-only renewals with a Windows publisher.
  The Linux helper verifies the exact draft and signed package hash chain.
  `sign_endpoint_apt_release.ps1` keeps DPAPI and the private key on Windows.

No Agent release archive, native package, selector or live server is a target of
the server archive normalizer. Historical qualified bytes remain immutable.

- `worktime_helpdesk_staging.py`: fixed .118 server-only preparation/activation
  adapter for the reviewed runbook. Requires exact old selector/schema, frozen
  archive/digests, private capsule, fresh request, no in-flight operations, verified
  DB backup and unchanged personnel/grants. Additive migration44 stays applied on
  selector rollback. It never targets production or enables the feature flag.

## Agent release status

Run `python tools/release/agent_release.py status` from a checkout to read the
compact JSON projection. The tool reads the existing records and linked
receipts. The root version remains a historical checkpoint. JSON marked
`repository_record` describes observations made at the recorded times.
Unknown fields require a current observation from their owning catalog.

| Pointer | Checked-in source | Live authority |
| --- | --- | --- |
| Windows primary download | `primary_windows_release` and linked Setup receipt | Console installer catalog, newest active published row |
| Windows enrollment | No current campaign pointer in the checked-in projection | Single active default Windows AUTO campaign and trusted installer catalog |
| Windows existing devices | `current_windows_rollout` with an exact-ID receipt join for digest | Full Setup release, policy and coverage preview; Core has a separate builds and rollout catalog |
| ALT primary and native enrollment source | `linux`, linked signed kit receipt and its production native-source record | Published kit bytes, Linux native registry and applicable platform-bound enrollment campaign |
| ALT existing devices | No current delivery pointer in the checked-in projection | Native acceptance and Core OTA builds and rollouts |
| Ubuntu Noble and Debian Bookworm | `ubuntu_servers_197` and `proxmox_debian` | Per-suite verified signed `InRelease` and its hash-bound package index |
| Provider | `current_provider` | Deployed selector/source, schema and verified archive receipt |

The Windows download and fleet policy use distinct release UUIDs. A target that
differs from the primary receipt has an unknown digest in this projection.
The ALT native registry identifies source bytes. Campaign eligibility is
verified at enrollment. APT package entries alone do not prove that the signed
index is current; verify signature and expiry before using that delivery path.

For a current provider DB snapshot, run `agent_catalog_snapshot.sql` with
`psql -X -Atq -v ON_ERROR_STOP=1 -f` using existing read access. It exports
one JSON object using a read-only transaction and a five-second query timeout.
Capture production and staging separately. The snapshot retains every occupied
catalog version, including retired releases and candidate-only installer rows.
Core rows keep platform and channel. Published canary fixtures can use unusual
versions such as `3.2.60000` or `99.0.3280`. Occupancy and the next version in
the supported release series require separate checks. APT package inventories,
Git records, signing-host candidates and concurrent reservations are additional
inputs to version allocation.

The provider snapshot also groups the latest accepted Windows MSI and Linux RPM
installations by exact native source and package digests. Session presence is
a separate count. Use this as input to compatibility planning. OS build,
companion versions, pending local transactions and other profile details
still require their own evidence.

## Choose Windows or ALT delivery

Run the planner before selecting a builder in QUALIFY. Get the baseline Git
revision from the relevant qualified release and the current profile from the
owning catalog. The tool resolves both revisions to immutable commits. Use the
selected delivery and the current exposure matrix to choose Lab scenarios.

```powershell
python tools/release/release_plan.py --platform windows --base $qualifiedSource --target $buildRevision
python tools/release/release_plan.py --platform alt --base $qualifiedSource --target $buildRevision
```

`changed_components` traces changed inputs through the old and new PyInstaller
specs, their transitive local imports, and the native builder inputs. Use
`artifact_reasons` to see which component required each deliverable. Treat
`unclassified` as a hold until the owner is established. Review dynamic build
inputs against the builder, and use the canonical gates to qualify its output.
An aggregate diff can include changes for several releases. Confirm which
changes already shipped through the separate owning catalogs before defining a
smaller candidate scope.

| Change | Delivery and qualification |
| --- | --- |
| Windows Core runtime | Core ZIP through the Core update catalog for a verified compatible Foundation. |
| Windows launcher, MSI, Setup or native services | Full Setup via the existing exact-source Console workflow. Check Support and the signed Setup observer separately when their inputs change. |
| ALT Core runtime | ALT Core OTA and the existing Linux admission checks. |
| ALT launcher, native service/helper, or RPM payload | ALT native RPM, signed kit and native Setup in the existing release cycle. |
| Browser extension | Browser Sensor release. The extension ID is also a Core and native package input where the builders include it. |
| Endpoint contracts, provider or Console | Review changed contracts and migration IDs. Qualify compatibility with old and new agents and rehearse migrations and rollback. Provider-only changes require no agent build. |

For each candidate Core profile, repeat with `--runtime-contract` and
`--observed-launcher`. For Windows, use `endpoint-runtime-contract.json` from
the digest-verified Core ZIP. For ALT, use the source-bound OTA receipt with
`source_revision` and the canonical `update_build_manifest_v1` under `build`.
The reported minimum must match the target commit and agent version. A missing
contract, unknown launcher, or version below the floor leaves the profile on
hold. Check the canonical build registration and updater admission independently
before using the exact payload. Native enrollment and existing-agent delivery
retain their own acceptance gates.

The earlier [Core 3.2.164 qualification](../../docs/verification/2026-11-05-power27-sensor187-core164.md)
demonstrated delivery on Foundation 3.2.158 including the retained Windows Lab
VM, with private identity and native Foundation preserved. The planner was
replayed against that Core change and the contract extracted from its unchanged
ZIP. Foundation 3.2.156 was held. The full diff from the old 3.2.158 runtime
source also includes separately released Setup and provider changes.

CUPS changes require the provider and ALT agent capability to agree. The CUPS
merge reports ALT Core OTA and provider migration `0040_cups_operations`.
Check that `cups-actions.sqlite3` survives the candidate's update and rollback
before admitting the new payload to a CUPS deployment.
Replay the same command after reapplying the candidate and verify that the
queue still contains only the original test job. Check submission and queue
control separately under the actual Endpoint service account and target CUPS
policy. Where the operator has configured a policy for a managed test queue,
verify both directions of enabled and accepting state. Also verify that the
default-policy queue, an unrelated local identity, and printer administration
remain restricted. See the [ALT Lab receipt](../../docs/verification/2026-11-26-alt-cups-ota-development.md#политика-выделенной-очереди).

## Reserve and bind a Windows or ALT version

In QUALIFY, capture a fresh production and a fresh staging JSON snapshot with
`agent_catalog_snapshot.sql`. Collect the occupied versions from every Windows
and ALT signing host used by the release. Include previously signed native
candidates even if they were never registered with a provider. Supply the
candidate inventory as a JSON object with `schema_version` 1, an ISO 8601
`observed_at` timestamp with a timezone, and `windows` and `alt` arrays of version
strings. Use an empty array for a platform after checking its signing sources.

Use the same operation ID when repeating a command after an interruption.

```powershell
$request = [guid]::NewGuid()
$inputs = @(
  '--platform', 'both', '--after', '3.2.205',
  '--request-id', $request, '--production-snapshot', $productionSnapshot,
  '--staging-snapshot', $stagingSnapshot, '--candidate-inventory', $signingInventory
)
python tools/release/agent_release.py reserve @inputs --dry-run
```

The preview reads the current origin refs and local history. It calculates a
proposal while leaving the remote ledger untouched. To reserve it, repeat the
command with the same arguments and omit the preview switch. The actual version
can advance if another operator reserved a number in the meantime. Windows and
ALT use the same namespace on origin under the `codex/agent-release-reservations`
branch. Append using the tool to preserve its compare-and-retry behavior. Git
identity is required to write the ledger.

The version advances within the series selected by `--after` and above the
applicable native and stable history. Every known version is treated as
occupied. Historical Core canaries block their own numbers while leaving the
native version floor below a synthetic number such as `3.2.60000`. Capture all
three input files within the preceding 30 minutes. The ledger stores their
hashes and observation times.

Commit the reviewed version change in the candidate checkout, then run:

```powershell
python tools/release/agent_release.py bind-source --request-id $request
```

Use the returned `build_revision` for the build and for exact-artifact evidence.
The command verifies that the checkout is clean, descends from the reserved
source, and carries the reserved `AGENT_VERSION`. The binding is write-once.
Use the existing signing and publication flow for the resulting bytes.

### Run the qualification build

Check out the bound revision on the approved build worker. Supply the reviewed
baseline from the relevant release. The command selects the agent builder from
the delivery planner and keeps independent provider and Browser Sensor work in
their own release cycles.

```powershell
python tools/release/agent_release.py qualify-build --request-id $request `
  --platform windows --base $qualifiedSource --output-root $newBuildRoot --inputs $buildInputs
```

The first invocation previews the build. Add `--execute` on the selected x64
worker to run the builder. Use a new output directory outside the checkout.
The builder writes `builder.log`. On success `qualification-build.json` pins the
reserved version, source, baseline and output SHA-256 values. Keep failed logs
and partial output in the original directory. Preserve already recorded
candidate bytes for subsequent checks.

For the ALT native pair, `qualify-build` checks each finished RPM's package
identity and manifest against its CPIO payload. Core and UserSensor must share
the bound source revision and the same native source manifest. The receipt
includes `alt_native.frozen_manifest_sha256` and `alt_native.setup_sha256`
from the package contents. Each RPM output also records the SHA-256 of the lead,
main header and compressed payload. Signing can change the signature envelope.
The signed RPM's header and payload must still match the unsigned build.

Before handing the pair to the signer, record the build from the ALT x64
worker with the receipt and both unsigned RPMs in its output directory.

```bash
python tools/release/agent_release.py record-alt-build --request-id "$request" \
  --build-receipt "$qualificationBuildReceipt"
```

The command reinspects the unsigned pair and binds the exact receipt digest
to the request in Git. A retry returns the same entry for the same receipt.
An already signed RPM or a different receipt is rejected.

Paths in the local inputs JSON are relative to its own directory unless absolute.

| Selected artifact | Local `--inputs` fields |
| --- | --- |
| Windows Full Setup | `endpoint_origin` and `ca_file`. For the existing frozen-runtime path supply `initial_runtime_manifest`, `initial_runtime_stage_root` and `initial_runtime_stage_evidence`. Supply the existing documented approval switches as booleans under `approve_initial_runtime_transition` and `approve_initial_runtime_source_change` where applicable. Signing uses `certificate_thumbprint` and `timestamp_server` on the protected Windows worker. |
| Windows Core ZIP | `runtime_root` with the authored `endpoint-runtime-contract.json`. |
| ALT native RPM | No JSON inputs are required for the standard build. The worker builds the paired Core and UserSensor RPMs with native Setup. |
| ALT Core OTA | `runtime_root` and `channel` (`canary` or `stable`). Supply existing bound compatibility evidence with `--runtime-contract` when available. |

For Core, pass `--observed-launcher` for the source profile being reviewed. A
launcher below the floor stops execution for that profile. A Core build can
freeze bytes while delivery awaits profile evidence. The build receipt has no
publication authority. Proceed with the existing signature gates, exact
candidate record, native qualification and provider admission. Keep the local
inputs and build log with the operator.

### Build the ALT native pair from the bound revision

Check out the `build_revision` returned by `bind-source` on the approved ALT
builder. Run `packaging/alt/build-rpm.sh --with-native-setup --with-user-sensor`
with the existing platform build inputs. Setup takes the version from the
bound `pc_agent/version.py`. Support keeps its own version. When supplying
prebuilt frozen binaries, use `--setup-executable` together with
`--support-directory`. The RPM builder checks the build revision and component
versions before staging them.

For a stock ALT 11.4 target, record the exact Qt/KF6 development inputs and the
OpenSSL libraries used by the frozen components. The reviewed KDE sysroot can
be selected with `CMAKE_TOOLCHAIN_FILE` on the build worker. Compare the
contained OpenSSL bytes and the KDE probe's symbol versions with the reviewed
inputs. Run `rpm -U --test` on the exact pair on stock 11.4 and updated p11.
The first full DEVELOP pair could run when extracted but failed RPM dependency
resolution on stock. The rebuild with the stock OpenSSL input passed both
dependency probes with unchanged RPM inventories. See the
[ALT build receipt](../../docs/verification/2026-11-25-windows-alt-release-engineering.md#полная-сборка-нативной-пары-alt-в-develop).

After signing the Core and UserSensor RPMs, assemble the kit using
`python -m tools.build_alt_native_kit --version VERSION --source-revision SHA
--build-receipt PATH` and its `--core`, `--sensor`, `--setup`, `--public-key`,
and `--output` paths. Use the `qualification-build.json` from the same
`qualify-build` execution. The assembler verifies both signed RPMs, compares
their source and shared native manifest with the build receipt, and matches the
Setup hash to both the signed Core and the receipt. It archives the retained
copies it checked. Historical kit assembly can still run with its original
arguments. Use the existing detached-signature procedure and source-specific
Lab checks before registration or publication.

### Record the exact candidate artifacts

After the normal native build and signature checks, record its fingerprints
under the same request ID. Keep the candidate inputs in a read-only build
output while recording. Place the Windows EXE, MSI and inspected MSI manifest
beside the Setup sidecar. Place the ALT archive beside its outer manifest.
Keep the canonical output filenames.

On the Windows x64 build worker, use the clean bound checkout and the
`qualification-build.json` from that Full Setup build. Keep the four
recorded outputs in its `releases` directory. The signer thumbprint and
publisher come from the approved Windows signing inputs.

```powershell
python tools/release/agent_release.py record-windows-build --request-id $request `
  --build-receipt $qualificationBuildReceipt --expected-publisher $trustedPublisher `
  --expected-thumbprint $trustedSignerThumbprint
```

The step checks embedded timestamped Authenticode on the EXE and MSI and pins
the receipt digest and all four output digests in Git. Record the candidate
using the same files. Its digests must match the signed build entry.

```powershell
python tools/release/agent_release.py record-candidate --request-id $request --platform windows `
  --manifest $setupSidecar --expected-publisher $trustedPublisher
```

On the approved Linux publisher, use the unsigned build receipt for the
first ALT recording. Use the exact receipt already recorded by
`record-alt-build` and keep the kit and receipt in protected paths.

```bash
python tools/release/agent_release.py record-candidate --request-id "$request" --platform alt \
  --manifest "$kitManifest" --archive-signature "$kitSignature" --manifest-signature "$manifestSignature" \
  --build-receipt "$qualificationBuildReceipt"
```

The command checks the reserved version, bound source and exact artifact
digests. Windows also checks the inspected MSI metadata against the Setup
sidecar. Before the first ALT candidate write, the command checks both detached
signatures, both RPM signatures and the exact retained archive members. It
matches the reservation and unsigned RPM lead, main header and payload to
the build receipt and records the receipt digest. The ledger retains one
artifact set per reserved platform. An identical retry returns the existing
record and can omit the receipt, including for historical entries. A different
artifact set requires a new reservation.

The ledger entry supplies fingerprints for exact-artifact Lab verification.
Registration, qualification and promotion retain their current publisher and
Console requirements, including their independent signature checks.

Generate the native Lab matrix from the same reservation and actual files.

```powershell
python tools/release/agent_release.py qualify-matrix --request-id $request `
  --platform windows --artifacts-dir $sealedDirectory --snapshot $providerSnapshot `
  --windows-preview $coverage --profile-evidence $profiles
```

For ALT, pass `--platform alt` and omit `--windows-preview`. Keep the Windows
candidate sidecar, MSI manifest and packages together, or the ALT kit, outer
manifest and detached signatures together. The command reads the target version
and digest from the ledger and rechecks every recorded file. It stops on a
missing or changed file and on a rejected candidate. The JSON includes the
bound source and artifact fingerprints alongside the existing compatibility
cases. Use `--format brief` for the existing summary. Keep the plan in operator
storage with the provider snapshot and profile evidence.

For timing comparisons, collect the completed Windows Full Setup upgrade on
the same dedicated Lab guest and boot. Save stdout from both collectors as
UTF-8 JSON in the operator evidence directory.

```powershell
& ./tools/release/Collect-WindowsSetupTiming.ps1 -AssignmentId $assignment `
  -ExpectedComputer $labComputer -ExpectedHardwareId $labHardwareId
```

```bash
psql -X -Atq -v ON_ERROR_STOP=1 -v assignment_id="$assignment" \
  -f tools/release/windows_setup_timing_snapshot.sql
```

```powershell
python tools/release/agent_release.py report-windows-setup-timing --request-id $request `
  --assignment-id $assignment --artifacts-dir $sealedDirectory `
  --windows-receipt $windowsTiming --provider-receipt $providerTiming
```

The report checks the recorded candidate files, exact assignment, attempt,
device, Foundation binding and successful native settlement. It measures the
replacement transaction from Windows Installer events that bracket old-product
removal and target installation. Reported Windows phases use the Windows
clock and the observed last-write time of the accepted journal. Assignment
time and reported soak use the provider record. Collect this evidence before
a reboot, another Setup run, or event log rotation. Use the Console workflow
for qualification and promotion.

For local preflight on a dedicated Windows guest, use the recorded Setup
candidate and the reviewed installed source fingerprint.

```powershell
python tools/canary/staged_windows_update.py preview --admission $admission --candidate $setup
```

Schema 2 admission binds `computer`, `hardware_uuid` (canonical lowercase
SMBIOS UUID), `edition` (Windows EditionID), `build` (CurrentBuild.UBR),
`candidate_version`, `baseline_fingerprint`, `artifact_sha256`,
`source_revision`, and `signer_thumbprint` (lowercase hex for the digests
and thumbprint). Use the signed artifact record and the separately reviewed
Lab source to prepare this input. The preview pins the exact EXE while it
verifies Authenticode and runs the signed `--preflight`. A ready result covers
local admission; use the provider workflow for network qualification and
health evidence. Existing matrix and timing receipts still replay separately.
Local `run` requires the same admission and an explicit
`--execute-dedicated-guest` after the approved Lab scope is established.

Read the reservation and its artifact history with
`python tools/release/agent_release.py status --request-id REQUEST`. To retire a
candidate from this release attempt, record the exact Windows EXE or ALT archive
digest as follows:

```powershell
python tools/release/agent_release.py reject --request-id $request --platform windows `
  --sha256 $setupSha256 --reason 'Native recovery verification failed'
```

Rejection is specific to that platform and digest. It preserves the version,
source, artifact fingerprints and the original rejection reason across retries.
The Git record changes independently of provider availability, policy and
assignments. Verify exposure and any required Lab reset through their owning
systems before excluding the source profile from future qualification.

### Promote the exact Windows Setup after native acceptance

After the authorized Console canary, native qualification, coverage preview
and bounded delivery, check the known candidate on the target provider. Use
the existing publisher's environment with `DATABASE_URL` and `ARTIFACT_ROOT`.

```powershell
python tools/release/agent_release.py promote --platform windows --request-id $request `
  --artifacts-dir $sealedDirectory --expected-publisher $trustedPublisher `
  --qualification-id $qualificationId
```

The preview reports the existing installer ID, visibility, qualification
expiry and current default AUTO campaign. It checks the recorded files and
provider evidence without changing publication, enrollment or assignments.
Add `--execute` for the authorized publication. The same publisher rechecks
the application of the exact native assignment, stored EXE and qualification
under transaction locks. It preserves the installer release ID and records the
qualification ID in the visibility audit event. The default AUTO campaign joins
the transaction with its authority and history intact. The diagnostic exclusion
uses `--without-auto-enrollment` under its existing policy.

### Verify and register the exact ALT native pair

Use the protected Linux publisher with the independently pinned ALT public key
and the recorded kit, manifest and detached signatures in its private staging
directory. Verify while holding the exact reservation.

```bash
python tools/release/agent_release.py register-alt-native --request-id "$request" \
  --artifacts-dir "$sealed_kit" --public-key "$publisher_key" --reviewed-by "$reviewer"
```

The default invocation checks both kit signatures and checks the two signed
RPM headers and payloads. It binds the RPMs and Setup to the recorded kit,
version, source and frozen native manifest. It emits the reviewed native
source without connecting to a provider. On the authorized provider worker,
load its `DATABASE_URL` and use `--execute` to register the pair through the
existing Linux native publisher. Registration returns the immutable native
release UUID. Kit download publication and Linux enrollment campaigns have
their own procedures and scope.

### Prepare the verified ALT download payload

On the protected Linux publisher, use an existing root-owned `0700` incoming
directory on the distribution filesystem. Keep it outside the Nginx alias.

```bash
python tools/release/agent_release.py prepare-alt-download --request-id "$request" \
  --artifacts-dir "$sealed_kit" --incoming-root "$private_incoming"
```

This previews the exact filenames, sizes and digests from the recorded kit.
Add `--execute` to prepare one private version directory containing the two
signed objects, their detached signatures, the pinned public key and both
checksum sidecars. It appears as a complete directory after all files have
been written and verified. An exact retry returns the same directory and
report. Conflicts require operator review. Use the reviewed version-specific
operator guide and the separately authorized activation procedure in
[ALT distribution](../../deploy/server/ALT_DISTRIBUTION.md).

### Verify the served ALT download

After authorized activation, use the environment CA and canonical origin.

```bash
python tools/release/agent_release.py verify-alt-download --request-id "$request" \
  --origin "$endpoint_origin" --ca-file "$endpoint_ca"
```

The command uses the same recorded candidate to check HEAD, GET size and
SHA-256 for all seven files over HTTPS. The report gives the URL prefix,
request ID and observed check time. It fails on redirects, TLS name or
authority failure and any different byte sequence. Complete the additional
download-path checks from the [distribution runbook](../../deploy/server/ALT_DISTRIBUTION.md).

### Verify ALT factory installation before enrollment

Use a reset, disconnected ALT Workstation K x64 Lab guest and the exact recorded native kit.
The Proxmox runner takes an operator export from
`agent_release.py status --request-id` and the four recorded kit files.
Stage those inputs and this repository code on the authorized local Proxmox
host. Use the exact VM name, ID, guest UUID and the SHA-256 of the reviewed
cold snapshot configuration from `qm config <vmid> --snapshot <name>`.

```bash
python3 tools/canary/run_alt_factory_offline.py \
  --vmid "$lab_vmid" --expected-name "$lab_name" --guest-uuid "$guest_uuid" \
  --snapshot "$clean_snapshot" --snapshot-sha256 "$snapshot_sha256" \
  --reservation-file "$reservation" --artifacts-dir "$sealed_kit" --output-dir "$new_receipts"
```

The preview checks the stopped VM, its offline hardware and exact recorded kit
bytes. Add `--execute` on the authorized host to check the clean guest, verify
the detached signatures inside it, install and capture native results.
The runner records the dispatch before starting Setup and follows one guest
process handle. A confirmed native RPM zero admits the ordinary reboot and
automatic retry check. Accepted receipts allow the runner to restore and
verify the original snapshot, then stop the guest. Failures preserve the guest
and captured receipts for review. The output directory and private guest
staging directory are single-use.

For independently collected evidence, use the same reset guest and kit.
Keep the clone and snapshot identity with the observations. Capture the raw
QEMU guest-agent JSON for each phase. Inside the guest run
`python3 -B observe_alt_factory_offline.py` from
[`tools/canary`](../canary/observe_alt_factory_offline.py) for `before.json`,
`after-install.json`, `after-reboot.json` and `after-timer.json`. Use the
verified signed kit and the native installation procedure in the
[ALT runbook](../../docs/runbooks/ALT_AGENT_INSTALL.md). Save the QEMU
result as `install.json` with the lines `stock_rpm_pair_test=0` and
`setup_install_exit=21` from the actual results. Reboot the clean Lab
guest normally. Preserve the timer and service properties as
`retry-timer-status.json` once the automatic retry completes.

```bash
systemctl show endpoint-agent-setup-retry.timer -p Id,LastTriggerUSecMonotonic,Result
printf '\n'
systemctl show endpoint-agent-setup-retry.service -p Id,ExecMainStartTimestampMonotonic,ExecMainStatus,Result
```

```bash
python tools/release/agent_release.py verify-alt-factory-offline --request-id "$request" \
  --artifacts-dir "$sealed_kit" --evidence-dir "$qga_receipts"
```

The check joins the six receipts to the exact recorded kit. It requires a
durable native RPM exit 0, the same RPM transaction after reboot and automatic
reconcile, preserved OS packages and public CA, and zero enrollment events
or ACKs. An outer exit 21 with pending registration is expected in this scope.
The result is read-only evidence for `factory_offline`. First enrollment
and publication use their respective acceptance gates.

The Proxmox runner captures guest monotonic timings for kit verification
and extraction, `rpm -U --test`, and the exact Setup process through its
pre-enrollment exit. Replay exposes the measurements as
`timing.guest_elapsed_ns` in the verified result. Compare timing on the
same stock snapshot and runner. Boot, QEMU transfers, and the subsequent
reboot and reconcile are outside these intervals. Historical receipts replay
without timings. A malformed timing observation is marked invalid while the
native acceptance checks still apply.

### Check first ALT enrollment on the Lab provider

On the protected Linux publisher, set `DATABASE_URL` for the selected Lab
provider. Use the recorded kit, the exact enrollment request and the
independently confirmed Lab device ID.

```bash
python tools/release/agent_release.py qualify-alt-enrollment --request-id "$request" \
  --artifacts-dir "$sealed_kit" --enrollment-request-id "$enrollment_id" --device-id "$lab_device_id"
```

The command verifies the signed kit and checks the immutable registered pair,
consumed claim, active credential and exact first installation ACK. It requires
one fresh matching WSS and an accepted ALT baseline collected on that session. The server must
have received a fresh interactive activity sample after the session opened.
It prints the kit and evidence IDs and omits user activity details. A missing
gate returns a structured `hold` report and exits with code 1. PostgreSQL is
read in a repeatable-read, read-only transaction. The report covers first
enrollment observations only. Release authorization, upgrade paths and
enrollment campaign changes follow their existing workflows.

### Record ALT acceptance and publish the versioned download

During live Lab acceptance add `--qualification-id "$qualification"` and
`--valid-until "$valid_until"` to `qualify-alt-enrollment`. Use a stable UUID
and a timestamp with an explicit UTC offset. The protected publisher writes
fresh acceptance to the existing Git ledger with the exact archive digest,
first-enrollment scope, observation IDs and validity. The maximum validity
is 30 days, matching the native Setup qualification window. Reuse the
accepted ID when retrying the same authorization.

After release authorization, use the prepared private directory and the
approved version-specific guide on the Linux distribution host.

```bash
python tools/release/agent_release.py publish-alt-download --request-id "$request" \
  --qualification-id "$qualification" --incoming-root "$private_incoming" \
  --origin "$endpoint_origin" --ca-file "$endpoint_ca" --worker-user "$nginx_user" \
  --guide "$reviewed_guide" --guide-sha256 "$approved_guide_sha256"
```

Preview checks the recorded qualification, retained bytes, guide and target
directory. Add `--execute` to check file readability as the unprivileged
worker and atomically add the version directory to the existing alias.
The publisher verifies all eight HTTPS responses and probes the directory
index and non-download access rules. A failed check withdraws the directory
created by that invocation and preserves the private prepared bytes. A retry
requires the exact same public files. Release authority for the primary
pointer, new enrollment campaigns and existing-device work is separate.

### Include a qualified ALT release in one enrollment campaign

Set `DATABASE_URL` for the provider that owns the existing, authorized RPM
campaign. The provider independently registers the same native pair and may
use a different native source UUID from the Lab.

```bash
python tools/release/agent_release.py include-alt-enrollment-release --request-id "$request" \
  --qualification-id "$qualification" --campaign-id "$campaign"
```

The read-only preview returns the target source and `scope_sha256` for the
kit, campaign ID, network ranges, mode, expiry, quota and other allowed RPM
sources. Apply the separately authorized grant with `--execute --scope-sha256
"$reviewed_scope_sha256"`. The provider rechecks the reviewed scope and the
exact active source under the campaign lock. It holds overlapping campaigns
for the same source and rejects campaigns for non-RPM sources. It appends
only the approved source and retains the campaign's expiry, mode, quota and
usage. A repeated grant returns the same state and leaves one audit event.

### Withdraw an ALT first-enrollment download

Use the reservation request and signed kit archive SHA-256 to preview the
revocation. The command returns its exact scope and reason. Add `--execute`
to record the authorized revocation in the shared release ledger.

```bash
python tools/release/agent_release.py record-alt-revocation --request-id "$request" \
  --sha256 "$kit_sha256" --reason "$approved_reason"
```

The record blocks new first-enrollment qualifications, download activations
and enrollment grants through the release CLI for that exact kit. The
ledger preserves the candidate and all prior qualifications. Inspect the
record with `status --request-id "$request"`.

On the distribution host, preview the local state using `withdraw-alt-download`.
Use an existing operator-owned mode-0700 archive on the same filesystem,
outside the public alias. Supply the approved guide and digest from the
original publication evidence.

```bash
python tools/release/agent_release.py withdraw-alt-download --request-id "$request" \
  --sha256 "$kit_sha256" --origin "$endpoint_origin" --ca-file "$trusted_ca" \
  --archive-root "$private_archive" --guide "$guide" --guide-sha256 "$approved_guide_sha256"
```

With `--execute` the command verifies the exact eight files, archives the
public directory with one rename and requires HTTPS 404 for HEAD and GET
on each URL. Failed HTTPS verification leaves the files private and is
safe to retry. Keep the withdrawal receipt and use the campaign procedure
for current provider grants.

### Withdraw existing ALT enrollment grants

Set `DATABASE_URL` for the provider that owns the RPM campaigns. Use the
same revoked reservation and kit digest. The read-only preview shows
the affected campaigns and their actions, including disabled or expired
campaigns, plus any pending delivery.

```bash
python tools/release/agent_release.py withdraw-alt-enrollment-grants --request-id "$request" \
  --sha256 "$kit_sha256"
```

Apply the approved scope with `--execute --scope-sha256 "$reviewed_scope_sha256"`.
The provider rechecks the exact RPM source and campaign scope under lock.
It removes the source from campaigns with alternatives, and canonically
revokes campaigns that allow only that source. A pending credential delivery
blocks execution until acknowledgement or expiry. Existing unconsumed
claims follow the canonical eligibility check. The native source, installed
device credentials and historical events support continued lifecycle
reporting. A replay returns the audited scope once that grant set is absent.

## Plan native qualification

Capture a fresh provider snapshot using `agent_catalog_snapshot.sql`. Keep this
snapshot and the planner JSON in operator storage. They include device and
native event IDs. The snapshot distinguishes installed evidence, open WSS,
active assignments, preparation, recovery, pending enrollment and catalog
campaign references. Campaign counts show active allowlist references with
quota remaining. Enrollment still depends on the owning provider, source
network, policy and request state.

```powershell
python tools/release/compatibility_matrix.py --snapshot $productionSnapshot `
  --platform windows --target-version 3.2.276 --target-sha256 $setupSha256 --format brief
python tools/release/compatibility_matrix.py --snapshot $productionSnapshot `
  --platform alt --target-version 3.2.274 --target-sha256 $kitSha256
```

The default JSON retains every held device, its source evidence and reason.
`--format brief` counts cases by reason. The factory first-registration test
remains required. A matching, settled and connected source profile adds a
native transition test. Identical source profiles, native package hashes and
Console decisions share one test case.

For Windows, capture the authenticated read-only Console fleet preview with
`scope=all_active` for the intended release. Pass `--windows-preview` a JSON
object with the capture time `observed_at`, the request `scope` and `release_id`,
the SHA-256 of that registered release, and the unchanged `response` from the
Console. The planner verifies the capture against the provider catalog. A
truncated preview cannot support the matrix. A Console `source_not_qualified`
result identifies a Lab test to perform for the matching profile. The Console
continues to own operational admission.

Current Console previews include `native_route`. `direct` has an empty step
list. `legacy_bridge_return` lists Core163 followed by the compatible Core155
or Core157 return. `observer_bootstrap` lists the registered upward Core166.
Every Core step carries its build ID, version and SHA-256. Routes are recorded
in JSON and shown with step versions in the brief output. An explicit null
route yields `HOLD / native_route_unconfirmed` for an otherwise testable
profile. Older previews still produce cases without route evidence.

The Windows source Foundation must agree with the confirmed native MSI event.
An observed mismatch yields `HOLD / native_foundation_mismatch`. An OTA Core
version stays independent and forms a separate profile when it differs.

For a direct Windows transition, supply `--windows-lab-evidence` and
`--qualification-environment` to reuse an existing qualification in the plan.
The latter is the SHA-256 of the reviewed current environment manifest. Keep
the provider revision, database revision and relevant trust and Setup policy
inputs in that manifest without credentials. The original Lab receipt must
identify the same environment. Capture an updated provider snapshot that
includes `release_planning.windows_qualifications`.

The evidence file has a fresh `observed_at` and `qualifications` array. Each
reviewed entry contains `qualification_id`, `evidence_assignment_id`,
`target_sha256`, `environment_sha256`, `receipt_sha256`, the full source
`native` object as `source`, the source `profile` described below and
`native_route`. The receipt digest identifies the retained Lab evidence
reviewed by the operator. The planner checks the live qualification and its
applied assignment, the exact EXE, source Core/Foundation/Setup Client, native
source, complete profile and route. The provider qualification must still be
valid and Console must return `eligible` for that device. A match preserves
`REQUIRED` and adds `satisfied_by` with the qualification, assignment, receipt
digest and expiry. Factory, bridge and ALT transitions keep their own test
requirements. This report grants no operational admission.

```powershell
$environmentHash = (Get-FileHash -LiteralPath $currentEnvironment -Algorithm SHA256).Hash.ToLowerInvariant()
python tools/release/compatibility_matrix.py --snapshot $productionSnapshot `
  --platform windows --target-version 3.2.276 --target-sha256 $setupSha256 `
  --windows-preview $coverage --profile-evidence $profiles `
  --windows-lab-evidence $reviewedLabEvidence --qualification-environment $environmentHash
```

Supply independently verified native profile observations via
`--profile-evidence`. The JSON has `observed_at` and `devices`. Each device
entry contains `device_id`, `native_event_id`, and a `profile` with the following
fields. Use `absent` only when absence was confirmed locally.

- `os_name`, `os_build`, `os_edition`, `architecture`
- `core_version`, `foundation_version`, `setup_client_version`, `support_version`
- `state_schema`, `acl_profile`, `local_transaction` (`settled` or observed hold)

`--lab-candidates` accepts a separately reviewed inventory with `observed_at`
and `candidates`. Each entry contains `platform`, `version`, artifact
`sha256`, the hash of the reviewed reset/exposure receipt `receipt_sha256`,
`exposure` and `reset`, plus an optional `regression_test` identifier. Use
`lab_only` and `verified` only after checking current and historical exposure
including staging, offline or pending work, and a completed Lab reset. A
conflicting provider observation keeps the candidate in `HOLD`. Otherwise the
verified Lab source can be `EXCLUDED` from mandatory transitions. An explicit
`regression_test` keeps that targeted scenario in the plan.

Input observations must be within 30 minutes of execution with a 30-second
clock tolerance. Use the canonical preview and Lab evidence for the actual
artifact and source route before a delivery decision.
