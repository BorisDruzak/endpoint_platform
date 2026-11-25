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

After signing the Core and UserSensor RPMs, assemble the kit using
`python -m tools.build_alt_native_kit --version VERSION --source-revision SHA`
and its `--core`, `--sensor`, `--setup`, `--public-key`, and `--output` paths.
The kit assembler verifies both signed RPMs, their common native manifest,
and the Setup digest carried by Core. Use the existing detached-signature
procedure and source-specific Lab checks before registration or publication.

### Record the exact candidate artifacts

After the normal native build and signature checks, record its fingerprints
under the same request ID. Keep the candidate inputs in a read-only build
output while recording. Place the Windows EXE, MSI and inspected MSI manifest
beside the Setup sidecar. Place the ALT archive beside its outer manifest.
Keep the canonical output filenames.

```powershell
python tools/release/agent_release.py record-candidate --request-id $request --platform windows `
  --manifest $setupSidecar --expected-publisher $trustedPublisher
python tools/release/agent_release.py record-candidate --request-id $request --platform alt `
  --manifest $kitManifest --archive-signature $kitSignature --manifest-signature $manifestSignature
```

The command checks the reserved version, bound source and exact artifact
digests. Windows also checks the inspected MSI metadata against the Setup
sidecar. ALT checks each archive member and the bundled manifest against the
outer manifest, pins the publisher key digest and records the detached
signature artifacts. The ledger retains one artifact set per reserved
platform. An identical retry returns the existing record. A different artifact
set requires a new reservation.

The ledger entry supplies fingerprints for exact-artifact Lab verification.
Signature authenticity and timestamps are verified through the existing
native gates. Registration, qualification and promotion retain their current
publisher and Console requirements.

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
