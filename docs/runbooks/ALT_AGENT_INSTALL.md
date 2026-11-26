# ALT Endpoint Agent installation

This describes operator-run installation. The signed native workstation kits
below are qualified on ALT Workstation K 11.4 x86_64 with compatible dependencies.
CA trust, credentials and configuration are provisioned separately.

## Current native RPM workstation path

The current native kit for ALT Workstation K 11.4 x86_64 is 3.2.278.
The production pilot upgraded the signed .183 RPM pair on one workstation
and confirmed the original device identity, fresh Activity and Support access.
First enrollment was qualified in Lab. A new production enrollment needs an
authorized campaign for this exact native source. Existing-device delivery
uses an individually authorized native Setup operation.
[Download .278](https://endpoint.sosnadmin.local/downloads/alt/endpoint-alt-pilot-3.2.278-1/endpoint-alt-pilot-3.2.278-1.tar.gz) · [Operator guide](https://endpoint.sosnadmin.local/downloads/alt/endpoint-alt-pilot-3.2.278-1/README.ru.md) · [Release record](../releases/linux-3.2.278-native.json)

The earlier .265 production pilot upgraded the registered .183 pair on one workstation.
The .267 kit has separate laboratory coverage. The signed
[.269 candidate](../releases/alt-3.2.269-candidate.json) is local laboratory media.
[Download .265](https://endpoint.sosnadmin.local/downloads/alt/endpoint-alt-pilot-3.2.265-1/endpoint-alt-pilot-3.2.265-1.tar.gz) · [Pilot instructions](https://endpoint.sosnadmin.local/downloads/alt/endpoint-alt-pilot-3.2.265-1/README.ru.md) · [Qualification matrix](../verification/2026-11-14-agent-release-qualification-matrix.md)

The signed .270 candidate has a verified .265 upgrade on one enrolled lab
device. Before a first install, check the existing `/etc/endpoint-agent`
directory, if present. The .270 package expects a real directory owned by
`root:root` with mode `0755`. A different mode stopped installation after
RPM had recorded both packages. The working version selector was absent and
Setup returned 21 again after reboot. Preserve existing CA and credentials
when reviewing such a device.
[Candidate record](../releases/alt-3.2.270-candidate.json)

For a lab upgrade to 3.2.274, use the version-specific guide. It gives the
archive and detached signature names, publisher fingerprint, and the accepted
source RPM pairs (.183, .265 and .270). On updated p11 with Plasma X11, the
.265 to .274 test included a normal login after reboot. Check the fresh
UserSensor sample, Core session and Support report on the original device
card. Use the preflight below before launching Setup.
[.274 operator guide](../releases/alt-3.2.274-lab.ru.md) | [Qualification evidence](../releases/alt-3.2.274-candidate.json)

After offline removal and reinstall of .274 on the updated p11 profile, run
the kit's ordinary `reconcile` when the enrolled Gateway is reachable. Check
the removal and install acknowledgements on the original card, then check the
new Core session. Final removal erased the local Support keys on the test
device. The Gateway retained its previous keys and reported a conflict when
Support presented new ones. Setup continued to return 21 with Core connected.
Treat Support as unavailable pending the administrator's key confirmation.
On the .274 lab device, one operator confirmation followed by the same
`reconcile` completed with code 0. After reboot, Core and Support both
reported on the original card. Installation ACK 6 remained current and SSH
access remained disabled.
[Operator procedure for confirming the device and resuming Setup](LINUX_NATIVE_SETUP.md#installation-and-removal) ·
[Offline reinstall and Support result](../releases/alt-3.2.274-candidate.json)

### Single-device pilot from .265 to .270

The approved target is `alt-a2-pc1`, device
`44e17f70-f23c-4c49-ae22-f43a5619258f`. In Console, confirm fresh Core
contact on this card, the accepted .265 installation, and an empty update
slot. On the workstation, match the installation journal to the same card
and accepted sequence. The source operation must be settled with native
exit 0 and bootstrap complete. Check Core and Support are running and
retain the verified .265 kit for an operator-approved return.

Use the file verification section of the .270 guide to verify and extract
the kit. The upgrade example in that guide selects .183. For this pilot,
record the eight desktop package versions and run the exact-pair preflight
with `version=3.2.270`. Check the mode and owner of the existing
`/etc/endpoint-agent` directory on the workstation. The .265 pilot
recorded modes and owners for the CA, configuration and identity files.
[Kit verification](../releases/alt-3.2.270-lab.ru.md) · [RPM preflight](#preflight-265-269-and-270) · [Desktop package query](#identify-the-tested-270-desktop-profile)

After these checks pass, run the following block once from the verified,
extracted .270 directory in an administrative session that survives the
agent service restart. Keep the workstation's configured Gateway and CA.

```sh
(
  set -eu
  test "$(hostname -s)" = alt-a2-pc1
  for package in endpoint-agent endpoint-agent-user-sensor; do
    source_evra=$(LC_ALL=C rpm -q --qf '%{EPOCH}:%{VERSION}-%{RELEASE}.%{ARCH}\n' "$package")
    test "$source_evra" = '(none):3.2.265-alt6.x86_64'
  done
  rpm -V endpoint-agent endpoint-agent-user-sensor
  ./endpoint-agent-setup upgrade \
    --core-rpm ./endpoint-agent-3.2.270-alt6.x86_64.rpm \
    --user-sensor-rpm ./endpoint-agent-user-sensor-3.2.270-alt6.x86_64.rpm \
    --public-key ./endpoint-rpm-release.asc
)
```

Record the Setup exit code. For exit 0, verify both installed .270 RPMs
with `rpm -V`, the .270 selector, the next linked installation ACK and fresh
Core and Support reports on the original card. For exit 21, inspect the
existing operation and its delivery state before using the documented
`reconcile` procedure. If the session disconnects, check the original
invocation and journal before taking another action. The .265 → .270
upgrade and return both passed on updated p11.
[Lab round trip](C:/endpoint-platform-wix-build/stab15-alt265-to270-roundtrip-307-308/qualification.md)

<a id="preflight-265-269-and-270"></a>

### Preflight for .265, .269, .270 and .274

Obtain the approved exact kit for the planned operation. Follow the published
.265 pilot guide for that version. In the [.270 operator kit](../releases/alt-3.2.270-lab.ru.md),
verify `.tar.gz` with `.tar.gz.sig` and `.manifest.json` with `.manifest.sig`.
In the .269 and .270 build output directories (`offline-kit`), the manifest
signature is named `.manifest.json.sig`. The .270 operator kit and build output
contain the same signature bytes. For .274, the archive is
`endpoint-alt-pilot-3.2.274-1.tar.gz` and its signature is
`endpoint-alt-pilot-3.2.274-1.tar.gz.sig`. The manifest is
`endpoint-alt-pilot-3.2.274-1.manifest.json` and its signature is
`endpoint-alt-pilot-3.2.274-1.manifest.json.sig`. Use the independently pinned publisher
fingerprint `BC24B8EE43DBB05A748E11A4343B5DA748370631`.
Verify both signatures before extraction, using the
[publisher trust procedure](LINUX_NATIVE_SETUP.md#trust-the-distribution-before-executing-it)
and the filenames for the selected version. After extraction, compare the detached manifest
to the embedded `native-kit-manifest.json` and check the size and SHA-256 of
every listed file. Keep the verified kit in a root-owned directory writable
only by root.

From that directory, run this check as root before ordinary installation or
upgrade. For .274, use the extracted `endpoint-alt-pilot-3.2.274-1`
directory. The example selects .274. Set `version` to the approved target
for the other kits. For the .265 pilot, also check the registered device
and the installed .183 pair as specified in the pilot guide.

```sh
set -eu
version=3.2.274
cat /etc/altlinux-release
grep -Eq '^ALT Workstation K 11[.]4([[:space:]]|$)' /etc/altlinux-release
test "$(uname -m)" = x86_64
case "$version" in
  3.2.270|3.2.274)
    if [ -e /etc/endpoint-agent ] || [ -L /etc/endpoint-agent ]; then
      test ! -L /etc/endpoint-agent
      test -d /etc/endpoint-agent
      test "$(stat -c '%u:%g:%a' -- /etc/endpoint-agent)" = 0:0:755
    fi
    ;;
esac
rpm -U --test \
  "./endpoint-agent-${version}-alt6.x86_64.rpm" \
  "./endpoint-agent-user-sensor-${version}-alt6.x86_64.rpm"
```

Continue to the approved Setup operation only after every check returns zero.
For .274, the command checks `endpoint-agent-3.2.274-alt6.x86_64.rpm`
and `endpoint-agent-user-sensor-3.2.274-alt6.x86_64.rpm`.
The dry run checks both exact RPMs together. A dependency error stops the
operation even on the correct OS edition. Use the approved platform package
procedure if dependencies need updating, then repeat the check. Omit
`--oldpackage` for ordinary installation or upgrade. An intentional return to
a previous version follows its separate verified rollback procedure.

The base 11.4 test image had OpenSSL 3.3.3-alt1 and Qt 6.10.3-alt2.
RPM rejected the .183, .265 and .269 pairs on that image. All three passed
the dependency check on the p11 image with OpenSSL 3.5.7-alt2 and Qt
6.11.2-alt2. These versions identify the two tested images. Use the RPM
dry run above to decide whether the actual target satisfies the complete
dependency set. [Base and p11 results](../verification/2026-11-14-agent-release-qualification-matrix.md)

<a id="identify-the-tested-270-desktop-profile"></a>

### Identify the tested .270 and .274 desktop profiles

On ALT Workstation K 11.4 x86_64, run this read-only query as an ordinary
local user to compare the desktop and runtime libraries with the lab images.
It prints the package name, version-release and architecture.

```sh
LC_ALL=C rpm -q --qf '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n' \
  plasma-workspace kwin-x11 libqt6-core libqt6-gui \
  libkf6idletime libssl3 libcrypto3 glibc-core
```

| Package | Base 11.4 image | Updated p11 image |
| --- | --- | --- |
| plasma-workspace | 6.6.5-alt1 | 6.7.5-alt2 |
| kwin-x11 | 6.6.5-alt1 | 6.7.5-alt1 |
| libqt6-core, libqt6-gui | 6.10.3-alt2 | 6.11.2-alt2 |
| libkf6idletime | 6.26.0-alt1 | 6.26.0-alt1 |
| libssl3, libcrypto3 | 3.3.3-alt1 | 3.5.7-alt2 |
| glibc-core | 2.38.0.123.650a0-alt1 | 2.38.0.123.650a0-alt1 |

All eight packages on both images were x86_64. A full match identifies the
tested library set. If a package is missing, has a different version, or has
an additional architecture, record the actual set as a separate profile.
Use the signed-pair RPM dry run above to check the actual host's dependencies.

**.270.** Gateway received fresh UserSensor samples from both profiles. On
the base image, the first approved enrollment produced ACK 1. Core, Support
and the Plasma X11 sensor reported again after reboot and login.
[Base image enrollment and reboot](../releases/alt-3.2.270-candidate.json)
[Base image receipt](C:/endpoint-platform-wix-build/stab15-alt270-stock-plasma/stock-plasma-late.json) ·
[Updated p11 receipt](C:/endpoint-platform-wix-build/stab15-alt270-usersensor/environment.json)

**.274.** On factory 11.4, the signed pair passed the RPM dry run, offline
installation and an ordinary reboot. Setup returned 21 pending enrollment.
First enrollment, registered Core and Support, and interactive UserSensor
remain unverified on that profile. On updated p11, the registered .265 to
.274 upgrade and reboot produced a fresh Core session and Support report.
A normal Plasma X11 login produced a fresh UserSensor sample on the original
card. [Qualification evidence](../releases/alt-3.2.274-candidate.json)

For the earlier native .183 release with independent Support 1.0.0,
use [Linux native Setup](LINUX_NATIVE_SETUP.md) and its exact
[release record](../releases/linux-3.2.183-native.json) for signed bytes, installation,
ordinary removal/reinstall, offline recovery and qualification limits. The canonical
coordinator verifies both RPMs and owns the known-native result. Existing-identity
upgrades preserve UUID/credential/history. A fresh install requires separately
approved bounded Linux enrollment authority; publication creates no new campaign.

The historical3.2.127-2 kit and its separate CUPS repair/rollback/source RPMs remain
archived under `packaging/alt/pilot/README.ru.md`. Keep their original qualification
and package ownership separate. Native183 media does not include a new CUPS release.

Build the current headless layout on ALT using `packaging/alt/README.md` and
`bash packaging/alt/build-rpm.sh --with-user-sensor`; freeze/review/sign its exact
source before distribution. Install the paired archives through native Setup.
Core-only runtime OTA must preserve RPM-owned privileged helpers and units.
The legacy offline layout below remains a separate historical procedure.

The optional package supplies KDE autostart and the restricted browser helper.
For a session already running during installation, execute
`systemctl --user daemon-reload` then
`/usr/lib/endpoint-agent/start-user-sensor --autostart` inside that graphical
session. Subsequent KDE logins publish the private session environment and restart
only this sensor unit. Do not import its variables into the whole user manager.

Preserve existing AD/SSSD and corporate browser policy. Agent-managed deployment
owns only its marked Endpoint extension file; conflicting foreign policy is an
explicit failure. External-managed deployment observes policy and heartbeat
without taking ownership. ALT Yandex 26.4 is detected by its verified installed
binary under /usr/lib64/yandex/browser. Its managed policies live under
/etc/opt/yandex/browser/policies/managed and it uses Chromium's system native-host
manifest. Unrelated valid forced extensions are preserved; conflicting policies
remain an explicit failure. Unrecognized installations remain unknown.
CUPS/USB audit requires actual sources; temporary CUPS unavailability recovers
without restarting Core. Physical USB acceptance is a separate operator test.

RPM upgrades preserve device state. The artifact sidecar is package documentation,
never an extra file inside an immutable runtime. Verify current.json and selected
release hashes/modes after installation; runtime OTA must never replace RPM-owned
units or privileged helpers. Require server terminal outcomes and a subsequent
successful WSS command; scheduled alone is insufficient. Use the parity ledger
and current baseline for the private 3.2.127 follow-up acceptance limits.

If CUPS reports "Max clients reached" during cups-browsed discovery, inspect
the number and owners of local socket connections before changing Agent
timeouts. On the reference host, cups-browsed 2.1.1 leaked local connections;
raising MaxClients to 256 only postponed exhaustion. The reviewed local
2.1.1-alt1.endpoint2 RPM retains the vendor build configuration and adds four
httpClose calls: the three-call
[upstream update_cups_queues fix](https://github.com/OpenPrinting/cups-browsed/commit/34da78b713a5d551471568f08f8c185c9f7dcac1)
plus a close at the start of the successful cupsDoRequest branch in is_disabled,
before inspecting the independently owned IPP response. The latter closes all
idle/stopped/missing-printer return paths; its existing failure-path close stays
unchanged. Native regression uses an isolated Unix-socket CUPS instance and
synthetic queues, without sending a document. Keep the original scheduler limit
and discovery configuration while checking descriptor stability and real query
latency. This OS package is not installed automatically by Endpoint RPM or OTA.
Retain the original vendor RPM for rollback and check both cleanup paths before
replacing this local pilot package with a future vendor build.
Restore previously active dependent services after an
outage test: starting cups alone does not start cups-browsed again. Keep print
ACLs, discovery scope and AD configuration unchanged.

## Inputs

Prepare four local inputs on the ALT machine as `root`:

- a reviewed Endpoint Agent release-bundle directory containing `launcher`,
  `pc_agent/`, and `manifest.json`;
- the Endpoint Platform CA PEM file;
- a root-owned, mode `0600` one-time provisioning handoff file; and
- the installer package directory from this repository.

Choose a bounded `installation_id` for the pilot before installation. It is a
non-secret, one-to-one operator label (1–128 printable ASCII characters with
no surrounding whitespace) that binds the issued claim to this installation.

The handoff contains an enrollment claim/campaign token only for its one-time
exchange. It must never be included in an image, command line, journal field,
Git commit, or regular configuration file. The permanent credential is written
by the approved enrollment runtime, not by this installer.

## Preflight

Inspect the exact package layout without root privileges:

```bash
bash deploy/agent/alt/install-endpoint-agent.sh --inspect-layout
```

Validate the local inputs without writing files or starting a service:

```bash
sudo bash deploy/agent/alt/install-endpoint-agent.sh \
  --endpoint https://endpoint.sosnadmin.local \
  --installation-id alt-test-agent-001 \
  --ca-file /root/input/sosnadmin-local-ca.crt \
  --handoff-file /root/input/endpoint-agent-one-time-claim \
  --agent-bundle /root/input/endpoint-agent-3.2.1 \
  --dry-run
```

The endpoint must be explicit HTTPS. The installer parses and verifies the CA
with OpenSSL, rejects symlinks, traversal, unexpected/missing onedir leaves,
digest mismatches, and manifest mode mismatches before it creates the service
account or changes host files. It also rejects any handoff that is not
root-owned mode `0600`.

## Installation

Run the same command without `--dry-run`. The installer creates only these
runtime roots: `/opt/endpoint-agent`, `/var/lib/endpoint-agent`,
`/etc/endpoint-agent`, and `/var/log/endpoint-agent`. It creates the dedicated
non-login `endpoint-agent` service user, stages and re-verifies the complete
bundle, then atomically selects `/opt/endpoint-agent/launcher`,
`/opt/endpoint-agent/versions/VERSION/pc_agent/`, and `current.json` before it
reloads/enables/restarts `endpoint-agent.service`. If activation fails, it
restores the prior launcher/current selection and keeps the prior immutable
version directory intact.

```bash
sudo bash deploy/agent/alt/install-endpoint-agent.sh \
  --endpoint https://endpoint.sosnadmin.local \
  --installation-id alt-test-agent-001 \
  --ca-file /root/input/sosnadmin-local-ca.crt \
  --handoff-file /root/input/endpoint-agent-one-time-claim \
  --agent-bundle /root/input/endpoint-agent-3.2.1
```

The installed config, CA and handoff at `/etc/endpoint-agent` are root-owned
and mode `0600`. The service data and logs are durable at `/var/lib` and
`/var/log`; inspect status with `systemctl status endpoint-agent.service` and
logs with `journalctl -u endpoint-agent.service` without printing credentials.

At runtime systemd exposes the three root-only inputs through its transient
credential directory to the dedicated service user; their persistent source
files stay unreadable to that account. The supplied ALT agent artifact must
consume the `ENDPOINT_AGENT_CONFIG`, `ENDPOINT_AGENT_CA_FILE`, and
`ENDPOINT_AGENT_PROVISIONING_HANDOFF_FILE` paths; the latter is the fixed
`endpoint-enrollment-claim` credential. The runtime validates the fixed
`https://endpoint.sosnadmin.local` HTTPS origin, derives the hardware proof,
and exchanges the one-time handoff before normal agent startup. This package
does not invent or emulate a permanent credential.

## One-time handoff completion

Do **not** delete the handoff merely because the service started. After the
Task 16 enrollment runtime has verified permanent credential persistence at
`/var/lib/endpoint-agent/device-credential`, owned by `endpoint-agent` with
mode `0600`, and the matching canonical server Device UUID record at
`/var/lib/endpoint-agent/enrollment-identity.json` with the same protection,
remove the one-time handoff using:

```bash
sudo bash deploy/agent/alt/install-endpoint-agent.sh --finalize-handoff
```

This is intentionally a separate, fail-closed action: it reads only the fixed
`/var/lib/endpoint-agent/claim-removal-request.json` request, checks its schema,
device UUID against the retained enrollment identity, credential path/name and
SHA-256 credential proof, and rejects
symlinked/unsafe path components before deleting the exact root claim source.
On success it also removes the matching `LoadCredential` and handoff environment
line from the fixed systemd unit, switches it to `ENDPOINT_AGENT_GATEWAY_READY=1`,
and reloads systemd. This prevents later restarts from depending on an
intentionally deleted claim and starts the TLS-only Endpoint Gateway transport.
It is idempotent after both the claim and request were removed: it first
revalidates the service-owned permanent credential and canonical enrollment
identity, then reapplies the fixed claim-free unit transformation. Therefore,
after replacing an already-finalized installed unit, run `--finalize-handoff`
before restarting the service; it removes any reintroduced claim dependency
without restoring the deleted one-time claim. Missing durable enrollment proof
fails closed and leaves the unit unchanged. A future test on
`test-agent-lin` must record enrollment, scheduled baseline/health/network
collections, update/rollback, and token-redacted journal evidence before any
broader rollout.

## Gateway update pilot

The finalized unit enables `ENDPOINT_AGENT_ALT_UPDATE_MODE=1`, selects
`gateway_wss`, and explicitly disables the migration HTTP-pull fallback. It
polls only the Endpoint controller's canary recommendation for `linux_amd64`;
it will not use an external artifact host. Before assigning a canary, place
the reviewed `.tar.gz` file under the controller's root-owned `ARTIFACT_ROOT`
using the exact `artifact_name` registered in the immutable build manifest.
The controller serves it at `/agent/v1/updates/artifacts/{build_identifier}`
only to the device that has an active target for that build.

Authorize the exact OTA release on each canary host before assigning it. Create
a UTF-8 JSON object with exactly these fields:

| Field | Value |
| --- | --- |
| `schema_version` | `endpoint_alt_ota_v1` |
| `target`, `channel`, `archive_type` | `linux_amd64`, `canary`, `tar.gz` |
| `version` | Exact version in the frozen archive manifest |
| `source_revision` | Full lowercase 40-character Git revision in that manifest |
| `sha256`, `size` | SHA-256 of the compressed archive and its integer byte size |

The offline publisher produces a binary detached signature over the exact JSON
bytes using the pinned Endpoint RPM signing key and SHA-256. Install the JSON as
`/etc/endpoint-agent/ota-authorizations/<archive-sha256>.json` and its signature
alongside it with the `.json.sig` suffix. The administrator installs both as
root:root with mode `0644` and keeps the directory root:root with mode `0755`.
The launcher verifies both files using the pinned key supplied by the signed
RPM at `/usr/share/endpoint-agent/endpoint-rpm-release.asc`. Rollback uses the
existing root-owned previous selector. A generic launcher deployment needs the
same independently provisioned public key before using OTA.

The launcher checks authorization before opening the archive, copies the
compressed bytes into a private file descriptor, checks its digest and expands
only that copy. The inspected archive manifest must match the authorized source.
Missing authorization or a bad signature rejects the operation before stopping
Core. Use the signed native RPM workflow to deploy the fixed launcher itself.

Verify the lifecycle in this order: `requested`, `scheduled`, service restart, then
`applied` (or `failed`/`rolled_back`). A `scheduled` acknowledgement alone is
not success. Pausing a rollout stops new recommendations and acknowledgements,
but an already assigned target may still submit its terminal launcher outcome;
complete the paused rollout only after every target is terminal.

The fixed root `launcher` is a separately reviewed deployment asset. It is not
part of a headless version payload and is not replaced by a controller update.
Build it from the same reviewed checkout with
`pc_agent/pyinstaller_launcher_linux.spec`, record its digest, and install it
root-owned, non-writable by group/other, before enabling this unit. The
launcher accepts the unit's migration arguments but forwards them by selected
release shape:

- a retained legacy `pc_agent/pc_agent` release receives only `--no-gui`;
- a headless `endpoint-agent/endpoint-agent` release receives
  `--transport-mode gateway_wss --no-migration-http-pull-fallback` and no GUI
  argument.

The Task 8 headless tar has a root `manifest.json` using the existing strict
ALT schema. Its sorted `files` list covers the exact
`endpoint-agent/endpoint-agent` onedir tree, including the canonical bytes of
PyInstaller's generated `base_library.zip`, with SHA-256 and POSIX mode for
every regular file. The installer accepts either this exact headless shape or
the retained legacy launcher/`pc_agent` shape, never a mixture.

The online agent verifies the artifact and persists the assigned and rollback
identities in its operation journal before publishing the watched
`pending_alt_update.json`. Publication fsyncs the file and updates directory.
The scheduled acknowledgement can be retried after restart, including when
the watcher stops the online agent immediately after the rename.

The agent service itself remains the dedicated unprivileged `endpoint-agent`
account and cannot write `/opt/endpoint-agent`. A root-owned
`endpoint-agent-update.path` watches the fixed ALT pending update and fixed
`updates/rollback-request.json`. That request contains only current/previous
version and source-revision identities; it contains no path or command. A
successful root update first re-verifies the selected release and records it in
root-owned `/opt/endpoint-agent/previous.json`, then publishes the candidate.
Selector publication is the commit point: replay of the same pending operation
preserves the distinct previous selector and resumes only durable history and
request cleanup. A failed selector replacement restores the former
`previous.json` record. If that authority is missing or inconsistent on replay,
the worker quarantines the pending record and publishes a fixed failure record
instead of leaving the path unit in an activation loop.
The root update helper asks the fixed stable launcher to check the archive
before stopping Core. The limits are 512 MiB compressed, 512 MiB per file,
2 GiB expanded payload, and 1,024 archive members. The helper checks bytes
and inodes on the release staging and update state filesystems with a 64 MiB
margin on each. Existing release directories count as used space. The launcher
checks capacity again before staging. A preflight rejection records the
operation outcome when update state is writable and leaves Core running. If
state writes fail, the pending request remains and systemd records the failure.
The 180-second updater service timeout covers preflight and publication.

Rollback mode compares the request
to root-owned `current.json` and `previous.json`, re-verifies the exact previous
manifest, files, hashes and modes, and atomically replaces only `current.json`.
It writes the terminal `startup_crash_rollback` marker only after selector
publication; rejected requests leave the selector unchanged.

The updater records the current boot ID in a root-only stop receipt before
stopping an active, enabled Core. systemd runs its recovery hook after normal
exit, timeout or a killed helper. The hook starts Core only while the receipt
is current and the unit is still enabled. It preserves a queued conflicting
stop and verifies the service is active before clearing the receipt. A stale
receipt from a prior boot is discarded. On boot, ordinary service enablement
starts the selected Core and the path unit can replay the request. A pending
request does not prevent the unprivileged launcher from starting the selected
Core. systemd bounds repeated helper activations with a start limit.

Run `tests/deploy/verify_alt_update_recovery.py` with the helper and service
source paths on a dedicated ALT systemd host to verify the recovery hook with
isolated units. The harness checks SIGKILL, systemd timeout, enablement,
synthetic selector preservation and an unchanged Core PID after preflight
rejection. Verify actual RPM installation and power-loss
recovery separately.

If interrupted after selector publication, the next fixed-request activation
idempotently finishes the terminal marker and cleanup. Rollback state I/O pins
the non-symlinked, service-owned `updates` directory and uses no-follow,
directory-relative operations; unsafe request leaves are consumed into a fixed
regular failure record. If the `updates` parent itself was replaced by an
unsafe leaf or symlink, the stopped-service helper quarantines that exact leaf,
recreates an empty service-owned directory, and restarts without a watched
request remaining.

Inspect both units during a canary without printing any credentials:

```bash
systemctl status endpoint-agent.service endpoint-agent-update.path endpoint-agent-update.service
journalctl -u endpoint-agent-update.service -u endpoint-agent.service --since '15 minutes ago'
```

### Mandatory headless WSS preflight

Stop before changing either host unless every item passes:

1. The local tree is clean and the full focused build, deployment, launcher,
   update, runtime and transport tests pass.
2. A clean Linux build reproduces the reviewed outer digest and strict embedded
   manifest; the version is a fresh SemVer above every controller build and
   matches the version reported in the WSS hello.
3. The deployed controller release contains the Gateway WSS route, the active
   proxy has the exact WebSocket upgrade location, strict HTTPS health passes,
   and the database is at `0011_gateway_wss` or its reviewed successor.
4. A new pre-canary database backup exists and its restore/readability check
   has passed.
5. The accepted rollback build has both immutable controller metadata and the
   exact regular artifact whose digest and size match it.
6. The same rollback release exists on the pilot and verifies its embedded
   manifest, exact file set, hashes and modes without changing `current.json`.
7. The service is active through the fixed root launcher; the selector is
   strict; the permanent credential is service-owned mode `0600`; and the
   credential-free canonical `enrollment-identity.json` matches the enrolled
   controller Device. Never copy the token-bearing legacy identity as the new
   identity record.
8. No active update target exists for any other device.

If the controller release, WSS route, migration, backup, rollback artifact or
canonical identity is missing, record a blocked preflight and stop. Do not use
Helpdesk or HTTP command pull as substitute acceptance.

### Single-device acceptance and rollback

Assign exactly the dedicated `test-agent-lin` Device. Acceptance requires all
of the following sanitized observations, not raw payloads:

- one authenticated WSS session and a later heartbeat;
- successful baseline, health and network command results over that session;
- startup update outcome `applied` for the selected headless version;
- zero Helpdesk requests and zero calls to the Gateway HTTP command-pull route;
- no migration fallback transition.

Then publish a distinct, correctly addressed and fully manifest-verified test
release whose headless process intentionally exits within the launcher's crash
window. Assign it only to the same pilot. Require the launcher to select the
already accepted headless release automatically and require the controller to
record `rolled_back`; a return to the historic Helpdesk monolith is a failure.
Finally re-check authenticated WSS, heartbeat and the three bounded profiles
with fallback still disabled.

Write only the sanitized result to
`docs/verification/ALT_HEADLESS_WSS_CANARY.md`: versions, digests, Boolean
gates, bounded status names and timestamps are allowed. Do not include
credentials, network observations, trust-anchor locations, raw context,
authorization headers, artifact URLs or journal bodies.
