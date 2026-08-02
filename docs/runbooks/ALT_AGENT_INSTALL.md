# ALT Endpoint Agent installation

This is an offline, operator-run package for the dedicated ALT test pilot. It
does not download software, CA certificates, credentials, or configuration.
Do not use it on a production host until the Wave 1 production gate is open.

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
only to the device that has an active target for that build. Verify the
lifecycle in this order: `requested`, `scheduled`, service restart, then
`applied` (or `failed`/`rolled_back`). A `scheduled` acknowledgement alone is
not success.

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
`previous.json` record.
The companion one-shot worker validates the request metadata, stops the agent,
and invokes only the fixed stable launcher. Rollback mode compares the request
to root-owned `current.json` and `previous.json`, re-verifies the exact previous
manifest, files, hashes and modes, and atomically replaces only `current.json`.
It writes the terminal `startup_crash_rollback` marker only after selector
publication; rejected requests leave the selector unchanged. The worker starts
the unprivileged service again after a handled request.

If interrupted after selector publication, the next fixed-request activation
idempotently finishes the terminal marker and cleanup. Rollback state I/O pins
the non-symlinked, service-owned `updates` directory and uses no-follow,
directory-relative operations; unsafe request leaves are consumed into a fixed
regular failure record.

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
