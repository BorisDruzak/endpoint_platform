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
mode `0600`, remove the one-time handoff using:

```bash
sudo bash deploy/agent/alt/install-endpoint-agent.sh --finalize-handoff
```

This is intentionally a separate, fail-closed action: it reads only the fixed
`/var/lib/endpoint-agent/claim-removal-request.json` request, checks its schema,
device UUID, credential path/name and SHA-256 credential proof, and rejects
symlinked/unsafe path components before deleting the exact root claim source.
It is idempotent after both the claim and request were removed. A future test on
`test-agent-lin` must record enrollment, scheduled baseline/health/network
collections, update/rollback, and token-redacted journal evidence before any
broader rollout.
