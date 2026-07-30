# ALT Endpoint Agent installation

This is an offline, operator-run package for the dedicated ALT test pilot. It
does not download software, CA certificates, credentials, or configuration.
Do not use it on a production host until the Wave 1 production gate is open.

## Inputs

Prepare four local files on the ALT machine as `root`:

- an executable, reviewed Endpoint Agent ALT artifact;
- the Endpoint Platform CA PEM file;
- a root-owned, mode `0600` one-time provisioning handoff file; and
- the installer package directory from this repository.

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
  --ca-file /root/input/sosnadmin-local-ca.crt \
  --handoff-file /root/input/endpoint-agent-one-time-claim \
  --agent-binary /root/input/endpoint-agent \
  --dry-run
```

The endpoint must be explicit HTTPS. The installer parses and verifies the CA
with OpenSSL, rejects symlinks for security-sensitive inputs, and rejects any
handoff that is not root-owned mode `0600`.

## Installation

Run the same command without `--dry-run`. The installer creates only these
runtime roots: `/opt/endpoint-agent`, `/var/lib/endpoint-agent`,
`/etc/endpoint-agent`, and `/var/log/endpoint-agent`. It creates the dedicated
non-login `endpoint-agent` service user, atomically installs files, and only
then reloads/enables/restarts `endpoint-agent.service`.

```bash
sudo bash deploy/agent/alt/install-endpoint-agent.sh \
  --endpoint https://endpoint.sosnadmin.local \
  --ca-file /root/input/sosnadmin-local-ca.crt \
  --handoff-file /root/input/endpoint-agent-one-time-claim \
  --agent-binary /root/input/endpoint-agent
```

The installed config, CA and handoff at `/etc/endpoint-agent` are root-owned
and mode `0600`. The service data and logs are durable at `/var/lib` and
`/var/log`; inspect status with `systemctl status endpoint-agent.service` and
logs with `journalctl -u endpoint-agent.service` without printing credentials.

At runtime systemd exposes the three root-only inputs through its transient
credential directory to the dedicated service user; their persistent source
files stay unreadable to that account. The supplied ALT agent artifact must
consume the `ENDPOINT_AGENT_CONFIG`, `ENDPOINT_AGENT_CA_FILE`, and
`ENDPOINT_AGENT_PROVISIONING_HANDOFF_FILE` paths. Task 16 supplies the
one-time enrollment implementation; this package deliberately does not invent
or emulate a permanent credential.

## One-time handoff completion

Do **not** delete the handoff merely because the service started. After the
Task 16 enrollment runtime has verified permanent credential persistence at
`/var/lib/endpoint-agent/device-credential` with root ownership and mode
`0600`, remove the one-time handoff using:

```bash
sudo bash deploy/agent/alt/install-endpoint-agent.sh --finalize-handoff
```

This is intentionally a separate, fail-closed action: it refuses to delete the
handoff unless the permanent credential exists with the required ownership,
mode, and non-empty content. A future test on `test-agent-lin` must record
enrollment, scheduled baseline/health/network collections, update/rollback,
and token-redacted journal evidence before any broader rollout.
