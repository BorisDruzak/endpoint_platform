# Endpoint Agent RPM for ALT Linux

This package is an offline ALT Linux 11.4 x86_64 bootstrap artifact. It
contains a manifest-attested launcher/agent release bundle and the provisioning
assets, but never a reusable Gateway secret, CA certificate, enrollment claim,
credential, or token.

## Build

Run on ALT Linux with the project checkout, Python dependencies, PyInstaller,
and `rpm-build` installed:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-ci.txt pyinstaller
PYTHON=.venv/bin/python bash deploy/agent/alt/rpm/build-rpm.sh \
  --version 0.1.0 --release 1 --output /tmp/endpoint-agent-rpm-out
```

Pass `--source /path/to/endpoint-agent-<version>` to package an already-built,
manifest-attested release bundle instead of running PyInstaller.

## Verify the artifact

Before installing, verify the RPM checksum, payload ownership, scriptlets, and
transaction planning:

```bash
rpm -K /tmp/endpoint-agent-rpm-out/endpoint-agent-0.1.0-1.x86_64.rpm
rpm -qlp /tmp/endpoint-agent-rpm-out/endpoint-agent-0.1.0-1.x86_64.rpm
rpm -qp --scripts /tmp/endpoint-agent-rpm-out/endpoint-agent-0.1.0-1.x86_64.rpm
sudo rpm -Uvh --test /tmp/endpoint-agent-rpm-out/endpoint-agent-0.1.0-1.x86_64.rpm
```

The payload must be limited to `/usr/lib64/endpoint-agent` and documentation.
On a first install, RPM scriptlets require a securely staged device claim and
then start the verified provisioner; upgrades do not consume bootstrap input.

## Install and provision

Before the first install, the deployment controller must issue a claim for this
specific device and stage the three inputs. The directory and every file must
be root-owned and have the exact modes below; do not put these inputs in the
RPM, command line, or a shared image.

```bash
sudo install -d -o root -g root -m 0755 /etc/endpoint-agent
sudo install -d -o root -g root -m 0700 /etc/endpoint-agent/bootstrap
sudo install -o root -g root -m 0600 /secure/endpoint-ca.crt \
  /etc/endpoint-agent/bootstrap/ca.crt
sudo install -o root -g root -m 0600 /secure/device-claim \
  /etc/endpoint-agent/bootstrap/provisioning-claim
sudo install -o root -g root -m 0600 /secure/installation-id \
  /etc/endpoint-agent/bootstrap/installation-id
sudo rpm -Uvh /tmp/endpoint-agent-rpm-out/endpoint-agent-0.1.0-1.x86_64.rpm
```

The transaction verifies the package bundle, creates the immutable
`/opt/endpoint-agent` release, enables the agent/update/finalizer systemd
units, and starts enrollment automatically. The first-boot claim is exchanged
for a durable device credential bound to the hardware fingerprint. The
root-owned finalizer removes the installed handoff only after verifying that
credential, switches the unit to Gateway-ready mode, and restarts the agent.

For repeatable remote installation, the repository also provides the external
controller role at `deploy/ansible/roles/endpoint_agent_alt`. It creates a
single-use enrollment campaign and host-bound claim for each target through the
Gateway service API, then revokes the campaign after that host's attempt. Store
only the narrow deployment service token in Ansible Vault; never store a claim.

Verify the completed transition without exposing secrets:

```bash
systemctl is-active endpoint-agent.service
sudo test -s /var/lib/endpoint-agent/device-credential
sudo test ! -e /etc/endpoint-agent/provisioning-claim
```

Later RPM upgrades do not require bootstrap files and must not overwrite the
device credential or current immutable selector. Gateway-directed updates use
the existing root-only update worker, manifest verification, rollback, and
post-restart handshake evidence.
