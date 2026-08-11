# Endpoint Agent RPM for ALT Linux

This package is an offline, unprovisioned bootstrap artifact for ALT Linux
11.4 x86_64. It contains a manifest-attested launcher/agent release bundle and
the existing provisioning assets. It never contains endpoint configuration,
CA certificates, enrollment claims, credentials, or tokens.

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

The payload must be limited to `/usr/lib64/endpoint-agent` and documentation;
the scriptlets must not control a systemd service.

## Install and provision

Install the RPM normally:

```bash
sudo rpm -Uvh /tmp/endpoint-agent-rpm-out/endpoint-agent-0.1.0-1.x86_64.rpm
```

The transaction only creates the `endpoint-agent` service account and durable
operator directories. It does not create an active `/opt/endpoint-agent`
release and does not control systemd.

Provision with local, root-owned inputs. The bundle comes from the package:

```bash
sudo /usr/lib64/endpoint-agent/provision/install-endpoint-agent.sh \
  --endpoint https://endpoint.sosnadmin.local \
  --installation-id example-agent-001 \
  --ca-file /secure/path/ca.crt \
  --handoff-file /secure/path/provisioning-claim \
  --agent-bundle /usr/lib64/endpoint-agent/release-bundle
```

Do not store the CA, handoff claim, a credential, or any rendered configuration
in the package or source archive.
