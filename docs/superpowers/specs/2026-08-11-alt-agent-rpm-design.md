# ALT Linux Endpoint Agent RPM Design

## Goal

Deliver an installable RPM for the Endpoint Platform agent on ALT Workstation K
11.4 (`x86_64`), and validate its complete package lifecycle on
`osn-admin@192.168.101.56`.

## Package boundary

The RPM is an offline, unprovisioned agent package. It contains only the
verified PyInstaller launcher/agent release, the systemd units, the root-owned
ALT update helper, and non-secret configuration templates. It must never
contain a CA certificate, endpoint URL, enrollment claim, credential, token,
or device-specific configuration.

## Installation model

The package owns static files under `/opt/endpoint-agent`, `/usr/lib/endpoint-agent`,
`/usr/share/doc/endpoint-agent`, and `/usr/lib/systemd/system`. RPM scriptlets
create the `endpoint-agent` system user and the persistent state directories:
`/etc/endpoint-agent`, `/var/lib/endpoint-agent`, and `/var/log/endpoint-agent`.
It must not enable or start the agent service: provisioning material is absent
until the operator supplies it.

The existing `install-endpoint-agent.sh` remains the privileged provisioning
entry point. A separate RPM helper will create the static filesystem and
service-account prerequisites; it will not duplicate, weaken, or bypass the
installer's validation, immutable-release selection, or service activation.

## Build and artifact contract

RPM is built natively on ALT Linux 11.4 `x86_64`. The build command first runs
the existing `pc_agent.build_linux_release_bundle --build` process, which
produces a manifest-attested release bundle. RPM packaging verifies this bundle
and installs its `launcher`, `pc_agent/`, and `manifest.json` under a versioned
release path. The artifact is named `endpoint-agent-<version>-<release>.x86_64.rpm`.

The package version and release must be supplied as bounded RPM-compatible
identifiers. The build must fail before producing an RPM if the source bundle is
missing its launcher, agent binary, manifest, or contains symbolic links.

## Upgrade and removal

Package upgrades replace only package-owned static code and unit/helper files.
They preserve `/etc/endpoint-agent`, `/var/lib/endpoint-agent`, and
`/var/log/endpoint-agent`; RPM removal also preserves these operator data
directories. No scriptlet starts, stops, enables, disables, or restarts the
agent automatically.

## Validation

Automated repository tests cover the RPM spec and helper layout: no secret
paths in the payload, correct paths and modes, no service autostart, and
preservation semantics. On the ALT test machine, verification consists of a
native RPM build, `rpm -K` integrity check, dry-run installation in an isolated
filesystem root or disposable VM/container if available, `rpm -qlp` payload
inspection, `rpm -Uvh --test`, install, query, removal, and proof that no
service was started and no credential-bearing files were created.

If the test host cannot provide a disposable installation root that supports
the required systemd/user-management scriptlets, the test performs package
metadata and scriptlet inspection locally and uses `rpm -Uvh --test`; it does
not mutate the host's running agent installation.
