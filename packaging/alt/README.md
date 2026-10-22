# Endpoint Agent ALT RPM

This directory builds the native unsigned ALT Linux RPM around the Task 8
`linux_amd64` headless release and the Task 9 stable launcher/update units. It
does not invoke the generic offline installer. The RPM owns executable code,
immutable initial-release files, systemd units, tmpfiles policy, and logrotate
policy only. Endpoint configuration, CA trust, enrollment claim, permanent
credential, and enrollment identity are supplied or created separately.

## Signed native distribution kit

`python3 tools/build_alt_pilot_kit.py build --inputs /safe/qualified-inputs --output /safe/pilot-output`
assembles the fixed Agent 3.2.127 Core/User Sensor RPMs, its frozen runtime/sidecar,
the reviewed cups-browsed repair, vendor rollback/source RPMs, repair patches,
and production/staging operator config templates. Input names, RPM identities,
and qualification SHA-256 values are pinned; same-version repacks are rejected.
Build it on ALT with native RPM tooling. Repeated builds produce identical archives.

Revision `3.2.127-2` requires publisher-signed Core, User Sensor, repaired CUPS
binary and source RPMs. Native verification uses a fresh RPM database containing
only the pinned public key, and requires both header and payload signatures.
The generated archive has separate archive and inner-manifest checksum files.
The external publisher also signs the archive and manifest. Verify these detached
signatures using the independently trusted publisher fingerprint before extraction;
use its `verify-kit.py check` with the independently reviewed manifest digest.
`--test-hostname` additionally performs a read-only clean-machine/RPM dependency
preflight. Existing Endpoint state and unreviewed CUPS versions are refused;
the helper never installs, enrolls, changes configuration or contacts a controller.
Native installation and the CUPS replacement remain explicit operator actions.
See `pilot/README.ru.md`. Unsigned revision 1 remains a staging qualification
artifact. No private key belongs here or on an ALT build worker.

## Build on a disposable ALT worker

Install the locked Linux build requirements and `rpm-build rpm-build-python3`,
then run. ALT's Python dependency scanner requires `rpm-build-python3` even
though the Agent payload is frozen: the RPM also installs two Python helpers.

```bash
bash packaging/alt/build-rpm.sh
rpm -qpi output/endpoint-agent-*.rpm
rpm -qpl output/endpoint-agent-*.rpm
```

For KDE Plasma 6 workstations, also install the native compiler, `cmake`,
`qt6-base-devel` and `kf6-kidletime-devel`, then build with
`bash packaging/alt/build-rpm.sh --with-user-sensor`. This emits the Core RPM
and an optional `endpoint-agent-user-sensor` RPM. Qt/KF6 runtime dependencies
belong to that optional package; the Core remains headless. Install both RPMs
together on a workstation. The sensor starts through KDE autostart at login.
For an existing session, run `systemctl --user daemon-reload` followed by
`/usr/lib/endpoint-agent/start-user-sensor --autostart` from that user's
graphical session. The wrapper writes only its own private graphical environment
file; it does not alter the global user-manager environment.

The per-user wrapper selects the same root-protected Core version in
`--linux-user-sensor` mode, before enrollment or server configuration is read.
The native KDE helper reads idle/lock state and only KWin's active PID; it
never reads captions, URLs or contents. On Wayland, elapsed idle remains
unknown until the backend observes a resume, because KIdleTime cannot poll
elapsed idle there. The System Agent authenticates every local frame with
kernel credentials and logind; user processes never receive its credential.

For a separately built Task 8 artifact and stable launcher:

```bash
bash packaging/alt/build-rpm.sh \
  --release-archive /safe/input/endpoint-agent-linux_amd64-3.1.76.tar.gz \
  --release-manifest /safe/input/endpoint-agent-linux_amd64-3.1.76.manifest.json \
  --launcher /safe/input/launcher
```

The wrapper verifies the outer Task 8 sidecar, every inner manifest digest and
mode, the exact archive shape, and the launcher before invoking `rpmbuild`.
Build output must be moved off the worker after verification; it is not a
deployment or canary artifact until separately reviewed and signed.

## Provisioning and start

The RPM intentionally enables but does not start a previously inactive agent.
Before the first start, install the environment-specific files as root:

```bash
install -d -o root -g root -m 0755 /etc/endpoint-agent
install -o root -g root -m 0600 config.yaml /etc/endpoint-agent/config.yaml
install -o root -g root -m 0600 ca.crt /etc/endpoint-agent/ca.crt
install -d -o root -g root -m 0700 /etc/credstore
install -o root -g root -m 0600 provisioning-claim \
  /etc/credstore/endpoint-enrollment-claim
systemctl start endpoint-agent-update.path
systemctl start endpoint-agent.service
```

The unit uses optional systemd credential-store loading for the one-time claim.
Its root pre-start condition validates the fixed root-owned `0600` config and CA
sources plus either the canonical service-owned `0600` permanent
credential/identity pair or the fixed root-owned `0600`
`/etc/credstore/endpoint-enrollment-claim` source. The main-process wrapper then
validates systemd's root-owned `0440` credential copies before it replaces itself
with the stable launcher. Validation failures use a non-restart status so a bad
or raced state cannot create a restart loop.

The fixed `/etc/credstore/endpoint-enrollment-claim` path is an intentional
fail-closed boundary. Although a relative `LoadCredential=` can import inherited
or alternate-store credentials, those sources are not inspectable by
`ExecCondition=` on the target systemd and therefore do not satisfy the package
precondition on their own. Provision the documented fixed source instead.

For the approved staging canary only, a root-owned service drop-in must set
`ENDPOINT_AGENT_DEPLOYMENT_ENVIRONMENT=staging`,
`CANARY_ENVIRONMENT=staging`, `CANARY_APPROVED=true`, and the exact
`ENDPOINT_AGENT_ORIGIN=https://endpoint-staging.sosnadmin.local`. The frozen
runtime rejects that staging origin unless all three markers are present; the
default remains the production Endpoint origin.

After enrollment has produced and verified both the permanent credential and
canonical enrollment identity, remove the one-time claim and restart. An already
finalized installation therefore upgrades without restoring a mandatory claim
dependency.

## Upgrade and removal

Upgrade replaces package-owned launcher, units, helper, and immutable release
files. It does not replace an existing `/opt/endpoint-agent/current.json`, and
it validates the installed selection before trying to restart an already active
service. The RPM never owns files below `/var/lib/endpoint-agent` or the endpoint
config and CA below `/etc/endpoint-agent`; normal upgrade and uninstall preserve
them. Final uninstall stops/disables the agent and update path but does not
purge device state.

An explicit purge is a separate operator decision. After verifying the exact
host and paths, remove `/var/lib/endpoint-agent`, `/etc/endpoint-agent`, and any
`endpoint-enrollment-claim` credential-store file manually. RPM uninstall never
performs that destructive action.

## External signing

No signing private key, passphrase, production credential, or one-time claim may
be present in this repository or on the disposable build worker. Transfer the
reviewed unsigned RPM by an authenticated channel to the external signing
environment, verify its digest and file list, then use the externally configured
RPM identity:

```bash
rpm --checksig endpoint-agent-*.rpm
rpm --addsign endpoint-agent-*.rpm
rpm --checksig endpoint-agent-*.rpm
```

Return only the signed RPM and its detached release evidence. Never copy the
private key or signing configuration into Git or the build tree.
