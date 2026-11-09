# Linux native Setup183

This workflow owns the exact two RPMs, independent Support1.0.0 and source-bound
installation facts. Published native Linux183 and Windows177 remain separate.
Exact signed media and scope: [Linux183 release](../releases/linux-3.2.183-native.json).
Core-only OTA156 remains historical; privileged183 Support/Setup requires native RPM.
No Linux fleet rollout or global Linux enrollment campaign was enabled.
Run only as root. Do not invoke RPM again after an uncertain result.

## Trust the distribution before executing it

The operator must independently possess the publisher public key with fingerprint
`BC24B8EE43DBB05A748E11A4343B5DA748370631` and SHA256
`12175df39caa5a67336aeb002b5c71d3a9d3047961f5ad90cf959650044b456c`.
Use an isolated root0700 GPG home, import ONLY that key, inspect its full fingerprint,
and verify both detached signatures before extracting or running any kit helper:

```sh
gpg --homedir "$TRUST_HOME" --batch --import endpoint-rpm-release.asc
gpg --homedir "$TRUST_HOME" --batch --with-colons --fingerprint --list-keys
gpg --homedir "$TRUST_HOME" --batch --verify endpoint-alt-pilot-3.2.183-1.tar.gz.sig endpoint-alt-pilot-3.2.183-1.tar.gz
gpg --homedir "$TRUST_HOME" --batch --verify endpoint-alt-pilot-3.2.183-1.manifest.sig endpoint-alt-pilot-3.2.183-1.manifest.json
```

The trust-home path is an explicitly prepared operator directory. A downloaded
key's own fingerprint claim is not independent trust. The archive signature must
match the independent publisher before native code is executed. Compare the
extracted Setup and RPM SHA256/size values with the separately verified manifest.
Keep the extracted directory root-owned and non-writable to other users.

## Installation and removal

Supply the canonical `/etc/endpoint-agent/config.yaml` and `ca.crt`, root:root0600,
before installation. Keep the configured existing Endpoint HTTPS origin; staging
also requires all three existing explicit canary environment markers. Never change
origin or relax TLS to repair enrollment. Fresh enrollment uses the existing
`provisioning.installation_id` and exact native source approved on the provider.

From the verified new183 kit, before Core starts:

```sh
./endpoint-agent-setup install --core-rpm ./endpoint-agent-3.2.183-alt6.x86_64.rpm --user-sensor-rpm ./endpoint-agent-user-sensor-3.2.183-alt6.x86_64.rpm --public-key ./endpoint-rpm-release.asc
```

Use `upgrade` for an existing installation. An ordinary removal uses the exact
archives of the installed native version:

```sh
endpoint-agent-setup remove --core-rpm /root/verified-kit/endpoint-agent-3.2.183-alt6.x86_64.rpm --user-sensor-rpm /root/verified-kit/endpoint-agent-user-sensor-3.2.183-alt6.x86_64.rpm --public-key /root/verified-kit/endpoint-rpm-release.asc
```

No Device credential is accepted on the command line. Canonical credential and
enrollment identity remain owned by the existing `endpoint-agent` NSS UID/GID,
mode0600; config/CA remain root0600. A partial enrollment attempt keeps its exact
claim/nonce/delivery. It never creates a replacement identity after timeout.

The onefile coordinator copies its verified executable outside removed RPM code,
and records its hash/source in `/var/lib/endpoint-agent-installation/executor.json`.
The root0700 directory retains archives, receipts, causal events and private
enrollment recovery. Ordinary removal preserves config, CA, canonical identity,
credential, history and this queue. Do not purge it as an uninstall workaround.

`reconcile` never invokes RPM. It can settle only an original durable native0 and
exact matching final package state. Native nonzero, unknown exit, external RPM
intent or contradictory files remain pending for explicit diagnosis. Exit21 is a
pending/recovery result, not permission to rerun installation. Direct bare RPM
hooks can stage intent but cannot assert native0; they do not start Core.

A nonmutating preflight refusal retains a separate refusal receipt and reserves
no native invocation. Preparation has its own durable phase and owned service
snapshots. `reconcile` may restore only the exact unchanged preparation state and
retain a `not_started_recovered` receipt; a later command can then proceed. The
invocation-possible phase is written before spawning RPM. It never takes this
recovery path, even if the subprocess exit was never recorded. An interrupted
stop without a confirmed matching snapshot, or externally changed service state,
remains pending rather than being restarted speculatively.
This includes an owned sensor's `stop_pending` receipt: recovery must prove the
unchanged pre-stop state or restore its exact confirmed stopped state. A missing
or changed session cannot silently complete that preparation. Transitional system
units, queued jobs and remaining native processes block preparation; an inactive
label alone is insufficient, and quiescence is checked again before RPM invocation.

Core and updater units additionally require a root-owned `runtime-ready` marker.
It is durably cleared before new native work and created only after causal event
delivery and successful Support registration. PID1 checks it; no user helper
reads the private directory. It is an installation-completion proof: later lease
expiry, disable or revocation never clears it or stops a healthy Core/updater.
Direct RPM intent clears this marker under the installation lock. The native
`%pre` hook uses existing Setup before replacing files, or refuses a stale marker
when no trusted installed helper is available. Only pre/post hooks from the same
actual RPM PID/start/boot identity share an unmanaged pending receipt.

The installed-only retry timer uses the same bounded reconciliation path after
offline installation. It stops after exact bootstrap completion. Runtime401,
revocation or key reset does not create another registration attempt. Final native
removal stops/removes the timer and service; no post-uninstall sender remains.
The next Setup sends an offline `removed` event before `installed` using the
retained canonical credential. Native result, local cleanup and delivery are
distinct facts. Failed offline Support unregister remains incomplete even after
owned local private cleanup succeeds.

Before stopping an active graphical UserSensor, Setup retains its session, boot,
environment identity and owned unit state. Reinstall may resume that exact stop
without enabling the user's boot unit. Changed sessions, environments, masks,
overrides or observed user state are preserved. A unit forgotten by systemd can
resume only with the same session proof and the confirmed native removal receipt.
Missing optional environment/runtime or a vanished session is a recorded skip;
it does not prevent machine bootstrap completion. Unsafe nodes remain refused.

An exact156 rollback additionally supplies the original signed156 kit manifest
and detached signature via `--legacy-kit-manifest` and `--legacy-kit-signature`.
Only the two immutable qualified156 archive digests are supported by this adapter.
Rollback is an upgrade event, not device removal.156 has no Support code or retry
unit; preserved private Support state/lease does not imply a running component.
Use the retained Setup executable for manual reconciliation while156 is installed.

## Build and verification boundaries

Freeze from a clean Git checkout matching the exact runtime source revision.
`packaging/alt/build-rpm.sh` creates183/alt6 with Setup onefile and Support onedir
outside Core's `/opt/endpoint-agent/versions` tree. Both RPMs contain the same
final payload/source manifest. The build checks both native components' embedded
`--build-info` source identity. Sign final RPM bytes only after freezing; never
overwrite an old RPM/kit slot. The operator retains the existing private signer.

Build the new distribution with:

```sh
python -m tools.build_alt_pilot_kit native178 --core CORE_RPM --sensor SENSOR_RPM --setup FROZEN_SETUP --public-key PUBLISHER_KEY --output NEW_DIRECTORY
```

The builder verifies actual signed RPMs and Setup's digest against the signed Core
payload. It emits an archive and external manifest; the operator signs both.
Provider publication must use `tools.release.linux_native_verifier.publication_verifier`
as the mandatory Task1 callback. It uses fresh isolated keyrings and native tools,
not declared hashes or a permissive callback. It imports no Core runtime.

Source/unit/isolated-RPM tests do not qualify an installed agent. Real signed178
freeze, publication, fresh HTTPS enrollment, native transitions, accepted telemetry,
independent SSH, offline removal/reinstall and historical-parent linkage remain
separate reviewed acceptance gates. Preserve their original failure receipts.

## Console, enrollment and independent Linux access

Console selects Support from authenticated provider platform discovery. Consumed
enrollment and canonical inventory/source binding must agree on Linux x86_64.
An OS label is not authority; conflicting proof blocks controls without trying
the Windows endpoint. Saved intent and original expiry are displayed separately
from effective policy. Refresh never changes authorization.

In **Доступ поддержки**, enter the exact existing NSS username and integer UID;
explicit `root` / `0` is supported. Use existing approved public operator keys,
a reason and a duration no longer than eight hours. The component independently
checks the account, UID, unlock state, shell and administrative readiness. No
account, sudo rule or password is created. Disable/revoke/reset are audited;
refresh, retries and reinstall cannot create a new initial lease. Qualified native
rebind resumes only unchanged authorization up to its original unexpired deadline.
Ordinary retained-identity reinstall preserves the journal generation, sequence
and previous-event chain. Offline removal is delivered before reinstall; a full
wipe/new identity requires the separately authorized journal archival workflow.

Temporary effective disablement at the same policy revision does not replace
administrator consent or restart its expiry. Support retains a fingerprint-bound
public consent snapshot only to check local readiness after errors, including
service restarts. It checks its owned keys, account and sshd configuration without
starting a listener or tunnel while disabled. Persistent local errors remain
reported. A new enabled server policy is required before starting children;
only actual forwarding acknowledgement makes `tunnel_connected` true.

Fresh defaults require explicit `SUPPORT_LINUX_INSTALL_AUTO_ENABLE`,
`SUPPORT_LINUX_INSTALL_OPERATOR_PUBLIC_KEYS`, `SUPPORT_LINUX_INSTALL_ADMIN_USERNAME`,
`SUPPORT_LINUX_INSTALL_ADMIN_UID` and bounded `SUPPORT_LINUX_INSTALL_ACCESS_HOURS`.
They never inherit Windows defaults. The single initial grant requires a fresh
healthy Support1.0.0 report. Registration, forwarding acknowledgement and a real
administrator command are separate evidence. **Подтвердить выполненную SSH-команду**
records only the operator's statement after that real command; Console executes
no SSH command itself.

Production remains `https://endpoint.sosnadmin.local`, gateway port2222. The only
alternate Linux path requires provider `SUPPORT_LINUX_STAGING_GATEWAY_ENABLED=true`,
public URL exactly `https://endpoint-staging.sosnadmin.local`,
`SUPPORT_GATEWAY_HOST=endpoint-staging.sosnadmin.local`, port2222 and all three
existing provider staging gates (`ENDPOINT_DEPLOYMENT_ENVIRONMENT=staging`,
`CANARY_ENVIRONMENT=staging`, `CANARY_APPROVED=true`). Agent bootstrap retains its
three gates, using `ENDPOINT_AGENT_DEPLOYMENT_ENVIRONMENT=staging`. The same gateway
public key participates in host/tunnel/operator role-conflict checks. This opt-in
does not authorize Windows staging or arbitrary hosts. Never send staging identity
or tokens to production. Live configuration remains a separate deployment gate.
The exporter receives the validated provider settings and applies the same Linux
origin/gateway/port/pin and authentication-availability predicate as policy delivery
and administrator admission. Removing staging opt-in suppresses Linux broker
leases without changing stored intent or its original expiry. Turning off initial
auto-grant defaults alone does not revoke an existing consent. Windows broker
selection and wire contracts retain their existing behavior.

For an actual command read device UUID, loopback remote port and public host pin
together from the authenticated Linux card. Prepare a public known-hosts file
containing `endpoint-device-UUID ssh-ed25519 BASE64` from that card. Preserve and
compare an existing UUID pin; do not overwrite a changed pin. With explicit values
from the card/config, a Windows OpenSSH example is:

```powershell
ssh -F NUL -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=NUL -o UserKnownHostsFile=C:/approved/device.known_hosts -o HostKeyAlias=endpoint-device-UUID -o 'ProxyCommand=ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ForwardAgent=no -o PermitLocalCommand=no -W %h:%p APPROVED_GATEWAY_ALIAS' -o ForwardAgent=no -o PermitLocalCommand=no -o ClearAllForwardings=yes -i C:/approved/operator-key -p REMOTE_PORT -l EXACT_LINUX_USERNAME 127.0.0.1 'hostname; id'
```

The gateway alias uses its ordinary administrator SSH and independently trusted
host key, never the device's outbound2222 identity. Use the trusted staging alias
for staging. A changed device host key fails closed until authorized reinstall and
authenticated rebind are verified. Never use scans or disable host checking.
Record real command output and UID separately from tunnel status; no private keys
belong in reports. The Windows connection helper keeps its Windows-only contract.

Linux requests under **Установка и регистрация** identify the native RPM source.
Without a frozen selected campaign, approval is unavailable: review existing Linux
authority before any distinct request, and only after the old attempt is confirmed
terminal, unclaimed and without device delivery. Do not replace active private
attempts automatically. A previous-device relation is server-verified history only;
credentials/grants remain separate. Ordinary removal retains UUID/card/history.
History displays received native0 events, cleanup and delivery time separately.
Native pending/offline queue contents stay local; no event/heartbeat absence proves
removal. Use the canonical `reconcile` procedure above, never replay unknown RPM.
