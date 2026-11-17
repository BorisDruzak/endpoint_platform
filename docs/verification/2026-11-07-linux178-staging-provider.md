# Linux178 staging provider checkpoint

Status: server preparation passed; Linux178 installation and release acceptance
remain pending. This receipt does not qualify a new Linux installer or primary.

## Exact sources and deployment

- Canonical Linux implementation/native source:
  `ece04b8add2d13c2603a4d52d61db3f9880f86f4`.
- Reviewed staging-only provider merge:
  `45612edbc5052501afc985bb9600aef04d200981`, preserving the original staging
  Worktime branch `0554e70b0d4c679173d502af6000cc53ac17f27f`.
  Never deploy this staging Worktime merge to production.
- Actual server: `192.168.101.118`, HTTPS origin
  `https://endpoint-staging.sosnadmin.local`.
- Provider archive: `endpoint-platform-45612edbc505-staging.tar.gz`, 512012 bytes,
  SHA256 `00ae2f98ba3ba280d869e6e9226daf867c9f05b044bd954a3f990ad99857e1ec`.
  Built from the clean reviewed commit with the canonical archive builder and
  Python3.12.14; archive members were checked again before extraction.
- New isolated venv uses the same 32 pinned package versions as the original
  staging venv. Creation, installation and `pip check` each returned 0.
- Actual activation completed `2026-11-07T14:04:47.941381Z`.
  API/worker PIDs 52389/52390; both active without restarts at post-deployment checks.

The canonical repository and group GitNexus tools were unavailable in this
session. Source, migration lineage, actual runtime and focused tests supplied
the architectural verification; no manual synchronization or index edits ran.

## Protected migration and history

The actual staging dump was restored into the separately marked same-host
`endpoint_linux178_compat_20261107` database, OID 23520001. The new code migrated
that copy naturally from `0044_worktime_helpdesk` to the staging-only merge head
`0051_staging_linux_worktime`. No revision stamping, Worktime replay or destructive
schema conversion was used.

After migration, all original columns and 179444 rows across 72 tables matched
their pre-migration ordered row hashes exactly. New columns/tables are allowed;
only the expected `alembic_version` change was excluded. A separate read-only
probe using the final provider source still resolved the existing canary
`29a8bed4-2894-40f7-89fb-07b3c7f633fe` as `linux_amd64`.

Before live migration, the operator checked that no commands, operations, update
targets or Worktime delivery leases were active. Only the two Endpoint staging
application services were stopped. A fresh quiescent private dump, original env
and unit definitions were saved under
`/var/backups/endpoint-linux178-20261107T140434Z`; the dump was fsynced and its
restore listing checked. Raw data and credentials stayed on the server.

The live migration then returned 0. Before restarting either application service,
the same exact old-column comparison passed for all 72 live tables and 180171 rows.
The difference from the earlier clone count is intervening ordinary telemetry.
The application current symlink and protected env were activated only after that
comparison passed.

## Configuration and independent gateway

Actual env-file and API/worker/exporter process checks confirmed:

- Existing 38 unrelated env values, including secrets and CIDRs, were preserved.
- Existing Policy, ActivitySensor, SSO, Worktime and Helpdesk Worktime remain true.
- BrowserSensor and DLP remain false, explicitly pinned before new-code startup.
  The old staging defaults were false despite absent env entries.
- Linux initial support access is enabled for the approved operator public key,
  existing `root`/UID0, for 8 hours. Windows installation auto-access remains false
  in staging. Gateway availability retains the explicit staging origin guards.
- The independent gateway listens only on `192.168.101.118:2222`.
  Gateway/exporter and broker timer are enabled and independently supervised.
  A fresh exported snapshot contained zero leases; broker state and authorized
  tunnel key directory were empty. This grants no canary login yet.
- The observed gateway Ed25519 key matched the original authenticated host pin:
  normalized SHA256
  `fc639dcbcf6f4abfedb3b1f001a07d27699ef8ca64e5835f695f4268a4f1ddc4`.
  Git's bundled `ssh-keyscan` confirmed network reachability and matching bytes.
- Ordinary SSH PID 1449 and `/etc/ssh/sshd_config` bytes remained unchanged.
  No global SSH key, PAM policy, sudoers or human account was changed.

Operational corrections are retained in the private operation journal. A copied
host-key hash had a one-character typo; its guard stopped before env writes,
and the existing saved and fresh public-key proofs agreed. The exporter unit's
first staging adaptation incorrectly renamed the env basename. It failed 19
starts before spawning the application; the exact path was corrected to
`/etc/endpoint-staging/endpoint-platform.env`. The historical restart counter was
preserved. Exporter PID 53429 subsequently produced fresh snapshots without a
further restart. The gateway failed closed while snapshots were absent.

## Existing client and telemetry

VM 107 remains the original test machine, SMBIOS
`db12fb5c-3732-487f-911f-80e31f79b29b`, current address 192.168.101.191.
Actual packages are still `endpoint-agent-3.2.156-alt5.x86_64` and matching
UserSensor. Core PID 1061 remained unchanged with zero restarts. Credential,
enrollment identity, config and CA hashes matched the original protected proof.
The support component has not been installed on that client.

The user-maintained KDE X11 session 6/UID 1000 remained active, with the original
probe PID 13037. At 14:11:13Z, the updated server accepted fresh UserSensor samples
from 14:10:53–55Z; ActivityListener, SecuritySpool, USB and Print were all READY.
Activity was fresh IDLE at 14:11:13Z, and WSS was open with last-seen 14:10:54Z.
Both canonical inventory/baseline contexts still reported Linux/x86_64.

HTTPS `/healthz` returned 200 with database OK using Python's required certificate
and hostname verification against the existing local CA. Windows Schannel curl
could not perform its revocation check; no TLS verification was disabled.

## Native release gate still open

Final native RPMs were built from the clean canonical implementation source and
their closed payload/source manifests checked. They remain **unsigned**:

| Package | Bytes | SHA256 |
|---|---:|---|
| Core178-alt6 | 53616717 | `4918d61e544c7cd50192d96a87001a428f9a41a017d21c907759290f6cd1160a` |
| UserSensor178-alt6 | 41250 | `5057748ca462c546eb2ac59a727267e4f5b6182baea25077464724ae412d0ec7` |

The existing release signing key is present, but GPG rejects the protected local
stored passphrase. A user request to unlock the existing key locally or identify
its current protected store is pending. No private signing key was copied to a
VM, no replacement trust was created, and waiting formatting jobs were stopped.
No valid 178 signature, client installation or publication has occurred.

After key access is restored, remaining live gates include signed native
verification; 156/178 upgrade/downgrade/reinstall; exact removal/full-clean identity
semantics; actual administrator SSH with Core/updater stopped for at least 90 s;
expiry/revoke/disable and recovery; then stable fresh user telemetry before
production provider deployment or Linux primary promotion. Production, Windows 177
distribution/policy and the existing Linux 156 primary were not changed here.

Public bounded receipts are retained at
`C:/endpoint-platform-wix-build/linux178-native/`:
`staging-clone-migration-proof.json`, `staging-deployment-proof.json`,
`staging-provider-gateway-proof.json`, `staging-gateway-network-proof.json`,
`canary-after-staging-provider.json` and
`staging-telemetry-after-provider.txt`. Private journals and rollback input remain
in the marked server operation directory. Task 6 remains unfinished.
