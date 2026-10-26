# Dedicated Keycloak SSO pilot

Status on 2026-10-27: assets prepared and independently reviewed. An AD-MAIN
non-exportable machine key and public CSR were generated; no certificate has
yet been issued/installed. Keycloak/DNS/account/service/database installation
and actual AD SSO acceptance remain separate gates.

## Inventory and prerequisites

Read-only SSH to `admin-2@192.168.100.11` confirmed hostname `AD-MAIN`,
no Keycloak services and no Java processes. AD DNS zone `sosnadmin.local`
contains no `sso` or `keycloak` record; both A lookups failed. Ports 389/636
listen, but `.19` secure LDAP TLS probe resets before receiving a certificate.
`Cert:\LocalMachine\My` has zero certificates; the NTDS service My store was
not found. No `certsvc` service/configuration or Sosnadmin CA match in the
Root/CA stores was found. This does not establish where the CA signing key is.

Host `.19` has PostgreSQL 16.15 and Nginx; inventory found approximately
12.4 GiB disk and 6.6 GiB RAM available, with no Java/container runtime.
Recheck capacity and reserved ports at installation. Existing wildcard SSO
TLS certificate has `*.sosnadmin.local` SAN and expires 2028-10-16. Its issuer
is `Sosnadmin Local CA`. Exact AD LDAP TLS needs its own DC certificate and
trusted chain; wildcard SSO certificate availability does not satisfy this.

`deploy/server/PRODUCTION_RUNBOOK.md` documents TLS leaf/key transfer from
`root@192.168.100.12:/etc/nginx/ssl/sosnadmin-wildcard.{crt,key}.pem` via SSH.
Read-only filename searches of that host's `/etc`, `/opt`, `/srv`, `/var/lib`,
`/home` (depth four) and `/root` (depth two) found no CA signing key or issuance
script. The operator-held CA at
`C:\Users\admin-2\Desktop\Новая папка (2)\тех\сертификат\sosnadmin-local-ca.crt`
is public deployment input; do not commit certificate/key copies or infer that
the wildcard leaf key can sign a DC certificate.

Subsequent operator-directed inventory located the actual CA on
`osn-admin@192.168.100.5:/root/sosnadmin-ca`. Its public certificate SHA256
fingerprint is `5525eccf01536b7f0436d96500c663f7a58edac463f00f0fb34a59dd8b3250be`,
matching the approved local public CA. Its signing key remains on that host,
encrypted and root-only; obtain its passphrase through the approved channel.
Do not put it in arguments, logs, source or a new unprotected passphrase file.

## Boundaries and runtime

The approved deployment is a separate service on `192.168.100.19` with issuer
`https://sso.sosnadmin.local/realms/sosnadmin`. Its own Unix user `keycloak`,
PostgreSQL cluster `16/keycloak` (loopback port 5544), DB/role `keycloak`,
`/opt/keycloak`, `/etc/keycloak` and `/var/lib/keycloak` are independent of
Endpoint and Helpdesk. Java21 and the distribution pinned by SHA256 in
`deploy/keycloak/release.json` are prerequisites. No containers are required.
Keycloak frontend 8088 and health 9008 bind loopback. Nginx exposes only the
realm/resources paths and replaces forwarded headers. Master/admin paths
remain blocked externally; administer via SSH and local CLI. The pilot is a
single instance with local cache; it provides no high availability.

`tools/keycloak/install.sh` is a first-install script, refusing existing
Keycloak paths, database cluster or occupied ports. It installs packages,
creates a dedicated cluster/role, generates the DB password on-host and writes
it only to root:keycloak `0640` configuration. It installs units and a new
Nginx site in `sites-available`; it leaves Keycloak stopped and does not
reload Nginx or restart either application. It requires four root-controlled
inputs: verified archive, CA PEM bundle, SSO fullchain and private key (0600).
The CA bundle must validate both the SSO leaf and the DC leaf. The optional
`--prepare-without-directory` flag permits preparation while LDAPS is broken;
this does not enable application clients or establish SSO readiness.

The live first-install gate found `pg_conftool` misclassifies a dotted IPv4
literal as numeric; adding quotes to its argument instead escapes those quotes
into the hostname. The installer now removes that inferred value, installs an
explicit quoted loopback include in this cluster's `conf.d`, and requires the
real PostgreSQL server parser to return exactly `127.0.0.1` before starting. If first
installation stopped at cluster startup, `--resume-before-database` verifies
the exact distribution, CA/TLS inputs, Unix identity, dedicated port and absence
of application configuration/service before continuing. It refuses an existing
application role instead of changing its password. This mode is solely for that
interrupted pre-database phase, never an upgrade or a way to overwrite an active
SSO installation. Keep the main PostgreSQL cluster untouched.

Only after reviewing assets and approving the exact DNS record, provision
`sso.sosnadmin.local A 192.168.100.19` on the AD DNS server. No scripts here
change DNS, GPOs, existing users or groups. Do not replace another record.
Copy TLS through the existing SSH source directly into root-only input paths.
Do not pass secrets in command arguments, transcripts, evidence or chat.

```bash
sudo bash tools/keycloak/install.sh /root/keycloak-input/keycloak-26.8.1.tar.gz \
  /root/keycloak-input/trust.pem /root/keycloak-input/fullchain.pem \
  /root/keycloak-input/key.pem
```

## Secure AD certificate remediation (review before execution)

Use `deploy/keycloak/ad-main-ldaps.inf` to generate a non-exportable RSA3072
machine private key and CSR on AD-MAIN. This is a scoped DC certificate
operation; obtain the parent's deployment approval first. Do not restart the
domain controller or alter LDAP signing/channel binding policy.

```powershell
certreq.exe -new -machine C:\ProgramData\SsoSetup\ad-main-ldaps.inf C:\ProgramData\SsoSetup\ad-main.req
```

Transfer only the public CSR to the approved CA operator. The CA must verify
the request signature, issue exactly `AD-MAIN.sosnadmin.local` CN/SAN,
`CA:FALSE`, digitalSignature/keyEncipherment and Server Authentication EKU,
and return the leaf and public chain. Locate the actual CA and its reviewed
issuance procedure before signing; no generic command in this repo opens or
copies a CA private key. Trust the validated public CA chain on AD-MAIN and
Keycloak through approved certificate provisioning. Never trust a new root
merely because it was returned alongside a leaf.

`tools/keycloak/sign_dc_certificate.sh` implements this scoped issuance using
the existing CA index and serial on `.5`. It pins the CA, expected direct-AD
CSR SHA256, exact subject/SAN, RSA>=3072 and Server Authentication. It first
copies the CSR to a root-only receipt, then verifies that immutable copy;
arbitrary CSR extensions are not copied. It serializes its CA updates with
`flock`; do not run another CA issuance workflow concurrently. Index/serial
snapshots and public checksums remain in a root-only receipt. Pass the public
CSR hash read directly from AD as the second argument; let OpenSSL prompt
privately for the encrypted key passphrase. Only the public issued certificate
is copied back to the operator home directory. A wrong-hash negative check
was executed and rejected before any CA database change.

```powershell
certreq.exe -accept -machine C:\ProgramData\SsoSetup\ad-main.cer
certutil.exe -verify C:\ProgramData\SsoSetup\ad-main.cer
```

Verify the issued leaf has the machine private-key association, intended SAN,
EKU, validity and approved chain in LocalMachine\My. With no existing NTDS
certificate, refresh the existing AD service certificate selection through the
documented rootDSE operation below instead of rebooting. If certificate
selection fails, stop and diagnose; do not weaken hostname/trust verification.

```powershell
$rootDse = [ADSI]'LDAP://localhost/RootDSE'
$rootDse.Put('renewServerCertificate', 1)
$rootDse.SetInfo()
```

On `.19`, require verified LDAPS before binding any account:

```bash
timeout 15 openssl s_client -connect AD-MAIN.sosnadmin.local:636 \
  -servername AD-MAIN.sosnadmin.local -verify_hostname AD-MAIN.sosnadmin.local \
  -verify_return_error -CAfile /etc/keycloak/trust/ad-ca.pem -brief </dev/null
```

Use an approved unprivileged bind account with directory-read rights only.
Creating a new single bind account, if required, is a separately reviewed AD
mutation; no domain-admin credential is needed or accepted as the normal
runtime bind. Keep its DN/password in an approved root-only runtime secret
file. Confirm read/authenticate and that no LDAP write operations are configured.

## Realm and client provisioning

The renderer requires an approved existing pilot OU/container DN, no
whole-domain base. It writes secret placeholders and disabled clients by
default, never domain users or local passwords. The LDAP component uses
LDAPS, `READ_ONLY`, `objectGUID`, no registration sync, no user cache or
scheduled full sync. Its built-in MSAD account-state mapper observes account
state. Domain passwords remain AD-only. Store MFA credentials in Keycloak,
and keep the application realm free of manually created local domain users.
Any break-glass administrator belongs to the separate master realm.

Exact callback contracts confirmed with the application implementers:

| Client | Callback |
| --- | --- |
| `helpdesk-web` | `https://<approved-helpdesk-host>/api/web/session/oidc/callback` |
| `endpoint-admin` | `https://endpoint.sosnadmin.local/auth/admin/callback` |
| `worktime-employee` | `https://endpoint.sosnadmin.local/auth/employee/callback` |

There are no wildcard callbacks or cross-client redirects. These BFFs use
confidential code clients and PKCE S256, with password/implicit/service-account
grants disabled. They use application-local logout; RP logout redirects are
not configured. Use an exact separately reviewed Helpdesk hostname; do not
infer it from the Endpoint origin.

```bash
python3 tools/keycloak/render_realm.py \
  --helpdesk-callback https://helpdesk.sosnadmin.local/api/web/session/oidc/callback \
  --endpoint-callback https://endpoint.sosnadmin.local/auth/admin/callback \
  --worktime-callback https://endpoint.sosnadmin.local/auth/employee/callback \
  --pilot-users-dn 'OU=<approved-existing-pilot>,DC=sosnadmin,DC=local' \
  --output /etc/keycloak/sosnadmin-realm.json
```

Do not run the example DN literally. The output uses exclusive creation to
avoid overwriting an operator-reviewed config. On-host, prepare a root-only
`0600` `/run/keycloak-provision.env` through the approved secret channel with
`SSO_LDAP_BIND_DN`, `SSO_LDAP_BIND_PASSWORD`, `SSO_HELPDESK_CLIENT_SECRET`,
`SSO_ENDPOINT_CLIENT_SECRET`, `SSO_WORKTIME_CLIENT_SECRET` and temporary
`SSO_BOOTSTRAP_PASSWORD`. Make the non-secret realm JSON root:keycloak 0640.
Never print this environment file, tokens, realm export or kcadm auth cache.

With Keycloak stopped, import once without overriding an existing realm:

```bash
sudo systemd-run --wait --collect --property=User=keycloak --property=Group=keycloak \
  --property=EnvironmentFile=/run/keycloak-provision.env \
  /opt/keycloak/current/bin/kc.sh --config-file=/etc/keycloak/keycloak.conf \
  import --file=/etc/keycloak/sosnadmin-realm.json --override=false --optimized
sudo systemd-run --wait --collect --property=User=keycloak --property=Group=keycloak \
  --property=EnvironmentFile=/run/keycloak-provision.env \
  /opt/keycloak/current/bin/kc.sh --config-file=/etc/keycloak/keycloak.conf \
  bootstrap-admin user --username sso-bootstrap --password:env SSO_BOOTSTRAP_PASSWORD --no-prompt --optimized
sudo systemctl start keycloak
curl --fail --silent http://127.0.0.1:9008/health/ready
```

Remove the provisioning environment after securely delivering independent
client secrets to their applications; it is not the runtime service env.
Use an authenticated local Admin CLI session to enable only the needed pilot
client for acceptance; preserve realm state with Admin API updates, never
reimport/overwrite an active realm. Establish a permanent master-realm
administrator with MFA, then delete the temporary bootstrap identity/cache.
Before exposing Nginx, validate `nginx -t`, create only the Keycloak site's
`sites-enabled` symlink and reload Nginx through the reviewed service workflow.
Do not restart Endpoint or Helpdesk as part of Keycloak installation.

`ad_object_guid` maps Keycloak's internal `LDAP_ID`, populated from the LDAP
provider's UUID parsing, to ID/access/introspection tokens. It is not an email,
username or a raw binary LDAP attribute mapper. Verify its canonical lowercase
UUID against read-only AD `objectGUID` for each pilot identity before linking.
Application code rejects missing/malformed GUID. Never add a hardcoded MFA ACR
claim. The realm step-up flow earns LoA2 only after required OTP, maps it to
exact `urn:sosnadmin:loa:2`, and bounds its age to 300 seconds. The privileged
clients also set minimum/default LoA2; applications must request and validate
the exact signed ACR. Employee LoA1 cannot grant administrator access.

## Acceptance, revocation, backup and rollback

Before enabling SSO in either application, capture redacted evidence of all
three PKCE code flows, wrong nonce/state/audience/issuer rejection, missing and
wrong ACR rejection, MFA enrollment/challenge, exact canonical AD GUID, distinct
client secrets/callbacks, and denied public master/admin paths. Confirm normal
Keycloak introspection returns `active`, exact `iss`, `sub`, `client_id`, `sid`
and future `exp` for each respective access token. Do not log token values.
Revoke the pilot's Keycloak session and verify existing application sessions
are denied within 60 seconds; provider/introspection outage must deny access
at the same revalidation boundary. An LDAP account disable by itself is not
proven to terminate an already active Keycloak SSO session: disable and revoke
the matching Keycloak session when immediate containment is required, and test
this workflow separately before claiming a 60-second AD-disable guarantee.

The access-token lifetime is 300 seconds, idle session 900 seconds, maximum
session eight hours, refresh rotation enabled with zero reuse, and no offline
scope is assigned. Enable clients and application feature flags independently
after acceptance. Keep current login/break-glass access available for rollback.
Stop services after temporary remote validation unless the deployment is
explicitly accepted to remain running.

`sudo /usr/local/sbin/keycloak-backup` creates a root-only consistent pg_dump
of the dedicated cluster plus secret-bearing config/TLS archive and checksums
under `/var/backups/keycloak`. A COMPLETE marker identifies successful pairs.
After a test restore, enable `keycloak-backup.timer`. Transfer encrypted copies
to the approved off-host vault, set a retention/capacity policy there, and
monitor local disk. No automatic pruning or off-host destination is assumed.
Realm JSON export is not a complete database backup.

Rollback application flags first, revoke pilot sessions, stop only Keycloak,
remove only the Keycloak Nginx symlink after validating Nginx and reload it.
Keep the isolated database and backups for review; do not drop a DB or rewind
the schema automatically. Restore only into a stopped isolated instance using
the matching pinned distribution/config and a verified backup. Never point
Keycloak at Endpoint/Helpdesk databases or restore over their clusters.

## Sources

Version/platform: [Keycloak downloads](https://www.keycloak.org/downloads),
[supported configurations](https://www.keycloak.org/server/supported-configurations).
Deployment: [production](https://www.keycloak.org/server/configuration-production),
[hostname](https://www.keycloak.org/server/hostname),
[reverse proxy](https://www.keycloak.org/server/reverseproxy),
[truststore](https://www.keycloak.org/server/keycloak-truststore),
[realm import/export](https://www.keycloak.org/server/importExport),
[bootstrap admin](https://www.keycloak.org/server/bootstrap-admin-recovery).
Identity: [administration guide](https://www.keycloak.org/docs/latest/server_admin/index.html),
[26.8.1 LDAP provider](https://github.com/keycloak/keycloak/blob/26.8.1/federation/ldap/src/main/java/org/keycloak/storage/ldap/LDAPStorageProvider.java).
AD certificate: [Microsoft LDAPS certificate requirements and renewal](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-over-ssl-3rd-certification-authority).
Context7 documentation lookup was attempted by the parent and unavailable due
to quota, so current official provider documentation/source was used.
