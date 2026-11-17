# Isolated SSO staging acceptance

This procedure prepares real application BFF acceptance on `.118`. It does not
activate production SSO, change production client secrets, widen LDAP scope,
migrate real employees, or assign personnel/DLP rights automatically.

## Read-only baseline and holds

Observed on 2026-10-27:

| Surface | Isolated staging value |
| --- | --- |
| Host | `test-helpdesk`, `192.168.101.118` |
| Endpoint current | `/opt/endpoint-staging/releases/endpoint-platform-3e3528fbb07a` |
| Endpoint user/group | `endpoint-staging` |
| Endpoint API | `127.0.0.1:18000`, one worker, `--no-access-log` |
| Endpoint units | `endpoint-staging.service`, `endpoint-staging-worker.service`, `endpoint-staging-migrate.service` |
| Endpoint config/data | `/etc/endpoint-staging/endpoint-platform.env`, `/var/lib/endpoint-staging` |
| Endpoint database | `endpoint_staging_db`, schema `0039_power_source_state`, 94,592,023 bytes |
| Python/PostgreSQL | Python3.12.3, PostgreSQL16.15 |
| Helpdesk current | `736f3ae81616fd9a6304457c2a512001f7d6337c`, schema151 |
| Helpdesk config/data | `/etc/helpdesk-staging/helpdesk.env`, `/var/lib/helpdesk-staging` |
| Both feature sets | SSO/WorkTime remain disabled |

The baseline is evidence, not permission to ignore drift. Reconcile selectors,
schema, active operations, units, free space and environment hashes immediately
before any apply. Parent-owned Windows canary work must not overlap a staging
Endpoint restart or credential handoff.

**Identity hold:** the pilot's AD GUID must remain
`ee51f8b3-a7a8-4a69-808f-45adc6b35139`; preserve its original Keycloak subject
and enrolled OTP. An AD-disable test exposed removal/reimport of the imported
Keycloak user under the old disabled-user filter/default removal policy. Do not
bind a replacement subject, re-enroll OTP or perform browser login while that
recovery is unresolved. The client helper refuses even its pilot lookup until
the exact single-user, read-only LDAP provider has both reviewed retention
settings: `customUserSearchFilter=(objectCategory=person)` and
`removeInvalidUsersEnabled=false`. It also requires `NO_CACHE` and the exact
existing MSAD account-state mapper's `always.read.enabled.value.from.ldap=true`
before any user lookup, including Plan. LDAP remains OBJECT scope0 at the same DN.

**Capacity hold:** observed available space was approximately6.29GiB. The
production upgrade runbook requires10GiB; this procedure does not silently
lower that gate or schedule disk expansion. Before staging upgrade, review a
concrete capacity decision or an archived, hash-verified cleanup of demonstrably
owned obsolete staging artifacts. Preserve current and previous releases,
private configurations, backups and evidence. A broad read-only `du` inspection
initially timed out; subsequent bounded scoped inventory completed. Helpdesk
release roots occupy16,380,964KiB and Endpoint release roots2,834,688KiB, mostly
unrelated history. The two clearly task-owned obsolete05d/c369 release directories
total only335,962,112 bytes, below the3.8GiB recovery goal. Shared root pip cache
is not proven task-owned; no historical release/cache cleanup is authorized by
this plan. Nothing was deleted.

The100GiB virtual disk already contains an approximately98GiB PV/VG with
52,613,349,376 free bytes. A separately approved alternative can extend only
the existing ext4 root LV from52,609,155,072 to63,346,573,312 bytes using existing
VG extents; no hypervisor disk or partition expansion is needed. The concrete
operator proposal is `capacity-review-plan.json`, including exact LV/VG UUIDs,
an absolute target of15103 extents, backup/size/concurrency/idempotence guards
and postchecks. It has not been executed and requires separate explicit approval;
it is not an exception to the10GiB release gate.

## Three independent staging clients

Same issuer: `https://sso.sosnadmin.local/realms/sosnadmin`.

| Client | Exact callback | Minimum/default LoA |
| --- | --- | --- |
| `helpdesk-staging-web` | `https://helpdesk-staging.sosnadmin.local/api/web/session/oidc/callback` | 2 |
| `endpoint-staging-admin` | `https://endpoint-staging.sosnadmin.local/auth/admin/callback` | 2 |
| `worktime-staging-employee` | `https://endpoint-staging.sosnadmin.local/auth/employee/callback` | 1 |

`tools/keycloak/staging_app_clients.py` owns only these three fixed names.
Production `helpdesk-web`, `endpoint-admin` and `worktime-employee` are read and
compared before/after each staging mutation; they are never update targets.
Creation uses independent CSPRNG secrets persisted exclusively as root0600
`/etc/keycloak/staging-apps-20261027.env` on `.19`. Retries validate the same
owned material and reconcile partial client creation, never rotate secrets or
adopt a foreign client/secret store.

Run the reviewed immutable helper closure as root on `.19`, after the identity
hold is cleared. The GUID is not a secret:

```bash
python3 tools/keycloak/staging_app_clients.py \
  --expected-ad-guid ee51f8b3-a7a8-4a69-808f-45adc6b35139
python3 tools/keycloak/staging_app_clients.py \
  --expected-ad-guid ee51f8b3-a7a8-4a69-808f-45adc6b35139 --apply
```

The first call is a plan; the second creates disabled clients only. It does not
restart applications or write their environment files. The existing pilot
inventory checks include the exact synthetic user lookup, so the identity hold
applies to the plan too. Reports contain fixed outcomes, IDs, callbacks and
counts; do not print the private secret store, payloads, tokens or headers.

Each client requires confidential code flow, PKCE S256, RS256, no direct grant,
implicit flow, service account or full scope, and explicit empty web origins.
Only `basic/profile/email/acr` default scopes are bound; optional scopes are
empty. The helper verifies the existing fixed basic/acr UUIDs and stock26.8.1
mapper definitions, no role mappings on all four scopes, and the client's exact
name-to-UUID bindings. A nonempty authentication-flow override is rejected.
The GUID mapper uses `LDAP_ID`; each direct audience mapper adds only its own
client to access/introspection tokens, leaving ID/userinfo audiences unchanged.

Client enablement is a separately reviewed operation, after app configuration,
logging, identity durability and server readiness gates below:

```bash
python3 tools/keycloak/staging_app_clients.py \
  --expected-ad-guid ee51f8b3-a7a8-4a69-808f-45adc6b35139 --enable-staging-clients
python3 tools/keycloak/staging_app_clients.py \
  --expected-ad-guid ee51f8b3-a7a8-4a69-808f-45adc6b35139 --enable-staging-clients --apply
```

Immediately before each enable PUT, current detail, scope definitions, role
absence, bindings, assurance and secret are revalidated. The largest path uses
88 of the fixed96-request budget including authentication and current pilot
preflight. Production postchecks use the initially verified immutable client IDs
and compare their complete representations, so fewer lookups remove no guard.
An uncertain HTTP write consumes its one-use permit: reconcile by GET before
retry rather than replaying the mutation blindly.

## Endpoint staging upgrade and callback hygiene

Reuse the already qualified server archive for
`62fb4c83efbea9e4acc19c779db034a80087d2f9` only after verifying its pinned digest
`d6df0a870dfb3bac3754533b905aa30274070fec89afe9bbe83b366240bd393d`.
Adapt the existing `deploy/server/PRODUCTION_RUNBOOK.md` upgrade procedure to
the exact staging units, database, user, paths and port in the table above.
Never run its first-install section or substitute production defaults.

1. Clear capacity and concurrency gates; verify archive membership and existing
   selector/schema. Back up only `endpoint_staging_db` consistently and validate
   the archive. Perform an isolated restore drill, verify schema0039 and remove
   only its task-owned temporary database. Record exact hashes and results.
2. Prepare immutable `/opt/endpoint-staging/releases/endpoint-platform-62fb4c83efbe`
   and its Python3.12 venv using pinned requirements. Validate settings and secret
   readability as the actual `endpoint-staging` user. Preserve all app flags.
3. Record the exact predecessor. Stop only the two Endpoint staging runtime
   units, switch its selector and run `endpoint-staging-migrate.service`.
   Require actual `0042_worktime_companion` before starting API/worker.
4. Verify loopback18000 health, normal CA/hostname HTTPS and WSS, unchanged
   independent Helpdesk service, retained legacy administration and fresh policy.
   No automatic schema downgrade or production service restart is permitted.

Before any staging authorization callback, apply a separately reviewed staging
Nginx variant. The actual site has only a443 server, an agent WSS location and
the generic proxy on18000. Preserve its TLS paths, ACLs, headers and timeouts;
do not copy the production site's names, port8000 or ALT snippet.

Prepared operator assets under `C:/Temp/endpoint-sso-staging-20261027` record
the before/candidate/helper hashes in `nginx-plan.json`. The engine is the
reviewed query-safe repair with a fixed one-server staging profile and exact
before/source checksum guards. Validate it independently, run the isolated
synthetic failed-upstream sentinel check and Plan, then apply with root-private
old-byte backup, non-logging parity, `nginx -t`, reload and failure restoration.
Both exact `/auth/admin/callback` and `/auth/employee/callback` need safe path
access outcomes and callback-only raw-error suppression. Native service health
and strict TLS checks follow. No real code/state/Referer values enter evidence.

## Disabled configuration and owned identity preparation

After independent review, transfer only the three staging secrets through the
approved SSH/stdin memory bridge to `.118`; never shell arguments, transcripts,
repository files or operator evidence. Prepare separate staging Fernet keys and
a new narrow Helpdesk identity-resolver service credential. Existing production
secrets, databases and client authorities must not be reused.

Endpoint candidates reference `/etc/endpoint-staging/secrets/` files, staging
client IDs, the common issuer, the staging Helpdesk origin and the trusted CA.
Helpdesk candidates use `helpdesk-staging-web`, its exact staging callback,
independent encryption key and that new resolver credential. Both flags remain
false during preparation; original environments and explicit backups are
byte-verified. No candidate alone enables or restarts an application.

The current Helpdesk portal-link allowlist accepts only the exact production
employee URL. Keep `WORKTIME_PORTAL_URL` blank on staging and navigate directly
to the exact staging employee URL for this acceptance. Do not loosen the
production trust rule or point staging users into production. Actual production
Helpdesk link acceptance remains a separate gate.

Once the original Keycloak subject/OTP is recovered and durability verified,
prepare only task-owned synthetic requester/support test records through the
existing application APIs with operator audit. Before SSO linking, create one
owned ticket, exercise idempotent retry, public chat, support private-note
isolation, assignment/status, resolution and requester confirmation. Keep exact
UiUser login/person PK, ticket/message IDs, state versions and audit references;
do not mutate a real employee or use a natural-name/email guess as evidence.

Propose and explicitly confirm the exact issuer/subject/GUID binding to the
same existing synthetic UiUser/person. The new resolver must deny unknown,
unconfirmed, conflicting and inactive identities and foreign service authority.
Do not disable the pilot's legacy password until an actual persisted BFF SSO
session has passed validation; then use the canonical audited migration API and
verify old password sessions are revoked while historical records are retained.

## Actual acceptance and rollback

Enable clients and application flags only through reviewed bounded operations.
Use one real browser identity across Helpdesk and employee BFF routes, then the
separate Admin route. Verify protected Secure/HttpOnly cookies, CSRF, one-use
PKCE/state/nonce, same stable person and tickets, refresh, logout, upstream
revocation and outage fail-closed behavior. Provider-only exchanges and fixture
UI tests do not substitute for these application-route outcomes.

Employee authority must deny admin and DLP endpoints; personnel/department roles
need explicit separate grants. WorkTime tests must use only synthetic personnel
events/schedules and verified task-owned OS/device mappings, preserve UNKNOWN
coverage and require an independent approver for corrections/monthly versions.
Do not label seeded or fabricated telemetry as measured idle/return evidence.

On failure, restore only the changed staging application configurations and
runtime selector through reviewed rollback; retain migrated schemas and forensic
receipts, revoke only task-owned sessions/credentials/grants, and verify legacy
service access. Preserve original identities, protected histories and all
production resources. Record actual provider runtime SHA separately from the
Helpdesk locked contract-provider SHA; no source or success evidence is rebound
to a different candidate without real checks.
