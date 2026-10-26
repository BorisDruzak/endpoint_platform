# Confirmed identity and independent browser sessions

SSO is disabled by default. Device credentials, Gateway/WSS and service-token
authorization retain their existing independent paths. WorkTime requires its own
`ENDPOINT_WORKTIME_ENABLED=true` switch in addition to configured employee SSO.

## Deployment configuration

Set `ENDPOINT_SSO_ENABLED=true` only after migration `0040_identity_sso`, a working
TLS-verified issuer and the Helpdesk identity authority have passed acceptance.
The settings below are runtime configuration, never committed secrets:

| Setting | Meaning |
| --- | --- |
| `OIDC_ISSUER` | Exact HTTPS realm issuer, proposed `https://sso.sosnadmin.local/realms/sosnadmin` |
| `OIDC_EMPLOYEE_CLIENT_ID` | Confidential employee client, `worktime-employee` |
| `OIDC_ADMIN_CLIENT_ID` | Distinct confidential admin client, `endpoint-admin` |
| `OIDC_EMPLOYEE_CLIENT_SECRET_FILE` | Private regular file containing employee client secret |
| `OIDC_ADMIN_CLIENT_SECRET_FILE` | Separate private regular file containing admin client secret |
| `OIDC_ADMIN_REQUIRED_ACR` | Exact required MFA assurance, `urn:sosnadmin:loa:2` |
| `OIDC_ENCRYPTION_KEY_FILE` | Private Fernet key file, generated with `Fernet.generate_key()` |
| `ENDPOINT_SSO_CA_FILE` | Optional PEM CA bundle added to system trust for issuer and Helpdesk HTTPS |
| `OIDC_BREAKGLASS_USERNAMES` | Explicit comma-separated existing administrator usernames eligible for temporary emergency login |
| `OIDC_BREAKGLASS_UNTIL` | Timezone-aware UTC expiry; startup rejects emergency windows beyond 24 hours |
| `HELPDESK_IDENTITY_BASE_URL` | Fixed trusted Helpdesk HTTPS origin |
| `HELPDESK_IDENTITY_CREDENTIAL_FILE` | Dedicated random identity-resolver credential (at least 32 random bytes encoded URL-safe) |

Install `requirements-server.txt` (Authlib 1.9.1 and HTTPX) in the application
environment. Configure the OS/application trust store for the issuer and Helpdesk
CA; supply the internal CA bundle through `ENDPOINT_SSO_CA_FILE` where needed.
Proxy and CA environment overrides are ignored. TLS verification and redirects
must never be disabled. Provider discovery
must publish the exact issuer and same-origin HTTPS authorization, token, JWKS
and introspection endpoints; RS256 is the permitted signing algorithm.

Register exact callback URLs:

- `https://endpoint.sosnadmin.local/auth/employee/callback`
- `https://endpoint.sosnadmin.local/auth/admin/callback`

The corresponding login URLs are `/auth/employee/login` and `/auth/admin/login`.
The fixed final destinations are `/employee` and `/admin`; return URLs from the
browser are not accepted. The ID token must contain canonical `ad_object_guid`,
case-sensitive `sub`, `sid`, issuer, audience, expiry and nonce. The admin token
also requires the configured `acr`. Keycloak introspection must return active,
matching issuer, subject, sid and client_id with a future numeric exp.

## Authority and provisioning

Only validated OIDC claims reach Helpdesk
`POST /api/integration/v1/identities/resolve`. Its v1 response must echo exact
identity identifiers and return one active confirmed person. Email, display name
and login aliases are never identity evidence. Unknown, inactive, conflicting or
unavailable authority grants no access. Endpoint persists a reference to that
confirmed Helpdesk identity and does not create or merge Helpdesk people.

Employee SSO never creates an administrator. An existing confirmed Endpoint
identity must be explicitly linked to an existing active `AdminUser` through
`POST /api/admin/identities/{identity_id}/admin-link` with JSON
`{"admin_user_id":"existing-admin-uuid"}`. Unlink with null. The caller needs
the persisted administrator scope `identities:manage` and the ordinary admin
CSRF token. This scope must be explicitly provisioned by the controlled admin
bootstrap/operations process. The explicit link records `sso_migrated_at` on the
administrator. That administrator's password login and old local sessions are
then disabled, including after unlinking or disabling SSO. Unmapped accounts
retain their existing login until an explicit migration.

Migrated administrators can use password login only when explicitly named in
`OIDC_BREAKGLASS_USERNAMES` with an unexpired `OIDC_BREAKGLASS_UNTIL`. Login creates
a newly audited `breakglass` session bounded by one hour and that configured
expiry. Existing old local sessions do not become emergency sessions. Expiry is
checked on every protected request. No default emergency allowlist is provided.

Personnel roles are independent scoped grants. Create a grant with
`POST /api/admin/identities/{identity_id}/grants`, JSON
`{"role":"manager","department_id":"department-uuid"}`. Revoke through
`DELETE /api/admin/identities/{identity_id}/grants/{grant_id}`. Both operations
require `identities:manage`, CSRF and immutable audit. New authority requires
fresh Helpdesk confirmation. Manager requires a non-null exact department;
global HR, WorkTime Admin or DLP Officer authority must be granted explicitly.
Technical Endpoint administrator rights do not imply personnel/DLP access.
An actor cannot approve their own corrections. Authorization resolves the
target's department from fresh Helpdesk confirmation on each protected target
operation, updating the local snapshot; failures deny access even if that target
has not logged in. Browser department parameters are never authority. Manager,
HR, WorkTime Admin and DLP Officer actions additionally require the exact signed
MFA ACR persisted with the upstream session. A grant added after a low-assurance
login cannot bypass MFA. `/auth/employee/step-up` starts a new fixed OIDC flow
requesting the configured ACR; self-only employee access can remain lower assurance.

## Session and revocation guarantees

Authlib implements Authorization Code with PKCE S256 and ID-token signature,
issuer, audience, expiry and nonce verification. One-use state is locked and
committed consumed before code exchange. A separate opaque short-lived browser
cookie binds each realm's callback; nonce and verifier are encrypted in the DB.
Employee and admin application cookies are independent random opaque values;
only HMAC digests are persisted. Provider tokens are Fernet-encrypted server
side, bound to sid and never exposed through browser JSON or URLs.

The opaque browser session has an eight-hour absolute ceiling. Effective access
remains bound to current provider token validity. If the token expires or has
at most 30 seconds left, Authlib spends the persisted refresh token under a
database row lock, validates refreshed signed identity/assurance and current
introspection, and atomically replaces the encrypted rotating tokens. Missing,
reused, rejected or changed refresh authority denies access. A short-lived access
token therefore does not force an active employee back to login; an idle user can
return within the valid provider refresh window and local absolute lifetime.
Protected operations load the current local account and current grants.
At most 60 seconds elapse between upstream introspection and Helpdesk identity
revalidation. Inactive authority or provider/Helpdesk failure during revalidation
denies the operation and revokes that upstream session. This is bounded
revalidation, not a promise of immediate AD deactivation: effective upstream
revocation also depends on working federation synchronization. No backchannel
logout endpoint is claimed. App logout uses local cookie/CSRF only and revokes
local persistence even during upstream outage or expiry; remote provider
SSO may remain active. Do not enable Authlib/OAuth or HTTP wire debug logging in
production because transport-level logs may expose tokens.

`GET /api/employee/session` returns person/department, explicit grants and a
session-bound CSRF token, with no-store. Unsafe employee calls require
`x-csrf-token`; `DELETE /api/employee/session` revokes the current local session.
The employee/DLP SPA uses the existing public `/admin/assets` bundle and public
sign-in shell, while every data API authenticates independently.

## Verification and rollback

Run `python -m pytest tests/server/test_identity_sso.py tests/server/test_admin_auth.py tests/server/test_config.py tests/deploy/test_server_runtime_requirements.py`.
The signed-token tests use Authlib with generated RSA fixture keys and mocked
HTTPS transports. They are not live LDAP, MFA or real identity acceptance.
Run migrations against an isolated PostgreSQL database before deployment.

To disable the feature set `ENDPOINT_SSO_ENABLED=false` and
`ENDPOINT_WORKTIME_ENABLED=false` and restart through the reviewed server release
procedure. OIDC employee and admin sessions then fail closed; unmigrated local
admins and explicitly configured unexpired emergency access remain available.
Migrated admin passwords do not become an indefinite rollback bypass.
Preserve DB identity/audit history and
encryption keys for controlled recovery; do not downgrade/drop tables while
dependent WorkTime migrations remain applied. No fleet rollout is authorized by
these server changes.

The implementation follows the [official Authlib HTTPX client documentation](https://docs.authlib.org/en/v1.6.9/client/httpx.html)
and verifies the installed 1.9.1 public APIs and claim validator source. Context7
was unavailable because its quota was exhausted.
