# Exact-account business sign-in

`tools/keycloak/business_ad_login.py` and `business_ad_login_native.py` repair a
specific pilot-boundary mismatch: the master owner can use AD, but the business
realm searches only the synthetic pilot DN and returns `user_not_found` for that
owner. The error does not establish whether a typed password is correct.

The selected account is the already authorized permanent owner. Fresh strict
LDAPS evidence must show its immutable GUID/SID/DN, enabled/unlocked/non-expired
state and a SID matching the current Windows identity. The native adapter also
matches the existing master provider and imported LDAP_ID. It refuses a business
username collision or an unqualified initial provider profile.

The operation creates one separate business LDAP provider, initially disabled:
exact user DN, base-object search, exact binary objectGUID filter, READ_ONLY,
LDAPS, no periodic/bulk sync or registration writes. It clones only the existing
pilot's attribute/MSAD mapper semantics into newly created mapper IDs and verifies
them before enabling the new provider. The pilot provider is never an update
target. No user password, AD account, group, application role, authentication flow,
MFA setting, client configuration or service is modified.

Both modules are inert by default. Native plan/apply require the fixed private
root capsule, committed source hashes, fresh proof, an exclusive lock, approved
operator secret channel and explicit bounded input. A new PGDMP/TOC-qualified
backup precedes configuration writes. Whole-row hashes preserve pre-existing
users, credentials, roles, groups, clients, flows and components. Only newly owned
provider/mapper rows are excluded from the component comparison. A failed enable
postcheck may disable only the created provider; it never deletes an imported
identity or replays an uncertain create. The operator session is logged out.

This changes the business LDAP profile from one exact account to two independently
bounded providers. Historical single-provider acceptance receipts and frozen
initial-provisioning scripts remain historical; they are not post-change proofs.
Subsequent acceptance must qualify both providers rather than weaken the old
cardinality guard or run a bulk user sync.

Successful directory authentication is separate from WorkTime access. Helpdesk
must still confirm the immutable employee/person binding, and personnel/technical
roles remain separate. The helper grants neither HR nor Endpoint administration.

The initial live attempt retained an owned **disabled** provider when Keycloak
added its AD `krbPrincipalAttribute=userPrincipalName` default. Its immutable v1
capsule, backup and failure evidence remain. The v2 continuation accepts only
that created ID, the original create-intent fingerprint, unchanged immutable
identity and the original full profile seal. It does not repeat provider POST.
The default is now explicit while Kerberos authentication remains disabled.

Fresh v2 backup and saved JSON precede reconciliation of this unused provider's
generated mappers. Only known generated children may be removed/recreated to
match the original pilot mapper semantics exactly; imported users and the pilot
mapper IDs remain untouched. Component PUT merges configuration keys, so a
different generated mapper is replaced rather than retaining unrequested keys.
Unknown names/types, enabled provider state or metadata changes stop the operation.

Provider operations use the Keycloak26.8.1 Component Admin REST API:
https://www.keycloak.org/docs-api/26.8.1/rest-api/index.html#_component
