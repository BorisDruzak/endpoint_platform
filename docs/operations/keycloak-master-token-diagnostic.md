# One-login private master-token diagnostic

Status: source and synthetic tests only. No native installation, restore, SQL,
API call, JVM, login or probe has been executed by this change. Run7's exact
failed guard remains unknown. This diagnostic cannot qualify or promote a
candidate, purge sessions, change AD, repair scopes/providers, use a browser,
look up an identity through IdP/LDAP/admin-user APIs, or alter a token policy.

## Concrete adapter and boundaries

`tools/keycloak/master_token_diagnostic.py` defaults to a metadata-only plan.
Its complete native adapter requires explicit `--run-once --candidate`, Linux
root on the existing approved `.19` host, an exact protected executor location,
source closure and authorization bindings. It never chooses/restores a database.
The parent separately owns fresh preparation. The source profile uses a fresh v10
namespace; consumed v9 remains preserved. Existing modified OIDs 20856, 22159 and
23462 remain forensic databases.

The adapter reuses the unchanged `PrivateCandidateRuntime` constructor,
`verify_pristine_attempt`, archive-backed `copy_and_configure`, owned-group
`start`/`stop`, and full PID/socket/JDBC/configuration/binary proof. Internal
read-only SQL comparison of the original UUID/OTP remains a safety precondition;
it does not perform an IdP/LDAP/user API lookup. No guard is bypassed by subclass,
`__new__`, patched global namespace, or `QualificationOperations` construction.
The latter is deliberately unused, as are its retention/scope/browser/purge
methods and broad environment loader.

Within the shared recovery lock, the native sequence is:

1. Validate the root-private source/authorization bindings, then exclusively create
   the fixed `master-token-probe-consumed.json` fence inside the reviewed executor
   root. This happens before the runtime constructor or any probe journal, copy,
   build, start or login. A failed prestart invocation remains consumed even when
   the v10 common root was never created; a second invocation cannot start/login.
   Never remove/reset this fence to retry. Validate the sealed original/failed evidence, explicit new candidate name/OID,
   unused common work root and original full-101/schema/ACL/sequence equivalence.
   Create a separate exclusive root-private `-master-token-probe-<nonce>` journal.
   Capture the new candidate and all three old forensic databases before startup.
2. Prepare/start the one isolated runtime using the existing owned lifecycle.
3. Select only `SSO_BOOTSTRAP_PASSWORD` from the approved root-private provision
   file. Other secret values are not decoded or stored in an environment dict.
   A wrapper of the pinned `LocalAdminClient` has request budget one and accepts
   only the exact master password-grant POST for `admin-cli`/`sso-bootstrap`.
   Its one-shot permission is consumed before proof/network. There is no retry.
4. Write a fixed boolean-only unverified-token-shape receipt. Construct the
   `CandidateSessionClient`, retaining the exact issuer/client/SID
   checks, and require at least 45 seconds of remaining lifetime. No extra delay
   or lifetime relaxation is added. Mutation capability sets remain empty.
5. Allow exactly one `GET /admin/realms`, pinned to candidate loopback, and
   require the two expected realms. A second request or any other receiver,
   path or mutation fails before HTTP. Existing runtime proof runs before login,
   in the constructor and before the GET; no redundant proof is added between
   these existing bounded checks.
6. Prove runtime provenance before exactly one read-only inventory using that
   precise in-memory SID. Preserve strict fresh-session/flag, realm, cutoff,
   notBefore, offline-bound and canonical-session-ID preconditions. Reduce the
   result to fixed booleans. Stop before any notBefore update, deletion or logout.
7. On every normal/failing/cancelled exit, clear token/password references and
   stop the owned group; confirm canonical process identity, absent private
   listeners, the unchanged candidate OID and zero candidate DB connections.
   Capture the candidate after-state and all three old full-101 forensic after-states
   privately. Compare all three old databases and every preserved source/evidence file
   to their sealed baselines. Failure of any check remains cleanup HOLD.

The shared lock is held through cleanup and all reconciliation. SIGINT, SIGTERM
and SIGHUP unwind through cleanup; repeated cancellation is ignored during that
unwind. The existing runtime protects canonical PIDs/groups and bounds TERM/KILL
handling. An unconfirmed earlier build/runtime cleanup cannot be erased by a
later successful stop. SIGKILL, machine failure or lost execution requires separate
read-only reconciliation; no program can claim confirmed cleanup after those
events without observation. No blind rerun or removal of a consumed root follows.

## Exact source pins and protected native inputs

All source files must be root-owned 0600 beneath the physical root-owned 0700
`/root/keycloak-identity-recovery-20261027-executor-v10` directory. Verified exact
source buffers are compiled directly, with no import reread or bytecode cache.

- Recovery backend SHA256:
  `5b46db376f6d83af5c94deed439459be055885fd034bcfadee307f8f4ade44f3`.
- Pilot helper SHA256:
  `7df5688f2c4de83cec4047c1788e56a8ccf1b84bd7297102545bea7bfa0a1cd8`.
- The probe's final reviewed hash belongs in the protected source closure below.
  This avoids a self-referential hash embedded inside its own source.

`master-token-source-closure.json` must have exactly these fields:

```json
{
  "schema": "keycloak_master_token_source_closure_v1",
  "probe_sha256": "<final independently reviewed probe hash>",
  "backend_sha256": "5b46db376f6d83af5c94deed439459be055885fd034bcfadee307f8f4ade44f3",
  "helper_sha256": "7df5688f2c4de83cec4047c1788e56a8ccf1b84bd7297102545bea7bfa0a1cd8"
}
```

`master-token-probe-authorization.json` is a small sealed root input, not another
user approval workflow. Its exact fields are `schema` (literal
`keycloak_master_token_probe_authorization_v1`), `candidate_database`,
`candidate_oid`, and `preserved_artifacts`. The explicit candidate must match it;
canonical/audit/20856/22159/23462 OIDs are rejected. `preserved_artifacts` contains
exactly these six entries, each an object with only `path` and `sha256`:

| Entry | Exact source/provenance |
| --- | --- |
| `original_snapshot` | Immutable original Stage1 `candidate-restored.json` under `/var/backups/keycloak-recovery/keycloak_recovery_20261027_55f72537` |
| `original_context` | `context.json` in that same original root, pinned dump and original OID 20856 |
| `original_identity` | `identity-before.json` in that same original root |
| `prepare_preservation_before` | `/root/keycloak-fresh-prepare-after-master-probe1-v1/attempt/preservation-before.json` |
| `prepare_preservation_after` | `/root/keycloak-fresh-prepare-after-master-probe1-v1/attempt/preservation-after.json` |
| `sealed_run7_source` | Existing reviewed root-private sealed v8 source, beneath its executor root or retained recovery evidence root |

The preparation preservation files are read directly, without extraction or a
new baseline. Their schema must be `failed_candidate_forensic_preservation_v1`,
`not_original_restore_baseline=true`, and `capture.failed_databases` must contain
exactly `keycloak_recovery_20261027_55f72537`/OID20856,
`keycloak_recovery_20261027_2190f3d5`/OID22159 and
`keycloak_recovery_20261027_82e14168`/OID23462. Each row has only `snapshot` and
`identity`, with the matching OID. The before file additionally binds
`actual_generated_candidate_name` to the explicit candidate. The before/after
failed maps must be exactly equal; their modified full-101 datasets cannot be
relabelled as the immutable original. Fresh read-only full inventories of all three
old databases are compared before and after the probe, under the same lock.
All tables, row multiplicities, schema/ACLs and sequences participate.

The reader rejects missing/duplicate fields, wrong paths/OIDs/schema/hash pins,
symlinks, hard-linked files, foreign/writeable ancestors, wrong modes/owners and
oversized inputs. Full before/after inventories and hashes remain exclusively in
root-private evidence; they are not emitted in the result. Historical sources and
evidence files are rechecked after the probe as well as before it.

## Results and future native gate

The public result and root-private result receipt contain only fixed status,
phase/refusal enums, booleans and boolean-only shape/inventory/cleanup objects.
No token, SID, claim payload/value, timestamp, username list, row, identifier or
fingerprint is exported. A malformed diagnostic object cannot be echoed through
failure handling. References are cleared; Python immutable strings are not
claimed to support secure memory erasure.

Even `MasterTokenDiagnosticCompleteHold` means only this narrow diagnostic
completed after confirmed cleanup. `semantic_reviewed=false`,
`switch_ready=false`, `purge_performed=false`, `browser_used=false`,
`identity_api_used=false`, and `ad_changed=false` remain literal result fields.
The new login necessarily changes the disposable candidate's persistent session
history; preserve its after-state and never reuse it as a pristine baseline.

The consumed v9 probe stopped at token construction with a false canonical-SID
witness. A separately collected read-only aggregate of its stopped database
found 18 master-bootstrap sessions with 24-character URL-safe IDs and zero UUID
IDs; this does not establish the former token's exact SID binding. The v10
source accepts only an exact lowercase canonical legacy UUID or exactly 24
Base64URL characters that decode to 18 bytes and reproduce the identical string
on encoding. The `sid` claim must still exist and be a string. No normalization
occurs, and exact SID-to-database count-one matching remains mandatory. See the
[pinned source analysis](keycloak-recovery-purge-diagnostics.md#session-id-contract-correction)
for the upstream generation chain. No scope, lightweight-token, issuer, TTL,
signature-proof, session/cutoff, revocation or process/socket rule changes.

Before native use: independently review/freeze this exact module, tests, backend,
helper and two root-input schemas; review fresh preparation and its forensic
seals; then separately authorize one installation/invocation of the explicit
candidate. No native action is authorized by this document. A future invocation
uses an isolated system Python (`python3 -I`) at the exact reviewed path with
`--run-once --candidate <the-explicit-reviewed-name>`; there is no automatic
candidate selection, fallback namespace or source pin override.

Synthetic validation: `python -m pytest tests/deploy/test_keycloak_master_token_diagnostic.py -q`.
The tests exercise failure/cancellation cleanup, one-shot HTTP scope, strict TTL
and inventory guards, fixed output shapes, nested preservation provenance and
full-101 old-database drift rejection. They do not establish native compatibility
or the Run7 cause. Keycloak 26.8.1's normal response-close commit behavior remains
the [pinned upstream baseline](https://github.com/keycloak/keycloak/blob/26.8.1/quarkus/runtime/src/main/java/org/keycloak/quarkus/runtime/integration/jaxrs/CloseSessionFilter.java);
no asynchronous SID-commit race is presumed.
