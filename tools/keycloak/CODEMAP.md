# Keycloak operator tools

- `master_token_diagnostic.py`: inert-by-default, one-login private diagnostic
  with a fixed consumed-attempt fence, one realm GET and one SID inventory.
  It reuses the unchanged runtime guards and preserves all three failed
  databases before/after owned cleanup; it cannot purge, repair or promote.
  Its source closure, protected input schema and limits are documented in
  `docs/operations/keycloak-master-token-diagnostic.md`.
- `recover_pilot_identity.py`: plan, exclusive verified full-DB restore, read-only
  identity/101-table evidence and explicit private qualification RPC. It owns
  private process lifecycle/session-revocation proof and ends at unreviewed drift
  HOLD; it has no public promotion command. Stage1 evidence stays immutable;
  each pristine candidate qualification has a separate exclusive attempt journal
  and the source-only v10 work root uses FD-validated exact directory permissions
  under umask077. Failed20856/v7, failed22159/v8 and probe23462/v9 are modified forensic
  databases; immutable Stage1 metadata and all historical namespaces stay retained.
  Run7 passed browser callbacks but failed before session provenance; its exact
  cause remains unknown. Token-shape booleans and closed purge subphases preserve
  diagnostic refusals without changing authorization/session/revocation guards.
  `is_canonical_session_id` is the shared exact legacy-UUID or canonical
  24-character/18-byte Base64URL session contract used by token shape/constructor,
  fresh-session SQL, offline inventory and one-shot DELETE path validation.
  Realm, subject and objectGUID UUID rules remain separate. The consumed v9
  profile and its evidence stay retained; v10 is a source-only fresh profile.
  Startup/proof fixed refusal diagnostics have explicit AST reachability coverage.
  The same strict exact-IP parser handles listener and JDBC mapped-loopback forms;
  accepted proof endpoints retain canonical IPv4 text and all ownership guards.
  TCP/UDP refusal witnesses are bounded and redact addresses/argv/logs. A private
  Narayana process-ID profile requires independent native library qualification;
  canonical configuration and strict socket policy remain unchanged.
- `pilot_acceptance.py`: pinned narrow Admin API retention/MSAD/audience/basic
  operations reused against the verified private process before pilot user APIs.
- `backup.sh`: canonical full `keycloak` database/configuration backup. Recovery
  preserves that canonical name and every forensic backup.
- `install.sh`, `prepare_runtime.py`, `render_realm.py`: separate first-install
  and initial disabled-realm preparation; never rerun as an identity repair.

The operation/evidence/secret/cleanup boundary is documented in
[`docs/operations/keycloak-identity-recovery.md`](../../docs/operations/keycloak-identity-recovery.md).
The general service workflow remains in
[`docs/operations/keycloak-sso.md`](../../docs/operations/keycloak-sso.md).
