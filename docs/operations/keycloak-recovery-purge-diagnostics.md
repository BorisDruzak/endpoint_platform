# Private recovery purge diagnostics: source-only review

The stopped Run7 candidate is modified forensic state, not a pristine recovery
baseline. Its accepted initial/SSO browser callbacks do not establish a completed
session purge, revocation proof, semantic acceptance or promotion readiness.
The failure preceded `session-provenance-before.json`; its old
`UnclassifiedRefusal` cannot identify which earlier guard failed. Preserve that
failed evidence and every pristine/consumed-attempt marker unchanged.

## Confirmed diagnostic defects and bounded correction

`RecoveryRefused` inherits `ValueError`. The former token-constructor catch
therefore replaced its own IAT/provenance/SID guard failures with
`CandidateTokenMalformed`; the HTTP response-bound guard was similarly replaced
with `CandidateRequestFailed`. Explicit re-raising now preserves those guards.
The closed diagnostic allowlist includes fixed purge/token/session refusals.
HTTP exceptions classify only exact integer status codes 100 through 599; any
other status becomes `CandidateHTTPUnclassified`. URLs, bodies, headers, arbitrary
exceptions and unknown refusal strings remain excluded from failure receipts.

The purge's pre-constructor `purge-token-shape.json` is written by the existing
exclusive root-private receipt writer. It contains only fixed booleans describing
bounded compact shape, JSON-object shape, positive integer IAT, EXP-after-IAT,
expected issuer/client matches, canonical SID shape and the existing 45-second
lifetime threshold. `signature_verified=false` is explicit: decoded claims are
untrusted diagnostic input. No claim value, token, SID, timestamp, payload,
identifier or fingerprint is included. A receipt-write failure stops execution.

The failure context additionally records a closed fixed `purge_subphase`, covering
permission, fresh login, shape receipt, constructor, lifetime, realm API,
inventory, provenance, purge APIs and revocation proof. This preserves the last
boundary reached without reconstructing it from missing files. It changes no
authorization, issuer, SID, lifetime, session, causal or revocation requirement;
no additional retry, login, API request, SQL query or delay was added.

## Exact Keycloak 26.8.1 behavior

Context7 was consulted for `/keycloak/keycloak/26.8.1`; important implementation
conclusions were checked against these public pinned sources:

- [Direct-access grant](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/protocol/oidc/grants/ResourceOwnerPasswordCredentialsGrantType.java#L130-L150)
  attaches the user/client session before building access/refresh tokens.
- [TokenManager.initToken](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/protocol/oidc/TokenManager.java#L1001-L1027)
  sets the authorized party from the client ID, the issuer from the client-session
  issuer note, and SID from the user-session ID. Presence of the stock `basic`
  scope alone cannot prove the actual token has the exact private issuer or SID.
- [Persistent user-session creation](https://github.com/keycloak/keycloak/blob/26.8.1/model/jpa/src/main/java/org/keycloak/models/jpa/session/JpaUserSessionPersisterProvider.java#L77-L97)
  stores the session ID and online/offline state in the JPA entity.
- [CloseSessionFilter](https://github.com/keycloak/keycloak/blob/26.8.1/quarkus/runtime/src/main/java/org/keycloak/quarkus/runtime/integration/jaxrs/CloseSessionFilter.java#L31-L73)
  closes a normal response's session before completing the response;
  [DefaultKeycloakSession](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/services/DefaultKeycloakSession.java#L352-L400)
  commits an active transaction unless rollback-only. This does not justify an
  assumed asynchronous SID-commit race or blind sleep/retry workaround.
- [Admin REST direct grant documentation](https://github.com/keycloak/keycloak/blob/26.8.1/docs/documentation/server_development/topics/admin-rest-api.adoc)
  documents the admin-cli master token's default one-minute lifetime. Keep the
  existing 45-second minimum and subsequent strict unexpired revocation proof.

The stopped read-only policy metadata reports a 60-second master TTL, no admin-cli
TTL override, no master frontend URL override, refresh enabled, stock basic scope
attached, two realms, 21 master-bootstrap online sessions and no unknown offline
flags. These counts do not link any session to the particular failed token. The
source `_client()` constructs a fresh client and logs in each time; an old cached
token is not an established explanation. The actual Run7 cause remains unknown.

## Proposed next diagnostic gate; not an executable procedure

First review the exact code/tests and freeze their source closure. No source
installation, namespace change, SQL/API execution, JVM or new attempt is
authorized by this document. Existing modified forensic databases must not be
reused as pristine candidates. If a future native probe is approved, its exact
bounded code and isolated disposable database/runtime must be reviewed separately
with the existing binary/config/PID/socket/database provenance checks intact.

Limit that probe to one fresh master admin-cli login, the boolean-only token
witness, the unchanged session-client constructor/lifetime guards, one authorized
realm-list GET and one read-only inventory tied to that exact in-memory SID.
Stop before notBefore updates, session deletion, logout-all, browser flows, AD
changes, identity lookups or full qualification. Tokens/SIDs stay only in server
memory, never argv, transcripts, emitted SQL, claim dumps or hashes. The inventory
result must be reduced to fixed booleans for exact fresh-session count, supported
flags, two expected realms and cutoff ordering; no session identifiers or values
may be exported. This is a design boundary, not completed probe code.

If the constructor fails, use the fixed code plus shape booleans to isolate the
claim boundary. If the GET fails, use its bounded HTTP class. If inventory fails,
keep the exact DB/session proof HOLD; a separately reviewed bounded observation
may investigate visibility without retrying the login or weakening SID identity.
No passing result would prove purge/revocation, justify another full qualification,
change AD, renew the identity, reuse a failed baseline or authorize promotion.
