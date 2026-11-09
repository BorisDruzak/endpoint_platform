# Production Helpdesk AD entry correction

Verified 2026-11-09T16:59:50Z, after the user reported that the deployed production
login page lacked the AD entry. This corrects the incomplete configuration portion
of the earlier [SSO/Worktime promotion](2026-11-09-worktime-production-parity.md).

## Confirmed cause

The accepted Helpdesk runtime already contained the AD login UI and OIDC BFF.
Production `OIDC_ENABLED` was false and its active environment lacked client ID,
client secret, callback and encryption key. Public session capabilities returned
sso_enabled=false, so the frontend correctly hid the entry. Waiting for identity
bindings before showing the entry was an incorrect activation decision.

The existing protected production preparation had a valid confidential client,
matching actual Keycloak secret, correct fixed callback and valid encryption key.
TLS discovery passed using the configured CA. Production `helpdesk-web` still
required assurance2, while the staging Helpdesk client used password-level1.
There were zero confirmed production identity bindings.

## Applied repair

- Selectively activated the existing production `helpdesk-web` client parameters
  and OIDC_ENABLED=true; no staging secret, new credential or whole environment
  was copied. The AD GUID claim uses its existing canonical name.
- Reused the reviewed strict provider transformation for the explicitly selected
  production Helpdesk client. Only default.acr.values and minimum.acr.value changed
  from level2 to level1, matching the approved password-only Helpdesk behavior.
  Exact full-client readback passed; PKCE S256, client secret, callbacks, empty
  webOrigins and protocol/access restrictions were preserved. All five other
  application clients, including both Endpoint admin MFA policies, were unchanged.
- Validated the candidate with the canonical production configuration validator
  and actual helpdesk Unix user performing TLS metadata discovery before apply.
  Private configuration/provider backups precede mutation; exact fingerprints
  fence concurrent changes. No user/person/binding/session was fabricated.
- Restarted only Helpdesk server/control through
  `scripts/manage_remote_stack.py restart all --remote endpoint-platform-server`.
  Deployed source, web assets and database schema were not changed.

Runtime remains `1dc2be0d358dec13b12c4861d4f43419c70672d8`, schema153.
Active configuration SHA256:
`fafba679a16c5f458d5c9b912bce63e5dbd1211053b105c5879b96a9cff548d0`.
Helpdesk server/control376699/376703 are active with NRestarts0 and exact release
cwd. Loaded process environment confirms OIDC and Worktime handoff enabled.
Endpoint API373261/worker373262, Support gateway24963/exporter334584 and SSH889
remain active, unchanged PIDs and NRestarts0. Services remain running as requested.

## Verification

- `python -m pytest scripts/test_configure_helpdesk_sso_password.py -q`:
  **15 passed**; transformation, scope guards, backup/concurrency/readback checks.
- `python -m pytest server/tests/test_sso_password_only.py -q -m no_db`:
  **14 passed**, two upstream deprecation warnings; password-level behavior still
  requires identity/session authority and rejects revoked upstream sessions.
- `python scripts/verify_workspace.py --workspace <isolated Helpdesk checkout>`:
  passed. The accepted Helpdesk checkout remains clean; exact-SHA full CI
  [42651948275](https://github.com/BorisDruzak/helpdesk/actions/runs/42651948275)
  remains its source qualification. No new runtime release/full CI was necessary
  for this configuration-only correction.
- Verified HTTPS capabilities return sso_enabled=true; API health returns200 using
  the approved public CA. The initial canonical curl smoke failed because its
  default trust store lacks the internal CA. Verification was retained and the
  explicit approved CA was used for the successful HTTPS request; no insecure
  TLS option or system-wide trust change was applied.
- In a separate Playwright browser, actual production `/app/login` displayed
  **Войти через AD**. Clicking it opened the real issuer's username/password form
  with client_id=helpdesk-web, the production callback and S256. No credential was
  entered. Browser console: zero errors/warnings. The temporary browser tab was
  closed; the user's existing Codex helpdesk_admin session/profile tab was retained.
- Screenshot evidence:
  `C:/endpoint-platform-wix-build/worktime-parity-20261109/candidate-1dc2be0d358d/production-ad-login.png`.
  Nonsecret readiness/plan/applied/accepted JSON receipts are in the same directory;
  protected originals/backups remain under the production root-owned capsule
  `/var/lib/endpoint-worktime-parity-20261109`.

Preparation guards initially rejected an absent optional/defaulted setting and a
one-off validation process missing the release-root Python path. Both stopped
before mutation; the final candidate passed canonical and actual-user validation.

## Remaining real-login prerequisite

Confirmed Helpdesk bindings and OIDC sessions are still zero. Therefore a visible
button and correct provider redirect are accepted; successful AD-to-Helpdesk login
and subsequent Worktime employee handoff are **not yet accepted**. An unmapped AD
identity must be denied instead of being attached to a guessed legacy profile.

Use the existing authenticated administrator propose/confirm operations after
independently verifying an existing active RegistryPerson, active UiUser, its
verified UI alias and exact AD GUID/issuer/subject. No automatic email/name match,
invented employee profile, root-forged administrator session or bypass is allowed.
The prior incomplete helpdesk_admin employee profile is not a substitute for this
verification. Real Worktime prompts additionally require genuine bindings/schedules.
