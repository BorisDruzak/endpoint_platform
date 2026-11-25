# Automatic support authorization after installation

Implemented and deployed provider `783cc21589e80115d395c4be8b89e710687804e6`
(`feat(support): authorize bounded access after installation`). Live verification
completed on 2026-11-06 at 19:15 UTC / 2026-11-07 at 00:15 Asia/Yekaterinburg.
The user explicitly selected automatic authorization after installation.

## Result and operational use

Production installation defaults now authorize a new/pristine installation once,
after an independently authenticated, fresh installed Support 1.0.1 report without
a component error. The existing approved Ed25519 operator public key and existing
`SOSNADM\admin-2` principal receive an initial eight-hour lease. The installer
intent is disabled and expires after fifteen minutes; registration does not assert
runtime capability. No account or password is created. Repeated registration or
status cannot extend or rearm a consumed/expired/manual policy.

Existing per-device choices take precedence, including `test_agent_win` on 120.
No existing policy was mass-enabled or renewed. After expiry, an operator can
enable another bounded lease in Endpoint -> Devices -> exact Device UUID ->
**Доступ поддержки**, even when Core/updater are stopped. Use the authenticated
card's UUID/port/public host key with
`tools/support/Connect-EndpointSupport.ps1`. Gateway and device host pins are
strict; changed pins are preserved and rejected. The helper uses the operator's
existing gateway SSH alias, not the device's outbound tunnel identity.

`AGENTS.md` now directs an agent to use this channel when ordinary diagnostics
cannot complete authorized agent/updater work, without requesting redundant
permission for the diagnostic connection. Native recovery ownership, private
identities, keys and failed-attempt history remain protected. The complete
procedure is in `docs/runbooks/INDEPENDENT_SUPPORT_ACCESS.md`.

## Verification

Verifier: `C:/Users/admin-2/Documents/endpoint/.venv-device-binding/Scripts/python.exe`,
running this worktree's source. No code was changed in that older checkout.

| Check | Result |
| --- | --- |
| `-m pytest -q --tb=short` on final frozen source | 6668 passed, 465 skipped, 7 warnings, 824.83 seconds, exit 0 |
| New PostgreSQL routes/races + existing Support PostgreSQL + installation unit tests | 52 passed, 2 warnings, 214.35 seconds, exit 0 |
| Support/config/contracts/migration head and deploy checks, plus Windows connection helper | 127 passed, 2 skipped, 149 deselected, 4.52 seconds, exit 0 |
| Independent final source/helper review | No remaining P1/P2; 49 focused tests passed |
| Independent activation-script review | Rollback metadata, retained error trap, fresh exporter snapshot and individual service gates checked |
| `git diff --check` | Passed before implementation commit |

PostgreSQL used only disposable loopback port 55446 through local 15446. Real
authenticated routes proved disabled registration, fixed intent deadline,
independent Support authentication, one grant/expiry under concurrent requests,
manual disable/revoke/reset/unregister precedence, source revocation removing
effective policy/authentication/broker authority, exact audit actor/revision and
additive migration roundtrip preserving existing rows. Initial red tests exposed
missing behavior and the cancellation audit attribution defect; both were fixed
before these final results. An earlier interrupted project run is not acceptance.

The full suite had no external PostgreSQL URL or optional pinned OpenSSH ZIP;
environment-dependent cases were skipped. The separate PostgreSQL run exercised
the new actual routes and locking. Windows 176 artifact qualification remains its
previous, separately recorded result, not a claim about these skipped checks.

## Exact deployment and preservation

New root-owned release:
`/opt/endpoint-platform/releases/endpoint-platform-783cc21589e8`.
The committed-source archive was 2539520 bytes, SHA256
`50e1be5e9a6a495939bb37352adeeb8ae68b5bbca0d836af26bba8172624c2aa`.
Its unchanged Console bundle SHA256 was
`dfb1356fbe05a1c764825cd899c3d9d7a9ad1c613b5ef89be45d7c7ceb3d0a7f`.
Requirements are byte-identical to retained ce46; that release's venv remains an
explicit dependency. Actual production SQLAlchemy 2.1.6 / Alembic 1.20.1 accepted
the candidate configuration before activation.

Pre-stage capacity was 1863667712 bytes against a conservative 790986686-byte
gate. Fresh root0700 backup directory
`/var/backups/endpoint-platform/support-install-20261106-783cc21589e8`
contains original environment/release markers and root0600 `endpoint_platform.dump`:
47204117 bytes, SHA256
`3d5f2def156b9057a65ecb97ec4bbb4796d78ecefaf6c1f914527f8ea6c31dd9`.
`pg_restore --list` passed; no secret values were printed.

Candidate validation caught an operational template substitution that altered the
username variable name; it was corrected and validated before live mutation.
A local helper-import guard also rejected an expired old task receipt before any
deployment request; activation then used the fresh R10 receipt. Neither rejection
changed the running provider, policies or database.

Immediately before activation, authenticated fleet policy 10 was enabled with
all-active dynamic scope, max_parallel 2 and active_chains 0. Additive migration
`0047_support_install_access` introduced one nullable column with no backfill;
all six existing markers remained NULL. The provider/config symlink switch
restarted API/worker and then the exporter with `RuntimeDirectoryPreserve=restart`.
Three readiness requests briefly returned 502, then trusted DNS/CA HTTPS health
returned 200/database ok. Activation to a newly generated exporter snapshot took
six seconds. A rollback restoring source/config/release markers was prepared but
not invoked; the additive column would be retained for compatibility.

Gateway PID 24963 was unchanged. Administrator SSH config SHA256 remained
`64325541513d33ea1d2ccd19c77750d458e67e7967fd2e7ef81d92f0aa2ffe21`;
dedicated gateway config remained
`4de83df4b89af498bd680d7f7c33901777c604c0106c42836922c108cb8ecaec`.
All five valid leases remained in a post-restart fresh export. Each API, worker,
exporter, gateway and broker timer was individually checked active. Actual process
cwd/environment for API PID87455, worker PID87447 and exporter PID87576 bound the
new release and enabled eight-hour defaults. No zero-interruption claim is made.

Before/after comparison preserved the complete six Support rows apart from
ordinary runtime status fields and the additive NULL marker: policy revision,
enabled state, expiry, existing principal/operator keys, source identity, host and
tunnel keys, generation, port and operator attestation were unchanged. All six
reported fresh installed 1.0.1 without error; five enabled policies retained their
tunnels and the unconfigured VM remained disabled. Installation-access audit count
stayed zero: deployment and existing heartbeats did not grant new authority.
Unauthenticated policy remained HTTP401. Final free capacity was1812836352 bytes.

Strict SSH actually succeeded before and after deployment on 192.168.101.120.
At19:15:05UTC the new helper proved hostname `DESKTOP-9ST5HO2`, existing local
administrator SID ending1001, Support Auto/Running PID6672 and exact immutable
1.0.1 binary SHA256
`224cbee71d3bc5f1151cc21491f36e7ba09eb87dfef9a10b082569243a61667e`.
Core was Running and Updater Manual/Stopped; neither was changed in this follow-up.
The prior 176 stopped-Core/stopped-updater SSH proof remains in the independent
support receipt. A newly installed physical Windows device was not fabricated or
tested here; first-install authorization is route/PostgreSQL evidence, while live
production evidence establishes deployed defaults and existing-device preservation.

Windows 3.2.176 media/source binding, Linux 3.2.156, AUTO campaign11 and fleet10
remain unchanged. The actual server EXE still has178184640 bytes/SHA256
`e0e3289fbdda59a368d01931518a38c6e1003a0be74002cf9e7313491101f6f8`.
AUTO preserved192.168.101.0/24, quota100/used6 and2030-09-27 expiry.
This is a server-only feature deployment; no177 build or native replay occurred.

## Cleanup and architectural limits

Only disposable PostgreSQL PID85004/port55446 was stopped after exact data path,
loopback and zero-client checks; its files were retained and production5432 stayed
active. The owned local15446 forward was closed. Only task session R10
`54283932-d10d-4f76-9168-c54391f23841` was revoked and audited at19:15:56UTC;
its verified root0600 private JSON was removed and local cookie/CSRF redacted.
Existing support leases and other administrator sessions were not revoked.

GitNexus was unavailable in the session catalog; source, current diff, runtime
wire and tests supplied the architectural verification. No manual indexing/group
synchronization or cross-repository contract change was made. Context7 SQLAlchemy
2.1 documentation was consulted for independent AsyncSession transactions and the
nullable migration. Source revocation retains existing effective-policy and bounded
broker semantics; this feature does not promise instantaneous SSH termination.

## Git record

Implementation commit: `783cc21589e80115d395c4be8b89e710687804e6`,
`feat(support): authorize bounded access after installation`.
Its exact sixteen files are:

- `AGENTS.md`
- `deploy/server/endpoint-platform.env.example`
- `docs/runbooks/INDEPENDENT_SUPPORT_ACCESS.md`
- `docs/superpowers/plans/2026-11-06-support-install-auto-access.md`
- `docs/superpowers/specs/2026-11-06-support-install-auto-access.md`
- `endpoint_server/config.py`
- `endpoint_server/db/migrations/versions/0047_support_install_access.py`
- `endpoint_server/support_access/installation.py`
- `endpoint_server/support_access/models.py`
- `endpoint_server/support_access/routes.py`
- `endpoint_server/support_access/service.py`
- `tests/server/test_migrations.py`
- `tests/server/test_support_install_access.py`
- `tests/server/test_support_install_access_postgresql.py`
- `tests/tools/test_support_connection_script.py`
- `tools/support/Connect-EndpointSupport.ps1`

The separate deployment documentation commit contains only this receipt,
`docs/releases/current-agent-release.json` and the completed implementation plan.
The current release record preserves the previous provider metadata and Windows/
Linux source/media qualification; new provider verification is recorded separately.
