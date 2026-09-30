# Device possession proof for Helpdesk

Account registration is independent of device binding. Endpoint Agent enrollment
is independent of Helpdesk user registration. Endpoint proves possession of a
device; Helpdesk Registry establishes and owns the Person↔Device relationship.
Endpoint never receives the Helpdesk person identity. This flow does not restore
legacy Helpdesk Agent pairing or account sessions.

## API and persistence

`POST /api/v1/device-binding/challenges` authenticates the existing device bearer
and agent source policy. Its only input is `purpose=helpdesk_device_binding`.
The authenticated server principal determines the device. The response is an
ephemeral six-digit code, NNN-NNN display, challenge UUID and UTC expiry (600s).
Responses use `Cache-Control: no-store`; never log their bodies.

`POST /api/v1/device-binding/challenges/redeem` accepts purpose and six ASCII
digits through a scoped service credential (`device-binding.redeem`). It returns
only verified device UUID, nullable hostname and windows/linux/unknown platform.
Hostname/platform come from validated canonical current inventory/baseline, not
from campaign labels or caller-supplied metadata. No device credentials or raw
inventory cross this boundary. Redeeming a proof does not grant user access or
authorize ownership transfer; Helpdesk performs its own requester, Registry and
conflict checks. Helpdesk must use strict HTTPS and pin this provider contract.

Migration `0036_device_binding` follows `0035_policy_sensor_health`. Challenge
rows contain only a domain-separated HMAC-SHA256 digest using the existing
device token pepper, device UUID, purpose, timestamps and active/redeemed/
expired/revoked status. Partial unique indexes enforce one active proof per
device/purpose and one active code digest. Device row locks serialize replacement;
conditional UPDATE RETURNING consumes exactly one live, unretired-device proof.
Recent redeemed/revoked codes cannot be reissued before their original expiry.
The bounded shared namespace lock prevents creation/redemption reuse races.
Existing server pepper files remain deployment inputs; changing the pepper
invalidates outstanding proofs.

Attempt budgets live in `device_binding_throttles` and use transactional row
locks and collision-safe bucket insertion. Creation allows three requests per
device per 600s. Redemption permits thirty attempts per service client and
globally per 60s; a separate budget blocks after 60 failed attempts per client
per 600s. Successful bindings do not consume the failed-attempt budget. Token
rotation does not reset the client budgets.
This service-level budget is a secondary circuit breaker. Helpdesk applies its
existing local limiter to each authenticated actor + trusted client IP pair
(5 attempts / 600s) before redeem. Endpoint receives no requester identity or IP.
An additional shared namespace budget permits 120 operations per 60s. Fixed
window expiry resets the counters; restarting the service does not. Failed
redemptions commit their budgets. Invalid, expired, revoked and replayed codes
share the same bounded rejection; throttling uses 429/Retry-After. Never enable
request-body logging for this route. Audit records IDs/purpose/lifecycle only.

## Windows tray boundary

The existing tray menu opens «Привязать компьютер к Helpdesk», a modal dialog in
the same executable. It provides copy, refresh and browser opening. Codes stay
in memory; new issuance revokes the previous proof. The browser link uses
`/app/requester/devices/link#code=NNNNNN`; Helpdesk must capture and remove the
fragment immediately and retain manual entry when navigation fails.
The tray defaults to the canonical Helpdesk HTTPS origin. Staging acceptance
starts the same executable with `--helpdesk-origin https://helpdesk-staging.sosnadmin.local`.
Only these two approved HTTPS origins are accepted; credentials, extra paths,
arbitrary domains and HTTP are rejected. This avoids altering workstation DNS.
The native tray uses pointer-sized Win32 window/module signatures and the
portable `wintypes.HANDLE` cursor field, since packaged Python 3.12 does not
provide `wintypes.HCURSOR`. A Windows-only subprocess smoke creates the real
notification icon and exits through the window message loop; model-only tests
are insufficient to establish tray startup.

Tray never opens the protected device credential or directly calls Endpoint.
`EndpointPlatform.Agent.DeviceBinding.v1` reuses the service-owned named pipe,
DACL, remote-client rejection, first-instance protection, server service-SID
check, and active-interactive-session client authorization. IPC accepts only
the fixed create action. The Windows runtime uses the service-owned
pipe DACL with `FILE_READ_ATTRIBUTES`, which Windows implicitly requires on
client open. Before publishing the listener, the service grants interactive
clients only `PROCESS_QUERY_LIMITED_INFORMATION` and `TOKEN_QUERY` on its own
process/token so the existing LocalService and service-SID checks can run.
It grants no process-memory, token-duplication, mutation or pipe-creation rights.
The connected Windows runtime uses the existing
device adapter/CA-verified HTTPS session, rejects redirects, bounds the reply
to 2048 bytes and returns only a challenge or a fixed unavailable error.
IPC and network operations time out, and the listener stops on disconnect/exit.
The tray spec packages the modal dialog and existing PyWin32 IPC helpers.
This adds no Gateway command, remote execution or diagnostic capability.

## Acceptance boundaries

Unit/ASGI/SQLite tests cover lifecycle, contracts, authenticated device/service
routes, budgets, redaction, IPC authorization and adapter parsing. Real
PostgreSQL tests in `tests/server/test_migrations.py` cover simultaneous
creation/redemption using isolated migration databases configured by
`ENDPOINT_TEST_POSTGRES_URL`; skipped cases do not prove concurrency.
Windows package and staging tray acceptance must identify exact source/version
and restore test state. ALT Linux Agent binding acceptance is intentionally
excluded from First Wave. No production deployment is authorized by this plan.
