# ALT Agent First-Boot Enrollment Bootstrap

This runbook describes the reviewed first-boot claim exchange only. It does
not authorize an installation, a service restart, a test-agent change, or a
production deployment.

## Boundary

`pc_agent.enrollment_bootstrap.bootstrap_enrollment()` is inert until a Linux
service integration explicitly calls it. The function receives a systemd
credentials directory, non-secret configuration and a hardware probe. It never
accepts a campaign bearer, administrator token, environment claim, command-line
secret, or legacy agent credential as an enrollment fallback.

The only systemd credential name is `endpoint-enrollment-claim`, supplied as
`LoadCredential=endpoint-enrollment-claim:<root-owned-source>`. The bootstrap
never derives a credential pathname from an environment variable, and its
permanent credential and root-finalizer request locations are fixed at
`/var/lib/endpoint-agent/device-credential`,
`/var/lib/endpoint-agent/enrollment-identity.json`, and
`/var/lib/endpoint-agent/claim-removal-request.json`.

## Preconditions for a future service integration

- Gateway URL is a literal `https://` origin and a readable local CA PEM file
  is configured; there is no IP/TLS-bypass or disabled verification mode.
- The provisioning claim is one-time and bound to the exact installation
  session and normalized `sha256:` hardware fingerprint that the agent will
  derive.
- The service runs as `endpoint-agent`; its durable credential path is
  `/var/lib/endpoint-agent/device-credential`, owned by that service user and
  group with mode `0600`.
- The authoritative server Device UUID is stored separately at
  `/var/lib/endpoint-agent/enrollment-identity.json` with the same owner and
  mode. Its `device_id` must be a canonical lowercase RFC 4122 UUID version
  1–5, matching the installer finalizer grammar; nil and later UUID versions
  fail closed. Legacy `identity.json.machine_id` is not an enrollment identity.
- The root-owned provisioning source remains outside the service user's write
  access. Systemd exposes only a transient credential copy to the process.

## First-boot outcome

The bootstrap derives the fingerprint through `endpoint_contracts`, calls
`POST /agent/v1/enroll` with the one-time claim, and retries only temporary
Gateway/transport errors, with a maximum of three attempts. Claims rejected as
expired, replayed or mismatched are terminal and leave no partial permanent
credential.

After a successful delivery, the permanent device credential and canonical
server-returned Device UUID record are atomically written, fsynced, and
rechecked for content, regular-file type, service ownership and mode. Only
then does the agent write the fixed-schema,
mode-`0600`, non-secret claim-removal request. It contains the fixed claim
name/path, returned device UUID and SHA-256 proof of the verified permanent
credential; it contains neither the install claim nor the device bearer.

The agent cannot delete the root-owned source. The installer finalizer reads
only that fixed request, requires the protected enrollment identity to match
its device UUID, rejects unsafe/symlink path components or mismatched schema,
claim name, credential path or credential proof, and then removes only the
exact installed claim source and request. The enrollment identity remains.
Re-running after both claim files were removed is idempotent. If this handoff
request cannot be written, the durable identity remains valid and the claim is
not removed automatically.

## Verification before a live pilot

Run locally first:

```powershell
python -m pytest pc_agent/tests/test_enrollment_bootstrap.py -q
python -m pytest tests/server/test_provisioning_claim_api.py -q
```

Before any permitted ALT test-host installation, verify a diff and generated
artifacts contain no real claim, device credential, `Authorization: Bearer`
value, CA private material, or TLS-verification bypass. A live test must use
only the dedicated test agent and record token-redacted service evidence.
