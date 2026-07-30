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

The primary systemd credential name is `endpoint-enrollment-claim`, supplied
as `LoadCredential=endpoint-enrollment-claim:<root-owned-source>`. During the
Task 15 package transition, the existing
`endpoint-agent-provisioning-handoff` name can be selected only through the
non-secret `BootstrapConfig.claim_credential_name` integration setting. The
bootstrap never derives a credential pathname from an environment variable.

## Preconditions for a future service integration

- Gateway URL is a literal `https://` origin and a readable local CA PEM file
  is configured; there is no IP/TLS-bypass or disabled verification mode.
- The provisioning claim is one-time and bound to the exact installation
  session and normalized `sha256:` hardware fingerprint that the agent will
  derive.
- The service runs as `endpoint-agent`; its durable credential path is
  `/var/lib/endpoint-agent/device-credential`, owned by that service user and
  group with mode `0600`.
- The root-owned provisioning source remains outside the service user's write
  access. Systemd exposes only a transient credential copy to the process.

## First-boot outcome

The bootstrap derives the fingerprint through `endpoint_contracts`, calls
`POST /agent/v1/enroll` with the one-time claim, and retries only temporary
Gateway/transport errors, with a maximum of three attempts. Claims rejected as
expired, replayed or mismatched are terminal and leave no partial permanent
credential.

After a successful delivery, the permanent device credential is atomically
written, fsynced, and rechecked for content, regular-file type, service
ownership and mode. Only then does the agent write a mode-`0600`, non-secret
claim-removal request containing the credential name, device ID and durable
credential path. It contains neither the install claim nor the device bearer.

The agent cannot delete the root-owned source. A privileged controller must
independently verify the durable credential and then perform its narrowly
reviewed claim-source removal action (Task 15's finalizer). If this handoff
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
