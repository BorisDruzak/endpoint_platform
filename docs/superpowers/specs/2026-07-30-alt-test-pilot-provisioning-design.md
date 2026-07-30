# ALT Test-Pilot Provisioning Design

## Purpose

Enable one controlled installation of the Endpoint agent on `test-agent-lin`
without modifying `web_ovpn`. The pilot must obtain a one-time, hardware-bound
claim through Endpoint Platform and must never expose a permanent device
credential to an operator tool, logs, Git, an image, or configuration.

## Scope

- Add the missing first-boot enrollment invocation to the Linux agent runtime.
- Add a narrowly scoped operator controller for the dedicated test host.
- Build, verify, install, enroll, restart, and finalize one ALT test pilot.
- Keep `web_ovpn`, network configuration, and production agent rollout out of
  scope.

## Agent Runtime

The Linux launcher/runtime performs enrollment before normal agent work. It
loads only the three systemd credential paths already supplied by
`endpoint-agent.service`: configuration, CA PEM, and
`endpoint-enrollment-claim`.

If `/var/lib/endpoint-agent/device-credential` is present and passes the
existing regular-file, owner, and `0600` checks, startup does not request or
consume a claim. Otherwise the runtime calls `bootstrap_enrollment()` with the
fixed credential directory and normal hardware probe. Temporary Gateway
failures retain the source claim for the bounded retry policy. Terminal,
expired, replayed, or fingerprint-mismatched claims fail closed without a
partial permanent credential. On success the existing root-finalizer request
is written; only the installer finalizer may remove the root-owned claim.

## Pilot Controller

The controller is an Endpoint Platform operator command restricted to the
dedicated `test-agent-lin` pilot. It is not a general provisioning UI and does
not alter `web_ovpn`.

It derives the normalized hardware fingerprint from the test host using the
same committed agent logic, creates the narrowly scoped provisioning identity
and campaign required for this pilot, and uses that service identity to request
an install claim over `https://endpoint.sosnadmin.local` with normal CA and
hostname verification. It keeps the show-once claim only in process memory and
writes it directly through SSH to the exact root-owned, mode-`0600` handoff
source consumed by the installer. The command never accepts a claim or service
token in an environment variable or command-line argument and never prints
either value.

The controller records only non-secret pilot evidence: installation session,
claim expiry, device ID after enrollment, release digest, and redacted command
status. It refuses a target other than the configured test host, an endpoint
other than the configured HTTPS origin, unsafe remote paths, or a nonmatching
fingerprint.

## Pilot Sequence

1. Run local tests and verify a clean test host.
2. Build a transient, manifest-attested Linux bundle.
3. Run the operator controller to stage the root-only claim source.
4. Execute installer dry-run, then the verified install.
5. Verify enrollment, durable credential ownership/mode, and the fixed
   claim-removal request without printing secret contents.
6. Run the installer finalizer, restart the service, and prove stable identity
   plus bounded baseline/Gateway health evidence.
7. Record token-redacted acceptance evidence only after all checks pass.

## Safety and Verification

- TLS remains mandatory; no IP endpoint, insecure mode, or verification bypass
  is permitted.
- The claim is one-time, short-lived, session-bound, and fingerprint-bound.
- The service identity has only `provisioning.install-claims.issue`; it is not
  an administrator credential.
- Tests cover startup success/restart, retry and terminal failures, no secret
  logging, controller target/path restrictions, and claim delivery.
- The live pilot is limited to `test-agent-lin`; production hosts remain
  untouched.
