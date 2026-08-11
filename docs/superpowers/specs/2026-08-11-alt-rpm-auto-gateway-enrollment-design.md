# ALT RPM Automatic Gateway Enrollment Design

## Goal

Installing `endpoint-agent` RPM on ALT Linux must activate a usable Endpoint
Gateway agent automatically, without embedding a reusable gateway secret in
the RPM and without involving the separate Helpdesk approval flow.

## Decision

The deployment system obtains a distinct Endpoint install claim for each
machine and writes it as a root-owned, regular file at a fixed staging path
before invoking `rpm -Uvh`.  The claim is short-lived, one-time, and is
validated by the existing Endpoint enrollment service against its target
platform, allowed source networks, installation identifier, and hardware
fingerprint.

The RPM transaction consumes only this fixed staging file.  Its post-install
script invokes the already-audited `install-endpoint-agent.sh` provisioner,
which verifies the bundled release, atomically populates the immutable
`/opt/endpoint-agent` layout, installs the systemd units, and starts the
agent.  The service exchanges the claim for the root-owned permanent device
credential, then connects only to `https://endpoint.sosnadmin.local` using the
installed CA.

## Boundaries

- Helpdesk provisioning and its confirmation flow remain unchanged.  The ALT
  systemd unit uses only the Endpoint Gateway runtime.
- The RPM contains neither a Gateway bearer credential nor a reusable
  campaign secret.
- The staging claim is accepted only when it is a regular root-owned file with
  mode `0600` at the fixed path.  A missing or invalid claim makes the RPM
  transaction fail before enabling the service.
- The public Gateway CA is packaged as deployment input, or supplied at a
  fixed root-owned staging path with the same ownership and mode checks.  The
  provisioner continues to require HTTPS and rejects a CA mismatch.
- RPM upgrade must not overwrite an already-provisioned `/opt/endpoint-agent`
  release, permanent credential, or current selector.  Gateway-directed
  updates remain responsible for immutable release activation, verification,
  rollback, and post-restart handshake evidence.

## Installation Flow

1. The deployment controller issues a one-time claim for the target host and
   writes the claim and trusted Endpoint CA to fixed root-only staging paths.
2. `rpm -Uvh endpoint-agent-<version>.rpm` installs the package payload and
   invokes the provisioner with the fixed Endpoint URL, installation ID,
   staged CA, staged claim, and embedded release bundle.
3. The provisioner validates all inputs, verifies the manifest/hash/mode of
   the embedded bundle, writes the immutable layout atomically, and enables
   `endpoint-agent.service` and the update path unit.
4. On first start, systemd passes the configuration, CA, and claim as
   credentials.  The agent exchanges the claim for a durable device
   credential bound to the local hardware fingerprint.
5. The root finalizer removes the consumed claim, switches the service to its
   Gateway-ready form, and restarts it.  The agent then maintains its
   HTTPS-only Gateway connection with bounded reconnect behaviour.

## Failure Handling

- A missing, insecure, malformed, expired, reused, or fingerprint-mismatched
  claim aborts installation; no active service is left behind.
- A provisioner or initial service failure rolls back the newly selected
  release and reports a non-zero RPM transaction result.
- The claim is removed only after the durable credential and signed
  claim-removal request are verified.  A restart before that point retains the
  claim for retry.
- A later RPM upgrade preserves provisioned state.  Failed remote updates are
  handled by the existing root-owned update worker and retain the prior
  verified release.

## Verification

Automated tests must cover RPM staging-path validation, generated scriptlet
arguments, service activation ordering, upgrade preservation, and refusal of
missing or insecure claim/CA files.  An ALT test-host scenario must install a
package with a generated claim, observe a successful Gateway enrollment and
handshake, then verify that the permanent credential exists while the
one-time claim no longer does.  A separately authorized canary must verify a
Gateway-directed update and post-restart handshake before any wider rollout.
