# Universal Windows Enrollment Installer Design

## Goal

Ship one signed, secret-free `EndpointAgentSetup.exe` for new Windows machines. The same executable installs the existing Endpoint Agent MSI and completes enrollment automatically when the server-selected Windows campaign is AUTO, or waits for an administrator decision when it is MANUAL. It does not change `web_ovpn` or Helpdesk.

## Non-goals and security boundary

This is an orchestration layer over the existing `ic_` install-claim and `/agent/v1/enroll` flow. It does not add Kerberos, ADFS, IIS authentication termination, a deployment controller, per-PC session files, a device bootstrap credential, campaign bearer, claim, password, or service credential to the installer. Claims remain short-lived, one-time, installation-bound, fingerprint-bound, and campaign-bound; their only local transport is the provisioner's stdin.

AUTO is policy-based admission, not cryptographic machine attestation. The perimeter is trusted TLS, a server-derived source IP, campaign CIDR/platform/release checks, quotas, rate limits, identity-conflict detection, claim binding, and audit. `installer_release_id` is bounded policy/audit evidence, not proof that a request originated in an unmodified signed executable; Authenticode is verified at release and Setup preflight.

## Campaign policy and selection

The source of truth is `EnrollmentCampaign.policy`, normalized by a strict Windows policy model:

```json
{
  "policy_id": "windows-office-v1",
  "enrollment_mode": "auto",
  "allowed_installer_releases": ["1.0.0"]
}
```

Only a Windows campaign with that valid policy participates in universal setup selection. On request creation, the server considers campaigns that are active, unrevoked, unexpired, targeted at `windows`, whose CIDR contains the trusted source address, whose approved release list contains `installer_release_id`, and whose use limit permits an eventual enrollment.

The server makes no implicit tie-break:

- zero candidates: `DENIED`;
- one candidate: persist its `selected_campaign_id` atomically;
- more than one: persist `REVIEW_REQUIRED` with `AMBIGUOUS_CAMPAIGN` and no selected campaign.

The installer never sends a campaign ID. A selected campaign is never recalculated during polling, approval, or claim delivery. Before manual approval and before claim issuance, the server rechecks that exact campaign. Revocation, expiry, quota exhaustion, or policy/release invalidation changes the request to `DENIED` or `EXPIRED`; it never falls through to a different campaign.

## Persisted lifecycle

`EnrollmentRequest` is an auditable entity. It stores a UUID, HMAC digests of installation ID, canonical hardware fingerprint, and request capability; Windows inventory evidence; trusted source address; installer version/release; selected campaign; status; reason; decision metadata; expiry; claim/device links; and timestamps. It never stores plaintext capability or claim.

The statuses are `CREATED`, `VALIDATING`, `AUTO_APPROVED`, `WAITING_APPROVAL`, `REVIEW_REQUIRED`, `DENIED`, `CLAIM_ISSUED`, `ENROLLING`, `DEVICE_REGISTERED`, `WAITING_WSS`, `COMPLETED`, `EXPIRED`, `FAILED`, and `CANCELLED`. A terminal transition is monotonic. `EnrollmentClaim` receives a nullable unique foreign key to its originating request, preserving `request -> selected campaign -> claim -> device` provenance.

The request expires after 24 hours. Claims retain their existing 15-minute maximum. A unique active installation digest and a conflict-aware active fingerprint index prevent parallel or repeated requests from silently creating a second device. Identical retransmission with the same in-memory capability is idempotent; a competing request is review-required or denied by the persisted conflict rule.

## Public request protocol

`POST /api/v1/enrollment/requests` is the only unauthenticated installer endpoint. It accepts bounded Windows evidence and an ephemeral, 256-bit request capability generated in memory by Setup. The server stores only its HMAC. This capability is never written to a file, registry, command line, environment, or log. It protects status polling and the claim handoff from simple request-ID enumeration while remaining neither a campaign token nor a device credential.

`POST /api/v1/enrollment/requests/{request_id}/status` requires that capability and returns a bounded public state. While pending, it discloses only status, reason, expiry, and retry information. When claim issuance is authorized, the controlled handoff returns the raw claim only to the same capability and source-policy context. It uses the existing encrypted retry-envelope primitive so response-delivery ambiguity does not force duplicate claims or disclose a raw claim at rest. Claim text is excluded from telemetry and audit.

The reverse-proxy configuration must derive the source address only from a trusted proxy boundary; an arbitrary `X-Forwarded-For` must never satisfy a campaign CIDR.

## Decision and conflict policy

MANUAL sends every valid single-campaign request to `WAITING_APPROVAL`. AUTO sends a valid request to `AUTO_APPROVED` only after no blocking identity condition exists. Duplicate active devices for the fingerprint, an active request on conflicting installation/fingerprint evidence, a corrupt/unknown enrollment ownership state, revoked release, and ambiguous campaign selection become `REVIEW_REQUIRED` with a bounded reason. A denied identical identity cannot bypass a decision merely by retransmission; a new installation ID is treated as a new request but is still subject to duplicate-fingerprint policy.

Admin approval is CSRF-protected and requires an administrator. It may transition only `WAITING_APPROVAL` and `REVIEW_REQUIRED` requests. Rejection transitions to `DENIED`. Both actions write actor, timestamp, selected campaign, and decision reason. The UI never creates a device credential or exposes an install claim.

Required audit actions are `enrollment_request.created`, `enrollment_request.auto_approved`, `enrollment_request.waiting_approval`, `enrollment_request.review_required`, `enrollment_request.manually_approved`, `enrollment_request.denied`, `enrollment_claim.issued`, `device_enrolled`, and `installer_wss_verified`. AUTO evidence records policy ID, mode, platform, source-network match, selected campaign, release match, and `identity_conflict=false`, never secrets.

## Admin API and UI

Campaign create/update contracts validate the Windows policy model; non-Windows campaigns do not gain universal-setup eligibility. Enrollment Admin exposes campaign configuration (mode, allowed releases, CIDRs, expiry and use limits), a read-only campaign summary, and a pending/review queue showing hostname, platform, manufacturer/model, serial, MACs, source IP, installer version, created time, status, and reason. Approve/deny are POST forms/endpoints protected by existing administrator and CSRF mechanisms.

The optional global “Windows enrollment” summary is a projection of selected campaigns, never a global enrollment-mode setting.

## Installer orchestration

`EndpointAgentSetup.exe` is a bootstrapper built from the current Windows packaging pipeline. It installs the existing MSI; it does not become a second agent installer. The MSI retains current protected paths, ACLs, service registration, CA/config, and `endpoint-agent-provision.exe`.

Before creating a request, Setup classifies local state:

- `VALID`: credential and enrollment identity are valid; return `10 ALREADY_INSTALLED` and retain Device UUID.
- `REPAIRABLE`: valid identity/credential with missing service; repair/start the existing service without enrollment.
- `CONFLICTED`: identity exists with missing/corrupt credential or unknown ownership; return `60 REPAIR_REQUIRED` and change no identity.
- `CLEAN`: install MSI, collect `collect_device_fingerprint()`, request enrollment, and continue.

The Setup process keeps installation ID, request capability, and raw claim only in memory. It polls every five seconds for at most 30 minutes. A delayed approval after timeout remains server-side until request TTL; a later rerun starts a clean request and cannot reuse an unpersisted capability. `/quiet` has identical flow and stable exit codes.

On claim receipt, Setup writes it directly to the stdin pipe of `endpoint-agent-provision.exe`. It never places it in argv, environment, registry, a persistent temporary file, or the log. The existing provisioner alone calls `/agent/v1/enroll` and writes the permanent credential/identity.

After provisioning, Setup starts `EndpointAgent` and waits boundedly for the server to observe a fresh WSS presence for the returned Device UUID and for `baseline_v1` (with `inventory_v1` when available). Only then does it set the request `COMPLETED` and audit `installer_wss_verified`.

## Exit and logging contract

Stable process exit codes are: `0 SUCCESS`, `10 ALREADY_INSTALLED`, `20 PREFLIGHT_FAILED`, `21 INSTALL_FAILED`, `30 ENROLLMENT_DENIED`, `31 APPROVAL_TIMEOUT`, `32 REVIEW_REQUIRED`, `33 REQUEST_EXPIRED`, `40 CLAIM_FAILED`, `41 PROVISIONING_FAILED`, `50 SERVICE_FAILED`, `51 WSS_TIMEOUT`, `52 CONTEXT_TIMEOUT`, and `60 REPAIR_REQUIRED`.

`%ProgramData%\\EndpointAgent\\install.log` contains timestamp, phase, bounded result code, installer/agent version, and Device UUID only after enrollment. Its redaction policy rejects claims, device tokens, bearer values, request capabilities, raw authorization headers, and secret responses.

## Release artifact

The release pipeline builds exactly one `EndpointAgentSetup.exe` that embeds or launches the matching, existing signed MSI. It produces detached release metadata: setup version, source commit, filename, SHA-256, Authenticode status/publisher, and embedded agent version. Signing is optional only when a signing certificate is unavailable, in which case metadata explicitly reports `unsigned`; release promotion requires a valid configured publisher. Static scans fail on known bearer/claim/device-token markers in artifact payloads and MSI properties.

## Verification and acceptance

Unit and integration coverage includes campaign selection, AUTO/MANUAL/deny/review transitions, campaign invalidation after selection, limits and concurrent request conflicts, HMAC capability checks, request expiry, rate limit, claim binding/replay/expiry, audit redaction, UI CSRF/admin enforcement, installer state classification, stdin-only claim transport, secret scan, and release metadata.

Disposable Windows VM acceptance runs the same artifact in AUTO, MANUAL, DENY, reboot, rerun, and five-VM `/quiet` scenarios. Completion requires distinct installation IDs, claims, Device UUIDs and credentials, fresh WSS presence, baseline context, and no manual approval in AUTO. No fleet rollout is authorized by this design.

## Production prerequisites

Before a production release: a trusted Windows VM snapshot, endpoint CA/DNS reachability, a configured signing certificate and permitted publisher, trusted-proxy source-address configuration, a migration backup/rollback plan, a dedicated non-overlapping Windows campaign, and verified release/policy values. A production fleet rollout remains out of scope.
