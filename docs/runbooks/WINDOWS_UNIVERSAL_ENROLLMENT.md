# Universal Windows enrollment

## Scope

`EndpointAgentSetup.exe` is the only operator-facing artifact for a new
Windows workstation. It embeds the matching MSI, public Endpoint CA, and a
public endpoint/release configuration. It does not carry a campaign bearer,
install claim, request capability, device credential, password, or service
credential.

This runbook authorizes disposable-VM acceptance only. It does not authorize a
production fleet rollout.

## Campaign configuration

Create one non-overlapping active Windows Enrollment Campaign. Its policy is
the authority for both the decision mode and permitted Setup release:

```json
{
  "policy_id": "windows-office-v1",
  "enrollment_mode": "auto",
  "allowed_installer_releases": ["3.2.42"]
}
```

Set `target_platform=windows`, the allowed CIDRs, expiry, revocation state, and
usage limit. Do not configure a global enrollment-mode environment variable.
The client does not send `campaign_id`; the server selects exactly one matching
campaign from its trusted source address and request evidence. Zero matches are
denied and overlapping matches require review.

For `MANUAL`, valid requests remain `WAITING_APPROVAL` until an administrator
approves or denies them in the Enrollment Admin queue. For `AUTO`, the server
approves only when there is no blocking identity conflict. An administrator
must never copy an `ic_` claim into MSI properties, a command line, or a log.

## Artifact verification and invocation

On the test machine, copy the EXE and its adjacent release JSON. Verify the
SHA-256 against `setup_sha256` before execution. The 3.2.42 artifact uses:

```text
EndpointAgentSetup-3.2.42-x64.exe
SHA-256 b31d670c076f190be5948612b2cd6276f5cd586a7fda9bee38f56ccb4aba32d7
```

Run interactively or with the identical non-interactive flow:

```powershell
.\EndpointAgentSetup-3.2.42-x64.exe
.\EndpointAgentSetup-3.2.42-x64.exe --quiet
```

`--quiet` changes presentation only. It does not bypass campaign selection,
approval, source CIDR validation, release policy, claim binding, or completion
observation.

## Expected outcomes

| Exit | Meaning | Operator action |
| --- | --- | --- |
| 0 | Enrollment provisioned and server completion observed | Verify device and audit projection. |
| 10 | Existing valid enrollment preserved | Do not re-enroll; inspect service only if unavailable. |
| 30 | Enrollment denied | Correct campaign/source/release evidence; create a new request only after correction. |
| 31 | Approval timed out locally | Approval may still occur until request TTL; rerun creates a new capability. |
| 32 | Review required | Resolve the queue item; never force a campaign selection. |
| 33 | Request expired | Start a new request after correcting the cause. |
| 60 | Local enrollment state is incomplete or corrupt | Repair under the protected ProgramData boundary; do not overwrite identity. |

## Acceptance matrix

Use disposable Windows snapshots for AUTO, MANUAL approval, denial, rerun,
reboot, and `/quiet` tests. For each successful enrollment, prove a distinct
installation ID, request capability, claim, Device UUID, credential, fresh WSS
presence, and `baseline_v1` context. Confirm no claim/capability/credential is
present in MSI properties, process arguments, environment, or installer logs.

Before production release, require a trusted Windows snapshot, Endpoint
DNS/CA reachability, trusted-proxy source-address configuration, migration
backup and rollback plan, one non-overlapping Windows campaign, and an approved
Authenticode publisher. An unsigned artifact is test-only and cannot be
promoted to production.
