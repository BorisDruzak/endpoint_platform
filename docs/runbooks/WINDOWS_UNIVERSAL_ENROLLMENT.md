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
  "allowed_installer_releases": ["3.2.49"]
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

## Console operator flow

Use `/admin/enrollment` as the canonical operator surface. The **Установщик**
tab shows the verified Setup release, **Кампании** controls the selected
Windows policy, and **Запросы регистрации** separates pending approval,
review, active, denied, completed, and failed requests. Each queue is paged;
use **Далее** to inspect older requests. Open a request to review its lifecycle
and safe device details, then approve or deny only pending/review requests.
The Console never displays the raw install claim or request capability.

## Artifact verification and invocation

On the test machine, copy the EXE and its adjacent release JSON. Verify the
SHA-256 against `setup_sha256` before execution. The release JSON is the
source of truth for SHA-256, source commit, embedded Agent version, and
Authenticode status. Without an approved local code-signing certificate,
`authenticode_status` is `unsigned` and the artifact is test-only. The 3.2.49
artifact uses:

```text
EndpointAgentSetup-3.2.49-x64.exe
```

Run interactively or with the identical non-interactive flow:

```powershell
.\EndpointAgentSetup-3.2.49-x64.exe
.\EndpointAgentSetup-3.2.49-x64.exe --quiet
```

`--quiet` changes presentation only. It does not bypass campaign selection,
approval, source CIDR validation, release policy, claim binding, or completion
observation.

### Staging inventory assignment

Use a signed staging Setup build with the matching signed MSI and its
inventory-capable provisioner. From
an elevated process on the selected workstation, capture the JSON output
of `--inventory-fingerprint` through a redirected stdout pipe. The probe
reads the same hardware fingerprint as Windows enrollment. Treat the output
as private and provide it only to the authorized inventory operator.

For a new installation, issue the assignment in staging for platform
`windows` and that fingerprint. The protected JSON handoff has exactly
`schema_version` (`endpoint_windows_inventory_assignment_v1`),
`installation_id`, and `hardware_fingerprint`. Save the file on the target
in an administrator-controlled local directory. Give the file a SYSTEM or
built-in Administrators owner and a protected ACL restricted to those trusted
principals. Use a regular file with one link. Launch the same signed Setup
with `--inventory-assignment-file <absolute-local-path>`. Remove the private
file from the target after the attempt and retain the operation status in
inventory.

Setup requires the staging origin, matching local fingerprint, a clean
installation slot and an approved claim with at least ten minutes remaining
before launching MSI. Existing
campaign selection and approval still apply. The signed wrapper repeats the
clean-slot check while holding its installer transaction. The helper
receives the assignment ID and claim over an inherited input pipe. The
installation is confirmed only after the Endpoint completion check. A claim
that expires during native installation is never sent to the provisioner.
If the attempt stops after claim issuance, reconcile its outcome in Endpoint before
issuing a new assignment or starting native recovery.

## What the person installing sees

The normal EXE asks Windows for administrator approval and then runs without
CMD or PowerShell windows. On completion it shows one native Windows result
dialog. A success dialog is shown only after the enrollment is provisioned and
the `EndpointAgent` Windows service is actually `RUNNING`; it is not merely an
MSI or provisioning-process exit result. Approval, review, and failure dialogs
show the stable exit code and a safe diagnostic class.

`--quiet` deliberately suppresses every dialog as well as console windows. It
is intended for software deployment systems and has the same checks and exit
codes as the normal EXE.

## Diagnostics and failure handling

Every run first records an in-progress state and then atomically replaces the
public operator result file:

```text
C:\ProgramData\Endpoint Platform\Installer\install-result.json
```

The JSON result contains `status`, `exit_code`, `stage`, `detail`, and an
update timestamp. `detail` is a bounded category such as `MSI_UNAVAILABLE`,
`MSI_EXIT_1603`, `PREFLIGHT_INVALID`, `CLAIM_FAILED`,
`PROVISIONING_UNEXPECTED`, or `SERVICE_NOT_RUNNING`; it never contains claims,
credentials, paths, response bodies, or raw exception text. The protected
installer log remains available at
`C:\ProgramData\Endpoint Platform\Installer\install.log` for correlated internal
diagnostics.

The result directory has an explicit Windows DACL: SYSTEM and Administrators
can manage it, while ordinary users can read it but cannot change or replace a
result. If this DACL cannot be established, setup preserves its actual exit
code and writes no untrusted public result file.

An outcome is successful only when the result is `COMPLETED` with
`stage=SERVICE` and `detail=SERVICE_RUNNING`. If service startup fails or the
installer cannot prove it within 30 seconds, the setup exits `50` with
`SERVICE_FAILED`; do not treat a visible MSI completion as a successful agent
installation.

## Expected outcomes

| Exit | Meaning | Operator action |
| --- | --- | --- |
| 0 | Enrollment provisioned and server completion observed | Verify device and audit projection. |
| 10 | Existing valid enrollment preserved | Do not re-enroll; inspect service only if unavailable. |
| 30 | Enrollment denied | Correct campaign/source/release evidence; create a new request only after correction. |
| 31 | Approval timed out locally | Approval may still occur until request TTL; rerun creates a new capability. |
| 32 | Review required | Resolve the queue item; never force a campaign selection. |
| 33 | Request expired | Start a new request after correcting the cause. |
| 40 | Claim handoff failed | Inspect the frozen selected campaign and request audit. |
| 41 | Provisioning failed | Inspect protected agent-side diagnostics. |
| 50 | Windows service repair/start failed | Repair the MSI-managed service without re-enrollment. |
| 51 | WSS timeout | Verify DNS, CA, service status, and Endpoint presence. |
| 52 | Context timeout | Inspect baseline context delivery and Endpoint verification. |
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
