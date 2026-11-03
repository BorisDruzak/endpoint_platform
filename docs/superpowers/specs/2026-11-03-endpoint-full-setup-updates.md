# Endpoint full Windows Setup updates

User-authorized outcome: assign immutable signed full Setup in Endpoint, have the
machine download/install/report automatically without SSH or interactive actions,
and accept target158 on the specifically selected test120. Prior one-shot SSH
staging is not acceptance of this feature.

## Design

The existing offline Core updater stays file-only and ZIP-only. Introduce a
durable, signed Windows Setup client scheduled as SYSTEM, stored outside the
MSI-owned Agent directory so immutable Setup158 cannot remove the executor while
it updates Foundation/services. It owns only a fixed HTTPS Setup-update protocol,
fixed installed agent locations and signed Setup execution with fixed arguments.
It is a separate network client; it never opens a listener or accepts commands.

Legacy machines get this client through an explicitly versioned Core OTA bridge.
The existing privileged updater already invokes the candidate's `--verify`.
After successful network-free verification, the bridge can install its bundled
publisher-signed client locally when executing as SYSTEM. Verification performs
no application-network request; the registered client defers while Core/native
transactions are active. Normal LocalService runtime and assets-absent historical
releases do not install a task. No unsigned script or caller-selected path is run.

The new Core bridge has a new immutable version160. To test frozen Setup158,
prepare a lower compatible registered Core157 through the canonical rollback
workflow after the160 bridge completes. Both assignments originate in Endpoint.
Then the durable Setup client applies the actual full158 EXE. This avoids
overwriting frozen158 code or disguising EXE bytes as a Core ZIP. The test120
Foundation is already158 from the prior authorized test; report that fact and
do not falsely claim a new156-Foundation source test. Existing actual156-to158
native success/compensation evidence remains separate.

## Control plane

Separate immutable Setup release registry and per-device assignments avoid
changing the old ZIP recommendation wire contract and public enrollment default.
Authenticated admin routes register releases, assign, cancel before install and
read status. Device routes authenticate the existing device credential, advertise
client capability, return only that device's assignment/artifact and record
bounded progress/outcome. Reuse existing source-CIDR, bearer authentication,
artifact containment, admin updates scope, audit and database patterns.

Status progression: assigned -> downloading -> verified -> installing ->
verifying -> applied/failed/rolled_back/blocked. Installing is an acknowledged
point of no return: cancellation is refused once installation may have started.
Already-current is a distinct verified no-op, never claimed as an installation.
One active Setup/Core update per device; serialize assignment through Device row
locks and check both assignment tables. No automatic second installer launch for
an uncertain operation. Persist protected receipts before launch; report retries
must not reinstall. Terminal success requires native/Core/source/MSI proof,
private-four preservation and a fresh server WSS session after install start.

An administrator can see client readiness and full Setup progress in the existing
device Updates view and assign a registered Setup there. No enrollment source,
quota, policy assignment or permission expansion is part of this work.

## Windows executor

- Fixed canonical Endpoint HTTPS origin; OS trust, no certificate bypass,
  redirects, proxy inheritance or credentials in logs/arguments.
- Protected Admin/SYSTEM staging and journals; reject reparse/hardlink/unsafe
  ownership before elevated execution. Hash/size and fixed trusted Authenticode
  publisher/timestamp checked while the executable is pinned against replacement.
- Fresh signed Setup preflight and current registered device binding required.
  Preserve exact private-four bytes/NTFS IDs/owner/group/DACL; keep history.
- Full Setup remains the owner of MSI transition, candidate proof and native
  compensation. The client does not edit its journals or forge readiness.
- Capture existing tray/sensor session owners before install and restore fixed,
  verified installed components under interactive-token Limited tasks in the
  same surviving sessions. Recognize the normal frozen tray parent/child pair;
  no duplicate launches, passwords, elevation of users or session restart.
- Bounded observations distinguish delayed cleanup, native failure and unknown
  outcome. Owned test fixtures are cleaned without touching unrelated rules.

## Acceptance and scope

Unit/DB/API tests cover old-client exclusion, unauthorized access, artifact
integrity, wrong device, overlapping assignment, cancellation/start races,
idempotent reports and preservation gates. Native Windows tests cover bootstrap
authorization, signature/path checks and exact-session companion restoration.

Live: only test120, prepare solely via existing Endpoint OTA, publish full signed
Setup158, assign through Endpoint, observe download/start/native acceptance and
server-side result, run a real readonly health command and observe CPU/session
stability for at least180seconds. No SSH, manual task creation or installer launch
on test120 during this feature acceptance. Read-only live evidence should come
through Endpoint where possible. Server deployment may use its canonical SSH
procedure; that is not workstation-side delivery.

General fleet release and other native source histories are not accepted by this
single-device test. Any unverified native compensation source must stay scoped.

The source157 ZIP is made from the exact retained qualified118-file tree, not a rebuilt old version. Source156 MSI history is preserved: the Core worker deliberately refuses changing an existing MSI-owned version directory into ZIP ownership. Preparation blocks unrelated Core/Setup assignments; cancellation prevents future stages without inventing completion of a running Core child.
