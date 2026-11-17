# Common Windows observer and user-session continuation

The user explicitly requires one solution for every Windows client and future
enrollment, delivered by full Setup through Endpoint with waves of two. The user
also approved one exceptional observer-only repair on101.146. That exception
does not qualify an unattended deployment or authorize other workstation repair.

Confirmed defect: client1.0.5 registers an interactive scheduled task with a
literal SID. Real Windows PowerShell5.1 registration fails0x80070057 UserId;
using the same account's resolved name succeeds. Client1.0.6 in96a487c resolves
SID->account->sameSID, retaining original SID/session for RunEx/ownership checks.
126 focused tests and independent review passed.146's original HRESULT remains
unconfirmed, but its local diagnostic identifies that registration line and its
native exit0/accepted. Current146 additionally fails preflight provenance and
state validity; do not relax its source guards or replay MSI.

The common release must fix delivery as well as that line. A fresh native MSI
does not have a Core ZIP pending assignment, so the current Core-only observer
bootstrap does not install its scheduled observer. Repointing the task during
native installation also cannot replace the already-loaded1.0.5 caller.

Implement an authenticated native post-settlement continuation shared by fresh
installation and staged upgrade. Provision the exact signed packaged observer
into protected versioned storage with its SYSTEM schedule. Restore and verify
both expected companions for every still-logged-on matching user/session, even
if they were absent before installation. Complete this before returning to the
old observer, so its process verification finds the correct running companions.
Use verified installed payload hashes, SID/account round trips, exact SID/session
launch binding, process ownership/path checks and temporary-task cleanup.

Preserve existing owner authentication, mutation checkpoints, MSI/provenance
bindings, private files and native receipts. No listener or arbitrary execution
API, forged Core pending record, service-account change, GPO change or native
replay. The native child must not acquire its parent's observer mutex. An
unaccepted/rolled-back native transaction must not activate an unqualified
observer. If continuation fails after acceptance, retain truthful native state
and recovery ownership; never fabricate successful telemetry or restart MSI.

Qualification must cover unchanged1.0.5 caller with absent companions, actual
domain-user launch, fresh enrollment, SYSTEM installation, multiple/disappearing
sessions, rollback/interruption, source158 and165, and180 seconds of fresh
telemetry. Mocks are not live SYSTEM/domain launch proof. Future installation
and source admission must share the same process, with no host-specific product
branches. Existing published165 and observer1.0.5 bytes remain immutable.
