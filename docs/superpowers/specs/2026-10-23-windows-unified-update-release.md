# Unified Windows update and reconnect release

The user requests the staged Foundation updater and TCP/WSS reconnect correction
as the primary release for existing and new agents. Reuse the approved staged
update design and existing audited enrollment/update mechanisms. Execute inline
in the current managed worktree; the primary checkout contains unrelated work.

Combine the staged branch with current main and the transport fix from
`61784dc6d35570404952f8c512641785e41b6904`. Allocate fresh version 3.2.147 after
the rejected 144/145/146 candidates; their immutable bytes remain preserved.
Existing versions and
published artifacts remain immutable. Preserve current ALT Linux functionality.
Preserve authentication/protocol/TLS rejection semantics and all installer
signature, ownership, ACL, namespace, health-window and automatic rollback gates.
The user accepted the measured approximately 130-second pause; do not relabel
historical failures of the original 120-second gate as passes.

Build matching signed MSI, Setup and Core ZIP from a clean pinned source, verify
embedded source closures and exact-source CI, then prove an actual Windows
upgrade, TCP interruption/reconnect, healthy operation and automatic rollback.
Review the integrated changes before main publication. Use existing production
domain services and audit paths for immutable artifact registration, Windows
campaign eligibility and device rollout; do not directly forge target outcomes.

Publish the verified integration to main, make the new Setup the Windows default
and allow it in the applicable active Windows campaigns. Assign existing
non-retired Windows agents through compatible Core/Foundation paths. Preserve
enrollment credentials, policy assignments and campaign selection boundaries.
Linux agents retain their applicable native release. Report actual fresh
device versions and APPLIED outcomes separately from assigned/offline targets;
never claim an offline device installed the release. Preserve backups and
rollback inputs and do not publish a candidate that fails its admission gates.
