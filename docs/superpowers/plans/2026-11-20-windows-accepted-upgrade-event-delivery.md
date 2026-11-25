# Windows accepted upgrade event delivery implementation plan

> For agentic workers: use `superpowers:subagent-driven-development` for implementation and review. Steps use checkboxes for tracking.

**Goal** — deliver the original installation event after a registered Windows client accepts an upgrade, loses its first confirmation and restarts.

**Architecture** — reuse the protected installation journal, the existing notification-only task and its ACK validation. Both ordinary and recovered Full Setup pass through staged terminal cleanup. The native MSI result and version selector remain authoritative for installation.

**Tech stack** — Windows PowerShell, Windows Task Scheduler, the packaged Python notification helper and pytest.

## 1. Implement and verify the change

- [x] In `tests/packaging/test_staged_cleanup_retry.py`, exercise the real terminal-cleanup function with recorded actions for an accepted transaction. Verify that notification delivery can resume across interruption of cleanup. Exercise a different operation ID, an unsettled phase and a conflicting task. Run the focused tests against the current wrapper to establish the failing case.
- [x] In `packaging/windows/Install-EndpointAgentCanary.ps1`, arrange delivery for the bound accepted upgrade before giving up responsibility for its terminal cleanup. Preserve the rollback path and its retry semantics. Use the existing protected notification entry point. Inspect `Register-InstallationEventRetry` and `pc_agent/platform/windows/installation_notification.py` to ensure a foreign task cannot be overwritten or deleted and an already acknowledged event incurs no further upload.
- [x] Run the Windows packaging cleanup tests, staged recovery roundtrip, installation lifecycle and notification tests. Verify the exact-ACK and response-loss tests against the active helper. Review the complete diff and commit the implementation separately.

## 2. Qualify the signed candidate

- [x] Use the exact signed .271 source as parent, port the reviewed change and tests, select the next available Windows candidate version, run its Windows source gate, build the signed media and verify the embedded wrapper and MSI against that source.
- [x] In a closed Windows lab with a paired Gateway and a registered source, allow normal Core traffic while temporarily withholding installation-event delivery. Run the ordinary signed upgrade once. Capture the native MSI status, accepted selector, old server ACK and retained event ID. Reboot normally, restore event delivery and observe the original event reaching the same card without operator intervention.
- [x] Check the single server row and exact ACK, retirement of the retry task, MSI activity before and after reboot and unchanged identity. Preserve receipts and report supported scope in the candidate record and release matrix. Remove only the temporary lab resources.

**Review focus** — unexpected task action or owner, transaction mismatch, crash between durable acceptance and cleanup, already confirmed events, and lost responses after server commit.

The first signed build delivered the retained event after restart, then kept running its minute task. On the same Windows 10 client, the next signed build handled the existing task, delivered the original event once and removed the task after acknowledgement. [3.2.272 qualification](../../releases/windows-3.2.272-candidate.json) · [3.2.273 qualification](../../releases/windows-3.2.273-candidate.json)
