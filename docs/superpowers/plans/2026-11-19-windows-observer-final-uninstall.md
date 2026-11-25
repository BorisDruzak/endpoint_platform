# Windows Setup Observer final uninstall

**Goal** — retire the product-owned Observer task on confirmed final uninstall. Match the operator-approved [design](../specs/2026-11-19-windows-observer-final-uninstall-design.md).

Use the current integration worktree, Python installer helper, PowerShell wrapper and existing Windows Task Scheduler API. Keep the original installer transaction, native result and lifecycle event. Review busy tasks, changed ownership, incomplete Support cleanup, interrupted cleanup and a newer installation. Use test-driven development for each step.

- [x] In `pc_agent/platform/windows/native_setup_observer.py`, add a bounded operation for the fixed Observer task. Test absent, owned, mismatched and busy tasks in `pc_agent/tests/windows/`. Verify the installed signed action, task identity and scheduler definition before removal. Reuse the existing permission and signature checks. Check absence after removal.
- [x] In `pc_agent/platform/windows/installer_transaction_bridge.py`, invoke cleanup on a proved final removal after native success. Archive cleanup state linked to the exact transaction and package. Exercise temporary MSI removal, recovery and repeated finalization in tests. Keep the delivery task independent.
- [x] In `packaging/windows/Install-EndpointAgentCanary.ps1`, map an authenticated incomplete Observer outcome to 69. Preserve 68 precedence and distinguish these outer results from native MSI errors. Cover the actual wrapper and the packaged entry point with tests.
- [x] Route cleanup retry through the protected original removal receipt, the installer transaction lock and current product-absence checks before starting MSI. Verify that a new installation invalidates the authority of an older receipt. Repeating cleanup must preserve the original event.
- [x] Run targeted Windows unit and wrapper tests, then the release tests. Build a separate signed candidate and exercise both approved uninstall profiles on disposable Windows guests, including one ordinary reboot and delivery of an enrolled device's pending event. Record native, wrapper and scheduler results independently.

All three Windows 10 guests rebooted with the Observer task absent. The offline registered removal stayed pending after network return and was delivered by the next signed Setup, followed by its own installation event. The [native report](C:/endpoint-platform-wix-build/stab15-win268-observer-uninstall/qualification.md) records each exit code, the original event and the separate Support outcome.
