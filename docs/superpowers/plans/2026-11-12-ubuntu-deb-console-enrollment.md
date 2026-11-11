# Ubuntu DEB Console Enrollment Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans for the installation and acceptance sequence below.

**Goal:** Approve native Ubuntu Server installation from an existing Endpoint Console session.

**Architecture:** The signed APT client submits its exact DEB source and an opaque request capability. Console shows the existing enrollment queue. An authenticated administrator creates the one-use, host-bound campaign as part of the approval transaction. The host retrieves the claim through the existing capability-protected handoff.

**Tech stack:** Ubuntu 24.04, FastAPI, PostgreSQL, React, signed APT, systemd.

- [x] Reject mismatched DEB sources, hosts, addresses, capabilities and duplicate identities before issuing a claim. Cover the pending, approved, issued and registered states.
- [x] Display Ubuntu DEB in the existing queue and keep RPM and Windows behavior intact. Build and check the Console before production deployment.
- [ ] Have `.30` submit from the host itself with the verified package. Approve it in Console, finish the native installation, then verify WSS, reserve, APT downgrade and upgrade, and reboot recovery.
- [ ] Start `.19` only after the `.30` acceptance checks pass.
