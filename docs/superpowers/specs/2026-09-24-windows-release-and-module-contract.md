# Windows release and canonical module contract

The next immutable Agent release is 3.2.65. It must accept zero-input module
operations through the canonical API, show Russian text in the Windows tray,
and install with protected MSI provenance through universal Setup. The
privileged updater must reuse an existing MSI-owned version directory only
when its runtime payload exactly matches a verified rollback ZIP. Diagnostic
preflight must distinguish installed MSI provenance from a selected ZIP
runtime, while validating both.

The next ZIP canary after 3.2.65 must update and roll back the local ADMIN-2
Agent without hand-editing the installed runtime. Both Console targets must
report `applied`; strict TLS/WSS, service state, and provenance must pass
post-update and post-rollback checks. Tampered payloads, manifests, and
installer evidence must fail closed.

For the next production server deployment, the rollback artifact must be the
currently verified `758043d02f3b` release, which handles zero-input recipes
in both frontend and Console backend. The earlier `a49cd5a` release is
internally inconsistent; `590e1ea` cannot read current published zero-input
module data. Verify the rollback marker and archive before promoting the new
release. Keep Helpdesk read-only.
