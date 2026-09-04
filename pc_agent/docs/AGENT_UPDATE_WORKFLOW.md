# Endpoint Agent release workflow

1. Build the headless core from a clean pinned revision using the platform
   packaging script.
2. Verify artifact manifests, source revision, and the runtime import boundary.
3. Install on the approved canary host and validate enrollment, Gateway
   transport, Device Context collection, module lifecycle, and update status.
4. Publish the immutable artifact only after the canary evidence is accepted;
   do not overwrite an existing version.
5. Keep rollback evidence and the previous selector until post-install
   verification succeeds.

The supported packaging entrypoints are `packaging/alt/build-rpm.sh` and
`packaging/windows/build-msi.ps1`. Historic GUI/Helpdesk artifact builders are
not part of this workflow.
