# Endpoint full Setup auto-update implementation plan

> Implement with superpowers:executing-plans. Use focused red/green checks and an
> independent review before live mutation; continue the already authorized task.

**Goal:** Endpoint-controlled unattended signed full Setup delivery and test120
acceptance of target158 without SSH or manual workstation actions.

**Architecture:** Separate Setup release/assignment API plus signed durable SYSTEM
client. Bootstrap legacy installations once via versioned Core OTA, preserve the
existing ZIP-only worker/protocol and delegate native transactions to full Setup.

**Tech Stack:** Existing FastAPI/Pydantic2/SQLAlchemy2/PostgreSQL/Alembic; Windows
PowerShell5.1/Task Scheduler; PyInstaller Core bridge and Authenticode.

**Spec:** ../specs/2026-11-03-endpoint-full-setup-updates.md

## Global Constraints

- Preserve device credential, identity, origin and CA content, IDs and security.
- Never overwrite signed158 media or its frozen source; no public enrollment change.
- Old Core clients must continue to receive only their old ZIP/tar contracts.
- Test only192.168.101.120; no fleet or GPO rollout and no workstation SSH delivery.
- Do not replay an uncertain native action or manufacture a success/rollback proof.

## Review Focus

- Cancellation racing an install acknowledgement must not grant stale authority.
- A local writable path, redirect or substituted EXE must never become SYSTEM code.
- A completed child/bootstrap or version-only heartbeat must not mark Setup applied.
- Losing the reporting response must cause a report retry rather than a reinstall.
- SYSTEM installation must preserve and restore ordinary interactive user sessions.

## Tasks

- [ ] Contracts and state: add failing tests for immutable Setup manifests,
      terminal native proof, transitions and cancellation. Implement typed shared
      contracts and pure state validation in endpoint_contracts/setup_updates.py.
- [ ] Server ownership/API: new models/migration under endpoint_server/setup_updates;
      authenticated admin/device endpoints, audit and artifact containment. Test
      real PostgreSQL locks, old/Core overlap and replay. Wire router and worker.
- [ ] Durable Windows client: signed fixed-purpose scheduled client plus protected
      state/download/native preflight, actual Setup, independent preservation and
      post-WSS acceptance. Tests include signature/path/unknown-outcome refusals.
- [ ] Legacy bootstrap: explicit Core160 bridge, bundled signed client asset,
      network-free privileged installation after valid --verify. Red/green tests
      prove normal/historical verification stays unchanged and failure blocks OTA.
- [ ] Console: full Setup release/readiness/assignment/status controls in device
      Updates view. Validate user-visible states and endpoint compatibility.
- [ ] Release/deploy: source-bound clean Core159 build and signed client, isolated
      tests, frozen-SHA canonical production deployment and immutable artifact
      registration. Update docs/CODEMAP/release records with actual scope.
- [ ] Live acceptance: Core bridge160 -> canonical Core157 rollback -> full Setup158,
      entirely assigned through Endpoint. Prove a real installation, new WSS,
      health command, preserved identity, restored companions and >=180s CPU.

Implementation notes: production baseline62fb4 preserves SSO and WorkTime absent from main50cb. Migration0043 follows live0042. Preparations use canonical Core children with Device ownership and Build-before-Device locks; no terminal reports are fabricated. Isolated PostgreSQL migration and prior Core persistence tests:10 passed. Agent/client focused gate:see verification evidence; live acceptance still pending.

## Live recovery extension

The genuine158-r2 attempt exited21 before an installer bridge/native journal was
created: its recompressed Core ZIP differed only in ZIP timestamps from the
immutable cache. Preserve the failed attempt and both artifacts. Build158-r3
with the original verified MSI and Core archive; do not remove or replace cache.

Deliver qualified client1.0.4 in Core162 as a child of the held native operation,
using the same Device lock and canonical Core services. Keep recovery_required
committed throughout, then automatically return the exact registered Core157.
Only the client can settle the old attempt, as failed with real exit21: verify
unchanged Foundation/Core versions, source revisions and original ZIP/MSI hashes,
unchanged terminal native journal, no pending transaction, all private metadata,
restored user companions,180 seconds of source-version observation and fresh WSS.
Unknown outcomes remain held. The server also requires a qualified fresh client
and the recovery return child's applied/completed authority. No new Setup runs
until that proof has been accepted. This recovery is qualified only for the
actual test120 Foundation158/Core157 profile.
