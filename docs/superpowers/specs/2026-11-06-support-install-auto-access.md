# Automatic first-install support access

User-approved direction: automatically authorize reserve SSH access after installation, not only start the service. This extends the176 independent channel; immutable176 Windows/ALT media are unchanged.

## Behavior

The signed176 installer already installs/starts an Auto LocalSystem Support1.0.1 service. The provider will offer explicitly configured installation defaults: approved Ed25519 operator public keys, an existing Windows principal (production SOSNADM\admin-2) and a bounded initial lease (8hours, preserving the current maximum). No password/account is created. After expiry the operator can enable a new temporary lease through Endpoint even when Core/updater are stopped.

Only a new or pristine never-configured registration (revision1, disabled, no policy keys/principal/expiry/revocation/reset) may queue these defaults during a real device-authenticated register call. Existing rows do not auto-enable merely because the deployment flag changes or a heartbeat arrives. Explicit per-device policies, including local test120, are preserved. Registration retries never extend intent or access; reset/revoke/disable/unregister cancel pending intent. A consumed or expired automatic intent is not rearmed by replay.

One nullable installation_access_pending_until column records a15minute installer-intent deadline. Queueing copies the approved public defaults into the disabled row without asserting runtime capability. A fresh independently authenticated installed Support1.0.1 status, without component error, may consume the pending intent once and atomically enable a lease. Source credential/device authority, canonical gateway, current matching defaults and global key-role separation remain required. Disabled/changed defaults or expired pending intent are disarmed and audited, never silently granted later. No WSS/Core liveness requirement is introduced. Only running-service status can advance runtime1.0.1 capability; registration still starts at1.0.0/uninstalled.

Operator defaults are deployment configuration, disabled when not explicitly configured. An enabled configuration must validate key grammar/uniqueness, principal grammar, canonical gateway and a finite lease in0.25..8hours. Device/tunnel/host/gateway keys cannot become operator keys; configured operator keys are reserved from device registration. Every pending/granted/cancelled/expired/default-conflict transition is audited in the same transaction. Row/key-authority locks preserve policy and registration race safety.

## Scope and operating rule

Production enables the feature with the current already-approved operator public key and explicit SOSNADM\admin-2. Standalone devices with a different administrator require an explicit per-device policy; no account is guessed. Existing disabled/revoked/manual policies are not mass changed. Unknown native results, private identities, keys, historical receipts, current Windows176/AUTO11/fleet10/max2 and Linux156 are preserved.

AGENTS.md must require independent reserve access when an authorized agent/updater issue cannot be diagnosed or fixed without a Windows connection. Try existing normal diagnostics first; then enable/renew the bounded policy if needed, verify UUID/hostname, obtain the host key through authenticated Endpoint, connect with strict gateway/device pins, collect evidence and restore only task-related changes. An unavailable reserve channel is reported honestly; native journals/locks are not cleared to regain access.

## Verification

TDD for configuration, queue/consume/cancel/expiry/replay/error/legacy reports/key-role conflicts/manual precedence/default changes. Real isolated PostgreSQL concurrency and Alembic upgrade/downgrade validation. Existing support/contracts/broker tests and server suite. Independent review before provider deployment. Fresh protected backup; additive0047 migration and atomic provider/config deployment; preserve valid exporter leases and gateway. Verify existing six component/policy identities unchanged, real service protocol remains compatible and strict SSH still works. The new first-registration auto-grant must be proven through the actual authenticated route transaction on isolated PostgreSQL; do not fabricate a newly installed production PC or erase test120 identity to simulate it.
