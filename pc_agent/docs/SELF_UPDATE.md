# Endpoint Agent updates

The headless runtime receives update recommendations through the Endpoint
Gateway and applies only verified immutable artifacts. The Linux launcher and
Windows selector retain the current version until the replacement has passed
local verification. Update state is managed by `pc_agent/gateway_update_runtime.py`,
`pc_agent/update_adapter.py`, and the platform packaging scripts.

Artifacts must be built from a clean reviewed revision, carry a manifest and
source revision, and be validated in a canary before wider assignment. The
update path has no Helpdesk server API, desktop GUI, or requester-session
fallback.
