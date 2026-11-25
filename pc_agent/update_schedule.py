"""One canonical HTTPS update interval, independent of command transports."""

UPDATE_POLL_INTERVAL_SEC = 300.0

# Core archive transfer may outlive an ordinary control request. Reserve time
# outside the transfer for startup reporting, discovery and update journals.
CORE_ARTIFACT_TOTAL_SECONDS = 900.0
CORE_ARTIFACT_CONNECT_SECONDS = 15.0
CORE_ARTIFACT_IDLE_SECONDS = 15.0
CORE_RECOVERY_CHECK_SECONDS = CORE_ARTIFACT_TOTAL_SECONDS + 120.0
