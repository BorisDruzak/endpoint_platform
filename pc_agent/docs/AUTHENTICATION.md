# Endpoint device credentials

Endpoint Agent authenticates with the device credential issued during
enrollment. Credentials and enrollment identity are scoped to the configured
Endpoint origin and stored under the agent data directory. They must not be
copied into source trees, logs, release archives, or command arguments.

The headless runtime reads the credential via
`pc_agent.device_credential.read_device_credential()` and verifies enrollment
identity before opening the Gateway transport. A missing, expired, or rejected
credential enters the explicit enrollment recovery path; it never falls back
to any Helpdesk identity flow.
