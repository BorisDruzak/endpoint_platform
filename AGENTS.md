# Repository scope

- The primary repository for this workspace is [`BorisDruzak/endpoint_platform`](https://github.com/BorisDruzak/endpoint_platform). Treat it as the default repository for all implementation, Git, and remote operations.
- [`BorisDruzak/helpdesk`](https://github.com/BorisDruzak/helpdesk) is a secondary, read-only data source. Do not edit it, push to it, or add it as a working repository from this workspace. Its data may be consulted in a future, explicitly requested task.
- The approved local Helpdesk server-code source is `C:\Users\admin-2\CodexProjects\pc_client\server`. Use it solely to check and analyze Helpdesk code from this workspace. Changes there are prohibited: do not edit, commit, push, or create worktrees in that directory.
- The shallow, sparse, read-only snapshot at `C:\Users\admin-2\Documents\endpoint-helpdesk-agent-source`, from branch `codex/helpdesk-process-model` at commit `8be364000089d70bac3ccf9aaef4f84397ca21a7`, remains an approved limited agent-contract reference. It intentionally contains only `pc_agent/`, `shared/tool_contracts.py`, `shared/builtin_tool_descriptors.py`, `shared/redaction.py`, `pytest.ini`, `requirements-ci.txt`, and the agent capability document. Do not expand it without a demonstrated runtime or test dependency.

# Canonical agent release

- The main qualified agent version is **3.2.158** for Windows and ALT Linux. Read [`docs/releases/current-agent-release.json`](docs/releases/current-agent-release.json) for exact source bindings, signed artifacts, rollout status and source restrictions. Historical156 evidence remains in [`docs/releases/agent-3.2.156.json`](docs/releases/agent-3.2.156.json).
- The signed Windows installer is `C:\endpoint-platform-wix-build\staged-3.2.158-9423d9c\native-setup-build\releases\EndpointAgentSetup-3.2.158-x64.exe`, bound by `packaging/windows/initial-runtime-3.2.158.json`. Current158 delivery uses full signed Setup for qualified existing authenticated devices. No Windows158 Core ZIP is published; a Core ZIP cannot upgrade an older Foundation.
- The public Windows **new-enrollment** installer at `https://endpoint.sosnadmin.local/admin/enrollment` remains156 because existing campaign allowlists do not permit158. Existing-device upgrade authorization does not expand enrollment source scopes, quotas or permissions.
- The signed Linux kit is `C:\endpoint-platform-wix-build\unified-3.2.158\linux-kit\endpoint-alt-pilot-3.2.158-1.tar.gz`, published at `/srv/endpoint-platform-distribution/alt/endpoint-alt-pilot-3.2.158-1/`. Its actual HTTPS bytes and pinned OpenPGP signatures are verified in the canonical record. ALT privileged OTA requires `canary`: use `agent-linux-unified32158-9423d9c-canary`. Its successful singleton does not establish broad qualification: historical pre158 private-state continuity remains unverified, and existing offline156 assignments remain distinct.
- Before administrative Windows delivery, qualify full-Setup success and genuine automatic compensation for the actual native source profile, then verify a production canary independently. Preserve protected previous-version history and legacy bridges. Use actual device/AD binding and current authentication when delivery runs; a registry snapshot, offline assignment or old heartbeat is not installation acceptance. The corrected156 bridge uses a versioned signed bootstrap and a registration trigger, preserving old policies, shares and history. Keep versioned delivery digests and unresolved source limits in the canonical record.
- Every subsequent agent release must update **this section's version and paths** and **the canonical release record**, together with runtime version, Windows source binding and Linux kit metadata. Verify published bytes/signatures before declaring a version primary; preserve immutable historical packages and distinguish native qualification, public enrollment and fleet rollout acceptance.

# Production host

- `osn_admin@192.168.100.19` (SSH host alias: `endpoint-platform-server`) is the production machine for the Endpoint Platform service.
- Use this host for live testing and verification when that is necessary to complete the task. Treat changes, deployments, service restarts, configuration changes, and data changes as production operations.
- The `endpoint.sosnadmin.local` DNS record is configured. The Endpoint Platform CA certificate is available on the operator workstation at `C:\Users\admin-2\Desktop\РќРѕРІР°СЏ РїР°РїРєР° (2)\С‚РµС…\СЃРµСЂС‚РёС„РёРєР°С‚\sosnadmin-local-ca.crt`; treat it as deployment input and do not commit it. Do not work around DNS/TLS with an IP address or by disabling TLS verification.
- PostgreSQL and Nginx installation and configuration on this host are part of the Endpoint Platform deployment work. Perform them when the deployment assets are ready, rather than before the application is ready to deploy.
- Disk resize is cancelled. Re-check actual available capacity at the deployment gate and proceed only if it is sufficient for the verified deployment footprint; do not schedule or wait for a resize.
- `openvpm@192.168.100.30` (SSH host alias: `ui-vpn-deploy`) is the production host for the network web panel. Use it for necessary live testing and verification; treat changes, deployments, service restarts, configuration changes, and data changes as production operations.

# Related production repositories

- [`BorisDruzak/web_ovpn`](https://github.com/BorisDruzak/web_ovpn) is the repository for the network web panel hosted on `192.168.100.30`.
- [`BorisDruzak/network_configuration`](https://github.com/BorisDruzak/network_configuration) contains the network configuration associated with that panel.

# Test host

- `test-agent-lin@192.168.101.162` (SSH aliases: `test-agent` and `test-agent-lin`) is a dedicated non-production test machine for installing, reinstalling, and validating the Endpoint Platform agent and related functionality.
- Use this host proactively for agent and integration tests. Changes, service restarts, and test data on this machine are permitted when they are needed for the task. SSH key authentication and passwordless `sudo` are configured for `test-agent-lin`.
