# Repository scope

- The primary repository for this workspace is [`BorisDruzak/endpoint_platform`](https://github.com/BorisDruzak/endpoint_platform). Treat it as the default repository for all implementation, Git, and remote operations.
- [`BorisDruzak/helpdesk`](https://github.com/BorisDruzak/helpdesk) is a secondary, read-only data source. Do not edit it, push to it, or add it as a working repository from this workspace. Its data may be consulted in a future, explicitly requested task.
- The approved local Helpdesk server-code source is `C:\Users\admin-2\CodexProjects\pc_client\server`. Use it solely to check and analyze Helpdesk code from this workspace. Changes there are prohibited: do not edit, commit, push, or create worktrees in that directory.
- The shallow, sparse, read-only snapshot at `C:\Users\admin-2\Documents\endpoint-helpdesk-agent-source`, from branch `codex/helpdesk-process-model` at commit `8be364000089d70bac3ccf9aaef4f84397ca21a7`, remains an approved limited agent-contract reference. It intentionally contains only `pc_agent/`, `shared/tool_contracts.py`, `shared/builtin_tool_descriptors.py`, `shared/redaction.py`, `pytest.ini`, `requirements-ci.txt`, and the agent capability document. Do not expand it without a demonstrated runtime or test dependency.

# Canonical agent release

- The main published agent version is **3.2.156** for Windows and ALT Linux. Read [`docs/releases/current-agent-release.json`](docs/releases/current-agent-release.json) for the exact runtime source, signed artifact digests, download links, qualification and compatibility limits.
- The signed Windows installer is `C:\endpoint-platform-wix-build\staged-3.2.156-6ed41cd\native-setup-build\releases\EndpointAgentSetup-3.2.156-x64.exe`. Its source binding is `packaging/windows/initial-runtime-3.2.156.json`; the product download is the installer shown at `https://endpoint.sosnadmin.local/admin/enrollment`. Windows Foundations older than 3.2.156 require the full signed Setup before the 3.2.156 Core-only update.
- The signed Linux kit is `C:\endpoint-platform-wix-build\unified-3.2.156\linux-kit\endpoint-alt-pilot-3.2.156-1.tar.gz`. Its server directory is `/srv/endpoint-platform-distribution/alt/endpoint-alt-pilot-3.2.156-1/`; its verified public URL is recorded in the canonical release record.
- Existing ALT privileged OTA installers require the `canary` channel. Deliver 3.2.156 through `agent-linux-unified32156-6ed41cd-canary`, whose immutable archive digest matches the published stable build. A stable catalog entry alone does not qualify delivery. Before a bulk rollout, verify a real successful canary on the same build identifier, post-restart runtime/source, private-state preservation and advancing authenticated telemetry. Record native RPM versions separately from the selected OTA runtime.
- Every subsequent agent release must update **this section's version and paths** and **the canonical release record**, together with the runtime version, Windows source binding and Linux kit metadata. Verify actual published download bytes and signatures before declaring the new version primary. Preserve historical immutable packages and distinguish native installation qualification from OTA/fleet rollout acceptance.

# Production host

- `osn_admin@192.168.100.19` (SSH host alias: `endpoint-platform-server`) is the production machine for the Endpoint Platform service.
- Use this host for live testing and verification when that is necessary to complete the task. Treat changes, deployments, service restarts, configuration changes, and data changes as production operations.
- The `endpoint.sosnadmin.local` DNS record is configured. The Endpoint Platform CA certificate is available on the operator workstation at `C:\Users\admin-2\Desktop\Новая папка (2)\тех\сертификат\sosnadmin-local-ca.crt`; treat it as deployment input and do not commit it. Do not work around DNS/TLS with an IP address or by disabling TLS verification.
- PostgreSQL and Nginx installation and configuration on this host are part of the Endpoint Platform deployment work. Perform them when the deployment assets are ready, rather than before the application is ready to deploy.
- Disk resize is cancelled. Re-check actual available capacity at the deployment gate and proceed only if it is sufficient for the verified deployment footprint; do not schedule or wait for a resize.
- `openvpm@192.168.100.30` (SSH host alias: `ui-vpn-deploy`) is the production host for the network web panel. Use it for necessary live testing and verification; treat changes, deployments, service restarts, configuration changes, and data changes as production operations.

# Related production repositories

- [`BorisDruzak/web_ovpn`](https://github.com/BorisDruzak/web_ovpn) is the repository for the network web panel hosted on `192.168.100.30`.
- [`BorisDruzak/network_configuration`](https://github.com/BorisDruzak/network_configuration) contains the network configuration associated with that panel.

# Test host

- `test-agent-lin@192.168.101.162` (SSH aliases: `test-agent` and `test-agent-lin`) is a dedicated non-production test machine for installing, reinstalling, and validating the Endpoint Platform agent and related functionality.
- Use this host proactively for agent and integration tests. Changes, service restarts, and test data on this machine are permitted when they are needed for the task. SSH key authentication and passwordless `sudo` are configured for `test-agent-lin`.
