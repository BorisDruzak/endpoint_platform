# Repository scope

- The primary repository for this workspace is [`BorisDruzak/endpoint_platform`](https://github.com/BorisDruzak/endpoint_platform). Treat it as the default repository for all implementation, Git, and remote operations.
- [`BorisDruzak/helpdesk`](https://github.com/BorisDruzak/helpdesk) is a secondary, read-only data source. Do not edit it, push to it, or add it as a working repository from this workspace. Its data may be consulted in a future, explicitly requested task.
- The approved local Helpdesk server-code source is `C:\Users\admin-2\CodexProjects\pc_client\server`. Use it solely to check and analyze Helpdesk code from this workspace. Changes there are prohibited: do not edit, commit, push, or create worktrees in that directory.
- The shallow, sparse, read-only snapshot at `C:\Users\admin-2\Documents\endpoint-helpdesk-agent-source`, from branch `codex/helpdesk-process-model` at commit `8be364000089d70bac3ccf9aaef4f84397ca21a7`, remains an approved limited agent-contract reference. It intentionally contains only `pc_agent/`, `shared/tool_contracts.py`, `shared/builtin_tool_descriptors.py`, `shared/redaction.py`, `pytest.ini`, `requirements-ci.txt`, and the agent capability document. Do not expand it without a demonstrated runtime or test dependency.

# Canonical agent release

- The primary published agent version remains **3.2.156** for Windows and ALT Linux. Read [`docs/releases/current-agent-release.json`](docs/releases/current-agent-release.json) for exact publication source, signed artifacts and compatibility limits. Existing-device158 qualification is preserved separately in [`docs/releases/agent-3.2.158.json`](docs/releases/agent-3.2.158.json); it does not change the primary publication or enrollment defaults.
- The primary Windows installer is `C:\endpoint-platform-wix-build\staged-3.2.156-6ed41cd\native-setup-build\releases\EndpointAgentSetup-3.2.156-x64.exe`, bound by `packaging/windows/initial-runtime-3.2.156.json`. The product download at `https://endpoint.sosnadmin.local/admin/enrollment` remains156. Foundations older than156 require full signed Setup before Core-only156.
- The primary Linux kit remains `C:\endpoint-platform-wix-build\unified-3.2.156\linux-kit\endpoint-alt-pilot-3.2.156-1.tar.gz`, published under `/srv/endpoint-platform-distribution/alt/endpoint-alt-pilot-3.2.156-1/`. Historical158 ALT singleton/kit evidence remains in the separate158 record; this Windows auto-update task publishes no new Linux release.
- Core **3.2.162**, source `b9976195cf68be57da7dd860fa062fba6b533b8d`, is only the Windows preparation/recovery bridge with signed client1.0.4. Its artifact is `C:\endpoint-platform-wix-build\setup-client-3.2.162-b997619\EndpointCore-3.2.162-b997619.zip`. It is not a primary installer or Linux release. Canonical Core157 return precedes full Setup158. Preserve immutable retained history and all failed attempt receipts.
- The tested automatic Setup revision is `C:\endpoint-platform-wix-build\setup158-r3-5cb267d\releases\EndpointAgentSetup-3.2.158-r3-x64.exe`. Its wrapper source is `5cb267d3440511a62e466f49e6cc4ce80c3897a8`; native MSI/Core remain source `9423d9c27ea6b2d6c544c1bcdc1edb7cc9d15421`, bound by `packaging/windows/initial-runtime-3.2.158.json`. Exact original MSI and Core ZIP bytes are preserved. Qualification is test120's existing Foundation158 plus ZIP Core157; see [`docs/verification/2026-11-03-test120-endpoint-full-setup158.md`](docs/verification/2026-11-03-test120-endpoint-full-setup158.md). No Windows158 Core-only release or public enrollment expansion is implied.
- Unknown native outcomes keep exclusive recovery ownership; do not cancel, delete journals/cache, or replay installation. A known exit21 may settle as failed only after exact unchanged-source/private/session/180-second proof and the completed recovery return. Preparation on test120 needed one explicitly user-approved directory-owner exception, recorded in the verification receipt.
- Every subsequent agent release must update this section's version/paths and the canonical record together with runtime version, Windows source binding and Linux kit metadata. Verify actual published bytes/signatures before declaring a new primary. Keep native source qualification, public enrollment, scoped bootstrap and fleet acceptance distinct.

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
