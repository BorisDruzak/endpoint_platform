# Agent ↔ Endpoint Residual Inventory

Audit baseline: `f97d4548098a2dac1c494d49af15a3982f847e8a` on 2026-08-18.
Released Linux and Windows headless roots are
`pc_agent/runtime/main.py`, `pyinstaller_endpoint_core_linux.spec`,
`pyinstaller_endpoint_core_windows.spec`, ALT `endpoint-agent.service`, and
the MSI builder's `endpoint_agent_core` payload.  “Included” below means in
those release paths, not merely present in the repository.

| Item | Classification | Importer/release use | Linux / Windows / RPM / MSI | Useful function | Remove now? / prerequisite |
| --- | --- | --- | --- | --- | --- |
| `pc_agent/runtime/**` | RELEASED_HEADLESS | RPM/MSI core entrypoint; Linux systemd and Windows service | yes / yes / yes / yes | neutral typed Gateway runtime | no; active release runtime |
| `pc_agent/transport/**` | REUSABLE_ENDPOINT_COMPONENT | runtime application | yes / yes / yes / yes | TLS Gateway WSS and transitional HTTP update/pull transport | no; operation delivery uses WSS |
| `pc_agent/context_profiles/**` | REUSABLE_ENDPOINT_COMPONENT | `CommandExecutor`, release specs | yes / yes / yes / yes | bounded context collection | no; diagnostic capability depends on it |
| `pc_agent/endpoint_gateway.py` | MIGRATE_TO_HEADLESS | runtime compatibility/update seam | yes / yes / yes / yes | fixed Endpoint HTTP update/pull integration | no; decouple updates from compatibility seam first |
| `pc_agent/ws_agent.py` | LEGACY_UNRELEASED | compatibility/tests; not core specs | no / no / no / no | historical Helpdesk WS/UI and ALT compatibility handoff | no; Helpdesk cutover and test migration |
| `pc_agent/ui_gui/**` | DELETE_AFTER_HELPDESK_CUTOVER | legacy `ws_agent` only | no / no / no / no | ticket/consent GUI | no; Helpdesk GUI/consent cutover |
| `pc_agent/ui_bridge/**` | DELETE_AFTER_HELPDESK_CUTOVER | legacy GUI tooling | no / no / no / no | local GUI bridge/status | no; GUI retirement |
| `pc_agent/auth/**` | DELETE_AFTER_HELPDESK_CUTOVER | legacy ws/UI auth | no / no / no / no | Helpdesk account/session/connection request | no; remove legacy client authentication |
| `pc_agent/remote_assist/**` | DELETE_AFTER_HELPDESK_CUTOVER | legacy UI/runtime | no / no / no / no | Remote Assist | no; separately designed consent and remote-assist migration |
| `pc_agent/core/database.py` | LEGACY_UNRELEASED | legacy Protocol V3 runtime | no / no / no / no | legacy agent local DB | no; migrate/remove tests and historic runtime |
| `pc_agent/core/orchestrator.py` | LEGACY_UNRELEASED | legacy `ws_agent` | no / no / no / no | `run_tool`, consent, jobs | no; arbitrary-code paths must remain excluded |
| `pc_agent/core/sender.py` | LEGACY_UNRELEASED | legacy Protocol V3 | no / no / no / no | Helpdesk outbox sender | no; Protocol V3 retirement |
| `pc_agent/core/job_manager.py` | LEGACY_UNRELEASED | legacy scheduler | no / no / no / no | generic jobs | no; old scheduler retirement |
| `pyinstaller_endpoint_core_linux.spec` | RELEASED_HEADLESS | ALT package builder | yes / n/a / yes / no | excludes Helpdesk/GUI modules | no; active RPM surface |
| `pyinstaller_endpoint_core_windows.spec` | RELEASED_HEADLESS | MSI builder | n/a / yes / no / yes | excludes Helpdesk/GUI modules | no; active MSI surface |
| `pyinstaller_agent_linux.spec` | LEGACY_UNRELEASED | historic GUI artifact only | no / no / no / no | historic agent bundle | no; Helpdesk cutover/reproducibility decision |
| `pyinstaller_agent_win*.spec` | LEGACY_UNRELEASED | historic GUI artifact only | no / no / no / no | historic Windows GUI bundle | no; Helpdesk cutover/reproducibility decision |
| `pc_agent/requirements.txt` | LEGACY_UNRELEASED | historic GUI/development requirements | no / no / no / no | broad legacy dependency set | no; retained test/historic artifacts |
| `requirements/build-linux.txt` | RELEASED_HEADLESS | RPM build | yes / no / yes / no | constrained build profile | no; active package build |
| `requirements/build-windows.txt` | RELEASED_HEADLESS | MSI build | no / yes / no / yes | constrained build profile | no; active package build |
| `deploy/agent/alt/install-endpoint-agent.sh` | RELEASED_HEADLESS | ALT installer | yes / no / yes / no | installs launcher/systemd unit | no; active release path |
| `deploy/agent/alt/endpoint-agent.service` | RELEASED_HEADLESS | production/test service declaration | yes / no / yes / no | WSS-only headless launch flags | no; active service |
| `packaging/alt/build-rpm.sh` | RELEASED_HEADLESS | RPM release build | yes / no / yes / no | packages core spec/unit | no; active release path |
| `packaging/windows/build-msi.ps1` | RELEASED_HEADLESS | MSI release build | no / yes / no / yes | packages core Windows spec/service host | no; active release path |
| `pc_agent/platform/windows/service_launcher.py` | RELEASED_HEADLESS | MSI Windows service entrypoint | no / yes / no / yes | launches WSS headless runtime | no; active service |

## Legacy capability disposition

| Legacy area | Future disposition |
| --- | --- |
| Baseline, health, network, diagnostic collection | typed read-only Endpoint capabilities (baseline/health/network already exist; this package exposes diagnostic operation) |
| Ticket actions, requester UX, ticket notes/status, queue logic | Helpdesk business logic; do not move to Endpoint |
| Consent prompts and approval decisions | requires a separate consent contract and user-interaction design |
| Remote Assist signaling/media/control | Remote Assist; separate package with consent and security model |
| `run_tool`, recipes, `exec_script`, arbitrary service/path/URL/shell execution | permanently excluded from Endpoint Operations |

The current release scan must inspect imported/package/service surface, rather
than treating the presence of these historical files as a defect.

