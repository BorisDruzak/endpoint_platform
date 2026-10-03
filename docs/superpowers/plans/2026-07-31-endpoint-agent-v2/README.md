# Headless Endpoint Agent, Gateway WSS, ALT RPM and Windows MSI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Use `superpowers:using-git-worktrees` before changing code. Every task follows TDD, ends with focused verification, and must be committed separately unless the task explicitly spans two repositories.

**Repository:** `BorisDruzak/endpoint_platform`

**Goal:** Replace the inherited Helpdesk runtime entrypoint with one neutral headless Endpoint Agent core, add a production Gateway WebSocket transport, migrate the accepted ALT pilot to that core, package ALT as RPM, implement the same core as a Windows service, and deliver a machine-wide Windows MSI with safe enrollment, update, verification, and rollback.

**Architecture:** Endpoint Platform is the exclusive control plane for endpoint agents, but it is not a universal integration bus for unrelated business systems. Agents connect only to Endpoint Platform. `web_ovpn`, Helpdesk, and future systems call scoped Endpoint Platform APIs when they need endpoint data or operations. Helpdesk and Knowledge communicate directly through their own versioned APIs or later through a separate integration/event layer; their traffic must not be proxied through Endpoint Platform.

**Tech Stack:** Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2, PostgreSQL, aiohttp, PyInstaller, systemd, RPM/rpmbuild for ALT, Windows Service Control Manager, pywin32 service entrypoints, WiX Toolset for MSI, pytest, PowerShell build scripts.

## Current Accepted Baseline

The implementation starts from the current `main` and records its exact commit before work. At planning time the repository records:

- production Endpoint Platform on `endpoint.sosnadmin.local`;
- accepted ALT enrollment and Gateway Device Context flow;
- accepted ALT update to `3.1.84`;
- accepted authenticated rollback to immutable `3.1.80`;
- rejected malformed `3.1.83` artifact without selector movement;
- deployed, least-privilege `web_ovpn` integration;
- ALT systemd runtime no longer using inherited Helpdesk WebSocket/API.

The existing production and test-agent state is a rollback baseline. Do not mutate it until the applicable local and disposable tests in this plan pass.

## Global Constraints

- Endpoint Platform MUST remain the only agent-facing server.
- No agent may connect directly to Helpdesk, Knowledge, or `web_ovpn`.
- Endpoint Platform MUST NOT become a generic proxy, ESB, message broker, or service-to-service relay for Helpdesk ↔ Knowledge communication.
- Do not add endpoints such as `/proxy`, `/relay`, `/invoke-service`, arbitrary URL forwarding, generic webhook forwarding, or arbitrary message topics to Endpoint Platform.
- The current HTTPS pull Gateway remains available only as a temporary compatibility transport until the new WSS transport passes ALT and Windows acceptance.
- Do not silently fall back from WSS to the legacy Helpdesk WebSocket.
- Do not silently fall back from WSS to HTTPS pull after authentication, authorization, or protocol rejection.
- A temporary HTTP-pull fallback may be selected only by explicit local configuration or server-assigned rollout policy during the migration window.
- The inherited Helpdesk Protocol V3 is not the target protocol.
- New Gateway envelopes must not require `ticket_id`, `job_id`, requester identity, Helpdesk role, Helpdesk status, or Helpdesk event types.
- One endpoint agent codebase supports ALT and Windows. Do not create a separate Linux Git repository.
- Linux and Windows packaging are different artifacts in the same repository.
- Linux production installation target is a signed RPM. The current shell installer remains a pilot/recovery tool.
- Windows production installation target is one MSI.
- Windows MSI installs a headless core service and a privileged demand-start updater. Session Helper is a later optional component and must not block context-only Windows acceptance.
- No enrollment token, campaign token, device token, service token, password, CA private key, code-signing private key, or package-signing private key may enter Git, command-line logs, MSI logs, RPM source archives, test fixtures, or screenshots.
- The public internal CA certificate may be deployed as configuration, but environment-specific CA material must not be baked into generic source packages.
- Update success means a healthy authenticated connection from the selected new version before the post-update deadline.
- Downloaded, staged, verified, switched, restarted, or scheduled are not sufficient success states.
- Rollback must preserve `device_id`, device credential, local database, configuration, update history, and context state.
- No arbitrary shell, PowerShell, Python, executable path, service name, URL, or command text is accepted from an API caller.
- ALT remains the first acceptance platform.
- Windows is mandatory before removing the inherited Helpdesk transport.
- Production changes require a separate rollout decision after local and disposable acceptance.
- Every changed runtime path must update `PLANS.md`, relevant runbooks, and source maps.
- Every PR must pass `git diff --check` and end with a clean worktree.

---

# Architectural Decision: Endpoint Platform Is Not the Inter-System Bus

## Allowed communication paths

```text
Endpoint Agent
    └── Endpoint Platform Agent Gateway

web_ovpn
    └── Endpoint Platform service API
        ├── devices.read
        ├── context.read
        └── context.collect

Helpdesk
    ├── Endpoint Platform service API
    │   ├── device context
    │   ├── endpoint commands
    │   ├── consent transport
    │   └── Remote Assist transport
    └── Knowledge Platform API
        ├── search
        ├── suggestions
        ├── feedback
        └── draft creation

Knowledge Platform
    └── its own database and API
```

## Forbidden path

```text
Helpdesk
    → Endpoint Platform
        → Knowledge Platform
```

Reasons:

1. Endpoint Platform would become a single failure domain for unrelated business workflows.
2. Device authorization and Knowledge authorization have different subjects and policies.
3. Endpoint Platform would accumulate generic service credentials and become a high-value lateral-movement point.
4. Deploying or restarting endpoint infrastructure could break Helpdesk ↔ Knowledge communication.
5. A generic relay would create a distributed monolith and hide real API ownership.

## Future integration option

When direct synchronous APIs are no longer sufficient, create a separate integration capability:

```text
integration_gateway or event_bus
```

It may provide:

- service identity;
- transactional outbox delivery;
- idempotent events;
- retries and dead-letter handling;
- audit and schema registry.

That is a separate project and security boundary. It must not be implemented inside `endpoint_platform`.

---

# Priority and Delivery Order

The next work is sequential:

```text
P0 — Freeze architecture and characterize the accepted ALT baseline
P1 — Create neutral headless core and split dependencies/builds
P2 — Add Gateway transport abstraction and neutral WSS
P3 — Migrate ALT to headless WSS core and produce RPM
P4 — Implement Windows service, updater, MSI, and pilot
P5 — Remove inherited Helpdesk WebSocket after dual-platform acceptance
```

P3 RPM scaffolding and P4 WiX scaffolding may begin in parallel only after P1 interfaces are frozen. Runtime cutover remains sequential: P1 → P2 → P3 → P4 → P5.

---

# Target Runtime

## Common agent core

```text
pc_agent/runtime/
├── main.py
├── application.py
├── lifecycle.py
├── command_executor.py
├── verification.py
├── local_state.py
└── status.py

pc_agent/transport/
├── base.py
├── http_pull.py
├── websocket.py
├── protocol.py
└── backoff.py

pc_agent/platform/
├── common/
├── linux/
└── windows/
```

The common runtime owns:

- device identity and credential loading;
- transport selection;
- Gateway connection lifecycle;
- heartbeat;
- command execution;
- local idempotency and outbox;
- Device Context collectors;
- update recommendation/staging;
- startup outcome reporting;
- local logs and bounded diagnostics.

It must not import:

- `pc_agent.ui_gui`;
- `pc_agent.ui_bridge`;
- `TicketApiClient`;
- Helpdesk account registration;
- Helpdesk ticket code;
- requester Knowledge UI;
- legacy Helpdesk authentication;
- legacy Protocol V3 transport.

## Target transport

```text
WSS:
  wss://endpoint.sosnadmin.local/agent/v1/connect

HTTPS:
  /agent/v1/enroll
  /agent/v1/updates/*
  /agent/v1/artifacts/*
  /api/v1/devices/*
  /api/v1/context/*
```

WSS carries only bounded control messages:

```text
agent.hello
gateway.hello
heartbeat
command
command_ack
command_result
command_cancel
result_ack
policy_update
server_shutdown_notice
```

Large artifacts and update payloads use HTTPS.

## ALT packaging

```text
endpoint-agent-VERSION-alt1.x86_64.rpm
```

The RPM installs:

```text
/opt/endpoint-agent/
/etc/endpoint-agent/
/var/lib/endpoint-agent/
/var/log/endpoint-agent/
/usr/lib/endpoint-agent/
/usr/lib/systemd/system/endpoint-agent.service
/usr/lib/systemd/system/endpoint-agent-update.path
/usr/lib/systemd/system/endpoint-agent-update.service
```

## Windows packaging

```text
EndpointAgent-VERSION-x64.msi
```

The MSI installs:

```text
C:\Program Files\Endpoint Platform\Agent\
    launcher.exe
    current.json
    versions\VERSION\...

C:\ProgramData\Endpoint Platform\Agent\
    identity.json
    device-credential
    storage.db
    config\
    logs\
    updates\
```

Windows services:

```text
EndpointAgent
EndpointAgentUpdater
```

`EndpointAgent` runs as `NT AUTHORITY\LocalService`.

`EndpointAgentUpdater` is demand-start, runs as `LocalSystem`, accepts no network input, and processes only a fixed pending-update path with strict ACL and schema validation.

---

# Blockers

## BLOCKER-WIN-BUILD-001

A Windows x64 build worker is required with:

- Python 3.12;
- project-pinned PyInstaller;
- project-pinned pywin32;
- project-pinned WiX Toolset;
- PowerShell;
- Git;
- no production credentials.

Local Codex Windows may be used if the required tools are installed and verified.

## BLOCKER-WIN-PILOT-001

One disposable Windows 10/11 x64 VM or workstation is required with permission to:

- install/uninstall MSI;
- create/remove services;
- write protected ProgramData state;
- reboot;
- enroll;
- update;
- force a failed update;
- roll back;
- purge test state after acceptance.

## BLOCKER-WIN-SIGN-001

Production MSI/EXE rollout is blocked until a code-signing method is approved. Lab pilot may use unsigned test artifacts only when the user explicitly approves that pilot.

## BLOCKER-RPM-SIGN-001

Production RPM rollout is blocked until an RPM signing key and verification policy are approved. The signing private key is external to Git and CI logs.

## BLOCKER-ALT-ROLLOUT-001

Do not change the accepted `test-agent-lin` production-pilot state until:

- a new release artifact is immutable;
- local tests pass;
- rollback target remains available;
- exact canary and rollback commands are reviewed.

---

# File Map

## Existing files to preserve until cutover

```text
pc_agent/ws_agent.py
pc_agent/endpoint_gateway.py
pc_agent/gateway_update_runtime.py
pc_agent/update_adapter.py
pc_agent/launcher/**
deploy/agent/alt/**
endpoint_server/gateway/routes.py
endpoint_server/updates/**
endpoint_server/context/**
```

## New common runtime files

```text
pc_agent/runtime/__init__.py
pc_agent/runtime/main.py
pc_agent/runtime/application.py
pc_agent/runtime/lifecycle.py
pc_agent/runtime/command_executor.py
pc_agent/runtime/verification.py
pc_agent/runtime/status.py
pc_agent/transport/__init__.py
pc_agent/transport/base.py
pc_agent/transport/protocol.py
pc_agent/transport/http_pull.py
pc_agent/transport/websocket.py
pc_agent/transport/backoff.py
```

## New server WSS files

```text
endpoint_server/gateway/ws_routes.py
endpoint_server/gateway/connection_registry.py
endpoint_server/gateway/protocol.py
endpoint_server/gateway/command_service.py
endpoint_server/gateway/presence_service.py
```

## New packaging files

```text
requirements/agent-core.txt
requirements/agent-collectors.txt
requirements/agent-session-helper.txt
requirements/agent-remote-assist.txt
requirements/build-linux.txt
requirements/build-windows.txt

pc_agent/pyinstaller_endpoint_core_linux.spec
pc_agent/pyinstaller_endpoint_core_windows.spec

packaging/alt/endpoint-agent.spec
packaging/alt/build-rpm.sh
packaging/alt/SOURCES/
packaging/alt/README.md

pc_agent/platform/windows/service.py
pc_agent/platform/windows/updater_service.py
pc_agent/platform/windows/provision.py
pc_agent/platform/windows/acl.py
pc_agent/platform/windows/service_control.py

packaging/windows/build-msi.ps1
packaging/windows/wix/Package.wxs
packaging/windows/wix/Directories.wxs
packaging/windows/wix/Components.wxs
packaging/windows/wix/Services.wxs
packaging/windows/wix/Upgrade.wxs
packaging/windows/README.md
```

---

# Plan Files

1. [Architecture and accepted baseline](01-architecture-and-baseline.md)
2. [Headless core and dependencies](02-headless-core-and-dependencies.md)
3. [Neutral Gateway WSS](03-gateway-wss.md)
4. [ALT artifact and RPM](04-alt-rpm.md)
5. [Windows service, updater and MSI](05-windows-msi.md)
6. [Transport cutover, CI, release gates and definition of done](06-cutover-ci-and-done.md)
