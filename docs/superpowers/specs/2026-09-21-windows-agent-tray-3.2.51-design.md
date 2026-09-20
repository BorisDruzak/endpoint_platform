# Windows Agent Tray 3.2.51 Design

## Intent and scope

Windows users need an unobtrusive local indication that Endpoint Agent is
running, connected to Endpoint Platform, and not awaiting or failing an update.
The release is a minimal, user-session-only companion for the existing
machine-wide headless agent. It does not add configuration, enrollment,
administration, diagnostics, or remote-control controls to the tray.

The release version is `3.2.51`. Version `3.2.50` is already installed on the
test targets, so a different payload with the same version would be correctly
rejected as an equal-version installation.

## Constraints

- `EndpointAgent` remains a headless Windows service. It must not create UI in
  session 0.
- The tray process runs independently in each interactive user session and has
  no elevated privileges.
- The tray must never read device credentials, enrollment identity, pending
  update bundles, command payloads, or writable agent configuration.
- The companion uses only a fixed, machine-owned public status projection. It
  never opens a new Endpoint API or WebSocket connection.
- Existing strict TLS, WSS-only connection behavior, update validation, and
  hardware-bound enrollment behavior remain unchanged.
- Existing Helpdesk GUI and bridge modules remain excluded from the release
  surface.

## Architecture

```text
EndpointAgent Windows service
    | atomically writes bounded public facts
    v
ProgramData/Endpoint Platform/Tray/agent-status.json
    | read-only to interactive users
    v
EndpointAgentTray.exe (one process per logged-on user)
    | Shell notification-area icon and local detail dialog
    v
Windows taskbar notification area
```

The service publishes an exact schema with only these values:

- current agent version;
- service/runtime health (`running`, `starting`, `stopped`, or `error`);
- endpoint connection (`connected`, `connecting`, `disconnected`, or `unknown`)
  and the time the value was observed;
- update state (`up_to_date`, `pending`, `applying`, `failed`, or `unknown`) and
  a bounded, non-sensitive reason code when relevant.

The projection is written to a temporary file and atomically replaced. The
machine service owns the directory; interactive users can read but cannot
modify status. The tray treats a missing, malformed, stale, or inaccessible
projection as `unknown`, displays a neutral icon, and remains available.

## Tray behavior

The tray binary is a small native-Windows-notification-area process built into
the Windows installer release. It polls the fixed status file at a bounded
interval and does not keep a network client.

Icon colours:

- green: service running and Endpoint WSS connected;
- yellow: service running but connection is starting, disconnected, stale, or
  unknown;
- blue: a verified update is pending or applying;
- red: service stopped or the latest agent/update status is an error;
- grey: status has not yet been published.

Right-click menu:

- `Endpoint Agent: <state>` (disabled status line);
- `Endpoint: <state>` (disabled status line);
- `Update: <state>` (disabled status line);
- `Details...` opens a read-only local dialog showing the same bounded fields
  and observation time;
- `Refresh` re-reads the status projection immediately;
- `Exit tray icon` closes only the current user's tray process, never the
  service.

The tooltip is a compact projection of the three status lines. No tray action
can trigger enrollment, install an update, restart a service, or change policy.

## Installation and lifecycle

The MSI owns `EndpointAgentTray.exe` and a machine-wide logon entry that starts
the executable for every interactive user. The setup does not attempt to launch
the tray process from the service's session 0. On a newly installed or upgraded
machine the icon appears at the next interactive logon; release validation may
start the executable in the active test session only to verify its UI process.

The component follows MSI version ownership. An upgrade replaces the companion
and preserves enrollment material in ProgramData. Uninstall removes the tray
binary and its logon entry while retaining the existing intentional ProgramData
identity/credential retention policy.

## Verification and release acceptance

Tests cover:

- strict validation and redaction of the public status schema;
- atomic writer behavior, stale/missing/malformed status handling, and status
  to icon/menu mapping;
- that the tray release surface imports no Helpdesk GUI/bridge code and opens
  no transport client;
- MSI component ownership, per-user logon registration, uninstall cleanup, and
  `3.2.51` initial-runtime manifest provenance;
- upgrade from installed `3.2.50` to `3.2.51`, including service health and
  preserved enrollment material.

Release validation runs first locally, then on exactly these existing Windows
targets: the local operator workstation, `192.168.101.2`, and
`192.168.101.120`. Each target must report selector version `3.2.51`, a running
`EndpointAgent`, a healthy updater service configuration, a readable safe tray
projection, and one tray process in the interactive validation session. Any
failed target stops the rollout; no host is silently skipped.
