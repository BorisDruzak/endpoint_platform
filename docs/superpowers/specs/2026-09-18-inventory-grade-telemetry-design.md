# Inventory-grade Telemetry Design

## Purpose

Endpoint Platform remains the sole owner of enrollment, Device UUIDs and
credentials, Agent WSS, presence, Device Context, commands and updates.  This
change makes it a reliable, privacy-bounded inventory source for downstream
service consumers.  `web_ovpn` and Helpdesk consume only the existing
TLS-verifying service API; neither receives an Agent credential, an Agent
bearer, a raw context payload, a database connection, or a second WebSocket.

## Delivery boundaries

The work is divided into independently releasable tracks:

1. **Server contract and presence correctness.** Add the additive
   `inventory_v1` and `session_v1` contracts; correct service projections to
   use `DeviceSession.last_seen_at`; calculate `online` on the server; preserve
   `/agent/v1/connect` as the one Agent realtime endpoint.
2. **Context lifecycle and service SDK.** Add profile capabilities, collection
   result ingestion, current snapshots, scheduling, bootstrap refresh,
   semantic canonicalization/diffs, safe projection and strict HTTPS SDK
   support.
3. **ALT collector parity.** Collect bounded hardware, physical storage,
   interface MACs and network details from already-readable OS sources.
4. **Windows P0 collector and correlation evidence.** Use bounded native APIs
   or fixed, parameter-free local commands to collect physical inventory and
   network facts, and improve non-authorizing reenrollment evidence.

The tracks must land in that order.  No production deployment, migration run,
agent rollout, `web_ovpn` change, or credential grant belongs to these tracks.

## Wire contracts

`baseline_v1`, `health_v1`, and `network_v1` remain byte-for-byte compatible;
their Pydantic contracts keep `extra=forbid`.  Rich inventory is therefore a
new `DeviceContextInventoryV1` envelope with profile `inventory_v1` and only
optional technical facts:

```text
system: hostname, platform, os_name, os_version, os_build, architecture
hardware: manufacturer, model, serial_number, product_uuid, cpu_model,
          bios and baseboard fields
memory: total_bytes, memory_type, module_count, bounded modules[]
storage: bounded physical_devices[]
interfaces: bounded interfaces with name, mac, IP addresses, link type/state
```

All text, collection and address fields are bounded. MACs are canonical
lowercase twelve-hex values and an interface with a valid MAC derives the
existing `mac-aabbccddeeff` stable key. Physical disks carry only normalized
`HDD|SSD|UNKNOWN` media and `SATA|NVME|USB|SAS|OTHER|UNKNOWN` bus types.
Logical volumes stay diagnostic and never stand in for physical disks.

`DeviceContextSessionV1` is separate and dynamic: `current_user_login`,
`interactive_session_present`, and `collected_at`. It never collects secrets,
browser state, file contents, passwords or tokens.

## Presence and safe API

Every safe device projection reads the newest `DeviceSession.last_seen_at`,
falling back to `created_at` only when it is null. `online` is calculated from
an unclosed session whose server-owned last-seen value is within the configured
presence TTL. Client `reported_at` is not sufficient proof. The same logic
applies to `/api/v1/devices`, `/api/v1/devices/network-identities`, and the
single-device context projection.

`devices.read` and `context.read` expose the new safe profiles through existing
routes. `context.collect` is the only added manual-refresh authority; no
operations, provisioning or module scope is implied. The projection layer
continues to validate persisted normalized JSON against contracts and refuses
diagnostic or malformed data.

## Lifecycle and scheduling

The command/profile maps accept `inventory_v1` and `session_v1` with the
existing idempotent collection path. Schedule rules remain baseline 24 h,
health 5 min and network 15 min, adding inventory 24 h and session 5 min.
On a successfully authenticated `/agent/v1/connect`, the server requests a
missing inventory snapshot, a stale/missing baseline, and a stale/missing
network snapshot. It uses the existing active-collection lock/outcome path, so
reconnects never create duplicate collections.

Inventory canonicalization ignores collection time, warnings and transient
ordering; it includes stable hardware, memory, physical storage and interface
identity fields. It writes only one current semantic state for an unchanged
snapshot and emits fixed safe change codes: `RAM_CHANGED`, `STORAGE_CHANGED`,
`HOSTNAME_CHANGED`, `OS_CHANGED`, `HARDWARE_CHANGED`, and
`NETWORK_ADAPTER_CHANGED`.

Authenticated HTTP-pull fallback updates the same server-side session/presence
state; it never creates a second device identity.

## Collector policy

ALT uses `/sys/class/dmi/id`, `/proc`, fixed `ip -j` and `lsblk -J` calls with
the existing timeout/output bounds. Lack of DMI/RAM-module access emits a safe
warning and null/empty optional data rather than a fabricated value or added
privileges.

Windows prefers direct bounded Win32/IP Helper APIs. Any necessary fallback is
a fixed command invoked with `shell=False`, a fixed timeout, bounded stdout,
and no input interpolated from the server or user. The collector returns
unknown/null rather than placeholder hardware data.

Fingerprint updates hash product UUID, system serial, baseboard serial and MAC
set after normalization. MachineGuid may remain a continuity signal but does
not replace hardware evidence. No fingerprint participates in authorization;
IP is excluded and hostname is weak evidence only.

## SDK and artifact

The Python SDK expands its literal safe profiles, discriminated strict snapshot
models and profile-specific getters for inventory/session. It continues to use
HTTPS only, file-backed bearer, supplied CA verification, disabled redirects,
and retry only for reads. Its project version is bumped and an sdist/wheel is
built from a clean tree; tests parse all five safe profiles and reject extra or
mismatched fields.

## Verification gates

- WSS acceptance confirms only `/agent/v1/connect`, authenticated UUID/Hello,
  heartbeat-driven last-seen updates, no redirect and no alternate inventory
  endpoint.
- API tests prove last-seen fallback, TTL-derived online, safe profile exposure
  and `mac-*` identity-feed keys.
- Context tests prove exact idempotency, no semantic churn, inventory fixed
  diff codes, and bootstrap refresh deduplication.
- Unit tests inject ALT/Windows bounded probes for all requested optional
  inventory fields and failure warnings.
- SDK tests parse `baseline_v1`, `health_v1`, `network_v1`, `inventory_v1` and
  `session_v1`; packaging tests install the generated wheel in a clean target.

## Non-goals

This change does not create a new Agent endpoint, send data to `web_ovpn`,
grant consumer privileges, alter Helpdesk, run a production migration, roll
out an Agent, or claim that an Endpoint Device UUID is a physical Asset ID.
