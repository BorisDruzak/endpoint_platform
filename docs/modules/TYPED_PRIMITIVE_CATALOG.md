# Typed Primitive Catalog — v1

This catalog defines the public, read-only Endpoint capabilities permitted as
recipe steps. It is intentionally a closed allowlist. Implementations are
released with the Endpoint agent and return bounded DTOs only.

| Capability | Parameters schema | Result schema | Platforms | Execution policy |
| --- | --- | --- | --- | --- |
| `context.baseline.collect` | existing fixed contract | existing context result | Linux, Windows | existing bounded context path |
| `context.health.collect` | existing fixed contract | existing context result | Linux, Windows | existing bounded context path |
| `context.network.collect` | existing fixed contract | existing context result | Linux, Windows | existing bounded context path |
| `context.diagnostic.collect` | existing fixed contract | existing context result | Linux, Windows | existing bounded context path |
| `dns.resolve` | `dns_resolve_parameters_v1` | `dns_resolve_result_v1` | Linux, Windows | target grammar validation; no raw resolver error |
| `network.ping` | `network_ping_parameters_v1` | `network_ping_result_v1` | Linux, Windows | target policy and fixed OS adapter |
| `tcp.connect` | `tcp_connect_parameters_v1` | `tcp_connect_result_v1` | Linux, Windows | target policy and bounded socket timeout |

## `dns.resolve`

`target` is a strict 1–253-character hostname or IP address. Schemes, paths,
userinfo, URLs, and control characters are rejected. `family` is exactly
`any`, `ipv4`, or `ipv6`. The result contains `target`, optional
`canonical_name`, at most 16 `{family, address}` values, `address_count`,
`status`, nullable stable `error_code`, and `collected_at`. Resolver exceptions
and resolver output are not serializable.

## `network.ping`

`target` follows the DNS grammar; `count` is 1–5 and `timeout_ms` is 100–5000.
The result contains `target`, optional `resolved_ip`, transmitted/received
counts, packet loss, nullable min/average/max latency, `reachable`, `status`,
nullable stable `error_code`, and `collected_at`. Neither command lines nor
stdout/stderr/localized text are exposed. The Windows and Linux adapters build
their fixed command internally and normalize it into the same result DTO.

## `tcp.connect`

`target` follows the DNS grammar; `port` is 1–65535 and `timeout_ms` is
100–10000. The result contains `target`, optional `resolved_ip`, `port`,
`reachable`, nullable `latency_ms`, `status`, nullable stable `error_code`, and
`collected_at`. Socket exceptions are mapped to stable codes rather than
returned.

## Network target policy

Both Endpoint server and agent use the same fail-closed policy shape:

- `ENDPOINT_NETWORK_PROBE_ALLOWED_CIDRS` and
  `ENDPOINT_NETWORK_PROBE_ALLOWED_SUFFIXES` on the server;
- `network_probe_allowed_cidrs` and `network_probe_allowed_suffixes` on the
  agent.

An empty allowlist denies ping and TCP. Loopback, unspecified, multicast,
broadcast, link-local, and public targets without explicit authorization are
denied. URLs and redirects are not valid targets. The server evaluates the
operation request and the agent re-evaluates the concrete command; mismatch or
denial is reported as a stable policy code and creates no network probe.

## Projection conditions

`GET /api/v1/devices/{device_id}/capabilities` projects a new primitive only
when it is globally enabled, agent-reported, compatible with the device
platform and agent version, and its target policy is configured. A disabled or
unconfigured primitive is not advertised as executable.
