# Endpoint Agent Presence in Network Devices — Design

## Goal

Show Endpoint Agent presence inside the existing `web_ovpn` network-device
list and device card. A link is automatically confirmed only when the latest
agent baseline and the network inventory contain one exact, unambiguous MAC
identity match. This is a view and correlation feature: it does not contact
or change network devices, install an agent, or expose raw agent results.

## User experience

`/network/hosts` gains an **Endpoint Agent** column. The network device card
gains an **Endpoint Agent** section. They show only the safe projection:

- **Confirmed automatically** — exactly one active Endpoint device and one
  network asset share one baseline interface MAC; show the agent display name,
  last Gateway activity, latest baseline time, and available safe profiles.
- **No agent** — no eligible unique MAC relationship exists.
- **Ambiguous** — a MAC maps to multiple assets or multiple Endpoint devices;
  no link is selected.
- **Updating / stale** — the last safe result is still displayed while a
  refresh is running or unavailable. It is not turned into a false negative.

The UI calls recent `last_seen_at` **Gateway activity**. It may label activity
within five minutes as “на связи”, but never claims that an old session is a
live connection. MAC values, interface names, raw snapshots, tokens and raw
upstream errors never appear in HTML, JSON, audit details or the cache.

## Safe data flow

```text
Endpoint Platform safe bulk identity feed
        │ TLS + existing devices.read/context.read service credential
        ▼
web_ovpn refresh worker
        │ uses MAC only in process; no IP input
        ▼
web_ovpn SQLite cache (safe link result only)
        ▼
existing /network/hosts and /network/hosts/{ip} views
```

Endpoint Platform adds one typed, scope-checked service endpoint and matching
SDK method. Its response is a bounded list of active Device Context identity
summaries: device UUID, identifier, display name, retirement state,
`last_seen_at`, latest baseline collection time, profile availability, and
normalised baseline interface MAC keys. It does not return diagnostic data,
arbitrary context sections, addresses, credentials, policy data or agent
result envelopes. The MAC keys are service-to-service matching material only;
the web application discards them before persisting or rendering data.

No new scope is introduced. The existing `web-ovpn-context` credential already
has the two read scopes required for the bulk feed. Collection requests remain
the existing separately authenticated and CSRF-protected flow.

## Correlation rules

The web refresh builds one graph from the complete current network inventory,
not from a filtered table page:

1. Normalise each inventory MAC and map it to its distinct network asset keys.
2. Normalise every latest baseline MAC key and map it to its distinct Endpoint
   device UUIDs.
3. Confirm a relationship only when a MAC has exactly one asset key and one
   Endpoint device UUID.
4. Treat more than one asset or more than one Endpoint device as ambiguous.
5. Do not inspect, compare, store or use IP addresses as correlation input.

An automatic relationship is recalculated from current evidence on every
successful refresh; it is not a permanent binding. A future manual-exception
workflow, if needed, is a separate audited feature and does not weaken these
automatic rules.

## Refresh and cache

`GET /network/hosts` checks a singleton refresh lease. If the last successful
refresh is older than five minutes, it queues one background refresh and
immediately renders the last cached result. Concurrent page loads share the
lease. A small session-protected status endpoint lets the page reload its
badges after the refresh completes without waiting for the Endpoint service.

The local cache stores only:

- network asset key;
- Endpoint device UUID and display metadata;
- correlation outcome and evidence kind (`baseline_interface_mac`);
- Gateway last activity, baseline collection time, profile availability;
- calculation and expiry timestamps.

It stores no MAC, IP, raw snapshot, service token or error body. A failed or
disabled upstream refresh preserves the previous cache, marks it stale, writes
a redacted audit outcome, and applies bounded retry/backoff. An empty cache is
shown as “обновляется” until the first completed refresh.

## Components

### Endpoint Platform

- Add typed safe bulk-identity schemas, client method and service route.
- Enforce `devices.read` and `context.read`; exclude retired devices unless an
  explicit later requirement changes that policy.
- Query only the latest baseline identity material and safe device presence
  metadata in bounded batches.

### web_ovpn

- Add a narrow service client/adapter method for the bulk feed.
- Add a web-owned cache and lease migration; do not modify `netctl` tables or
  network configuration.
- Add a pure correlation module with explicit MAC-only inputs and safe output.
- Extend the existing host list and detail render context, templates and small
  polling script. Existing host and asset routes remain the navigation model.

## Verification

Endpoint Platform tests prove the bulk response schema, scope denial, bounded
ordering, latest Gateway activity and absence of raw/diagnostic fields.

web_ovpn tests prove unique MAC confirmation, all ambiguous cases, no-IP
correlation, cache contents, five-minute lease behaviour, refresh failure
staleness and no exposure of MAC/raw data. Page tests prove the badge and card
states for confirmed, absent, ambiguous, updating and stale evidence. Browser
verification uses the existing authenticated device list only after a deployed
feature gate is enabled.

## Rollout and acceptance

Deploy the Endpoint Platform safe bulk-feed release first, then the matching
web SDK/application release. The existing root-managed CA and least-privilege
credential remain in use. Enable the UI feature only after unit tests and a
strict-TLS service smoke check pass.

Acceptance requires a live, uniquely MAC-confirmed test-agent relationship in
the existing network device list; an ambiguous fixture that remains unlinked;
proof that changing IP alone cannot change a relationship; and an upstream
outage that leaves a labelled stale cache rather than a blank or false status.
