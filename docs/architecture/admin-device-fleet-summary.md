# Admin device fleet summary

`GET /api/v1/devices/context-summary` is a service-only bounded read model for
Helpdesk administration. Both `devices.read` and `context.read` are required.
It accepts `limit=1..250` (default 250) and an optional UUID cursor. Pages use
ascending Device ID; `data.next_cursor` is the final returned ID when another
page exists. Consumers must expose pagination rather than treat one page as
the entire fleet. Retired devices and devices without context remain visible.

Each `data.items` entry contains authoritative Device/DeviceSession presence,
up to five safe profile availability records, and nullable `inventory_summary`.
Presence uses the existing provider session projection with a 90-second TTL;
the consumer must not infer presence from its own timestamps. Inventory comes
only from validated current `inventory_v1`. Freshness uses the current last
observed timestamp, including identical repeated observations. Collection
status comes from the latest collection, ordered by request time and ID.
Malformed current projections fail the request instead of becoming offline.

The response excludes raw snapshots, secrets, credentials, diagnostic/activity
profiles, policy internals and agent version. Device context and profile
collection/history remain on their existing scoped APIs. Business ownership,
department, location and inventory number belong to the consuming Registry.
Helpdesk must join by its verified Endpoint-to-Registry mapping.

The fleet performs three bulk reads, independent of device count: device and
latest session, current snapshots, latest safe collections. No schema migration
or scheduler change is required. Coverage includes SQLite service API checks
and isolated migration-backed PostgreSQL cases in `test_fleet_postgresql.py`.
