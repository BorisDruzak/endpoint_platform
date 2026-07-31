# Endpoint Agent Presence in Network Devices Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show a safe, automatically MAC-confirmed Endpoint Agent status in the existing `web_ovpn` network-device list and detail page.

**Architecture:** Endpoint Platform publishes a paginated, typed service-to-service identity feed containing only active-device metadata, safe current-profile timestamps, and normalized baseline MAC keys. `web_ovpn` fetches that feed in a five-minute background refresh, correlates it with the complete current network inventory only when one MAC identifies exactly one Endpoint device and one network asset, then saves a MAC-free result cache for the session-authenticated pages.

**Tech Stack:** FastAPI, SQLAlchemy (async Endpoint Platform / synchronous `web_ovpn`), Pydantic v2, Jinja2, vanilla JavaScript, pytest, httpx SDK.

## Global Constraints

- Implement in `BorisDruzak/endpoint_platform` first; use `BorisDruzak/web_ovpn` only from a new clean worktree at its current `main`, never the user-dirty root worktree.
- Keep Helpdesk read-only and do not add it as a dependency.
- Correlation is exact normalized MAC-only. IP addresses, hostnames, agent identifiers and names are never matching inputs.
- Retired Endpoint devices are excluded. A link is confirmed only when one normalized MAC maps to exactly one active Endpoint device and exactly one inventory asset key.
- The Endpoint bulk response is a typed, bounded, cursor-paginated service API requiring both existing `devices.read` and `context.read` scopes. Do not create a scope or broaden the `web-ovpn-context` credential.
- The web cache, HTML, JSON status response, audit rows and logs contain no MAC, IP copied from inventory, raw context section, token, certificate path, or upstream exception body.
- Use the existing strict HTTPS SDK client, root-managed CA and token file. Do not use an IP address or disable TLS verification.
- A page open may enqueue a refresh only after five minutes from the last successful refresh; it must return cached state immediately. One database-backed lease suppresses concurrent refreshes.
- Refresh failure preserves the last successful cache as `stale`; an empty cache is `updating`, never a false `no_agent` state.
- Do not modify netctl schema, netctl commands, network configuration, existing Bearer API authentication, or the existing collection-request flow.

---

## File structure

### Endpoint Platform (`C:\Users\admin-2\Documents\endpoint`)

| File | Responsibility |
| --- | --- |
| `endpoint_server/context/projection.py` | Validate one current baseline projection and extract only canonical `mac-<12 lowercase hex>` keys. |
| `endpoint_server/context/routes.py` | Serve the scope-checked, cursor-paginated safe identity feed. |
| `sdk/python/endpoint_platform_client/models.py` | Validate the public SDK identity-feed payload and reject extra/raw fields. |
| `sdk/python/endpoint_platform_client/client.py` | Fetch all bounded pages through one SDK method. |
| `tests/context/test_service_api.py` | Prove scopes, pagination, ordering, safe field boundary, active-device filtering and latest snapshot selection. |
| `tests/sdk/test_client.py` | Prove SDK pagination, malformed response rejection and endpoint path. |

### web_ovpn (`C:\Users\admin-2\Documents\ui_vpn`)

| File | Responsibility |
| --- | --- |
| `app/endpoint_platform_client.py` | Add the narrow service-client method for the safe feed. |
| `app/endpoint_context_adapter.py` | Project the feed into private correlation input without exposing it to the existing Bearer API. |
| `app/endpoint_agent_network.py` | Pure MAC normalization/correlation, safe cache projection, five-minute freshness rules and refresh worker. |
| `app/models.py` | Define web-owned cache rows and a singleton refresh state/lease. |
| `app/main.py` | Queue refreshes from session pages, enrich list/detail render contexts, and provide a session-protected status endpoint. |
| `app/templates/network_hosts.html` | Render an Endpoint Agent column using only safe cached status. |
| `app/templates/network_host_detail.html` | Render the Endpoint Agent detail section. |
| `app/static/endpoint-agent-status.js` | Poll session status while a refresh is pending and reload the page once. |
| `app/templates/base.html` | Offer an optional scripts block without changing unrelated pages. |
| `tests/test_endpoint_agent_network.py` | Unit-test MAC-only rules, cache projection, freshness and failure handling. |
| `tests/test_endpoint_agent_network_pages.py` | Test authenticated list/detail/status routes and rendered safety. |

## Task 1: Publish the Endpoint Platform safe identity feed

**Files:**
- Modify: `endpoint_server/context/projection.py`
- Modify: `endpoint_server/context/routes.py`
- Modify: `tests/context/test_service_api.py`

**Interfaces:**
- Consumes: `ContextCurrent(device_id, profile, snapshot_id, updated_at)`, `ContextSnapshot.normalized_projection`, `DeviceSession`, `Device.retired_at`, and existing `require_service_scope`.
- Produces: `GET /api/v1/devices/network-identities?limit=250&cursor=<uuid>` with an envelope `{"data": [AgentNetworkIdentity], "next_cursor": "<uuid>" | null}`. `AgentNetworkIdentity` has `id`, `device_identifier`, `display_name`, `last_seen_at`, `baseline_collected_at`, `profiles`, and `baseline_mac_keys`; it has no addresses, raw projection, warnings, interface name or diagnostic field.

- [ ] **Step 1: Write failing service-route tests for a uniquely safe page**

  Add fixtures that create two active devices, one retired device, several `DeviceSession` rows, `ContextCurrent` rows and snapshots. Make the current baseline snapshot contain two keys, only one of which is canonical.

  ```python
  response = client.get(
      "/api/v1/devices/network-identities",
      headers=service_headers({"devices.read", "context.read"}),
  )

  assert response.status_code == 200
  assert response.json() == {
      "data": [{
          "id": str(active_device.id),
          "device_identifier": "agent-01",
          "display_name": "Office workstation",
          "last_seen_at": active_latest_session.created_at.isoformat().replace("+00:00", "Z"),
          "baseline_collected_at": latest_baseline.collected_at.isoformat().replace("+00:00", "Z"),
          "profiles": [
              {"profile": "baseline_v1", "collected_at": latest_baseline.collected_at.isoformat().replace("+00:00", "Z")},
              {"profile": "health_v1", "collected_at": latest_health.collected_at.isoformat().replace("+00:00", "Z")},
          ],
          "baseline_mac_keys": ["mac-aabbccddeeff"],
      }],
      "next_cursor": None,
  }
  assert "raw_payload" not in response.text
  assert "interfaces" not in response.text
  assert str(retired_device.id) not in response.text
  ```

  Add parameterized tests that expect `401` with no bearer token and `403` when either required scope is absent. Add a two-page fixture and assert the cursor excludes the first page on the second request, uses `Device.id` ascending order, rejects an invalid UUID cursor with `422`, and clamps `limit` to `1..250`.

- [ ] **Step 2: Run the new test selection and verify that the route is absent**

  Run: `python -m pytest tests/context/test_service_api.py -k network_identities -q`

  Expected: FAIL because `/api/v1/devices/network-identities` and its projection helper do not exist.

- [ ] **Step 3: Extract only canonical baseline MAC keys**

  In `endpoint_server/context/projection.py`, add a compiled lower-case-only matcher and a helper that validates the existing normalized envelope before selecting keys. It must never read `raw_payload`.

  ```python
  _BASELINE_MAC_KEY_RE = re.compile(r"^mac-([0-9a-f]{12})$")

  def baseline_interface_mac_keys(snapshot: ContextSnapshot) -> tuple[str, ...]:
      try:
          envelope = DeviceContextEnvelopeV1.model_validate(snapshot.normalized_projection)
      except Exception:
          return ()
      if envelope.profile != "baseline_v1":
          return ()
      return tuple(sorted({interface.stable_key for interface in envelope.sections.interfaces
                           if _BASELINE_MAC_KEY_RE.fullmatch(interface.stable_key)}))
  ```

  Export this helper in `__all__`. Do not return interface names or sections.

- [ ] **Step 4: Implement the cursor-paginated route with both scopes**

  Add `AgentNetworkIdentity` and `AgentNetworkProfile` Pydantic response models in `endpoint_server/context/routes.py`, both `extra="forbid"`; use `UUID`, aware datetimes, `SafeContextProfile`, `baseline_mac_keys: list[Annotated[str, Field(pattern=r"^mac-[0-9a-f]{12}$")]]` and a maximum of 64 keys.

  Add the route before `/devices/{device_id}/context` so the literal path wins clearly:

  ```python
  @router.get("/devices/network-identities")
  async def list_network_identities(
      request: Request,
      _: Annotated[ServicePrincipal, Depends(require_service_scope(DEVICES_READ_SCOPE))],
      __: Annotated[ServicePrincipal, Depends(require_service_scope(CONTEXT_READ_SCOPE))],
      limit: Annotated[int, Query(ge=1, le=250)] = 250,
      cursor: UUID | None = None,
  ) -> dict[str, object]:
      ...
  ```

  Query only `Device.retired_at.is_(None)` and `Device.id > cursor` in ascending `Device.id` order in fixed chunks of 250 devices. Build a `DeviceSession` window subquery identical to `/devices`, and one joined `ContextCurrent`/`ContextSnapshot` query for every chunk and `_SAFE_SERVICE_PROFILES`. Continue through chunks until collecting `limit + 1` qualifying identities or reaching the end: that avoids a short or terminal page merely because a device lacks a usable baseline. For every device, select only valid safe current snapshots; derive profiles from those snapshots, derive `baseline_collected_at` and `baseline_mac_keys` from the current `baseline_v1` snapshot, and skip a device that has no valid current baseline MAC key. Return the first `limit` projections and the final returned UUID as `next_cursor` only when an additional qualifying row exists. Never issue per-device queries.

- [ ] **Step 5: Run the focused service tests**

  Run: `python -m pytest tests/context/test_service_api.py -k "network_identities or service" -q`

  Expected: PASS, including empty valid response, scope denials, deterministic pages, retired exclusion and no raw/diagnostic fields.

- [ ] **Step 6: Commit the self-contained Endpoint route**

  ```bash
  git add endpoint_server/context/projection.py endpoint_server/context/routes.py tests/context/test_service_api.py
  git commit -m "feat: add safe endpoint network identity feed"
  ```

## Task 2: Add the typed SDK boundary

**Files:**
- Modify: `sdk/python/endpoint_platform_client/models.py`
- Modify: `sdk/python/endpoint_platform_client/client.py`
- Modify: `sdk/python/endpoint_platform_client/__init__.py`
- Modify: `tests/sdk/test_client.py`

**Interfaces:**
- Consumes: Task 1 envelope and its literal path.
- Produces: `EndpointPlatformClient.list_agent_network_identities() -> list[AgentNetworkIdentity]`, which follows all pages and cannot deserialize arbitrary context sections.

- [ ] **Step 1: Write failing SDK tests**

  Add a mock transport test with two JSON pages and assert one returned ordered list. Assert calls use:

  ```python
  [
      ("GET", "/api/v1/devices/network-identities", {"limit": "250"}),
      ("GET", "/api/v1/devices/network-identities", {"limit": "250", "cursor": str(second_device_id)}),
  ]
  ```

  Add a malformed payload carrying `"interfaces"`, uppercase `"mac-AABBCCDDEEFF"`, an extra `"raw_payload"` field, or a repeated cursor. Assert each raises `EndpointPlatformMalformedResponse` rather than returning partial data.

- [ ] **Step 2: Run the SDK test selection and verify it fails**

  Run: `python -m pytest tests/sdk/test_client.py -k network_identities -q`

  Expected: FAIL because the public model and method do not exist.

- [ ] **Step 3: Define strict feed models**

  In `models.py`, add:

  ```python
  class AgentNetworkProfile(SafeModel):
      profile: SafeContextProfile
      collected_at: datetime

  class AgentNetworkIdentity(SafeModel):
      id: UUID
      device_identifier: str = Field(min_length=1, max_length=256)
      display_name: str = Field(min_length=1, max_length=256)
      last_seen_at: datetime | None
      baseline_collected_at: datetime
      profiles: list[AgentNetworkProfile] = Field(max_length=3)
      baseline_mac_keys: list[str] = Field(min_length=1, max_length=64)

      @field_validator("baseline_mac_keys")
      @classmethod
      def canonical_keys(cls, keys: list[str]) -> list[str]:
          if keys != sorted(set(keys)) or any(not re.fullmatch(r"mac-[0-9a-f]{12}", key) for key in keys):
              raise ValueError("baseline MAC keys must be canonical")
          return keys
  ```

  Add `AgentNetworkIdentityPage(SafeModel)` with `data: list[AgentNetworkIdentity] = Field(max_length=250)` and `next_cursor: UUID | None`; export the three types from the SDK package.

- [ ] **Step 4: Implement page iteration with a loop guard**

  In `client.py`, add `MAX_NETWORK_IDENTITY_PAGES = 100` and:

  ```python
  def list_agent_network_identities(self) -> list[AgentNetworkIdentity]:
      cursor: UUID | None = None
      seen: set[UUID] = set()
      result: list[AgentNetworkIdentity] = []
      for _ in range(MAX_NETWORK_IDENTITY_PAGES):
          params = {"limit": "250"}
          if cursor is not None:
              params["cursor"] = str(cursor)
          page = AgentNetworkIdentityPage.model_validate(
              self._get("/api/v1/devices/network-identities", params=params)
          )
          result.extend(page.data)
          if page.next_cursor is None:
              return result
          if page.next_cursor in seen:
              raise EndpointPlatformMalformedResponse()
          seen.add(page.next_cursor)
          cursor = page.next_cursor
      raise EndpointPlatformMalformedResponse()
  ```

  Route parsing through `_validate` so Pydantic, missing envelopes and extra fields have the same redacted exception behavior as every other SDK call.

- [ ] **Step 5: Run all SDK tests**

  Run: `python -m pytest tests/sdk/test_client.py -q`

  Expected: PASS, including HTTPS/TLS validation, retries and the new feed pagination tests.

- [ ] **Step 6: Commit the SDK change**

  ```bash
  git add sdk/python/endpoint_platform_client tests/sdk/test_client.py
  git commit -m "feat: expose endpoint network identities in sdk"
  ```

## Task 3: Build the web-owned MAC-only correlation cache

**Files:**
- Create: `app/endpoint_agent_network.py`
- Modify: `app/models.py`
- Modify: `app/endpoint_platform_client.py`
- Modify: `app/endpoint_context_adapter.py`
- Test: `tests/test_endpoint_agent_network.py`

**Interfaces:**
- Consumes: `EndpointPlatformServiceClient.list_agent_network_identities()`, `EndpointContextAdapter.list_agent_network_identities()`, and complete unfiltered `unified_network_rows()` output.
- Produces: `refresh_endpoint_agent_network(db: Session, inventory: list[dict[str, Any]]) -> RefreshResult`, `cached_endpoint_agent_statuses(db: Session) -> dict[str, dict[str, object]]`, and only MAC-free safe status dictionaries for views.

- [ ] **Step 1: Write failing pure-correlation and persistence tests**

  Create identity fixtures with baseline keys and inventory fixtures with a `device_key` and MAC. Test these invariants:

  ```python
  result = correlate_endpoint_agents(
      inventory=[{"device_key": "mac:aa-bb", "mac": "AA:BB:CC:DD:EE:01", "ip": "192.168.100.55"}],
      identities=[identity(device_id=DEVICE_A, mac_keys=["mac-aabbccddee01"])],
  )
  assert result == {"mac:aa-bb": {"state": "confirmed", "device_id": str(DEVICE_A)}}

  assert correlate_endpoint_agents(inventory_two_same_mac, one_identity)["asset-a"]["state"] == "ambiguous"
  assert correlate_endpoint_agents(one_inventory, two_identities)["asset-a"]["state"] == "ambiguous"
  assert correlate_endpoint_agents(inventory_with_changed_ip, one_identity) == result
  assert "mac" not in cache_payload(result["mac:aa-bb"])
  assert "ip" not in cache_payload(result["mac:aa-bb"])
  ```

  Add database tests proving `EndpointAgentNetworkLink` stores only asset key, state, device UUID/display metadata, activity/baseline/profile timestamps, evidence kind and calculation time; inspect its `__table__.columns.keys()` and assert MAC/IP/raw fields are absent. Test an upstream `EndpointPlatformServiceUnavailable` leaves the prior confirmed row, changes state presentation to `stale`, and persists only `endpoint_platform_unavailable` as an error code.

- [ ] **Step 2: Run the new web unit tests and verify they fail**

  Run: `python -m pytest tests/test_endpoint_agent_network.py -q`

  Expected: FAIL because neither the models nor correlation module exist.

- [ ] **Step 3: Add minimal web-owned state tables**

  In `app/models.py`, define:

  ```python
  class EndpointAgentNetworkLink(Base):
      __tablename__ = "endpoint_agent_network_links"
      asset_key: Mapped[str] = mapped_column(String(255), primary_key=True)
      state: Mapped[str] = mapped_column(String(16), nullable=False)  # confirmed | ambiguous
      device_id: Mapped[str | None] = mapped_column(String(36))
      device_display_name: Mapped[str | None] = mapped_column(String(256))
      gateway_last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
      baseline_collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
      profile_summary: Mapped[str] = mapped_column(String(128), default="", nullable=False)
      evidence_kind: Mapped[str] = mapped_column(String(48), nullable=False)
      calculated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

  class EndpointAgentNetworkRefresh(Base):
      __tablename__ = "endpoint_agent_network_refresh"
      id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
      last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
      lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
      last_error_code: Mapped[str] = mapped_column(String(64), default="", nullable=False)
  ```

  Enforce `id == 1` inside the repository helper rather than depending on a database-specific check constraint. `Base.metadata.create_all()` is the established compatible migration path; do not alter netctl tables.

- [ ] **Step 4: Implement the narrow client and pure correlation boundary**

  Add one forwarding method in `EndpointPlatformServiceClient` and a private projection in `EndpointContextAdapter`; only the new internal module consumes it:

  ```python
  def list_agent_network_identities(self) -> list[dict[str, Any]]:
      return [_pick(item, (
          "id", "display_name", "last_seen_at", "baseline_collected_at",
          "profiles", "baseline_mac_keys",
      )) for item in self._client.list_agent_network_identities()]
  ```

  In `app/endpoint_agent_network.py`, implement `normalize_mac(value: object) -> str | None` by stripping all non-hex separators, requiring exactly 12 hex characters, and returning lower case. `correlate_endpoint_agents()` must build `dict[str, set[str]]` maps for inventory asset keys and Endpoint UUIDs, then only produce a confirmed candidate where both set lengths are one. It must not read any `ip`, `hostname`, `display_name` or `device_identifier` field while matching. Return safe candidate records only after dropping `baseline_mac_keys`.

  Implement `refresh_endpoint_agent_network()` to replace link rows atomically only after a successful complete fetch/correlation. On failure, retain links, set `last_error_code` to the fixed redacted code, clear the lease, and return `RefreshResult(state="stale")`. In a `finally` block close the adapter. Do not write upstream exception text.

- [ ] **Step 5: Run focused correlation tests**

  Run: `python -m pytest tests/test_endpoint_agent_network.py -q`

  Expected: PASS for unique, duplicate asset, duplicate Endpoint device, invalid MAC, IP-invariance, cache-column and stale-failure cases.

- [ ] **Step 6: Commit the correlation/cache unit**

  ```bash
  git add app/models.py app/endpoint_platform_client.py app/endpoint_context_adapter.py app/endpoint_agent_network.py tests/test_endpoint_agent_network.py
  git commit -m "feat: cache endpoint agent network correlation"
  ```

## Task 4: Add five-minute refresh orchestration and existing-page UI

**Files:**
- Modify: `app/main.py`
- Modify: `app/templates/base.html`
- Modify: `app/templates/network_hosts.html`
- Modify: `app/templates/network_host_detail.html`
- Create: `app/static/endpoint-agent-status.js`
- Test: `tests/test_endpoint_agent_network_pages.py`

**Interfaces:**
- Consumes: Task 3 refresh/cache functions and `EndpointAgentNetworkRefresh` state.
- Produces: session-authenticated `GET /network/endpoint-agent-status`, enriched `host["endpoint_agent"]` render projection, and a list-open refresh that runs at most once per five minutes.

- [ ] **Step 1: Write failing page and route tests**

  In a TestClient setup that logs in through `/login`, monkeypatch the refresh runner and test:

  ```python
  page = client.get("/network/hosts")
  assert page.status_code == 200
  assert "Endpoint Agent" in page.text
  assert "Подтвержден автоматически" in page.text
  assert "Office workstation" in page.text
  assert "AA:BB:CC:DD:EE:01" not in page.text

  detail = client.get("/network/hosts/192.168.100.55")
  assert "Gateway activity" in detail.text
  assert "baseline_interface_mac" in detail.text
  assert "192.168.100.55" not in detail.text.split("Endpoint Agent", 1)[1]

  denied = anonymous_client.get("/network/endpoint-agent-status", follow_redirects=False)
  assert denied.status_code == 303
  status = client.get("/network/endpoint-agent-status")
  assert status.json() == {"state": "updating", "last_success_at": None}
  ```

  Test a fresh `last_success_at` does not invoke the worker, an expired one invokes it exactly once across two requests, `stale` cache renders the last confirmed identity plus an explicit stale badge, and a device without a row renders `No agent` only after a successful refresh. Assert the existing `/api/v1/endpoints` remains Bearer-authenticated and is not called by HTML routes.

- [ ] **Step 2: Run page tests and verify the feature is absent**

  Run: `python -m pytest tests/test_endpoint_agent_network_pages.py -q`

  Expected: FAIL because the session status route, rendered projection and polling asset do not exist.

- [ ] **Step 3: Implement the transaction-safe refresh lease and render projections**

  In `app/endpoint_agent_network.py`, add `queue_refresh_if_due(db, inventory)` using `utcnow()`, `with_for_update()` where supported, and a 60-second `lease_expires_at`. A refresh is due when `last_success_at is None` or older than `timedelta(minutes=5)` and no unexpired lease exists. Commit the lease before dispatching a `BackgroundTasks` callback; callback opens its own `session_scope()` and never reuses the request session.

  In `app/main.py`, make `network_hosts` obtain the full `unified_network_rows(request, status="all")` before filtering; pass that complete inventory to `queue_refresh_if_due`, then attach cache output to filtered rows by `device_key`. Make `network_host_detail` use the same full inventory before selecting the target row. The attachment contract is exactly:

  ```python
  host["endpoint_agent"] = {
      "state": "confirmed" | "ambiguous" | "no_agent" | "updating" | "stale",
      "device_display_name": str | None,
      "gateway_last_seen_at": str | None,
      "baseline_collected_at": str | None,
      "profiles": list[str],
      "evidence_kind": "baseline_interface_mac" | None,
  }
  ```

  Add `GET /network/endpoint-agent-status` after `require_user`; return exactly `{"state": ..., "last_success_at": ISO8601-or-null}`. It returns no per-asset data, no error text and no MAC material. This is a session route, not an API-router route and it must not accept/use Bearer credentials.

- [ ] **Step 4: Render the safe state and polling behavior**

  Add an `Endpoint Agent` column to `network_hosts.html`; every state is a textual badge. Confirmed shows only display name and `Gateway activity`; ambiguous says `Ambiguous match`; updating says `Updating`; stale says `Stale cached result`; no agent says `No agent`. Do not render `evidence_kind` in the UI; it remains an internal fixed provenance field.

  Add an `Endpoint Agent` panel to `network_host_detail.html`, with confirmed display name, Gateway activity, latest baseline and safe profiles. Do not include the host IP in that panel, because it is not correlation evidence.

  In `base.html`, add `{% block page_scripts %}{% endblock %}` after `app.js`. In `network_hosts.html`, load `endpoint-agent-status.js` only when `endpoint_agent_refresh_state == "updating"`. The script polls `/network/endpoint-agent-status` every 3 seconds, calls `window.location.reload()` once when state changes from `updating`, and stops after 40 attempts; it never logs response bodies or modifies page data.

- [ ] **Step 5: Run focused UI tests**

  Run: `python -m pytest tests/test_endpoint_agent_network_pages.py tests/test_web_network_observer.py -q`

  Expected: PASS, including existing host navigation and filtering behavior.

- [ ] **Step 6: Commit the session UI unit**

  ```bash
  git add app/main.py app/templates/base.html app/templates/network_hosts.html app/templates/network_host_detail.html app/static/endpoint-agent-status.js tests/test_endpoint_agent_network_pages.py
  git commit -m "feat: show endpoint agent status on network devices"
  ```

## Task 5: Verify, package, deploy in dependency order and document the rollout

**Files:**
- Modify: `PLANS.md` in each repository only to mark the completed Wave 1 UI work and verification evidence.
- Modify: `deploy/server/PRODUCTION_RUNBOOK.md` only if a repeatable Endpoint SDK wheel/release command is missing; do not add secrets.

**Interfaces:**
- Consumes: all completed Tasks 1-4 and the existing production service token/CA deployment.
- Produces: tested Endpoint package first, tested web application second, and production acceptance evidence without weakening TLS or exposing credentials.

- [ ] **Step 1: Run Endpoint Platform verification before producing a wheel**

  Run from the Endpoint Platform feature worktree:

  ```bash
  python -m pytest tests/context/test_service_api.py tests/context/test_safe_projection.py tests/sdk/test_client.py -q
  python -m pytest tests/contracts/test_contract_models.py tests/contracts/test_contract_artifacts.py -q
  python tools/contracts/generate_contract_artifacts.py --check
  python -m compileall -q endpoint_server endpoint_contracts sdk/python/endpoint_platform_client
  git diff --check
  ```

  Expected: all selected tests pass, generated artifacts are current, compile succeeds and the diff check is empty. Build the already-established SDK wheel only after those commands pass; record filename and SHA-256 in release notes, never a token value.

- [ ] **Step 2: Run web application verification in its clean feature worktree**

  Run:

  ```bash
  python -m pytest tests/test_endpoint_agent_network.py tests/test_endpoint_agent_network_pages.py tests/test_endpoint_context_api.py tests/test_web_network_observer.py -q
  python -m compileall -q app
  git diff --check
  ```

  Expected: all tests pass; existing Bearer API tests still require Bearer authentication; no route or rendered page test contains a MAC/raw endpoint projection.

- [ ] **Step 3: Run a deliberate local strict-TLS integration smoke test**

  Install the newly built SDK wheel into the web release environment only through its existing deployment dependency mechanism. With the existing root-managed CA and token-file configuration, call `EndpointPlatformClient.list_agent_network_identities()` against `https://endpoint.sosnadmin.local`; assert it returns typed data or an intentionally redacted availability failure. Do not use an IP URL, `verify=False`, curl `-k`, or print the Authorization header.

- [ ] **Step 4: Deploy Endpoint Platform before web_ovpn**

  On `endpoint-platform-server`, re-check free space, deploy the verified Endpoint service release, restart only its service, then verify the new feed over its DNS name and CA with the existing `web-ovpn-context` credential. Check only HTTP status and response schema keys in terminal output. Roll back to the prior Endpoint release if the service fails health checks; do not alter the credential scopes.

- [ ] **Step 5: Deploy web_ovpn and execute production acceptance**

  On `ui-vpn-deploy`, deploy the verified web release and its matching SDK wheel, restart `openvpn-web`, then verify:

  ```text
  1. Existing authenticated /network/hosts opens and first page returns promptly.
  2. A unique test-agent baseline MAC shows Confirmed automatically after one refresh.
  3. A duplicate-MAC fixture is labelled Ambiguous and has no selected agent.
  4. Changing only an inventory IP leaves the selected agent unchanged.
  5. Temporarily simulating unavailable upstream preserves prior confirmed data as Stale.
  6. The page and status endpoint contain neither MAC keys nor raw context fields.
  ```

  Restore the normal service configuration after the controlled outage check. Do not create a manual confirmation operation as part of this rollout.

- [ ] **Step 6: Document evidence and commit rollout documentation**

  Record only date, release commit IDs, test command outcomes, strict-DNS/TLS result, feature gate state and the six acceptance outcomes in the two `PLANS.md` files. Then commit each repository separately:

  ```bash
  git add PLANS.md deploy/server/PRODUCTION_RUNBOOK.md
  git commit -m "docs: record endpoint agent network status rollout"
  ```

  Omit a path from `git add` when it was not changed. Never include certificate, token, password, host key or raw request/response data.

## Self-review

- **Spec coverage:** Task 1 implements the single safe bulk feed, two existing scopes, active-only filter and no diagnostic/raw response. Task 2 prevents raw data entering the SDK. Task 3 implements exact MAC-only correlation, ambiguous outcomes, cache contents, failure retention and no netctl changes. Task 4 implements the five-minute singleton lease, session-only status endpoint, list/detail UI and bounded polling. Task 5 verifies strict TLS, staged deployment and every acceptance criterion.
- **Placeholder scan:** The plan contains no deferred-marker phrases or vague implementation wording. Every task names exact files, test commands, interfaces and implementation behavior.
- **Type consistency:** The producer route is `/api/v1/devices/network-identities`; the SDK method and the narrow web service boundary both use `list_agent_network_identities`; cached render data uses `host["endpoint_agent"]` with the same five state literals throughout.
