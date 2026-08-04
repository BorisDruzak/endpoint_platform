# Current ALT runtime baseline

This is the accepted runtime behavior that the Endpoint Agent V2 split must
preserve.  The executable characterization lives in
`pc_agent/tests/runtime/test_current_gateway_characterization.py` and
`pc_agent/tests/runtime/test_current_update_characterization.py`.

## Gateway transport

- The only runtime controller origin is `https://endpoint.sosnadmin.local`.
- The Gateway creates its TLS context from the configured CA file and uses that
  context for the connector and Gateway request.
- A 401 or 403 device-credential rejection exits the Gateway loop; it is not
  retried or redirected to Helpdesk.
- Only transient connection failures and timeouts retry after the bounded poll
  delay.  TLS connector/certificate verification failures, HTTP response
  failures, credential/configuration failures, malformed controller payloads,
  and update-integrity failures are terminal for the process.
- Gateway command execution is restricted to `context.baseline.collect`,
  `context.health.collect`, `context.network.collect`, and
  `context.diagnostic.collect`.  Each command is parsed, acknowledged, run by
  the fixed context executor, and reported through the Endpoint origin; other
  contract capabilities receive a rejected result rather than dynamic execution.

## ALT update lifecycle

- The installed version is read from the strict immutable
  `/opt/endpoint-agent/current.json` selector schema:
  `schema_version`, `source_revision`, and `version`.
- Candidate artifacts must use the configured Endpoint HTTPS origin.  Redirects
  are disabled, so an artifact request cannot continue to another host.
  Streaming download verifies the expected SHA-256 and byte count before atomic
  publication.
- A verified eligible recommendation creates
  `updates/pending_alt_update.json` by atomic replace.  It targets
  `linux_amd64`/`canary`, records the Gateway request, and preserves the
  selected release as the rollback version.
- The unprivileged ALT launcher detects that durable pending path and delegates
  publication to the root-owned update worker.
- Before selecting a candidate, the root worker verifies the current immutable
  release and records its strict identity in root-owned `previous.json`.
- Selector replacement is the update commit point. Same-operation replay keeps
  a distinct verified previous selector and resumes history/request cleanup; a
  failed replacement restores the earlier `previous.json` record. Invalid
  replay authority is consumed into a fixed failure record, not left watched.
- Repeated candidate crashes create only the fixed service-writable rollback
  request. The root worker requires it to match `current.json` and
  `previous.json`, re-verifies the previous release, and atomically replaces
  the root-owned current selector. No request field chooses a path or command.
- A post-selector rollback replay recognizes the already-authorized previous
  selector and idempotently finishes terminal marker/request cleanup. Selector,
  complete release-tree, and pinned state-directory metadata are validated.
- After restart, the Gateway reports only a durable launcher outcome
  (`applied`, `failed`, or `rolled_back`) and retries the scheduled
  acknowledgement first.
  `startup_crash_rollback_requested` is not terminal; only the root worker's
  post-publication `startup_crash_rollback` marker becomes `rolled_back`.
