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
- Transport failures (`aiohttp` client errors, timeouts, and local I/O errors)
  retry after the bounded poll delay.
- Gateway command execution is restricted to `context.baseline.collect`,
  `context.health.collect`, `context.network.collect`, and
  `context.diagnostic.collect`.

## ALT update lifecycle

- The installed version is read from the strict immutable
  `/opt/endpoint-agent/current.json` selector schema:
  `schema_version`, `source_revision`, and `version`.
- Candidate artifacts must use the Endpoint HTTPS origin.  Streaming download
  verifies the expected SHA-256 and byte count before atomic publication.
- A verified eligible recommendation creates
  `updates/pending_alt_update.json` by atomic replace.  It targets
  `linux_amd64`/`canary`, records the Gateway request, and preserves the
  selected release as the rollback version.
- The unprivileged ALT launcher detects that durable pending path and delegates
  publication to the root-owned update worker.
- After restart, the Gateway reports only a durable launcher outcome
  (`applied`, `failed`, or `rolled_back`) and retries the scheduled
  acknowledgement first.
- A rollback may select an already-present immutable release, using its
  manifest source revision to restore the strict selector schema.
