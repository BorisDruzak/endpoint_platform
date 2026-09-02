# ALT headless agent staging canary

This runbook is for an explicitly approved staging canary only. It never
authorizes production deployment, a database downgrade, or a retry that would
create a second diagnostic operation.

Before execution, record the reviewed revisions, independent staging database
names, service unit names, DNS origin, CA fingerprint, safe device reference,
and baseline counts in the protected evidence directory. Confirm that the ALT
unit is active and enabled, launches `/opt/endpoint-agent/launcher` with
`--no-gui --transport-mode gateway_wss --no-migration-http-pull-fallback`, and
has no Helpdesk reference.

Run the read-only local preflight:

```text
python tools/canary/verify_installed_alt_agent.py \
  --expected-endpoint-origin https://endpoint-staging.sosnadmin.local \
  --expected-source-revision <approved-endpoint-sha> \
  --output <protected-evidence-root>/preflight-agent.json
```

The preflight accepts no credential input and does not read a credential file.
It verifies only metadata and writes an owner-only JSON projection. Do not
continue on a preflight failure.

During the single permitted operation, collect the local
`endpoint_agent_command_completed` marker. Its allowed fields are command ID,
capability, status, duration, result-item count and timestamp. Parameters, raw
results, URLs, credentials and Helpdesk metadata are prohibited.

After the terminal result, perform only observation and reconciliation. Confirm
one operation and one evidence item, then return new Endpoint execution flags
to disabled/fail-closed state. Preserve the operation, evidence and enrollment.
