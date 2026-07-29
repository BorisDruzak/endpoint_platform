# Device Context Foundation Runbook

## Scope and safety boundary

This runbook describes the local foundation only. It does not authorize a
remote Alembic upgrade, deployment, agent installation, real device collection,
ALT pilot, `web_ovpn` checkout/change, Network Context correlation, or network
device action. Perform those later only under their separately approved plans.

The collection transport is the existing device-bound `AgentCommandV1` /
`AgentResultV1` path. Raw agent results, diagnostics, credentials, artifact
URLs, local paths and tracebacks are not safe service output.

## Fixed profile rules

| Profile | Capability | Invocation rule |
| --- | --- | --- |
| `baseline_v1` | `context.baseline.collect` | Periodic, at most every 24 hours. |
| `health_v1` | `context.health.collect` | Periodic, at most every 5 minutes. |
| `network_v1` | `context.network.collect` | Periodic, at most every 15 minutes. |
| `diagnostic_v1` | `context.diagnostic.collect` | Manual only with a bounded reason; not exposed by the safe service API. |

No caller may select a module, method, arbitrary probe, command or shell
argument. Collector failures use stable bounded warning/result codes. The
server scheduler creates only the first three profiles, locks one active
collection per device/profile, and gives periodic requests an interval-bounded
expiry for offline devices.

## Service access

Service clients receive least-privilege scopes:

- `devices.read` lists safe device identity.
- `context.read` reads normalized non-diagnostic context, collection state and
  baseline comparison.
- `context.collect` requests a non-diagnostic collection with an idempotency
  key and audit record.

Keep service tokens in their configured private secret storage. Do not copy a
bearer into ticket text, agent data, panel configuration, logs or diagnostics.

## Snapshot lifecycle and retention

Validated results create immutable snapshots. The server computes the baseline
semantic hash and does not trust an agent-supplied hash. Failed results do not
move the current pointer. Retention deletes at most 100 snapshots per batch and
preserves the current snapshot, the snapshot immediately before it, and every
snapshot whose `pinned_at` is set. Dependent diffs/findings cascade with a
deleted snapshot; collection audit records remain.

Before an operational retention run, verify that any comparison evidence that
must survive has been explicitly pinned through the server-owned retention
boundary. There is no raw-payload export procedure in this runbook.

## Local verification gate

Run these only against the local worktree and a disposable local test database:

```powershell
python -m pytest tests/contracts/test_context_contracts.py pc_agent/tests/context tests/context -q
python -m pytest tests -q
python tools/contracts/generate_contract_artifacts.py --check
git diff --check
```

Do not treat green local tests as authorization to run an SSH command, migrate
production PostgreSQL, contact a test agent, or connect `web_ovpn`. A later
Wave 1 adapter must use a typed service client over verified internal TLS and
must retain `web_ovpn` Network Context as a separate source; correlation is
never inferred from an IP address alone.
