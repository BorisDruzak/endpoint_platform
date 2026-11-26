# pc_agent/AGENTS.md - PC Agent Instructions

## Scope

This file applies to work under `pc_agent/`.

Use it for:

- desktop/client agent runtime
- agent startup/shutdown behavior
- Endpoint Gateway transport and typed command handling
- local machine automation
- agent logs/smoke checks
- agent packaging or deployment assumptions
- `pc_agent` CODEMAP/docs updates

Root `AGENTS.md` still applies.

## Local context

Before non-trivial `pc_agent` edits, consult available project routing docs:

- `docs/QUICK_LOOKUP.md`
- `docs/CODEX_WORKFLOW.md`
- `docs/CONTEXT_INDEX.md`
- `docs/ARCHITECTURE_BOUNDARIES.md`
- `docs/LIVE_TESTING_DEBUG_RULES.md`
- `pc_agent/docs/CODEMAP.md`

Use focused context tools when available:

```powershell
python scripts/build_context_pack.py --topic "<pc_agent task>"
python scripts/search_context_index.py "<agent protocol error symbol>"
python scripts/agent_find.py "<pattern>" --dir pc_agent
```

## Relevant skills

Use repo-local skills when applicable:

- Context discovery: `.agents/skills/pc-client-context-pack/SKILL.md`
- Bugs, regressions, runtime errors: `.agents/skills/pc-client-systematic-debug/SKILL.md`
- Code review: `.agents/skills/pc-client-code-review/SKILL.md`
- Docs/CODEMAP drift: `.agents/skills/pc-client-docs-drift/SKILL.md`

## Development and release

Use the [Endpoint Agent release workflow](docs/AGENT_UPDATE_WORKFLOW.md)
to select the mode and platform delivery path. **DEVELOP** is the default.
Run targeted verification and normal integration CI. Keep the released agent
and native package versions at their existing baseline and identify isolated
development builds by Git SHA. Move to **QUALIFY** for distributable Lab
candidates, **RELEASE** for authorized delivery of qualified artifacts, or
**HOTFIX** for an urgent fix based on the affected deployed source.

Use the [release CLI guide](../tools/release/CODEMAP.md) for candidate and
publication checks. The [provider release workflow](../.github/workflows/endpoint-operations-provider.yml)
runs the Windows and provider/Linux integration gates.

## PC agent implementation rules

- Treat Endpoint Gateway message/lifecycle changes as boundary-sensitive.
- Check Endpoint Platform compatibility before changing client-side transport behavior.
- Do not introduce behavior that silently diverges from server contracts.
- Preserve existing startup/shutdown and recovery semantics unless the task explicitly changes them.
- Do not log raw tokens, secrets, credentials, private keys, auth headers, or sensitive local-machine data.
- Preserve UTF-8; Russian text mojibake is a defect.
- Prefer existing agent runtime patterns over parallel mechanisms.
- If protocol handling, entrypoints, lifecycle states, runtime behavior, or packaging/deploy assumptions change, update relevant docs and CODEMAP.

## Verification

Before claiming completion for `pc_agent` work:

- Run workspace sanity when available:
  - `python scripts/verify_workspace.py`
- Run targeted agent tests/checks relevant to the changed files.
- For GUI/live-debug work, follow `docs/LIVE_TESTING_DEBUG_RULES.md`.
- For Gateway contract changes, verify both producer and consumer sides.
- For runtime/deploy-sensitive changes, use project-approved smoke/log scripts.

## Docs/CODEMAP drift

Use `.agents/skills/pc-client-docs-drift/SKILL.md` when `pc_agent` work changes:

- agent entrypoints
- Gateway contract handling
- runtime lifecycle
- startup/shutdown behavior
- packaging/deployment assumptions
- files listed in `pc_agent/docs/CODEMAP.md`

## Final response requirements

For `pc_agent` tasks, include:

- agent files changed
- Gateway/runtime impact
- server compatibility impact
- tests/checks run
- docs/CODEMAP updates or why not needed
- residual agent/runtime risks
