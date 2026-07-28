# Endpoint Platform minimal-agent bootstrap design

## Goal

Create the first runnable Endpoint Platform repository from the existing Helpdesk endpoint agent without importing the Helpdesk server, web application, ticketing, Knowledge, or other unrelated product code.

## Source boundary

The source of agent behavior is the read-only sparse Helpdesk snapshot from `BorisDruzak/helpdesk`, branch `codex/helpdesk-process-model`, commit `8be364000089d70bac3ccf9aaef4f84397ca21a7`.

The initial import contains only:

- `pc_agent/`
- `shared/tool_contracts.py`
- `shared/builtin_tool_descriptors.py`
- `shared/redaction.py`
- `pytest.ini`
- `requirements-ci.txt`

`shared/redaction.py` is included because the agent imports it directly. No `server/`, `webapp/`, `mcp_helpdesk_server/`, ticket, Knowledge, or content-pack path is imported. Further Helpdesk paths may be added only after a runtime or test demonstrates the dependency and the source provenance is updated.

## Bootstrap sequence

1. Create the Endpoint Platform repository's initial branch from the minimal source subset and record the source repository, branch, commit, import policy, and retained paths.
2. Keep the `pc_agent` package name, launcher layout, and behavior unchanged during the baseline phase.
3. Add a machine-readable baseline runner that executes the retained agent tests, the launcher/update tests, and `compileall` for `pc_agent` and `shared`.
4. Run the baseline on `test-agent` before any functional extraction, Gateway transport, collector, or deployment change.
5. Record the observed baseline result without secrets, tokens, host paths, or environment dumps.
6. Use that baseline as the acceptance gate for the later behavior-neutral extraction and for every focused platform change.

## Component boundaries

`pc_agent` remains the endpoint runtime. Its existing orchestrator, identity, durable state, launcher, update, and module behavior are treated as the compatibility surface.

The three imported `shared` modules provide the current tool contracts, built-in descriptors, and redaction behavior required by `pc_agent`. They are source dependencies, not a new shared Helpdesk runtime.

Endpoint Platform server, contracts, Gateway, Device Context, web_ovpn adapter, headless split, Windows service, and Helpdesk client integration are deliberately outside this bootstrap. They start only after the baseline is understood and recorded.

## Testing and safety

All new bootstrap behavior is test-first. The baseline runner itself must have a focused test that verifies its command inventory and sanitized JSON output. The runner is executed first locally, then on the `test-agent` machine when dependencies are installed there.

No production deployment, DNS workaround, TLS bypass, PostgreSQL installation, Nginx installation, or service restart is part of the bootstrap. Production work begins only with the deployment stage after its assets and checks exist.

## Acceptance criteria

- The Endpoint Platform working tree contains no Helpdesk server or web application paths.
- Every imported source path is named in provenance and retained-path documentation.
- Static import inspection finds no dependency on Helpdesk server packages.
- The baseline runner records exact commands and exit statuses in sanitized JSON.
- Baseline results are available before agent behavior is modified.
