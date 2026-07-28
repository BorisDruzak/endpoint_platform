# Helpdesk extraction map

## Retained source paths

- `pc_agent/`
- `shared/tool_contracts.py`
- `shared/builtin_tool_descriptors.py`
- `shared/redaction.py`
- `pytest.ini`
- `requirements-ci.txt`
- `docs/AGENT_CAPABILITIES_AND_REQUIREMENTS.md`

## Excluded source paths

- `server/`
- `webapp/`
- `mcp_helpdesk_server/`
- `content_packs/`
- `scripts/`
- ticket, Knowledge, quality, problem, change, and deploy code

The excluded paths remain recoverable from the pinned Helpdesk source commit. They are not copied into an Endpoint Platform `legacy` runtime.

## Formatting preservation

`pc_agent/` is copied without formatting changes so its baseline behavior can be characterized. Its pre-existing trailing whitespace is excluded from bootstrap `git diff --check` validation; newly authored Endpoint Platform files remain subject to that check.
