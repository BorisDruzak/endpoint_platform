# Endpoint capabilities and managed module source

The headless runtime executes typed Endpoint commands through
`pc_agent/runtime/command_executor.py`. Its explicit
`BUILTIN_ENDPOINT_CAPABILITIES` registry selects the approved local context,
network, and read-only handlers; an unknown capability is rejected. The agent
receives Endpoint command envelopes, without ticket or requester semantics.

`pc_agent/modules/` retains collector contracts. `pc_agent/core/module_manager.py`
and `pc_agent/core/loader.py` retain managed-package validation and loading
helpers; their presence does not enable arbitrary module execution in the
headless command executor.

`pc_agent/modules_packages/` and `pc_agent/remote_assist/` remain separately
managed source. They are excluded from the Endpoint Core artifact and have no
core activation path. Remote Assist requires its own approved Endpoint session
and consent contracts before it can become a product surface.

The removed `AgentOrchestrator`, Helpdesk WebSocket transport, and Protocol V3
are not execution paths for Endpoint commands. See
[CODEMAP.md](CODEMAP.md) and
[the residual inventory](../../docs/segmentation/AGENT_ENDPOINT_RESIDUAL_INVENTORY.md)
for the active runtime and packaging boundaries.
