## GitNexus MCP

GitNexus is the canonical architectural index for this project.

When investigating, planning, debugging, refactoring, or estimating impact:

1. Use GitNexus MCP before broad manual source exploration.
2. Start with query/context/impact/trace as appropriate.
3. For work involving both helpdesk and endpoint_platform, use the
   helpdesk-platform GitNexus group.
4. Check group_status before treating the group registry as stale.
5. Do not run group_sync manually. The central GitNexus server updates
   repository indexes and the Contract Registry automatically.
6. Treat GitNexus as the indexed Git baseline, not as the source of truth
   for uncommitted local changes. Always account for the current local diff.
7. A negative no_path / no ContractLink result is not proof that no
   dependency exists. Verify dynamic Python relationships against source
   and tests when relevant.
8. Do not create manifest links merely to make a cross-repo relation appear.
9. Do not commit or push code only to refresh GitNexus.
