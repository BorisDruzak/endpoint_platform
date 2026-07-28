# Agent baseline artifacts

Each baseline result is a UTF-8 JSON file with schema version `agent_baseline_v1`.

The JSON records a UTC generation timestamp, an ordered command inventory, each command's exit code and elapsed seconds, and one overall exit code. Command output is sanitized before it is written: tokens, bearer credentials, environment values, home directories, and absolute host paths are not retained.

Artifacts named for a stable test host, such as `test-agent.json`, may be committed with a matching summary. Local exploratory artifacts are not committed.
