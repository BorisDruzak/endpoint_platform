#!/usr/bin/env bash
# Root-owned bridge between the unprivileged agent and immutable release root.
set -u

readonly AGENT_SERVICE=endpoint-agent.service
readonly DATA_ROOT=/var/lib/endpoint-agent
readonly INSTALL_ROOT=/opt/endpoint-agent

resolve_current_launcher() {
    python3 - "$INSTALL_ROOT" <<'PY'
import json
import os
import re
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
selector_path = root / "current.json"
try:
    selector = json.loads(selector_path.read_text(encoding="utf-8"))
    version = selector.get("version") if isinstance(selector, dict) else None
    if (
        not isinstance(selector, dict)
        or set(selector) != {"schema_version", "source_revision", "version"}
        or selector.get("schema_version") != 1
        or not isinstance(selector.get("source_revision"), str)
        or not isinstance(version, str)
        or re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version) is None
    ):
        raise ValueError("invalid immutable release selector")
    launcher = root / "versions" / version / "launcher"
    details = os.lstat(launcher)
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != 0
        or details.st_gid != 0
        or details.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not details.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    ):
        raise ValueError("selected immutable launcher is unsafe")
except (OSError, ValueError, json.JSONDecodeError):
    raise SystemExit("unable to resolve selected immutable launcher")
print(launcher)
PY
}

restore_update_state_owner() {
    local state
    # The root worker may create a terminal history file. Return only those
    # fixed, regular state files to the service account; never recursively
    # chown an agent-writable tree.
    for state in \
        "$DATA_ROOT/updates/update_history.json" \
        "$DATA_ROOT/updates/last_failed_alt_update.json" \
        "$DATA_ROOT/logs/action_trace.jsonl"; do
        if [[ -f "$state" && ! -L "$state" ]]; then
            chown endpoint-agent:endpoint-agent "$state"
            chmod 0600 "$state"
        fi
    done
}

systemctl stop endpoint-agent.service || exit $?

status=0
CURRENT_LAUNCHER="$(resolve_current_launcher)" || exit $?
"$CURRENT_LAUNCHER" --apply-alt-update --no-gui \
    --data-dir "$DATA_ROOT" --install-root "$INSTALL_ROOT" || status=$?
restore_update_state_owner

# The launcher records handled apply failures and exits successfully. Retain
# this explicit fallback for unexpected process failures too: the old selected
# bundle is safer than a stopped management agent.
systemctl start endpoint-agent.service || exit $?
exit "$status"
