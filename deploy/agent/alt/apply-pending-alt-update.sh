#!/usr/bin/env bash
# Root-owned bridge between the unprivileged agent and immutable release root.
set -u

readonly AGENT_SERVICE=endpoint-agent.service
readonly DATA_ROOT=/var/lib/endpoint-agent
readonly INSTALL_ROOT=/opt/endpoint-agent
readonly STABLE_LAUNCHER=/opt/endpoint-agent/launcher

validate_stable_launcher() {
    python3 - "$STABLE_LAUNCHER" <<'PY'
import os
import stat
import sys
from pathlib import Path

launcher = Path(sys.argv[1])
try:
    details = os.lstat(launcher)
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != 0
        or details.st_gid != 0
        or details.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not details.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    ):
        raise ValueError("stable launcher is unsafe")
except (OSError, ValueError):
    raise SystemExit("unable to validate stable launcher")
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

validate_stable_launcher || exit $?
systemctl stop endpoint-agent.service || exit $?

status=0
"$STABLE_LAUNCHER" --apply-alt-update --no-gui \
    --data-dir "$DATA_ROOT" --install-root "$INSTALL_ROOT" || status=$?
restore_update_state_owner

# The launcher records handled apply failures and exits successfully. Retain
# this explicit fallback for unexpected process failures too: the old selected
# bundle is safer than a stopped management agent.
systemctl start endpoint-agent.service || exit $?
exit "$status"
