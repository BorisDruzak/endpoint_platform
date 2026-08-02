#!/usr/bin/env bash
# Root-owned bridge between the unprivileged agent and immutable release root.
set -u

readonly AGENT_SERVICE=endpoint-agent.service
readonly DATA_ROOT=/var/lib/endpoint-agent
readonly INSTALL_ROOT=/opt/endpoint-agent
readonly STABLE_LAUNCHER=/opt/endpoint-agent/launcher
readonly ROLLBACK_REQUEST=/var/lib/endpoint-agent/updates/rollback-request.json
readonly FAILED_ROLLBACK_REQUEST=/var/lib/endpoint-agent/updates/last_failed_alt_rollback_request.json

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

validate_updates_directory() {
    python3 - "$DATA_ROOT" <<'PY'
import os
import stat
import sys
from pathlib import Path

data_root = Path(sys.argv[1])
updates = data_root / "updates"
try:
    data_details = os.lstat(data_root)
    updates_details = os.lstat(updates)
    if (
        not stat.S_ISDIR(data_details.st_mode)
        or not stat.S_ISDIR(updates_details.st_mode)
        or updates_details.st_uid != data_details.st_uid
        or updates_details.st_gid != data_details.st_gid
        or updates_details.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ValueError("unsafe updates directory")
except (OSError, ValueError):
    raise SystemExit("unable to validate updates directory")
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
        "$DATA_ROOT/updates/last_failed_alt_rollback_request.json" \
        "$DATA_ROOT/updates/last_failed_launch.json" \
        "$DATA_ROOT/logs/action_trace.jsonl"; do
        if [[ -f "$state" && ! -L "$state" ]]; then
            chown endpoint-agent:endpoint-agent "$state"
            chmod 0600 "$state"
        fi
    done
}

validate_stable_launcher || exit $?
validate_updates_directory || exit $?
worker_mode=update
if [[ -e "$ROLLBACK_REQUEST" || -L "$ROLLBACK_REQUEST" ]]; then
    worker_mode=rollback
fi
systemctl stop endpoint-agent.service || exit $?

status=0
if [[ "$worker_mode" == rollback ]]; then
    "$STABLE_LAUNCHER" --apply-alt-rollback --no-gui \
        --data-dir "$DATA_ROOT" --install-root "$INSTALL_ROOT" || status=$?
else
    "$STABLE_LAUNCHER" --apply-alt-update --no-gui \
        --data-dir "$DATA_ROOT" --install-root "$INSTALL_ROOT" || status=$?
fi
restore_update_state_owner

# The launcher records handled apply failures and exits successfully. Retain
# this explicit fallback for unexpected process failures too: the old selected
# bundle is safer than a stopped management agent.
systemctl start endpoint-agent.service || exit $?
exit "$status"
