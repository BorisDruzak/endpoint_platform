#!/usr/bin/env bash
# Root-owned bridge between the unprivileged agent and immutable release root.
set -u

readonly AGENT_SERVICE=endpoint-agent.service
readonly LAUNCHER=/opt/endpoint-agent/launcher
readonly DATA_ROOT=/var/lib/endpoint-agent
readonly INSTALL_ROOT=/opt/endpoint-agent

restore_update_state_owner() {
    local state
    # The root worker may create a terminal history file. Return only those
    # fixed, regular state files to the service account; never recursively
    # chown an agent-writable tree.
    for state in \
        "$DATA_ROOT/updates/update_history.json" \
        "$DATA_ROOT/updates/last_failed_pending_update.json"; do
        if [[ -f "$state" && ! -L "$state" ]]; then
            chown endpoint-agent:endpoint-agent "$state"
            chmod 0600 "$state"
        fi
    done
}

systemctl stop endpoint-agent.service || exit $?

status=0
"$LAUNCHER" --apply-alt-update --no-gui \
    --data-dir "$DATA_ROOT" --install-root "$INSTALL_ROOT" || status=$?
restore_update_state_owner

# The launcher records handled apply failures and exits successfully. Retain
# this explicit fallback for unexpected process failures too: the old selected
# bundle is safer than a stopped management agent.
systemctl start endpoint-agent.service || exit $?
exit "$status"
