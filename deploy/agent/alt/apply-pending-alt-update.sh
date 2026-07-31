#!/usr/bin/env bash
# Root-owned bridge between the unprivileged agent and immutable release root.
set -u

readonly AGENT_SERVICE=endpoint-agent.service
readonly LAUNCHER=/opt/endpoint-agent/launcher
readonly DATA_ROOT=/var/lib/endpoint-agent
readonly INSTALL_ROOT=/opt/endpoint-agent

systemctl stop endpoint-agent.service || exit $?

status=0
"$LAUNCHER" --apply-alt-update --no-gui \
    --data-dir "$DATA_ROOT" --install-root "$INSTALL_ROOT" || status=$?

# The launcher records handled apply failures and exits successfully. Retain
# this explicit fallback for unexpected process failures too: the old selected
# bundle is safer than a stopped management agent.
systemctl start endpoint-agent.service || exit $?
exit "$status"
