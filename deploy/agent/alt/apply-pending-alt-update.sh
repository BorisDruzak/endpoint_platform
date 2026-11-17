#!/usr/bin/env bash
# Root-owned bridge between the unprivileged agent and immutable release root.
set -u

readonly AGENT_SERVICE=endpoint-agent.service
readonly DATA_ROOT=/var/lib/endpoint-agent
readonly INSTALL_ROOT=/opt/endpoint-agent
readonly STABLE_LAUNCHER=/opt/endpoint-agent/launcher
readonly PENDING_UPDATE=/var/lib/endpoint-agent/updates/pending_alt_update.json
readonly ROLLBACK_REQUEST=/var/lib/endpoint-agent/updates/rollback-request.json
readonly STOP_OWNER=/var/lib/endpoint-agent-update/core-stop
readonly BOOT_ID_FILE=/proc/sys/kernel/random/boot_id

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
import json
import os
import stat
import sys
import uuid
from pathlib import Path

data_root = Path(sys.argv[1])
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

def reject_updates_leaf(data_fd, data_details):
    quarantine = f".rejected-updates.{uuid.uuid4().hex}"
    try:
        os.stat("updates", dir_fd=data_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        os.replace("updates", quarantine, src_dir_fd=data_fd, dst_dir_fd=data_fd)
    os.mkdir("updates", 0o700, dir_fd=data_fd)
    os.chown(
        "updates",
        data_details.st_uid,
        data_details.st_gid,
        dir_fd=data_fd,
        follow_symlinks=False,
    )
    updates_fd = os.open("updates", flags, dir_fd=data_fd)
    try:
        name = "last_failed_alt_rollback_request.json"
        temporary = f".{name}.{uuid.uuid4().hex}.tmp"
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=updates_fd,
        )
        try:
            payload = json.dumps(
                {"reason": "unsafe_alt_updates_directory"},
                separators=(",", ":"),
            ).encode()
            view = memoryview(payload)
            while view:
                view = view[os.write(descriptor, view):]
            os.fchown(descriptor, data_details.st_uid, data_details.st_gid)
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(
            temporary,
            name,
            src_dir_fd=updates_fd,
            dst_dir_fd=updates_fd,
        )
        os.fsync(updates_fd)
    finally:
        os.close(updates_fd)

try:
    data_details = os.lstat(data_root)
    if not stat.S_ISDIR(data_details.st_mode):
        raise ValueError("unsafe data root")
    data_fd = os.open(data_root, flags)
    try:
        try:
            updates_fd = os.open("updates", flags, dir_fd=data_fd)
        except OSError:
            reject_updates_leaf(data_fd, data_details)
            raise SystemExit("rejected unsafe updates directory")
        try:
            updates_details = os.fstat(updates_fd)
        finally:
            os.close(updates_fd)
        if (
            updates_details.st_uid != data_details.st_uid
            or updates_details.st_gid != data_details.st_gid
            or updates_details.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            reject_updates_leaf(data_fd, data_details)
            raise SystemExit("rejected unsafe updates directory metadata")
    finally:
        os.close(data_fd)
except SystemExit:
    raise
except (OSError, ValueError):
    raise SystemExit("unable to validate updates directory")
PY
}

# The root-only StateDirectory is writable under ProtectSystem=strict.
# Commit ownership before systemctl can make Core inactive.
set_stop_owner() {
    python3 - "$STOP_OWNER" "$1" "$BOOT_ID_FILE" <<'PYTHON'
import os
import sys
from pathlib import Path

marker = Path(sys.argv[1])
directory = os.open(marker.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    if sys.argv[2] == "acquire":
        boot = Path(sys.argv[3]).read_bytes()
        with marker.open("xb") as stream:
            stream.write(boot)
            stream.flush()
            os.fsync(stream.fileno())
    else:
        marker.unlink(missing_ok=True)
    os.fsync(directory)
finally:
    os.close(directory)
PYTHON
}

core_enablement() {
    local state
    state=$(timeout 5s systemctl is-enabled "$AGENT_SERVICE")
    case "$state" in
        enabled|enabled-runtime) return 0 ;;
        disabled|masked|masked-runtime|static|not-found) return 1 ;;
        *) return 2 ;;
    esac
}

recover_service() {
    [[ -f "$STOP_OWNER" ]] || return 0
    local boot owner system_state
    boot=$(cat "$BOOT_ID_FILE") || return 1
    owner=$(cat "$STOP_OWNER") || return 1
    # On a new boot systemd follows normal Core enablement. A receipt
    # from a previous boot cannot override current administrative state.
    if [[ -z "$boot" || "$owner" != "$boot" ]]; then
        set_stop_owner release
        return
    fi
    system_state=$(timeout 5s systemctl is-system-running)
    case "$system_state" in
        running|degraded|starting) ;;
        stopping) return 0 ;;
        *) return 1 ;;
    esac
    core_enablement
    case "$?" in
        0) ;;
        1) set_stop_owner release; return $? ;;
        *) return 1 ;;
    esac
    # A stop queued by the operator or shutdown must win over recovery.
    timeout 45s systemctl --job-mode=fail start "$AGENT_SERVICE" || return 1
    timeout 5s systemctl is-active --quiet "$AGENT_SERVICE" || return 1
    set_stop_owner release
}

if [[ "${1:-}" == --recover-service ]]; then
    recover_service
    exit $?
fi
if [[ "$#" != 0 ]]; then
    exit 2
fi

validate_stable_launcher || exit $?
if [[ -f "$STOP_OWNER" ]]; then
    recover_service || exit $?
fi
core_enablement
case "$?" in
    0) ;;
    1) exit 0 ;;
    *) exit 1 ;;
esac
systemctl is-active --quiet "$AGENT_SERVICE" || exit 0
if [[ -f "$PENDING_UPDATE" && ! -e "$ROLLBACK_REQUEST" && ! -L "$ROLLBACK_REQUEST" ]]; then
    "$STABLE_LAUNCHER" --preflight-alt-update --no-gui \
        --data-dir "$DATA_ROOT" --install-root "$INSTALL_ROOT" || exit $?
fi
set_stop_owner acquire || exit $?
systemctl --job-mode=fail stop "$AGENT_SERVICE" || exit $?
[[ "$(systemctl show --property=ActiveState --value "$AGENT_SERVICE")" == inactive ]] || exit 1
validate_updates_directory || exit $?
worker_mode=update
if [[ -e "$ROLLBACK_REQUEST" || -L "$ROLLBACK_REQUEST" ]]; then
    worker_mode=rollback
fi
status=0
if [[ "$worker_mode" == rollback ]]; then
    "$STABLE_LAUNCHER" --apply-alt-rollback --no-gui \
        --data-dir "$DATA_ROOT" --install-root "$INSTALL_ROOT" || status=$?
else
    "$STABLE_LAUNCHER" --apply-alt-update --no-gui \
        --data-dir "$DATA_ROOT" --install-root "$INSTALL_ROOT" || status=$?
fi
exit "$status"
