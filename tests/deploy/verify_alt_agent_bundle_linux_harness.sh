#!/usr/bin/env bash
# Exercise the ALT release-bundle installer without writing host paths, using
# only a per-case mktemp root plus local systemctl/useradd stand-ins.
set -euo pipefail
IFS=$'\n\t'

source_installer=${1:?usage: verify_alt_agent_bundle_linux_harness.sh INSTALLER_PATH (with adjacent ALT package assets)}
source_dir=$(dirname "$source_installer")

validate_harness_inputs() {
    local asset label
    for asset in "$source_installer" "$source_dir/default-config.yaml" "$source_dir/endpoint-agent.service" \
        "$source_dir/endpoint-agent-update.service" "$source_dir/endpoint-agent-update.path" \
        "$source_dir/apply-pending-alt-update.sh"; do
        label=$(basename "$asset")
        [[ -f "$asset" && ! -L "$asset" ]] || {
            printf 'ALT bundle Linux harness: missing required harness asset: %s\n' "$label" >&2
            exit 2
        }
        ! LC_ALL=C grep -q $'\r' "$asset" || {
            printf 'ALT bundle Linux harness: required harness asset must use LF: %s\n' "$label" >&2
            exit 2
        }
    done
    bash -n "$source_installer" || {
        echo 'ALT bundle Linux harness: installer syntax is invalid' >&2
        exit 2
    }
}

[[ "$(uname -s)" == Linux ]] || { echo 'ALT bundle Linux harness: skipped (Linux required)'; exit 0; }
validate_harness_inputs
[[ "${EUID}" -eq 0 ]] || { echo 'ALT bundle Linux harness: run with sudo on a Linux test host' >&2; exit 2; }

readonly SERVICE_UID=42420
readonly SERVICE_GID=42420
failures=0

safe_digest() {
    sha256sum -- "$1" | awk '{print $1}'
}

snapshot_live_paths() {
    python3 - <<'PY'
import hashlib
import os

paths = (
    "/opt/.endpoint-agent-stage",
    "/opt/endpoint-agent",
    "/var/lib/endpoint-agent",
    "/etc/endpoint-agent",
    "/var/log/endpoint-agent",
    "/etc/systemd/system/endpoint-agent.service",
    "/etc/systemd/system/endpoint-agent-update.service",
    "/etc/systemd/system/endpoint-agent-update.path",
    "/usr/lib/endpoint-agent",
)
digest = hashlib.sha256()
for path in paths:
    try:
        state = os.lstat(path)
        value = (state.st_dev, state.st_ino, state.st_mode, state.st_uid, state.st_gid,
                 state.st_size, state.st_mtime_ns, state.st_ctime_ns)
    except FileNotFoundError:
        value = None
    digest.update(repr((path, value)).encode("utf-8"))
print(digest.hexdigest())
PY
}

assert_live_paths_unchanged() {
    [[ "$(snapshot_live_paths)" == "$1" ]] || return 1
}

contains_live_root_path() {
    python3 - "$1" <<'PY'
from pathlib import Path
import re
import sys

text = Path(sys.argv[1]).read_text(encoding="utf-8")
path = r"(?:/opt/(?:endpoint-agent|\.endpoint-agent-stage)(?:\.[A-Za-z0-9_-]+)?|/var/lib/endpoint-agent|/etc/endpoint-agent|/var/log/endpoint-agent|/usr/lib/endpoint-agent|/etc/systemd/system(?:/\$(?:SERVICE_NAME|UPDATE_SERVICE_NAME|UPDATE_PATH_NAME)|/endpoint-agent(?:-update)?\.(?:service|path))?|/etc/login\.defs)"
pattern = re.compile(r"(?<![A-Za-z0-9_./-])" + path + r"(?![A-Za-z0-9_.-])")
raise SystemExit(0 if pattern.search(text) else 1)
PY
}

assert_isolated_installer_copy() {
    local root=$1 copy="$root/installer-dir/install-endpoint-agent.sh" prohibited
    for prohibited in \
        'readonly INSTALL_ROOT=/opt/endpoint-agent' \
        'readonly DATA_ROOT=/var/lib/endpoint-agent' \
        'readonly CONFIG_ROOT=/etc/endpoint-agent' \
        'readonly LOG_ROOT=/var/log/endpoint-agent' \
        'readonly UPDATE_HELPER_ROOT=/usr/lib/endpoint-agent' \
        'mktemp -d /opt/.endpoint-agent-stage' \
        'require_trusted_root_parent /opt' \
        'require_trusted_root_parent /etc' \
        'require_trusted_root_parent /var' \
        'require_trusted_root_parent /var/lib' \
        'require_trusted_root_parent /var/log' \
        'require_trusted_root_parent /usr' \
        'require_trusted_root_parent /usr/lib' \
        'require_trusted_root_parent /etc/systemd' \
        'require_trusted_root_parent /etc/systemd/system' \
        '"/etc/systemd/system/$SERVICE_NAME"' \
        '"/etc/systemd/system/$UPDATE_SERVICE_NAME"' \
        '"/etc/systemd/system/$UPDATE_PATH_NAME"'; do
        ! grep -F -- "$prohibited" "$copy" >/dev/null || return 1
    done
    ! contains_live_root_path "$copy" || return 1
}

make_installer_copy() {
    local root=$1
    mkdir -p "$root/installer-dir"
    cp -- "$source_dir/default-config.yaml" "$source_dir/endpoint-agent.service" \
        "$source_dir/endpoint-agent-update.service" "$source_dir/endpoint-agent-update.path" \
        "$source_dir/apply-pending-alt-update.sh" "$root/installer-dir/"
    sed \
        -e "s|/opt/\\.endpoint-agent-stage|$root/opt/.endpoint-agent-stage|g" \
        -e "s|/opt/endpoint-agent|$root/opt/endpoint-agent|g" \
        -e "s|/var/lib/endpoint-agent|$root/var/lib/endpoint-agent|g" \
        -e "s|/etc/endpoint-agent|$root/etc/endpoint-agent|g" \
        -e "s|/var/log/endpoint-agent|$root/var/log/endpoint-agent|g" \
        -e "s|/usr/lib/endpoint-agent|$root/usr/lib/endpoint-agent|g" \
        -e "s|require_trusted_root_parent /etc/systemd/system|require_trusted_root_parent $root/etc/systemd/system|g" \
        -e "s|require_trusted_root_parent /etc/systemd|require_trusted_root_parent $root/etc/systemd|g" \
        -e "s|require_trusted_root_parent /var/lib|require_trusted_root_parent $root/var/lib|g" \
        -e "s|require_trusted_root_parent /var/log|require_trusted_root_parent $root/var/log|g" \
        -e "s|^    require_trusted_root_parent /usr/lib$|    require_trusted_root_parent $root/usr/lib|" \
        -e "s|^    require_trusted_root_parent /usr$|    require_trusted_root_parent $root/usr|" \
        -e "s|require_trusted_root_parent /opt|require_trusted_root_parent $root/opt|g" \
        -e "s|require_trusted_root_parent /etc|require_trusted_root_parent $root/etc|g" \
        -e "s|require_trusted_root_parent /var|require_trusted_root_parent $root/var|g" \
        -e "s|/etc/systemd/system/\\\$SERVICE_NAME|$root/etc/systemd/system/\\\$SERVICE_NAME|g" \
        -e "s|/etc/systemd/system/\\\$UPDATE_SERVICE_NAME|$root/etc/systemd/system/\\\$UPDATE_SERVICE_NAME|g" \
        -e "s|/etc/systemd/system/\\\$UPDATE_PATH_NAME|$root/etc/systemd/system/\\\$UPDATE_PATH_NAME|g" \
        -e "s|/etc/login.defs|$root/etc/login.defs|g" \
        -e "s|-o \\\"\\\$SERVICE_USER\\\" -g \\\"\\\$SERVICE_GROUP\\\"|-o $SERVICE_UID -g $SERVICE_GID|g" \
        "$source_installer" > "$root/installer-dir/install-endpoint-agent.sh"
    chmod 700 "$root/installer-dir/install-endpoint-agent.sh"
}

setup_root() {
    local root=$1
    mkdir -p "$root"/{opt,etc,etc/systemd/system,var,var/lib,var/log,usr,usr/lib,bin,input}
    chown -R root:root "$root/opt" "$root/etc" "$root/var" "$root/usr"
    chmod 755 "$root/opt" "$root/etc" "$root/etc/systemd" "$root/etc/systemd/system" \
        "$root/var" "$root/var/lib" "$root/var/log" "$root/usr" "$root/usr/lib"
    printf 'SYS_UID_MAX 65535\n' > "$root/etc/login.defs"
    cat > "$root/bin/getent" <<EOF
#!/usr/bin/env bash
if [[ -f "$root/account-created" && "\$1" == passwd && "\$2" == endpoint-agent ]]; then
    printf 'endpoint-agent:x:$SERVICE_UID:$SERVICE_GID::/nonexistent:/usr/sbin/nologin\\n'
    exit 0
fi
if [[ -f "$root/account-created" && "\$1" == group && "\$2" == endpoint-agent ]]; then
    printf 'endpoint-agent:x:$SERVICE_GID:\\n'
    exit 0
fi
exit 2
EOF
    cat > "$root/bin/id" <<EOF
#!/usr/bin/env bash
if [[ "\$1" == -u && "\$2" == endpoint-agent ]]; then printf '$SERVICE_UID\\n'; exit 0; fi
if [[ "\$1" == -g && "\$2" == endpoint-agent ]]; then printf '$SERVICE_GID\\n'; exit 0; fi
exec /usr/bin/id "\$@"
EOF
    cat > "$root/bin/useradd" <<EOF
#!/usr/bin/env bash
touch "$root/account-created"
printf 'called\\n' >> "$root/useradd.log"
exit 0
EOF
    cat > "$root/bin/systemctl" <<EOF
#!/usr/bin/env bash
printf '%s\\n' "\$*" >> "$root/systemctl.log"
if [[ "\${ALT_HARNESS_SYSTEMCTL_FAIL:-}" == restart && "\$1" == restart ]]; then exit 1; fi
if [[ "\${ALT_HARNESS_SYSTEMCTL_FAIL:-}" == inactive && "\$1" == is-active ]]; then exit 3; fi
exit 0
EOF
    chmod 700 "$root/bin/getent" "$root/bin/id" "$root/bin/useradd" "$root/bin/systemctl"
}

write_inputs() {
    local root=$1 bundle=$2 version=$3 label=$4 manifest
    mkdir -p "$bundle/pc_agent/_internal"
    printf '#!/usr/bin/env sh\nexit 0\n' > "$bundle/launcher"
    printf '#!/usr/bin/env sh\n# %s\nexit 0\n' "$label" > "$bundle/pc_agent/pc_agent"
    printf 'runtime-%s\n' "$label" > "$bundle/pc_agent/_internal/runtime.dat"
    chmod 755 "$bundle/launcher" "$bundle/pc_agent/pc_agent"
    chmod 644 "$bundle/pc_agent/_internal/runtime.dat"
    manifest=$(python3 - "$bundle" "$version" <<'PY'
import hashlib
import json
import os
import stat
import sys

root, version = sys.argv[1:]
paths = ["launcher", "pc_agent/_internal/runtime.dat", "pc_agent/pc_agent"]
files = []
for path in paths:
    full = os.path.join(root, path)
    with open(full, "rb") as stream:
        digest = hashlib.sha256(stream.read()).hexdigest()
    files.append({"path": path, "sha256": digest, "mode": f"{stat.S_IMODE(os.stat(full).st_mode):04o}"})
print(json.dumps({"schema_version": 1, "version": version, "source_revision": "harness-revision", "files": files}, separators=(",", ":")))
PY
)
    printf '%s\n' "$manifest" > "$bundle/manifest.json"
    chmod 644 "$bundle/manifest.json"
    printf 'one-time-handoff\n' > "$root/input/handoff"
    chmod 600 "$root/input/handoff"
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=endpoint-alt-harness \
        -keyout "$root/input/key" -out "$root/input/ca.crt" >/dev/null 2>&1
    rm -f -- "$root/input/key"
    chmod 600 "$root/input/ca.crt"
}

run_install() {
    local root=$1 bundle=$2 output=$3
    shift 3
    set +e
    PATH="$root/bin:$PATH" "$@" bash "$root/installer-dir/install-endpoint-agent.sh" \
        --endpoint https://endpoint.sosnadmin.local --installation-id alt-test-agent-001 --ca-file "$root/input/ca.crt" \
        --handoff-file "$root/input/handoff" --agent-bundle "$bundle" > "$output" 2>&1
    local status=$?
    set -e
    printf '%s' "$status"
}

emit_safe_failure_diagnostic() {
    local scenario=$1 requested_category=$2 output=$3
    python3 - "$scenario" "$requested_category" "$output" <<'PY'
from pathlib import Path
import sys

scenario, requested_category, output = sys.argv[1:]
try:
    with Path(output).open("rb") as stream:
        captured = stream.read(8192).decode("utf-8", "replace").lower()
except OSError:
    captured = ""

# Never emit the captured text. These fixed labels retain only the failing
# boundary needed to repair a harness stub or rewritten path.
if "fixed destination parent" in captured:
    category, message = "installer-fixed-parent", "fixed_destination_parent"
elif "fixed destination" in captured:
    category, message = "installer-fixed-destination", "fixed_destination"
elif "invalid user" in captured or "service account" in captured:
    category, message = "installer-service-account", "service_account"
elif "service did not become active" in captured:
    category, message = "installer-service-activation", "service_activation"
elif "agent bundle verification" in captured:
    category, message = "installer-bundle-verification", "bundle_verification"
elif "mktemp" in captured or "staging" in captured:
    category, message = "installer-staging", "staging"
elif "permission denied" in captured:
    category, message = "installer-file-permission", "file_permission"
elif "no such file" in captured:
    category, message = "installer-missing-path", "missing_path"
elif captured:
    category, message = requested_category, "redacted"
else:
    category, message = requested_category, "unavailable"

print(f"CASE {scenario} status=failed failure_category={category} last_safe_message={message}")
PY
}

reset_systemctl_log() {
    : > "$1/systemctl.log"
}

assert_no_account_or_selection() {
    local root=$1
    [[ ! -e "$root/useradd.log" ]] || return 1
    [[ ! -e "$root/opt/endpoint-agent/launcher" ]] || return 1
    [[ ! -e "$root/opt/endpoint-agent/current.json" ]] || return 1
}

run_case() {
    local scenario=$1 root bundle status digest first_bundle first_status second_status live_before
    root=$(mktemp -d /tmp/endpoint-alt-bundle.XXXXXX)
    trap 'rm -rf -- "$root"' RETURN
    make_installer_copy "$root"
    assert_isolated_installer_copy "$root" || return 1
    setup_root "$root"
    live_before=$(snapshot_live_paths)
    bundle="$root/input/bundle"
    write_inputs "$root" "$bundle" v1 first
    case "$scenario" in
        valid)
            status=$(run_install "$root" "$bundle" "$root/output")
            if [[ "$status" != 0 ]]; then
                emit_safe_failure_diagnostic "$scenario" "installer-exit" "$root/output"
                return 1
            fi
            [[ -e "$root/useradd.log" ]] || return 1
            [[ "$(python3 - "$root/opt/endpoint-agent/current.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])
PY
)" == v1 ]] || return 1
            ;;
        digest-mismatch)
            printf 'tampered\n' >> "$bundle/pc_agent/_internal/runtime.dat"
            status=$(run_install "$root" "$bundle" "$root/output")
            [[ "$status" != 0 ]] || return 1
            assert_no_account_or_selection "$root" || return 1
            ;;
        bundle-symlink)
            mv "$bundle" "$root/input/bundle.real"
            ln -s "$root/input/bundle.real" "$bundle"
            status=$(run_install "$root" "$bundle" "$root/output")
            [[ "$status" != 0 ]] || return 1
            assert_no_account_or_selection "$root" || return 1
            ;;
        incomplete-onedir)
            rm -rf -- "$bundle/pc_agent/_internal"
            status=$(run_install "$root" "$bundle" "$root/output")
            [[ "$status" != 0 ]] || return 1
            assert_no_account_or_selection "$root" || return 1
            ;;
        activation-failure-rollback)
            first_status=$(run_install "$root" "$bundle" "$root/first-output")
            [[ "$first_status" == 0 ]] || return 1
            first_bundle=$(safe_digest "$root/opt/endpoint-agent/launcher")
            rm -rf -- "$bundle"
            write_inputs "$root" "$bundle" v2 second
            reset_systemctl_log "$root"
            status=$(run_install "$root" "$bundle" "$root/output" env ALT_HARNESS_SYSTEMCTL_FAIL=restart)
            [[ "$status" != 0 ]] || return 1
            grep -Fx -- "restart endpoint-agent.service" "$root/systemctl.log" >/dev/null || return 1
            [[ "$(safe_digest "$root/opt/endpoint-agent/launcher")" == "$first_bundle" ]] || return 1
            [[ ! -e "$root/opt/endpoint-agent/versions/v2" ]] || return 1
            [[ "$(python3 - "$root/opt/endpoint-agent/current.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])
PY
)" == v1 ]] || return 1
            ;;
        idempotent-second-install)
            first_status=$(run_install "$root" "$bundle" "$root/first-output")
            second_status=$(run_install "$root" "$bundle" "$root/output")
            [[ "$first_status" == 0 && "$second_status" == 0 ]] || return 1
            [[ -d "$root/opt/endpoint-agent/versions/v1" ]] || return 1
            [[ "$(find "$root/opt/endpoint-agent/versions" -mindepth 1 -maxdepth 1 -type d | wc -l)" == 1 ]] || return 1
            status=$second_status
            ;;
        *) echo "ALT bundle Linux harness: unknown scenario" >&2; return 2 ;;
    esac
    case "$scenario" in
        valid|activation-failure-rollback|idempotent-second-install)
            assert_live_paths_unchanged "$live_before" || return 1
            ;;
    esac
    digest=$(safe_digest "$bundle/manifest.json")
    printf 'CASE %s status=%s bundle_sha256=%s\n' "$scenario" "$status" "$digest"
    trap - RETURN
    rm -rf -- "$root"
}

for scenario in valid digest-mismatch bundle-symlink incomplete-onedir activation-failure-rollback idempotent-second-install; do
    if ! run_case "$scenario"; then
        failures=$((failures + 1))
        printf 'CASE %s status=failed\n' "$scenario"
    fi
done

(( failures == 0 )) || { echo "ALT bundle Linux harness: $failures cases failed" >&2; exit 1; }
echo 'ALT bundle Linux harness: all cases passed'
