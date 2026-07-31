#!/usr/bin/env bash
# Offline installer for the Endpoint Platform ALT pilot agent.
# It deliberately accepts only operator-supplied local files; it never fetches code,
# certificates, or credentials from a network location.
set -euo pipefail
IFS=$'\n\t'
umask 077

readonly INSTALL_ROOT=/opt/endpoint-agent
readonly DATA_ROOT=/var/lib/endpoint-agent
readonly CONFIG_ROOT=/etc/endpoint-agent
readonly LOG_ROOT=/var/log/endpoint-agent
readonly SERVICE_NAME=endpoint-agent.service
readonly SERVICE_USER=endpoint-agent
readonly SERVICE_GROUP=endpoint-agent
readonly LAUNCHER_TARGET="${INSTALL_ROOT}/launcher"
readonly VERSIONS_ROOT="${INSTALL_ROOT}/versions"
readonly CURRENT_TARGET="${INSTALL_ROOT}/current.json"
readonly CONFIG_TARGET="${CONFIG_ROOT}/config.yaml"
readonly CA_TARGET="${CONFIG_ROOT}/ca.crt"
readonly HANDOFF_TARGET="${CONFIG_ROOT}/provisioning-claim"
readonly PERMANENT_CREDENTIAL_TARGET="${DATA_ROOT}/device-credential"
readonly HANDOFF_REQUEST_TARGET="${DATA_ROOT}/claim-removal-request.json"
readonly CLAIM_CREDENTIAL_NAME=endpoint-enrollment-claim
readonly HANDOFF_REQUEST_SCHEMA_VERSION=endpoint_claim_removal_request_v1

endpoint=''
installation_id=''
ca_file=''
handoff_file=''
agent_bundle=''
bundle_version=''
bundle_revision=''
release_stage=''
release_backup=''
release_version_target=''
release_version_was_new=false
previous_launcher_backed_up=false
previous_current_backed_up=false
launcher_published=false
current_published=false
dry_run=false
inspect_layout=false
finalize_handoff=false
prepare_service_account=false

die() {
    printf 'endpoint-agent installer: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'USAGE'
Usage:
  install-endpoint-agent.sh --endpoint https://endpoint.example --installation-id ID --ca-file FILE \
    --handoff-file FILE --agent-bundle DIRECTORY [--dry-run]
  install-endpoint-agent.sh --inspect-layout
  install-endpoint-agent.sh --prepare-service-account
  install-endpoint-agent.sh --finalize-handoff

The release bundle, CA and one-time provisioning handoff must already be local.
No network download is performed by this installer.
USAGE
}

print_layout() {
    printf '%s\n' "$INSTALL_ROOT" "$DATA_ROOT" "$CONFIG_ROOT" "$LOG_ROOT"
}

require_root() {
    [[ "${EUID}" -eq 0 ]] || die 'must run as root'
}

require_https_endpoint() {
    [[ "$endpoint" =~ ^https://[^/[:space:]]+(/[^[:space:]]*)?$ ]] || \
        die 'endpoint must be an explicit HTTPS URL'
}

require_installation_id() {
    python3 - "$installation_id" <<'PY' || die 'installation ID must use 1-128 ASCII letters, digits, dots, underscores, or hyphens'
import sys
import re

value = sys.argv[1]
valid = (
    re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value) is not None
)
raise SystemExit(0 if valid else 1)
PY
}

require_regular_file() {
    local label=$1 path=$2
    require_safe_parent_components "$path"
    [[ -f "$path" && ! -L "$path" ]] || die "$label must be a regular local file"
}

path_is_symlink() {
    [[ -L "$1" ]]
}

require_safe_parent_components() {
    local path=$1 parent component current
    [[ "$path" == /* ]] || die 'security-sensitive path must be absolute'
    parent=${path%/*}
    [[ -n "$parent" && "$parent" != "$path" ]] || die 'security-sensitive path has no parent'
    current=/
    IFS=/ read -r -a _safe_path_components <<< "${parent#/}"
    for component in "${_safe_path_components[@]}"; do
        [[ -n "$component" ]] || continue
        if [[ "$current" == / ]]; then
            current="/$component"
        else
            current="$current/$component"
        fi
        [[ -d "$current" ]] && ! path_is_symlink "$current" || \
            die "security-sensitive path traverses an unsafe parent: $current"
    done
}

require_safe_existing_parent_components() {
    local path=$1 parent component current
    [[ "$path" == /* ]] || die 'security-sensitive path must be absolute'
    parent=${path%/*}
    [[ -n "$parent" && "$parent" != "$path" ]] || die 'security-sensitive path has no parent'
    current=/
    IFS=/ read -r -a _safe_path_components <<< "${parent#/}"
    for component in "${_safe_path_components[@]}"; do
        [[ -n "$component" ]] || continue
        if [[ "$current" == / ]]; then
            current="/$component"
        else
            current="$current/$component"
        fi
        if [[ ! -e "$current" && ! -L "$current" ]]; then
            continue
        fi
        [[ -d "$current" ]] && ! path_is_symlink "$current" || \
            die "security-sensitive path traverses an unsafe parent: $current"
    done
}

root_owner_uid() {
    id -u root
}

root_owner_gid() {
    id -g root
}

service_owner_uid() {
    id -u "$SERVICE_USER"
}

service_owner_gid() {
    getent group "$SERVICE_GROUP" | awk -F: 'NR == 1 { print $3 }'
}

file_owner_uid() {
    stat -c %u -- "$1"
}

file_owner_gid() {
    stat -c %g -- "$1"
}

file_mode() {
    stat -c %a -- "$1"
}

require_exact_owner_and_mode() {
    local label=$1 path=$2 ownership=$3 expected_mode=$4 owner group expected_owner expected_group mode
    owner=$(file_owner_uid "$path") || die "$label owner could not be read"
    group=$(file_owner_gid "$path") || die "$label group could not be read"
    mode=$(file_mode "$path") || die "$label mode could not be read"
    [[ "$mode" == "$expected_mode" ]] || die "$label ($path) must have mode $expected_mode"
    case "$ownership" in
        root)
            expected_owner=$(root_owner_uid) || die 'root account lookup failed'
            [[ "$owner" == "$expected_owner" ]] || die "$label must be owned by root"
            ;;
        service)
            expected_owner=$(service_owner_uid) || die 'service account lookup failed'
            expected_group=$(service_owner_gid)
            [[ "$expected_group" =~ ^[0-9]+$ ]] || die 'service group lookup failed'
            [[ "$owner" == "$expected_owner" && "$group" == "$expected_group" ]] || \
                die "$label must be owned by $SERVICE_USER:$SERVICE_GROUP"
            ;;
        *) die 'invalid fixed destination ownership class' ;;
    esac
}

require_trusted_root_parent() {
    local path=$1 mode owner group group_digit other_digit
    [[ -d "$path" ]] && ! path_is_symlink "$path" || \
        die 'fixed destination parent is missing or unsafe'
    owner=$(file_owner_uid "$path") || die 'fixed destination parent owner could not be read'
    group=$(file_owner_gid "$path") || die 'fixed destination parent group could not be read'
    mode=$(file_mode "$path") || die 'fixed destination parent mode could not be read'
    [[ "$owner" == "$(root_owner_uid)" && "$group" == "$(root_owner_gid)" ]] || \
        die 'fixed destination parent must be owned by root:root'
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || die 'fixed destination parent has invalid mode'
    group_digit=${mode: -2:1}
    other_digit=${mode: -1}
    (( (10#$group_digit & 2) == 0 && (10#$other_digit & 2) == 0 )) || \
        die 'fixed destination parent must not be group or world writable'
}

validate_fixed_directory_or_absent() {
    local path=$1 ownership=$2 expected_mode=$3
    # Nested fixed roots (versions/ below the install root) may not exist on a
    # first install.  Validate every existing parent and validate the complete
    # chain once the directory itself exists.
    require_safe_existing_parent_components "$path"
    path_is_symlink "$path" && die 'fixed destination directory must not be a symlink'
    [[ ! -e "$path" ]] && return
    require_safe_parent_components "$path"
    [[ -d "$path" ]] || die 'fixed destination must be a directory'
    require_exact_owner_and_mode 'fixed destination directory' "$path" "$ownership" "$expected_mode"
}

validate_fixed_regular_target_or_absent() {
    local path=$1 ownership=$2 expected_mode=$3
    path_is_symlink "$path" && die 'fixed destination file must not be a symlink'
    if [[ ! -e "$path" ]]; then
        require_safe_existing_parent_components "$path"
        return
    fi
    require_safe_parent_components "$path"
    [[ -f "$path" ]] || die 'fixed destination must be a regular file'
    require_exact_owner_and_mode 'fixed destination file' "$path" "$ownership" "$expected_mode"
}

validate_install_destinations() {
    # These existing system parents are deliberately not created by the
    # installer.  Validating them first prevents every later write from
    # traversing a pre-existing attacker-controlled link or writable directory.
    require_trusted_root_parent /opt
    require_trusted_root_parent /etc
    require_trusted_root_parent /var
    require_trusted_root_parent /var/lib
    require_trusted_root_parent /var/log
    require_trusted_root_parent /etc/systemd
    require_trusted_root_parent /etc/systemd/system

    validate_fixed_directory_or_absent "$INSTALL_ROOT" root 755
    validate_fixed_directory_or_absent "$VERSIONS_ROOT" root 755
    validate_fixed_directory_or_absent "$CONFIG_ROOT" root 755
    validate_fixed_directory_or_absent "$DATA_ROOT" service 750
    validate_fixed_directory_or_absent "$LOG_ROOT" service 750
    validate_fixed_regular_target_or_absent "$LAUNCHER_TARGET" root 755
    validate_fixed_regular_target_or_absent "$CURRENT_TARGET" root 644
    validate_fixed_regular_target_or_absent "$CONFIG_TARGET" root 600
    validate_fixed_regular_target_or_absent "$CA_TARGET" root 600
    validate_fixed_regular_target_or_absent "$HANDOFF_TARGET" root 600
    validate_fixed_regular_target_or_absent "$PERMANENT_CREDENTIAL_TARGET" service 600
    validate_fixed_regular_target_or_absent "$HANDOFF_REQUEST_TARGET" service 600
    validate_fixed_regular_target_or_absent "/etc/systemd/system/$SERVICE_NAME" root 644
}

require_root_secret_file() {
    local label=$1 path=$2
    require_regular_file "$label" "$path"
    require_exact_owner_and_mode "$label" "$path" root 600
    [[ -s "$path" ]] || die "$label must not be empty"
}

is_nonlogin_shell() {
    case "$1" in
        /usr/sbin/nologin|/sbin/nologin) return 0 ;;
        *) return 1 ;;
    esac
}

system_uid_max() {
    local configured
    configured=$(awk '$1 == "SYS_UID_MAX" && $2 ~ /^[0-9]+$/ { print $2; exit }' /etc/login.defs 2>/dev/null || true)
    printf '%s\n' "${configured:-999}"
}

validate_existing_service_account() {
    local account_entry group_entry account_name account_uid account_gid account_home account_shell
    local group_name group_gid system_max
    account_entry=$(getent passwd "$SERVICE_USER") || die 'service account lookup failed'
    group_entry=$(getent group "$SERVICE_GROUP") || die 'service group lookup failed'
    IFS=: read -r account_name _ account_uid account_gid _ account_home account_shell <<< "$account_entry"
    IFS=: read -r group_name _ group_gid _ <<< "$group_entry"
    [[ "$account_name" == "$SERVICE_USER" ]] || die 'service account name is conflicting'
    [[ "$group_name" == "$SERVICE_GROUP" ]] || die 'service group name is conflicting'
    [[ "$account_uid" =~ ^[1-9][0-9]*$ ]] || die 'service account must have a non-root numeric UID'
    system_max=$(system_uid_max)
    [[ "$account_uid" -le "$system_max" ]] || die 'service account must be a system account'
    [[ "$account_gid" =~ ^[0-9]+$ && "$group_gid" =~ ^[0-9]+$ ]] || die 'service account group must have a numeric GID'
    [[ "$account_gid" == "$group_gid" ]] || die 'service account primary group is conflicting'
    [[ "$account_home" == '/nonexistent' ]] || die 'service account home is conflicting'
    is_nonlogin_shell "$account_shell" || die 'service account must use a non-login shell'
}

require_service_secret_file() {
    local label=$1 path=$2
    require_regular_file "$label" "$path"
    require_exact_owner_and_mode "$label" "$path" service 600
    [[ -s "$path" ]] || die "$label must not be empty"
}

require_opaque_permanent_credential() {
    local contents size
    require_service_secret_file 'permanent credential' "$PERMANENT_CREDENTIAL_TARGET"
    size=$(wc -c < "$PERMANENT_CREDENTIAL_TARGET")
    [[ "$size" == '43' ]] || die 'permanent credential has an invalid length'
    contents=$(<"$PERMANENT_CREDENTIAL_TARGET")
    [[ "$contents" =~ ^[A-Za-z0-9_-]{43}$ ]] || \
        die 'permanent credential has an invalid format'
}

validate_handoff_request() {
    local request request_pattern credential_digest actual_digest
    require_service_secret_file 'claim-removal request' "$HANDOFF_REQUEST_TARGET"
    request=$(<"$HANDOFF_REQUEST_TARGET")
    [[ ${#request} -le 512 ]] || die 'claim-removal request is too large'
    request_pattern='^\{"claim_credential_name":"endpoint-enrollment-claim","credential_path":"/var/lib/endpoint-agent/device-credential","credential_sha256":"([0-9a-f]{64})","device_id":"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}","schema_version":"endpoint_claim_removal_request_v1"\}$'
    [[ "$request" =~ $request_pattern ]] || \
        die 'claim-removal request has an invalid schema or binding'
    credential_digest=${BASH_REMATCH[1]}
    actual_digest=$(sha256sum -- "$PERMANENT_CREDENTIAL_TARGET" | awk '{ print $1 }')
    [[ "$actual_digest" == "$credential_digest" ]] || \
        die 'claim-removal request does not prove the permanent credential'
}

validate_ca() {
    require_regular_file 'CA file' "$ca_file"
    command -v openssl >/dev/null 2>&1 || die 'openssl is required to validate the CA file'
    openssl x509 -in "$ca_file" -noout >/dev/null 2>&1 || die 'CA file is not a PEM certificate'
    openssl verify -CAfile "$ca_file" "$ca_file" >/dev/null 2>&1 || \
        die 'CA file does not verify as a trust anchor'
}

verify_agent_bundle() {
    # Python's lstat-based walk gives this security boundary one unambiguous
    # interpretation; shell globbing must never decide which payload is trusted.
    local bundle=${1:-$agent_bundle} verified
    require_safe_parent_components "$bundle"
    [[ -d "$bundle" && ! -L "$bundle" ]] || \
        die 'agent bundle must be a local directory, not a symbolic link'
    command -v python3 >/dev/null 2>&1 || die 'python3 is required to verify the agent bundle'
    verified=$(python3 - "$bundle" <<'PY'
import hashlib
import json
import os
import re
import stat
import sys

VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
REVISION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MODE = re.compile(r"[0-7]{4}\Z")

def fail(message):
    raise ValueError(message)

def load_json_no_duplicates(path):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                fail("manifest contains a duplicate key")
            value[key] = item
        return value
    with open(path, "r", encoding="utf-8") as stream:
        return json.load(stream, object_pairs_hook=pairs)

def safe_relative(path):
    if not isinstance(path, str) or not path or path.startswith("/"):
        fail("manifest path traversal")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        fail("manifest path traversal")
    if path != "launcher" and not path.startswith("pc_agent/"):
        fail("unexpected manifest payload path")
    return path

def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()

def collect(root, relative=""):
    actual = {}
    with os.scandir(root) as entries:
        for entry in entries:
            name = entry.name if not relative else relative + "/" + entry.name
            entry_stat = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(entry_stat.st_mode):
                fail("symbolic link is not allowed: " + name)
            if stat.S_ISREG(entry_stat.st_mode):
                actual[name] = entry
            elif stat.S_ISDIR(entry_stat.st_mode):
                actual.update(collect(entry.path, name))
            else:
                fail("unexpected nonregular bundle entry: " + name)
    return actual

try:
    root = os.path.abspath(sys.argv[1])
    root_stat = os.lstat(root)
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        fail("agent bundle must be a directory")
    top = {entry.name: entry for entry in os.scandir(root)}
    if set(top) != {"launcher", "pc_agent", "manifest.json"}:
        fail("unexpected bundle entry or incomplete bundle top-level tree")
    manifest_entry = top["manifest.json"]
    if manifest_entry.is_symlink() or not manifest_entry.is_file(follow_symlinks=False):
        fail("manifest.json must be a regular file")
    if manifest_entry.stat(follow_symlinks=False).st_size > 1024 * 1024:
        fail("manifest.json is too large")
    manifest = load_json_no_duplicates(manifest_entry.path)
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version", "version", "source_revision", "files"
    }:
        fail("manifest has an invalid schema")
    if manifest["schema_version"] != 1:
        fail("manifest schema_version must be 1")
    version = manifest["version"]
    revision = manifest["source_revision"]
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        fail("manifest version is invalid")
    if not isinstance(revision, str) or not REVISION.fullmatch(revision):
        fail("manifest source_revision is invalid")
    files = manifest["files"]
    if not isinstance(files, list) or not files:
        fail("manifest files must be a nonempty list")
    expected = {}
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "mode"}:
            fail("manifest file entry has an invalid schema")
        path = safe_relative(item["path"])
        if path in expected:
            fail("manifest contains a duplicate payload path")
        if not isinstance(item["sha256"], str) or not SHA256.fullmatch(item["sha256"]):
            fail("manifest digest is invalid")
        if not isinstance(item["mode"], str) or not MODE.fullmatch(item["mode"]):
            fail("manifest mode is invalid")
        expected[path] = item
    if list(expected) != sorted(expected):
        fail("manifest payload paths must be sorted")
    if {"launcher", "pc_agent/pc_agent"} - set(expected):
        fail("missing manifest payload entry")
    launcher = top["launcher"]
    agent_root = top["pc_agent"]
    if launcher.is_symlink() or not launcher.is_file(follow_symlinks=False):
        fail("launcher must be a regular file")
    if agent_root.is_symlink() or not agent_root.is_dir(follow_symlinks=False):
        fail("pc_agent must be a directory")
    actual = {"launcher": launcher}
    actual.update(collect(agent_root.path, "pc_agent"))
    if set(actual) != set(expected):
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        fail("missing manifest payload" if missing else "unexpected bundle entry: " + extra[0])
    for path, item in expected.items():
        entry = actual[path]
        entry_stat = entry.stat(follow_symlinks=False)
        actual_mode = f"{stat.S_IMODE(entry_stat.st_mode):04o}"
        if actual_mode != item["mode"]:
            fail("mode mismatch: " + path)
        if digest(entry.path) != item["sha256"]:
            fail("digest mismatch: " + path)
    for executable in ("launcher", "pc_agent/pc_agent"):
        if not actual[executable].stat(follow_symlinks=False).st_mode & 0o111:
            fail("required payload executable is not executable: " + executable)
except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
    print("agent bundle verification: " + str(error), file=sys.stderr)
    raise SystemExit(1)

print(version)
print(revision)
PY
) || die 'agent bundle verification failed'
    mapfile -t _bundle_details <<< "$verified"
    [[ ${#_bundle_details[@]} -eq 2 ]] || die 'agent bundle verifier returned invalid release metadata'
    bundle_version=${_bundle_details[0]}
    bundle_revision=${_bundle_details[1]}
}

validate_inputs() {
    require_https_endpoint
    require_installation_id
    validate_ca
    require_root_secret_file 'one-time provisioning handoff' "$handoff_file"
}

ensure_service_account() {
    if getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
        validate_existing_service_account
        return
    fi
    if getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
        die 'existing group without dedicated service account'
    fi
    command -v useradd >/dev/null 2>&1 || die 'useradd is required to create the service account'
    useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin "$SERVICE_USER"
    validate_existing_service_account
}

render_config() {
    local destination=$1
    awk -v endpoint_value="$endpoint" -v installation_value="$installation_id" '
        { gsub(/__ENDPOINT_URL__/, endpoint_value); gsub(/__INSTALLATION_ID__/, installation_value); print }
    ' "$(dirname "$0")/default-config.yaml" > "$destination"
}

fsync_tree() {
    python3 - "$1" <<'PY'
import os
import stat
import sys

root = sys.argv[1]
for directory, dirs, files in os.walk(root, followlinks=False):
    for name in dirs + files:
        path = os.path.join(directory, name)
        if stat.S_ISLNK(os.lstat(path).st_mode):
            raise SystemExit("refusing to fsync a symbolic link")
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
PY
}

fsync_path() {
    python3 - "$1" <<'PY'
import os
import sys

descriptor = os.open(sys.argv[1], os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

verify_existing_release_identity() {
    python3 - "$1" "$2" <<'PY'
import hashlib
import os
import stat
import sys

def tree(root):
    entries = {}
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in dirs + names:
            path = os.path.join(directory, name)
            entry = os.lstat(path)
            if stat.S_ISLNK(entry.st_mode):
                raise ValueError("symbolic link")
            relative = os.path.relpath(path, root)
            if stat.S_ISREG(entry.st_mode):
                digest_value = hashlib.sha256()
                with open(path, "rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest_value.update(chunk)
                digest = digest_value.hexdigest()
                entries[relative] = ("file", stat.S_IMODE(entry.st_mode), digest)
            elif stat.S_ISDIR(entry.st_mode):
                entries[relative] = ("directory", stat.S_IMODE(entry.st_mode))
            else:
                raise ValueError("nonregular entry")
    return entries

try:
    raise SystemExit(0 if tree(sys.argv[1]) == tree(sys.argv[2]) else 1)
except (OSError, ValueError):
    raise SystemExit(1)
PY
}

read_previous_selection() {
    local prior
    [[ ! -e "$CURRENT_TARGET" ]] && return
    prior=$(python3 - "$CURRENT_TARGET" <<'PY'
import json
import re
import sys

version = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
revision = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
with open(sys.argv[1], encoding="utf-8") as stream:
    current = json.load(stream)
if not isinstance(current, dict) or set(current) != {"schema_version", "version", "source_revision"}:
    raise SystemExit(1)
if current["schema_version"] != 1 or not version.fullmatch(current["version"]) or not revision.fullmatch(current["source_revision"]):
    raise SystemExit(1)
print(current["version"])
PY
) || die 'existing current selection is invalid'
    [[ -d "$VERSIONS_ROOT/$prior/pc_agent" && ! -L "$VERSIONS_ROOT/$prior" && ! -L "$VERSIONS_ROOT/$prior/pc_agent" ]] || \
        die 'existing current selection is incomplete or unsafe'
}

backup_previous_selection() {
    # The prior version directory stays immutable in versions/.  Only the two
    # selectors are moved aside, so rollback restores a complete prior release.
    release_backup="$release_stage/previous-selection"
    mkdir -m 0700 "$release_backup" || return 1
    read_previous_selection
    if [[ -e "$LAUNCHER_TARGET" ]]; then
        mv -f "$LAUNCHER_TARGET" "$release_backup/launcher" || return 1
        previous_launcher_backed_up=true
    fi
    if [[ -e "$CURRENT_TARGET" ]]; then
        mv -f "$CURRENT_TARGET" "$release_backup/current.json" || return 1
        previous_current_backed_up=true
    fi
}

rollback_release_selection() {
    local rollback_failed=false
    if [[ "$release_version_was_new" == true && -n "$release_version_target" ]]; then
        rm -rf -- "$release_version_target" || rollback_failed=true
    fi
    if [[ "$launcher_published" == true ]]; then
        rm -f -- "$LAUNCHER_TARGET" || rollback_failed=true
    fi
    if [[ "$current_published" == true ]]; then
        rm -f -- "$CURRENT_TARGET" || rollback_failed=true
    fi
    if [[ "$previous_launcher_backed_up" == true ]]; then
        [[ ! -e "$LAUNCHER_TARGET" ]] || rollback_failed=true
        mv -f "$release_backup/launcher" "$LAUNCHER_TARGET" || rollback_failed=true
    fi
    if [[ "$previous_current_backed_up" == true ]]; then
        [[ ! -e "$CURRENT_TARGET" ]] || rollback_failed=true
        mv -f "$release_backup/current.json" "$CURRENT_TARGET" || rollback_failed=true
    fi
    fsync_path "$VERSIONS_ROOT" || rollback_failed=true
    fsync_path "$INSTALL_ROOT" || rollback_failed=true
    [[ "$rollback_failed" == false ]] || die 'release activation failed and rollback could not be completed'
}

cleanup_release_backup() {
    [[ -n "$release_stage" ]] && rm -rf -- "$release_stage"
    release_stage=''
    release_backup=''
    release_version_target=''
    release_version_was_new=false
    previous_launcher_backed_up=false
    previous_current_backed_up=false
    launcher_published=false
    current_published=false
}

publish_release_selection() {
    local launcher_stage=$1 current_stage=$2
    # current.json is the durable selector.  It is not published until the
    # promoted version and its parent are fsynced, and the launcher is durable.
    fsync_tree "$release_version_target" || return 1
    fsync_path "$VERSIONS_ROOT" || return 1
    backup_previous_selection || return 1
    mv -f "$launcher_stage" "$LAUNCHER_TARGET" || return 1
    launcher_published=true
    fsync_path "$INSTALL_ROOT" || return 1
    mv -f "$current_stage.secure" "$CURRENT_TARGET" || return 1
    current_published=true
    fsync_path "$INSTALL_ROOT"
}

install_atomically() {
    local bundle_stage version_stage version_target launcher_stage current_stage
    local config_stage ca_stage handoff_stage service_stage
    validate_install_destinations
    release_stage=$(mktemp -d /opt/.endpoint-agent-stage.XXXXXX)
    trap 'rm -rf -- "$release_stage"' RETURN

    bundle_stage="$release_stage/bundle"
    version_stage="$release_stage/version"
    config_stage="$release_stage/config.yaml"
    ca_stage="$release_stage/ca.crt"
    handoff_stage="$release_stage/provisioning-claim"
    service_stage="$release_stage/$SERVICE_NAME"
    launcher_stage="$release_stage/launcher"
    current_stage="$release_stage/current.json"

    mkdir -m 0700 "$bundle_stage"
    cp -a -- "$agent_bundle/." "$bundle_stage/"
    chown -R root:root "$bundle_stage"
    verify_agent_bundle "$bundle_stage"
    fsync_tree "$bundle_stage"

    mkdir -m 0755 "$version_stage"
    mv -f "$bundle_stage/pc_agent" "$version_stage/pc_agent"
    cp -a -- "$bundle_stage/launcher" "$version_stage/launcher"
    mv -f "$bundle_stage/launcher" "$launcher_stage"
    install -o root -g root -m 0644 "$bundle_stage/manifest.json" "$version_stage/manifest.json"
    printf '{"schema_version":1,"source_revision":"%s","version":"%s"}\n' \
        "$bundle_revision" "$bundle_version" > "$current_stage"
    install -o root -g root -m 0644 "$current_stage" "$current_stage.secure"

    render_config "$config_stage"
    install -o root -g root -m 0600 "$config_stage" "$config_stage.secure"
    install -o root -g root -m 0600 "$ca_file" "$ca_stage"
    install -o root -g root -m 0600 "$handoff_file" "$handoff_stage"
    install -o root -g root -m 0644 "$(dirname "$0")/endpoint-agent.service" "$service_stage"
    fsync_tree "$release_stage"

    install -d -o root -g root -m 0755 "$INSTALL_ROOT" "$VERSIONS_ROOT" "$CONFIG_ROOT"
    install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0750 "$DATA_ROOT" "$LOG_ROOT"
    validate_install_destinations
    version_target="$VERSIONS_ROOT/$bundle_version"
    release_version_target="$version_target"
    if [[ -e "$version_target" || -L "$version_target" ]]; then
        [[ -d "$version_target" && ! -L "$version_target" ]] || die 'existing release version is unsafe'
        verify_existing_release_identity "$version_target" "$version_stage" || \
            die 'existing release version does not match the verified bundle'
        rm -rf -- "$version_stage"
    else
        mv -f "$version_stage" "$version_target"
        release_version_was_new=true
    fi
    mv -f "$config_stage.secure" "$CONFIG_TARGET"
    mv -f "$ca_stage" "$CA_TARGET"
    mv -f "$handoff_stage" "$HANDOFF_TARGET"
    mv -f "$service_stage" "/etc/systemd/system/$SERVICE_NAME"
    if ! publish_release_selection "$launcher_stage" "$current_stage"; then
        rollback_release_selection
        cleanup_release_backup
        trap - RETURN
        die 'could not atomically select the verified release bundle'
    fi
    trap - RETURN
}

install_package() {
    validate_inputs
    verify_agent_bundle
    if [[ "$dry_run" == true ]]; then
        printf 'dry-run: validated local HTTPS endpoint, CA, handoff and agent bundle\n'
        return
    fi
    require_root
    validate_install_destinations
    ensure_service_account
    install_atomically
    if ! command -v systemctl >/dev/null 2>&1 || ! systemctl daemon-reload || \
        ! systemctl enable endpoint-agent.service || ! systemctl restart endpoint-agent.service || \
        ! systemctl is-active --quiet endpoint-agent.service; then
        rollback_release_selection
        cleanup_release_backup
        die 'service did not become active'
    fi
    cleanup_release_backup
}

finalize_handoff() {
    require_root
    validate_existing_service_account
    validate_install_destinations
    if [[ ! -e "$HANDOFF_REQUEST_TARGET" && ! -L "$HANDOFF_REQUEST_TARGET" ]]; then
        if [[ ! -e "$HANDOFF_TARGET" && ! -L "$HANDOFF_TARGET" ]]; then
            printf 'one-time provisioning handoff was already finalized\n'
            return
        fi
        die 'no verified claim-removal request exists'
    fi
    require_opaque_permanent_credential
    validate_handoff_request
    if [[ -e "$HANDOFF_TARGET" || -L "$HANDOFF_TARGET" ]]; then
        require_root_secret_file 'installed provisioning handoff' "$HANDOFF_TARGET"
    fi
    # These are the only state-changing operations.  Both locations are fixed
    # constants, validated immediately above, and no caller-supplied pathname
    # can reach this finalizer.
    rm -f -- "$HANDOFF_TARGET" "$HANDOFF_REQUEST_TARGET"
    printf 'one-time provisioning handoff finalized after verified credential proof\n'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --endpoint) endpoint=${2:-}; shift 2 ;;
        --installation-id) installation_id=${2:-}; shift 2 ;;
        --ca-file) ca_file=${2:-}; shift 2 ;;
        --handoff-file) handoff_file=${2:-}; shift 2 ;;
        --agent-bundle) agent_bundle=${2:-}; shift 2 ;;
        --dry-run) dry_run=true; shift ;;
        --inspect-layout) inspect_layout=true; shift ;;
        --prepare-service-account) prepare_service_account=true; shift ;;
        --finalize-handoff) finalize_handoff=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

if [[ "$inspect_layout" == true ]]; then
    [[ "$finalize_handoff" == false && "$prepare_service_account" == false && -z "$endpoint$installation_id$ca_file$handoff_file$agent_bundle" ]] || \
        die '--inspect-layout cannot be combined with installation options'
    print_layout
    exit 0
fi
if [[ "$prepare_service_account" == true ]]; then
    [[ "$finalize_handoff" == false && -z "$endpoint$installation_id$ca_file$handoff_file$agent_bundle" && "$dry_run" == false ]] || \
        die '--prepare-service-account cannot be combined with installation options'
    require_root
    ensure_service_account
    printf 'endpoint-agent service account is ready\n'
    exit 0
fi
if [[ "$finalize_handoff" == true ]]; then
    [[ -z "$endpoint$installation_id$ca_file$handoff_file$agent_bundle" && "$dry_run" == false ]] || \
        die '--finalize-handoff cannot be combined with installation options'
    finalize_handoff
    exit 0
fi
[[ -n "$endpoint" && -n "$installation_id" && -n "$ca_file" && -n "$handoff_file" && -n "$agent_bundle" ]] || {
    usage >&2
    die 'endpoint, installation ID, CA, handoff file and local agent bundle are required'
}
install_package
