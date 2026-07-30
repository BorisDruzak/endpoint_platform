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
readonly CONFIG_TARGET="${CONFIG_ROOT}/config.yaml"
readonly CA_TARGET="${CONFIG_ROOT}/ca.crt"
readonly HANDOFF_TARGET="${CONFIG_ROOT}/provisioning-claim"
readonly PERMANENT_CREDENTIAL_TARGET="${DATA_ROOT}/device-credential"
readonly HANDOFF_REQUEST_TARGET="${DATA_ROOT}/claim-removal-request.json"
readonly CLAIM_CREDENTIAL_NAME=endpoint-enrollment-claim
readonly HANDOFF_REQUEST_SCHEMA_VERSION=endpoint_claim_removal_request_v1

endpoint=''
ca_file=''
handoff_file=''
agent_binary=''
dry_run=false
inspect_layout=false
finalize_handoff=false

die() {
    printf 'endpoint-agent installer: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'USAGE'
Usage:
  install-endpoint-agent.sh --endpoint https://endpoint.example --ca-file FILE \
    --handoff-file FILE --agent-binary FILE [--dry-run]
  install-endpoint-agent.sh --inspect-layout
  install-endpoint-agent.sh --finalize-handoff

The agent binary, CA and one-time provisioning handoff must already be local.
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
    require_safe_parent_components "$path"
    path_is_symlink "$path" && die 'fixed destination directory must not be a symlink'
    [[ ! -e "$path" ]] && return
    [[ -d "$path" ]] || die 'fixed destination must be a directory'
    require_exact_owner_and_mode 'fixed destination directory' "$path" "$ownership" "$expected_mode"
}

validate_fixed_regular_target_or_absent() {
    local path=$1 ownership=$2 expected_mode=$3
    require_safe_parent_components "$path"
    path_is_symlink "$path" && die 'fixed destination file must not be a symlink'
    [[ ! -e "$path" ]] && return
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
    validate_fixed_directory_or_absent "$CONFIG_ROOT" root 755
    validate_fixed_directory_or_absent "$DATA_ROOT" service 750
    validate_fixed_directory_or_absent "$LOG_ROOT" service 750
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

validate_inputs() {
    require_https_endpoint
    validate_ca
    require_root_secret_file 'one-time provisioning handoff' "$handoff_file"
    require_regular_file 'agent binary' "$agent_binary"
    [[ -x "$agent_binary" ]] || die 'agent binary must be executable'
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
    awk -v endpoint_value="$endpoint" '
        { gsub(/__ENDPOINT_URL__/, endpoint_value); print }
    ' "$(dirname "$0")/default-config.yaml" > "$destination"
}

install_atomically() {
    local stage config_stage ca_stage handoff_stage binary_stage service_stage
    validate_install_destinations
    stage=$(mktemp -d /opt/.endpoint-agent-stage.XXXXXX)
    trap 'rm -rf "$stage"' RETURN

    config_stage="$stage/config.yaml"
    ca_stage="$stage/ca.crt"
    handoff_stage="$stage/provisioning-claim"
    binary_stage="$stage/endpoint-agent"
    service_stage="$stage/$SERVICE_NAME"

    render_config "$config_stage"
    install -o root -g root -m 0600 "$config_stage" "$config_stage.secure"
    install -o root -g root -m 0600 "$ca_file" "$ca_stage"
    install -o root -g root -m 0600 "$handoff_file" "$handoff_stage"
    install -o root -g root -m 0755 "$agent_binary" "$binary_stage"
    install -o root -g root -m 0644 "$(dirname "$0")/endpoint-agent.service" "$service_stage"

    install -d -o root -g root -m 0755 "$INSTALL_ROOT" "$CONFIG_ROOT"
    install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0750 "$DATA_ROOT" "$LOG_ROOT"
    validate_install_destinations
    mv -f "$binary_stage" "$INSTALL_ROOT/endpoint-agent"
    mv -f "$config_stage.secure" "$CONFIG_TARGET"
    mv -f "$ca_stage" "$CA_TARGET"
    mv -f "$handoff_stage" "$HANDOFF_TARGET"
    mv -f "$service_stage" "/etc/systemd/system/$SERVICE_NAME"
    rm -f "$config_stage"
    rmdir "$stage"
    trap - RETURN
}

install_package() {
    validate_inputs
    if [[ "$dry_run" == true ]]; then
        printf 'dry-run: validated local HTTPS endpoint, CA, handoff and agent binary\n'
        return
    fi
    require_root
    ensure_service_account
    install_atomically
    command -v systemctl >/dev/null 2>&1 || die 'systemctl is required after package files are installed'
    systemctl daemon-reload
    systemctl enable endpoint-agent.service
    systemctl restart endpoint-agent.service
    systemctl is-active --quiet endpoint-agent.service || die 'service did not become active'
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
        --ca-file) ca_file=${2:-}; shift 2 ;;
        --handoff-file) handoff_file=${2:-}; shift 2 ;;
        --agent-binary) agent_binary=${2:-}; shift 2 ;;
        --dry-run) dry_run=true; shift ;;
        --inspect-layout) inspect_layout=true; shift ;;
        --finalize-handoff) finalize_handoff=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

if [[ "$inspect_layout" == true ]]; then
    [[ "$finalize_handoff" == false && -z "$endpoint$ca_file$handoff_file$agent_binary" ]] || \
        die '--inspect-layout cannot be combined with installation options'
    print_layout
    exit 0
fi
if [[ "$finalize_handoff" == true ]]; then
    [[ -z "$endpoint$ca_file$handoff_file$agent_binary" && "$dry_run" == false ]] || \
        die '--finalize-handoff cannot be combined with installation options'
    finalize_handoff
    exit 0
fi
[[ -n "$endpoint" && -n "$ca_file" && -n "$handoff_file" && -n "$agent_binary" ]] || {
    usage >&2
    die 'endpoint, CA, handoff file and local agent binary are required'
}
install_package
