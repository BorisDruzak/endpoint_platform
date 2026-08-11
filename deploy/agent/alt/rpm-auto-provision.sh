#!/usr/bin/env bash
# Fixed-path first-install bridge from RPM to the verified ALT provisioner.
set -euo pipefail
IFS=$'\n\t'
umask 077

readonly ENDPOINT_URL=https://endpoint.sosnadmin.local
readonly BOOTSTRAP_ROOT=/etc/endpoint-agent/bootstrap
readonly INSTALLATION_ID_FILE="$BOOTSTRAP_ROOT/installation-id"
readonly CA_FILE="$BOOTSTRAP_ROOT/ca.crt"
readonly CLAIM_FILE="$BOOTSTRAP_ROOT/provisioning-claim"
readonly PROVISION_DIR=/usr/lib64/endpoint-agent/provision
readonly INSTALLER="$PROVISION_DIR/install-endpoint-agent.sh"
readonly BUNDLE=/usr/lib64/endpoint-agent/release-bundle

die() {
    printf 'endpoint-agent RPM provisioner: %s\n' "$*" >&2
    exit 1
}

require_root_file() {
    local label=$1 path=$2
    [[ -f "$path" && ! -L "$path" ]] || die "$label must be a regular file"
    [[ "$(stat -c %u -- "$path")" == 0 && "$(stat -c %g -- "$path")" == 0 ]] || \
        die "$label must be owned by root:root"
    [[ "$(stat -c %a -- "$path")" == 600 ]] || die "$label must have mode 600"
}

[[ "${EUID}" -eq 0 ]] || die 'must run as root'
for parent in /etc /etc/endpoint-agent "$BOOTSTRAP_ROOT"; do
    [[ -d "$parent" && ! -L "$parent" ]] || die 'bootstrap directory is unsafe'
    [[ "$(stat -c %u -- "$parent")" == 0 && "$(stat -c %g -- "$parent")" == 0 ]] || \
        die 'bootstrap directory must be below root:root directories'
done
[[ "$(stat -c %a -- "$BOOTSTRAP_ROOT")" == 700 ]] || die 'bootstrap directory must have mode 700'
require_root_file 'installation ID' "$INSTALLATION_ID_FILE"
require_root_file 'Gateway CA' "$CA_FILE"
require_root_file 'provisioning claim' "$CLAIM_FILE"

installation_id=$(cat -- "$INSTALLATION_ID_FILE")
[[ "$installation_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || die 'installation ID is invalid'
[[ -x "$INSTALLER" && -d "$BUNDLE" ]] || die 'packaged provisioner payload is incomplete'

"$INSTALLER" \
    --endpoint "$ENDPOINT_URL" \
    --installation-id "$installation_id" \
    --ca-file "$CA_FILE" \
    --handoff-file "$CLAIM_FILE" \
    --agent-bundle "$BUNDLE"

# The installer made its private copy.  Keep only that copy until the
# enrollment proof activates the root-owned finalizer.
rm -f -- "$CLAIM_FILE"
