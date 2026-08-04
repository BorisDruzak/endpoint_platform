#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

die() {
    printf 'ALT RPM lifecycle harness: %s\n' "$*" >&2
    exit 1
}

snapshot_digest() {
    sha256sum -- "$@" | sha256sum | cut -d' ' -f1
}

run_inside() {
    local initial_rpm=$1 upgrade_rpm=$2 work=$3
    local database="$work/rpmdb" state_before state_after selector_version
    check_prerequisites() {
        /usr/lib/endpoint-agent/check-start-prerequisites \
            --credential-representation source \
            --config /etc/endpoint-agent/config.yaml \
            --ca /etc/endpoint-agent/ca.crt \
            --claim "$work/missing-claim"
    }
    expect_prerequisite_rejection() {
        local scenario=$1
        if check_prerequisites >/dev/null 2>&1; then
            die "checker accepted invalid durable state: $scenario"
        fi
        printf 'durable-state-rejected=%s\n' "$scenario"
    }
    mkdir -p "$database"
    /bin/rpm --dbpath "$database" --initdb

    /bin/rpm --dbpath "$database" -ivh --nodeps --ignoresize --notriggers "$initial_rpm"
    /bin/rpm --dbpath "$database" -q endpoint-agent | \
        grep -Fx 'endpoint-agent-3.1.76-alt1.x86_64'
    test -x /opt/endpoint-agent/launcher
    test -x /opt/endpoint-agent/versions/3.1.76/endpoint-agent/endpoint-agent
    test -f /usr/lib/systemd/system/endpoint-agent.service
    test -f /usr/lib/systemd/system/endpoint-agent-update.service
    test -f /usr/lib/systemd/system/endpoint-agent-update.path

    install -o root -g root -m 0600 /dev/null /etc/endpoint-agent/config.yaml
    install -o root -g root -m 0600 /dev/null /etc/endpoint-agent/ca.crt
    printf 'fixture-config\n' > /etc/endpoint-agent/config.yaml
    printf 'fixture-ca\n' > /etc/endpoint-agent/ca.crt
    install -o root -g root -m 0600 /dev/null "$work/loaded-claim"
    printf 'fixture-claim\n' > "$work/loaded-claim"
    /usr/lib/endpoint-agent/check-start-prerequisites \
        --credential-representation source \
        --config /etc/endpoint-agent/config.yaml \
        --ca /etc/endpoint-agent/ca.crt \
        --claim "$work/loaded-claim"

    install -o endpoint-agent -g endpoint-agent -m 0600 /dev/null \
        /var/lib/endpoint-agent/device-credential
    install -o endpoint-agent -g endpoint-agent -m 0600 /dev/null \
        /var/lib/endpoint-agent/enrollment-identity.json
    printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
        > /var/lib/endpoint-agent/device-credential
    printf '{"device_id":"00000000-0000-4000-8000-000000000010","schema_version":"endpoint_enrollment_identity_v1"}' \
        > /var/lib/endpoint-agent/enrollment-identity.json
    chown endpoint-agent:endpoint-agent \
        /var/lib/endpoint-agent/device-credential \
        /var/lib/endpoint-agent/enrollment-identity.json
    chmod 0600 \
        /var/lib/endpoint-agent/device-credential \
        /var/lib/endpoint-agent/enrollment-identity.json
    rm -f -- "$work/loaded-claim"
    check_prerequisites

    printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
        > /var/lib/endpoint-agent/device-credential
    expect_prerequisite_rejection credential-truncated
    printf '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!' \
        > /var/lib/endpoint-agent/device-credential
    expect_prerequisite_rejection credential-format
    printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
        > /var/lib/endpoint-agent/device-credential

    mv /var/lib/endpoint-agent/device-credential "$work/credential.saved"
    expect_prerequisite_rejection credential-missing
    mv "$work/credential.saved" /var/lib/endpoint-agent/device-credential
    mv /var/lib/endpoint-agent/enrollment-identity.json "$work/identity.saved"
    expect_prerequisite_rejection identity-missing
    mv "$work/identity.saved" /var/lib/endpoint-agent/enrollment-identity.json
    printf '{"device_id":"not-a-uuid","schema_version":"endpoint_enrollment_identity_v1"}\n' \
        > /var/lib/endpoint-agent/enrollment-identity.json
    expect_prerequisite_rejection identity-invalid
    printf '{"schema_version":"endpoint_enrollment_identity_v1","device_id":"00000000-0000-4000-8000-000000000010"}' \
        > /var/lib/endpoint-agent/enrollment-identity.json
    expect_prerequisite_rejection identity-noncanonical
    printf '{"device_id":"00000000-0000-4000-8000-000000000010","schema_version":"endpoint_enrollment_identity_v1"}' \
        > /var/lib/endpoint-agent/enrollment-identity.json
    chmod 0640 /var/lib/endpoint-agent/enrollment-identity.json
    expect_prerequisite_rejection identity-mode
    chmod 0600 /var/lib/endpoint-agent/enrollment-identity.json
    chown root:root /var/lib/endpoint-agent/enrollment-identity.json
    expect_prerequisite_rejection identity-owner
    chown endpoint-agent:endpoint-agent \
        /var/lib/endpoint-agent/enrollment-identity.json
    check_prerequisites

    state_before=$(snapshot_digest \
        /etc/endpoint-agent/config.yaml \
        /etc/endpoint-agent/ca.crt \
        /var/lib/endpoint-agent/device-credential \
        /var/lib/endpoint-agent/enrollment-identity.json)
    /bin/rpm --dbpath "$database" -Uvh --nodeps --ignoresize --notriggers "$upgrade_rpm"
    /bin/rpm --dbpath "$database" -q endpoint-agent | \
        grep -Fx 'endpoint-agent-3.1.77-alt1.x86_64'
    state_after=$(snapshot_digest \
        /etc/endpoint-agent/config.yaml \
        /etc/endpoint-agent/ca.crt \
        /var/lib/endpoint-agent/device-credential \
        /var/lib/endpoint-agent/enrollment-identity.json)
    test "$state_before" = "$state_after"
    printf 'identity-preserved-after-upgrade\n'
    test ! -e /opt/endpoint-agent/versions/3.1.76
    test -x /opt/endpoint-agent/versions/3.1.77/endpoint-agent/endpoint-agent
    selector_version=$(
        /usr/lib/endpoint-agent/check-start-prerequisites --print-selected-version
    )
    test "$selector_version" = 3.1.77

    /bin/rpm --dbpath "$database" -e endpoint-agent --notriggers
    test -f /etc/endpoint-agent/config.yaml
    test -f /etc/endpoint-agent/ca.crt
    test -f /var/lib/endpoint-agent/device-credential
    test -f /var/lib/endpoint-agent/enrollment-identity.json
    state_after=$(snapshot_digest \
        /etc/endpoint-agent/config.yaml \
        /etc/endpoint-agent/ca.crt \
        /var/lib/endpoint-agent/device-credential \
        /var/lib/endpoint-agent/enrollment-identity.json)
    test "$state_before" = "$state_after"
    printf 'state-preserved-after-uninstall\n'
    grep -Fx 'disable --now endpoint-agent.service' "$work/systemctl.log"
    grep -Fx 'disable --now endpoint-agent-update.path' "$work/systemctl.log"
}

if [[ ${1:-} == --inside ]]; then
    shift
    run_inside "$@"
    exit 0
fi

[[ $# -eq 2 ]] || die 'usage: verify_alt_rpm_lifecycle.sh INITIAL_RPM UPGRADE_RPM'
initial_rpm=$(readlink -f -- "$1")
upgrade_rpm=$(readlink -f -- "$2")
[[ -f "$initial_rpm" && ! -L "$initial_rpm" ]] || die 'initial RPM must be regular'
[[ -f "$upgrade_rpm" && ! -L "$upgrade_rpm" ]] || die 'upgrade RPM must be regular'
command -v bwrap >/dev/null 2>&1 || die 'bubblewrap is required'
sudo --non-interactive true || die 'passwordless sudo is required for mapped service ownership'

mount_targets=(
    /usr/lib/endpoint-agent
    /usr/lib/systemd/system
    /usr/lib/tmpfiles.d
    /usr/share/doc
    /var/lib/endpoint-agent
    /var/log/endpoint-agent
)
created_mount_targets=()

work=$(mktemp -d /tmp/endpoint-agent-rpm-lifecycle.XXXXXX)
case "$work" in
    /tmp/endpoint-agent-rpm-lifecycle.*) ;;
    *) die 'unexpected lifecycle work path' ;;
esac
cleanup() {
    local index
    for ((index = ${#created_mount_targets[@]} - 1; index >= 0; index -= 1)); do
        sudo --non-interactive rmdir -- "${created_mount_targets[$index]}" || true
    done
    case "$work" in
        /tmp/endpoint-agent-rpm-lifecycle.*) \
            sudo --non-interactive rm -rf -- "$work" ;;
        *) return 1 ;;
    esac
}
trap cleanup EXIT

mutable_etc="$work/etc"
sudo --non-interactive install -d -o root -g root -m 0700 -- "$mutable_etc"
for account_file in passwd group shadow gshadow; do
    source_file="/etc/$account_file"
    [[ -f "$source_file" && ! -L "$source_file" ]] || \
        die "account source is unsafe: $source_file"
    sudo --non-interactive cp --preserve=mode -- "$source_file" \
        "$mutable_etc/$account_file"
done
for system_file in nsswitch.conf login.defs; do
    source_file="/etc/$system_file"
    [[ -f "$source_file" && ! -L "$source_file" ]] || \
        die "system source is unsafe: $source_file"
    sudo --non-interactive cp --preserve=mode -- "$source_file" \
        "$mutable_etc/$system_file"
done
for system_directory in pam.d security default; do
    source_directory="/etc/$system_directory"
    [[ -d "$source_directory" && ! -L "$source_directory" ]] || \
        die "system directory is unsafe: $source_directory"
    sudo --non-interactive cp -a -- "$source_directory" "$mutable_etc/"
done
sudo --non-interactive install -d -o root -g root -m 0755 -- \
    "$mutable_etc/endpoint-agent" "$mutable_etc/logrotate.d"
sudo --non-interactive install -d -o root -g auth -m 0710 -- \
    "$mutable_etc/tcb"
sudo --non-interactive install -d -o root -g root -m 0770 -- \
    "$mutable_etc/shadow-maint/groupadd-pre.d" \
    "$mutable_etc/shadow-maint/groupadd-post.d" \
    "$mutable_etc/shadow-maint/useradd-pre.d"
# The isolated RPM database needs a resolvable service account for file
# ownership. Real account creation is accepted separately on the disposable
# host; invoking ALT's TCB-aware useradd inside an unshared /etc is not a
# meaningful package lifecycle assertion.
printf 'endpoint-agent:x:65530:\n' | \
    sudo --non-interactive tee -a "$mutable_etc/group" >/dev/null
printf 'endpoint-agent:x:65530:65530:Endpoint Agent:/nonexistent:/sbin/nologin\n' | \
    sudo --non-interactive tee -a "$mutable_etc/passwd" >/dev/null

ensure_mount_target() {
    local target=$1 parent
    if [[ -L "$target" ]]; then
        die "mount target is a symlink: $target"
    fi
    if [[ -e "$target" ]]; then
        [[ -d "$target" ]] || die "mount target is not a directory: $target"
        return
    fi
    parent=$(dirname -- "$target")
    [[ -d "$parent" && ! -L "$parent" ]] || \
        die "mount target parent is unsafe: $parent"
    sudo --non-interactive mkdir -- "$target" || \
        die "cannot create mount target: $target"
    created_mount_targets+=("$target")
}

for target in "${mount_targets[@]}"; do
    ensure_mount_target "$target"
done

mkdir -p "$work/bin" "$work/inputs"
install -m 0444 "$initial_rpm" "$work/inputs/initial.rpm"
install -m 0444 "$upgrade_rpm" "$work/inputs/upgrade.rpm"
install -m 0555 "$0" "$work/harness.sh"
initial_rpm=/mnt/inputs/initial.rpm
upgrade_rpm=/mnt/inputs/upgrade.rpm
chmod 0755 "$work" "$work/inputs"
cat > "$work/bin/systemctl" <<'SYSTEMCTL'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$RPM_LIFECYCLE_WORK/systemctl.log"
exit 0
SYSTEMCTL
chmod 0700 "$work/bin/systemctl"
sudo --non-interactive chown -R root:root "$work"
sudo --non-interactive chmod 0700 "$work" "$work/bin"
sudo --non-interactive chmod 0755 "$work/inputs"

service_before=$(systemctl is-active endpoint-agent.service 2>/dev/null || true)
sudo --non-interactive bwrap --unshare-pid --unshare-ipc --unshare-uts \
    --unshare-cgroup --die-with-parent \
    --ro-bind / / --bind "$mutable_etc" /etc --proc /proc --dev /dev \
    --tmpfs /tmp \
    --bind "$work" /mnt \
    --ro-bind "$work/inputs" /mnt/inputs \
    --tmpfs /root \
    --tmpfs /opt \
    --tmpfs /etc/endpoint-agent \
    --tmpfs /etc/logrotate.d \
    --tmpfs /usr/lib/endpoint-agent \
    --tmpfs /usr/lib/systemd/system \
    --tmpfs /usr/lib/tmpfiles.d \
    --tmpfs /usr/share/doc \
    --tmpfs /var/lib/endpoint-agent \
    --tmpfs /var/log/endpoint-agent \
    --ro-bind "$work/bin/systemctl" /usr/bin/systemctl \
    --setenv RPM_LIFECYCLE_WORK /mnt \
    --setenv PATH /mnt/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    /bin/bash /mnt/harness.sh --inside "$initial_rpm" "$upgrade_rpm" /mnt
service_after=$(systemctl is-active endpoint-agent.service 2>/dev/null || true)
test "$service_before" = "$service_after"
printf 'ALT RPM lifecycle harness: all cases passed\n'
