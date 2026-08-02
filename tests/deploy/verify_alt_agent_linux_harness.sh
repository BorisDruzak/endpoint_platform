#!/usr/bin/env bash
# Run only as root on a disposable Linux test host.  SOURCE is an LF Git blob
# supplied by the caller; this harness never reads the checkout installer.
set -euo pipefail
IFS=$'\n\t'

source_blob=${1:?usage: verify_alt_agent_linux_harness.sh INSTALLER_GIT_BLOB}
[[ -f "$source_blob" ]] || { echo "missing installer Git blob" >&2; exit 2; }
! LC_ALL=C grep -q $'\r' "$source_blob" || { echo "installer blob is not LF" >&2; exit 2; }
bash -n "$source_blob"

failures=0
test_uid=900
test_gid=900

make_copy() {
    local root=$1
    sed \
        -e "s|/opt/endpoint-agent|$root/opt/endpoint-agent|g" \
        -e "s|/var/lib/endpoint-agent|$root/var/lib/endpoint-agent|g" \
        -e "s|/etc/endpoint-agent|$root/etc/endpoint-agent|g" \
        -e "s|/var/log/endpoint-agent|$root/var/log/endpoint-agent|g" \
        -e "s|/etc/systemd/system/\$SERVICE_NAME|$root/etc/systemd/system/\$SERVICE_NAME|g" \
        -e "s|require_trusted_root_parent /opt|require_trusted_root_parent $root/opt|" \
        -e "s|require_trusted_root_parent /etc/systemd/system|require_trusted_root_parent $root/etc/systemd/system|" \
        -e "s|require_trusted_root_parent /etc/systemd|require_trusted_root_parent $root/etc/systemd|" \
        -e "s|require_trusted_root_parent /etc|require_trusted_root_parent $root/etc|" \
        -e "s|require_trusted_root_parent /var/lib|require_trusted_root_parent $root/var/lib|" \
        -e "s|require_trusted_root_parent /var/log|require_trusted_root_parent $root/var/log|" \
        -e "s|require_trusted_root_parent /var|require_trusted_root_parent $root/var|" \
        "$source_blob" > "$root/installer"
    chmod 700 "$root/installer"
}

setup_layout() {
    local root=$1
    mkdir -p "$root/opt/endpoint-agent" "$root/etc/endpoint-agent" \
        "$root/etc/systemd/system" "$root/var/lib/endpoint-agent" \
        "$root/var/log/endpoint-agent" "$root/bin" "$root/input"
    chown -R root:root "$root/opt" "$root/etc" "$root/var"
    chmod 755 "$root/opt" "$root/etc" "$root/etc/endpoint-agent" "$root/etc/systemd" \
        "$root/etc/systemd/system" "$root/var" "$root/var/lib" "$root/var/log" \
        "$root/opt/endpoint-agent"
    chown "$test_uid:$test_gid" "$root/var/lib/endpoint-agent" "$root/var/log/endpoint-agent"
    chmod 750 "$root/var/lib/endpoint-agent" "$root/var/log/endpoint-agent"
cat > "$root/bin/getent" <<EOF
#!/usr/bin/env bash
if [[ "\$1" == passwd && "\$2" == endpoint-agent ]]; then printf 'endpoint-agent:x:$test_uid:$test_gid::/nonexistent:/usr/sbin/nologin\\n'; exit 0; fi
if [[ "\$1" == group && "\$2" == endpoint-agent ]]; then printf 'endpoint-agent:x:$test_gid:\\n'; exit 0; fi
exit 2
EOF
    cat > "$root/bin/id" <<EOF
#!/usr/bin/env bash
if [[ "\$1" == -u && "\$2" == endpoint-agent ]]; then printf '$test_uid\\n'; exit 0; fi
exec /usr/bin/id "\$@"
EOF
    cat > "$root/bin/useradd" <<EOF
#!/usr/bin/env bash
touch "$root/useradd-was-called"
exit 91
EOF
    chmod 700 "$root/bin/getent" "$root/bin/id" "$root/bin/useradd"
}

write_finalizer_state() {
    local root=$1 digest
    printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' > "$root/var/lib/endpoint-agent/device-credential"
    printf '%s' '{"device_id":"9c83f6de-3435-4fc3-a7e0-7bcddc744f3b","schema_version":"endpoint_enrollment_identity_v1"}' > "$root/var/lib/endpoint-agent/enrollment-identity.json"
    printf 'one-time-handoff' > "$root/etc/endpoint-agent/provisioning-claim"
    chown "$test_uid:$test_gid" "$root/var/lib/endpoint-agent/device-credential" "$root/var/lib/endpoint-agent/enrollment-identity.json"
    chmod 600 "$root/var/lib/endpoint-agent/device-credential" "$root/var/lib/endpoint-agent/enrollment-identity.json" "$root/etc/endpoint-agent/provisioning-claim"
    digest=$(sha256sum "$root/var/lib/endpoint-agent/device-credential" | awk '{print $1}')
    printf '{"claim_credential_name":"endpoint-enrollment-claim","credential_path":"%s","credential_sha256":"%s","device_id":"9c83f6de-3435-4fc3-a7e0-7bcddc744f3b","schema_version":"endpoint_claim_removal_request_v1"}' \
        "$root/var/lib/endpoint-agent/device-credential" "$digest" > "$root/var/lib/endpoint-agent/claim-removal-request.json"
    chown "$test_uid:$test_gid" "$root/var/lib/endpoint-agent/claim-removal-request.json"
    chmod 600 "$root/var/lib/endpoint-agent/claim-removal-request.json"
}

run_finalizer_case() {
    local scenario=$1 root status claim request credential identity
    root=$(mktemp -d /tmp/endpoint-alt-finalizer.XXXXXX)
    trap 'rm -rf -- "$root"' RETURN
    make_copy "$root"; setup_layout "$root"; write_finalizer_state "$root"
    claim="$root/etc/endpoint-agent/provisioning-claim"
    request="$root/var/lib/endpoint-agent/claim-removal-request.json"
    credential="$root/var/lib/endpoint-agent/device-credential"
    identity="$root/var/lib/endpoint-agent/enrollment-identity.json"
    case "$scenario" in
        valid) ;;
        idempotent) rm -f "$claim" "$request" ;;
        claim-mode) chmod 640 "$claim" ;;
        request-mode) chmod 640 "$request" ;;
        credential-mode) chmod 640 "$credential" ;;
        identity-mode) chmod 640 "$identity" ;;
        identity-missing) rm -f "$identity" ;;
        identity-mismatch) printf '%s' '{"device_id":"00000000-0000-4000-8000-000000000001","schema_version":"endpoint_enrollment_identity_v1"}' > "$identity" ;;
        claim-owner) chown 42425:42425 "$claim" ;;
        request-owner) chown 42425:42425 "$request" ;;
        credential-owner) chown 42425:42425 "$credential" ;;
        identity-owner) chown 42425:42425 "$identity" ;;
        claim-symlink) mv "$claim" "$claim.real"; ln -s "$claim.real" "$claim" ;;
        request-symlink) mv "$request" "$request.real"; ln -s "$request.real" "$request" ;;
        credential-symlink) mv "$credential" "$credential.real"; ln -s "$credential.real" "$credential" ;;
        parent-symlink)
            mv "$root/etc/endpoint-agent" "$root/etc/endpoint-agent.real"
            ln -s "$root/etc/endpoint-agent.real" "$root/etc/endpoint-agent"
            ;;
        *) echo "unknown finalizer scenario: $scenario" >&2; return 2 ;;
    esac
    set +e
    PATH="$root/bin:$PATH" bash "$root/installer" --finalize-handoff >"$root/output" 2>&1
    status=$?
    set -e
    printf 'FINALIZER %-22s status=%s claim=%s request=%s credential=%s identity=%s\n' "$scenario" "$status" \
        "$([[ -e "$claim" || -L "$claim" ]] && echo present || echo absent)" \
        "$([[ -e "$request" || -L "$request" ]] && echo present || echo absent)" \
        "$([[ -e "$credential" || -L "$credential" ]] && echo present || echo absent)" \
        "$([[ -e "$identity" || -L "$identity" ]] && echo present || echo absent)"
    cat "$root/output"
    if [[ "$scenario" == valid || "$scenario" == idempotent ]]; then
        [[ "$status" == 0 && -f "$identity" ]] || failures=$((failures + 1))
    else
        [[ "$status" != 0 ]] || failures=$((failures + 1))
    fi
    trap - RETURN
    rm -rf -- "$root"
}

run_binary_case() {
    local scenario=$1 root target status
    root=$(mktemp -d /tmp/endpoint-alt-binary.XXXXXX)
    trap 'rm -rf -- "$root"' RETURN
    make_copy "$root"; setup_layout "$root"; write_finalizer_state "$root"
    target="$root/opt/endpoint-agent/endpoint-agent"
    printf '#!/bin/sh\nexit 0\n' > "$root/input/agent"
    chmod 755 "$root/input/agent"
    printf 'handoff' > "$root/input/handoff"
    chmod 600 "$root/input/handoff"
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=endpoint-test \
        -keyout "$root/input/key" -out "$root/input/ca.crt" >/dev/null 2>&1
    chmod 600 "$root/input/ca.crt"
    case "$scenario" in
        binary-symlink) printf x > "$root/elsewhere"; ln -s "$root/elsewhere" "$target" ;;
        binary-symlink-to-directory) mkdir "$root/elsewhere-dir"; ln -s "$root/elsewhere-dir" "$target" ;;
        binary-existing-directory) mkdir "$target" ;;
        *) echo "unknown binary scenario: $scenario" >&2; return 2 ;;
    esac
    set +e
    PATH="$root/bin:$PATH" bash "$root/installer" --endpoint https://endpoint.sosnadmin.local --installation-id alt-test-agent-001 \
        --ca-file "$root/input/ca.crt" --handoff-file "$root/input/handoff" \
        --agent-binary "$root/input/agent" >"$root/output" 2>&1
    status=$?
    set -e
    printf 'BINARY    %-22s status=%s useradd=%s\n' "$scenario" "$status" \
        "$([[ -e "$root/useradd-was-called" ]] && echo called || echo absent)"
    cat "$root/output"
    [[ "$status" != 0 && ! -e "$root/useradd-was-called" ]] || failures=$((failures + 1))
    trap - RETURN
    rm -rf -- "$root"
}

for scenario in valid idempotent claim-mode request-mode credential-mode identity-mode identity-missing identity-mismatch claim-owner request-owner credential-owner identity-owner claim-symlink request-symlink credential-symlink parent-symlink; do
    run_finalizer_case "$scenario"
done
for scenario in binary-symlink binary-symlink-to-directory binary-existing-directory; do
    run_binary_case "$scenario"
done
(( failures == 0 )) || { echo "$failures harness cases failed" >&2; exit 1; }
echo 'ALT installer Linux safety harness: all cases passed'
