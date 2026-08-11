#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

die() {
    printf 'systemd credential gate harness: %s\n' "$*" >&2
    exit 1
}

[[ $# -eq 1 ]] || die 'usage: verify_systemd_credential_gate.sh RPM'
rpm_path=$(readlink -f -- "$1")
[[ -f "$rpm_path" && ! -L "$rpm_path" ]] || die 'RPM must be a regular file'
command -v rpm2cpio >/dev/null 2>&1 || die 'rpm2cpio is required'
command -v cpio >/dev/null 2>&1 || die 'cpio is required'
sudo --non-interactive true || die 'passwordless sudo is required'

probe=$(mktemp -d /tmp/endpoint-agent-systemd-gate.XXXXXX)
case "$probe" in
    /tmp/endpoint-agent-systemd-gate.*) ;;
    *) die 'unexpected probe path' ;;
esac
unit_name=endpoint-task10-credential-gate.service
unit_path="/run/systemd/system/$unit_name"
probe_token=$(basename -- "$probe")
account_gid=$(id -g endpoint-agent)
service_before=$(systemctl is-active endpoint-agent.service 2>/dev/null || true)
journal_count() {
    sudo --non-interactive journalctl -u "$unit_name" --no-pager | \
        grep -Fc "$1" || true
}
wait_for_journal_count() {
    local pattern=$1 expected=$2 attempt
    for attempt in {1..50}; do
        if [[ $(journal_count "$pattern") -ge "$expected" ]]; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}
cleanup() {
    sudo --non-interactive systemctl stop "$unit_name" >/dev/null 2>&1 || true
    sudo --non-interactive rm -f -- "$unit_path"
    case "$probe" in
        /tmp/endpoint-agent-systemd-gate.*) \
            sudo --non-interactive rm -rf -- "$probe" ;;
        *) return 1 ;;
    esac
    sudo --non-interactive systemctl daemon-reload
}
trap cleanup EXIT

mkdir -p \
    "$probe/extracted" \
    "$probe/etc-endpoint" \
    "$probe/credstore" \
    "$probe/data" \
    "$probe/log" \
    "$probe/install/versions/3.1.76/endpoint-agent"
(
    cd "$probe/extracted"
    rpm2cpio "$rpm_path" | cpio -idm --quiet
)
for name in config ca claim; do
    printf 'fixture-%s\n' "$name" > "$probe/$name.source"
    chmod 0600 "$probe/$name.source"
done
cp -- "$probe/config.source" "$probe/etc-endpoint/config.yaml"
cp -- "$probe/ca.source" "$probe/etc-endpoint/ca.crt"
cp -- "$probe/claim.source" "$probe/credstore/endpoint-enrollment-claim"
chmod 0600 \
    "$probe/etc-endpoint/config.yaml" \
    "$probe/etc-endpoint/ca.crt" \
    "$probe/credstore/endpoint-enrollment-claim"
install -m 0755 /usr/bin/true \
    "$probe/install/versions/3.1.76/endpoint-agent/endpoint-agent"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    "printf 'credential-gate-launcher=%s\\n' '$probe_token'" \
    'for name in endpoint-agent-config endpoint-agent-ca; do' \
    "    printf 'credential-gate-mode=$probe_token:%s\\n' \"\$(stat -c '%u:%g:%a' \"\$CREDENTIALS_DIRECTORY/\$name\")\"" \
    'done' \
    'if [[ -e "$CREDENTIALS_DIRECTORY/endpoint-enrollment-claim" ]]; then' \
    "    printf 'credential-gate-mode=$probe_token:%s\\n' \"\$(stat -c '%u:%g:%a' \"\$CREDENTIALS_DIRECTORY/endpoint-enrollment-claim\")\"" \
    'fi' \
    > "$probe/install/launcher"
chmod 0755 "$probe/install/launcher"
printf '%s\n' \
    '{"schema_version":1,"source_revision":"fixture","version":"3.1.76"}' \
    > "$probe/install/current.json"
chmod 0644 "$probe/install/current.json"

sed \
    -e '/^ConditionPathExists=/d' \
    -e "s#^LoadCredential=endpoint-agent-config:.*#LoadCredential=endpoint-agent-config:$probe/config.source#" \
    -e "s#^LoadCredential=endpoint-agent-ca:.*#LoadCredential=endpoint-agent-ca:$probe/ca.source#" \
    -e "s#^LoadCredential=endpoint-enrollment-claim.*#LoadCredential=endpoint-enrollment-claim:$probe/claim.source#" \
    "$probe/extracted/usr/lib/systemd/system/endpoint-agent.service" \
    > "$probe/test.service"
printf '%s\n' \
    '[Service]' \
    'StateDirectory=' \
    'LogsDirectory=' \
    "BindReadOnlyPaths=$probe/extracted/usr/lib/endpoint-agent:/usr/lib/endpoint-agent" \
    "BindReadOnlyPaths=$probe/install:/opt/endpoint-agent" \
    "BindReadOnlyPaths=$probe/etc-endpoint:/etc/endpoint-agent" \
    "BindReadOnlyPaths=$probe/credstore:/etc/credstore" \
    "BindPaths=$probe/data:/var/lib/endpoint-agent" \
    "BindPaths=$probe/log:/var/log/endpoint-agent" \
    >> "$probe/test.service"
sudo --non-interactive chown -R root:root "$probe"
sudo --non-interactive find "$probe/install" -type d -exec chmod 0755 {} +
sudo --non-interactive chown endpoint-agent:endpoint-agent "$probe/data" "$probe/log"
sudo --non-interactive chmod 0755 "$probe"
sudo --non-interactive chmod 0750 "$probe/data" "$probe/log"
sudo --non-interactive install -o root -g root -m 0644 \
    "$probe/test.service" "$unit_path"
sudo --non-interactive systemctl daemon-reload
sudo --non-interactive systemctl start "$unit_name"

if ! wait_for_journal_count "credential-gate-launcher=$probe_token" 1; then
    sudo --non-interactive systemctl show "$unit_name" \
        -p Result -p ActiveState -p SubState -p ExecCondition -p ExecMainStatus \
        --no-pager
    sudo --non-interactive journalctl -u "$unit_name" -n 15 --no-pager
    die 'package pre-start gate did not reach the launcher'
fi
[[ $(journal_count "credential-gate-mode=$probe_token:0:$account_gid:440") -eq 3 ]] || \
    die 'systemd credentials were not delegated root:agent-group 0440'

sudo --non-interactive systemctl stop "$unit_name"
sudo --non-interactive sed -i \
    's#^LoadCredential=endpoint-enrollment-claim:.*#LoadCredential=endpoint-enrollment-claim#' \
    "$unit_path"
sudo --non-interactive rm -f -- \
    "$probe/credstore/endpoint-enrollment-claim"
sudo --non-interactive install -o endpoint-agent -g endpoint-agent -m 0600 \
    /dev/null "$probe/data/device-credential"
printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
    | sudo --non-interactive tee "$probe/data/device-credential" >/dev/null
sudo --non-interactive chown endpoint-agent:endpoint-agent \
    "$probe/data/device-credential"
printf '%s' \
    '{"device_id":"00000000-0000-4000-8000-000000000010","schema_version":"endpoint_enrollment_identity_v1"}' \
    | sudo --non-interactive tee "$probe/data/enrollment-identity.json" >/dev/null
sudo --non-interactive chown endpoint-agent:endpoint-agent \
    "$probe/data/enrollment-identity.json"
sudo --non-interactive chmod 0600 "$probe/data/enrollment-identity.json"
sudo --non-interactive systemctl daemon-reload
sudo --non-interactive systemctl start "$unit_name"
wait_for_journal_count "credential-gate-launcher=$probe_token" 2 || \
    die 'canonical durable pair did not satisfy claim-free start'
[[ $(journal_count "credential-gate-mode=$probe_token:0:$account_gid:440") -eq 5 ]] || \
    die 'claim-free start did not receive config and CA credentials'

sudo --non-interactive systemctl stop "$unit_name"
printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
    | sudo --non-interactive tee "$probe/data/device-credential" >/dev/null
sudo --non-interactive chown endpoint-agent:endpoint-agent \
    "$probe/data/device-credential"
sudo --non-interactive systemctl reset-failed "$unit_name" >/dev/null 2>&1 || true
sudo --non-interactive systemctl start "$unit_name"
[[ $(systemctl is-active "$unit_name" 2>/dev/null || true) == inactive ]] || \
    die 'invalid pre-start state did not skip the service'
[[ $(journal_count "credential-gate-launcher=$probe_token") -eq 2 ]] || \
    die 'truncated durable state reached the launcher'
[[ $(systemctl show "$unit_name" -p NRestarts --value) -eq 0 ]] || \
    die 'invalid pre-start state caused a restart loop'
service_after=$(systemctl is-active endpoint-agent.service 2>/dev/null || true)
[[ "$service_before" == "$service_after" ]] || die 'live endpoint-agent service state changed'
printf 'systemd credential gate harness: all cases passed\n'
