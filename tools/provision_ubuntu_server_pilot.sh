#!/bin/bash
# Runs as root on an approved Ubuntu server after its claim is staged.
set -euo pipefail
umask 077

package=endpoint-agent-ubuntu
version=3.2.192-1ubuntu1
digest=8affee69264c5cbdc76237ba83dfe5db91ab7a34562ee92f024d9d2b24471a7d
distro=ubuntu
os_version=24.04
origin=https://endpoint.sosnadmin.local
unit=endpoint-agent.service

role=${1:?Ubuntu role required}
server_role=$role
case "$role" in
    openvpn)
        expected_host=openvpn
        address=192.168.100.30
        ca=/etc/apt/keyrings/endpoint-ubuntu-ca.crt
        probe_user=openvpm
        expected_services=(openvpn-server@server.service openvpn-web.service)
        ;;
    endpoint_platform)
        expected_host=endpointplatform
        address=192.168.100.19
        ca=/etc/endpoint-platform/sosnadmin-local-ca.crt
        probe_user=osn_admin
        expected_services=(endpoint-platform.service endpoint-platform-worker.service nginx.service postgresql.service)
        ;;
    dirpost)
        expected_host=dirpost
        address=192.168.100.27
        ca=/etc/apt/keyrings/endpoint-ubuntu-ca.crt
        probe_user=flashvagon
        expected_services=(postgresql@14-main.service)
        server_role=
        ;;
    acti_v3|registry_engine)
        version=3.2.197-1ubuntu1
        digest=1d30e147ef8e108a2b379ffffcfb765d66ddb24926974592b23d86e491a6d573
        ca=/etc/apt/keyrings/endpoint-ubuntu-ca.crt
        if [ "$role" = acti_v3 ]; then
            expected_host=acti-v3
            address=192.168.100.45
            probe_user=osn-admin
            expected_services=(docker.service containerd.service)
        else
            expected_host=registoryengine
            address=192.168.100.12
            probe_user=osn_admin
            expected_services=(nginx.service reg-engine.service postgresql@16-main.service)
        fi
        ;;
    pve1|pve2|pve3)
        expected_host=$role
        address="10.83.1.1${role#pve}"
        distro=debian
        os_version=12
        package=endpoint-agent-debian
        version=3.2.194-1deb12u1
        digest=a6345b2a4385b62965732f558d9f950df4f9beaf1e70ba75cf9c2a06d46317f1
        ca=/etc/apt/keyrings/endpoint-debian-ca.crt
        probe_user=$package
        expected_services=(pveproxy.service pvedaemon.service pvestatd.service)
        server_role=
        ;;
    *) exit 2 ;;
esac
stage="/run/endpoint-$distro-pilot"
work="/var/cache/endpoint-$distro-pilot"
state="/var/lib/$package"
check_services() {
    for service in "${expected_services[@]}"; do
        systemctl is-active --quiet "$service" || return
    done
}

test "$(hostname -s)" = "$expected_host"
ip -4 -o address show | grep -F " inet $address/" >/dev/null
test "$(dpkg --print-architecture)" = amd64
test "$(. /etc/os-release; printf '%s/%s' "$ID" "$VERSION_ID")" = "$distro/$os_version"
test "$(systemctl show "$unit" -p LoadState --value)" = not-found
test ! -e /var/lib/endpoint-agent
test ! -L /var/lib/endpoint-agent
test "$(openssl x509 -in "$ca" -outform DER | sha256sum | cut -d ' ' -f 1)" = \
    5525eccf01536b7f0436d96500c663f7a58edac463f00f0fb34a59dd8b3250be
check_services

exec 9>/run/lock/endpoint-ubuntu-pilot.lock
flock -n 9
installed=$(dpkg-query -W -f='${Version}' "$package" 2>/dev/null || true)
test -z "$installed" || test "$installed" = "$version"
test ! -L "$work"
payload="$work/identity"
test ! -L "$payload"
identity_files=(device-credential enrollment-identity.json)
if [ ! -s "$payload/claim-removal-request.json" ]; then
    if [ ! -f "$stage/claim" ] || [ ! -f "$stage/installation-id" ]; then
        exit 3
    fi
    test ! -L "$stage"
    test ! -L "$stage/claim"
    test ! -L "$stage/installation-id"
    test "$(stat -c '%u:%g:%a' "$stage")" = 0:0:700
    test "$(stat -c '%u:%g:%a' "$stage/claim")" = 0:0:600
    test "$(stat -c '%u:%g:%a' "$stage/installation-id")" = 0:0:600
fi
install -d -o root -g root -m 0711 "$work"

tmp=$(mktemp -d "$work/package.XXXXXXXX")
cleanup() {
    rm -rf -- "$tmp"
}
trap cleanup EXIT
chmod 0755 "$tmp"
cd "$tmp"
apt-get download "$package=$version" >&2
deb="$tmp/${package}_${version}_amd64.deb"
printf '%s  %s\n' "$digest" "$deb" | sha256sum -c - >&2
dpkg-deb -x "$deb" "$tmp/unpacked"
exe="$tmp/unpacked/usr/lib/$package/endpoint-agent"

# Create the dedicated account from the verified DEB before starting the pilot.
systemd-sysusers "$tmp/unpacked/usr/lib/sysusers.d/$package.conf"
test "$(runuser -u "$probe_user" -- "$exe" --print-hardware-fingerprint)" = \
    "$(runuser -u "$package" -- "$exe" --print-hardware-fingerprint)"
install -d -o "$package" -g "$package" -m 0700 "$payload"

if [ ! -s "$payload/claim-removal-request.json" ]; then
    installation_id=$(cat "$stage/installation-id")
    [[ $installation_id =~ ^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$ ]]
    cat >"$tmp/bootstrap.yaml" <<EOF
gateway:
  endpoint: $origin
  ca_file: /etc/endpoint-agent/ca.crt
provisioning:
  installation_id: $installation_id
  systemd_claim_credential_name: endpoint-enrollment-claim
  permanent_credential_file: /var/lib/endpoint-agent/device-credential
EOF

    credentials=/run/credentials/$unit
    systemd-run --unit="$unit" --quiet --collect \
        -p "User=$package" -p "Group=$package" -p ProtectSystem=strict \
        -p ProtectHome=yes -p NoNewPrivileges=yes -p PrivateTmp=yes \
        -p RuntimeMaxSec=110 -p UMask=0077 \
        -p 'TemporaryFileSystem=/var/lib:rw,mode=0755,size=16M' \
        -p "BindPaths=$payload:/var/lib/endpoint-agent" \
        -p "ReadWritePaths=$payload /var/lib/endpoint-agent" \
        -p "LoadCredential=endpoint-agent-config:$tmp/bootstrap.yaml" \
        -p "LoadCredential=endpoint-agent-ca:$ca" \
        -p "LoadCredential=endpoint-enrollment-claim:$stage/claim" \
        --setenv=ENDPOINT_AGENT_DEPLOYMENT_ENVIRONMENT=production \
        --setenv=ENDPOINT_AGENT_ENROLLMENT_REQUIRED=1 \
        --setenv=ENDPOINT_AGENT_ENROLLMENT_ONLY=1 \
        --setenv=ENDPOINT_AGENT_CONFIG="$credentials/endpoint-agent-config" \
        --setenv=ENDPOINT_AGENT_CA_FILE="$credentials/endpoint-agent-ca" \
        --setenv=ENDPOINT_AGENT_PROVISIONING_HANDOFF_FILE="$credentials/endpoint-enrollment-claim" \
        "$exe" --endpoint-origin "$origin" --data-dir /var/lib/endpoint-agent \
        --install-root "$(dirname "$exe")" --transport-mode gateway_wss --package-managed-updates
    for attempt in $(seq 1 100); do
        [ ! -s "$payload/claim-removal-request.json" ] || break
        systemctl is-active --quiet "$unit" || break
        sleep 1
    done
    if [ "$(systemctl show "$unit" -p LoadState --value)" != not-found ]; then
        systemctl stop "$unit"
    fi
fi

test -s "$payload/claim-removal-request.json"
owner="$(id -u "$package"):$(id -g "$package"):600"
for name in "${identity_files[@]}"; do
    test ! -L "$payload/$name"
    test -s "$payload/$name"
    test "$(stat -c '%u:%g:%a' "$payload/$name")" = "$owner"
done
device_id=$(/usr/bin/python3 -c 'import json, sys; from uuid import UUID
with open(sys.argv[1]) as f:
    identity = json.load(f)
assert identity["schema_version"] == "endpoint_enrollment_identity_v1"
print(UUID(identity["device_id"]))' "$payload/enrollment-identity.json")

test ! -L "$state"
for name in "${identity_files[@]}"; do
    test ! -L "$state/$name"
    if [ -e "$state/$name" ]; then
        cmp -s "$payload/$name" "$state/$name"
    fi
done
apt-get install -y "$deb" >&2
install -o root -g root -m 0644 "$ca" "/etc/$package/ca.crt"
site="/etc/$package/site.conf"
dropin="/etc/systemd/system/$package.service.d"
printf 'ENDPOINT_AGENT_SERVER_ROLE=%s\nENDPOINT_AGENT_FALLBACK_ORIGIN=%s:8443\n' "$server_role" "$origin" > "$tmp/site.conf"
printf '[Service]\nEnvironmentFile=%s\n' "$site" > "$tmp/site-environment.conf"
install -d -m 0755 "$dropin"
for config in "$site" "$dropin/site-environment.conf"; do
    test ! -L "$config"
    input="$tmp/$(basename "$config")"
    if [ -e "$config" ]; then
        cmp -s "$input" "$config"
    else
        install -o root -g root -m 0644 "$input" "$config"
    fi
done
for name in "${identity_files[@]}"; do
    if [ ! -e "$state/$name" ]; then
        install -o "$package" -g "$package" -m 0600 "$payload/$name" "$state/$name"
    fi
    cmp -s "$payload/$name" "$state/$name"
    test "$(stat -c '%u:%g:%a' "$state/$name")" = "$owner"
done

systemctl daemon-reload
systemctl enable --now "$package.service" >&2
systemctl is-active --quiet "$package.service"
check_services
rm -f -- "$stage/claim" "$stage/installation-id"
if [ -d "$stage" ]; then rmdir -- "$stage"; fi
rm -rf -- "$payload"
rm -f -- "$work-request/request.json" "$work-request/id"
printf '%s\n' "$device_id"
