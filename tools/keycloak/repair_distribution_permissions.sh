#!/usr/bin/env bash
# Narrow recovery of the stopped 26.8.1 public distribution only.
set -euo pipefail
umask 077
die() { printf '%s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die 'Run as root on the approved .19 host'
[[ $# -eq 1 || ( $# -eq 2 && $2 == --apply ) ]] || die 'Usage: repair_distribution_permissions.sh pinned.tar.gz [--apply]'
[[ -f $1 && ! -L $1 ]] || die 'Expected a physical verified distribution archive'
archive=$(realpath -e "$1")
expected_version=26.8.1
expected_digest=4e2740b181faa2ea623a1c2ecf00855935311e546046e2f857615a47ed24cbe8
release_dir=/opt/keycloak/keycloak-$expected_version
[[ $(hostname -I) == *192.168.100.19* ]] || die 'Wrong deployment host'
[[ ! -L /opt/keycloak && $(realpath -e /opt/keycloak) == /opt/keycloak ]] || die 'Unexpected installation root'
[[ -d $release_dir && ! -L $release_dir ]] || die 'Expected physical pinned release directory'
[[ -L /opt/keycloak/current && $(readlink /opt/keycloak/current) == keycloak-$expected_version ]] || die 'Unexpected current release link'
[[ $(readlink -f /opt/keycloak/current) == "$release_dir" ]] || die 'Unexpected resolved release'
[[ -L $release_dir/data && $(readlink "$release_dir/data") == /var/lib/keycloak ]] || die 'Unexpected data link; no repair permitted'
[[ $(getent passwd keycloak | cut -d: -f6) == /var/lib/keycloak ]] || die 'Unexpected service Unix identity'
[[ $(id -Gn keycloak) == keycloak ]] || die 'Unexpected supplemental service groups'
[[ $(systemctl show keycloak --property=ActiveState --value) == inactive ]] || die 'Keycloak must be installed and stopped'
[[ $(systemctl show keycloak --property=User --value) == keycloak ]] || die 'Unexpected service identity'
printf '%s  %s\n' "$expected_digest" "$archive" | sha256sum --check --status || die 'Pinned archive checksum mismatch'
# The runtime config is external to this tree. Check that the stock config
# still matches the archive before making any physical distribution readable.
tar -xOf "$archive" "keycloak-$expected_version/conf/keycloak.conf" | cmp -s - "$release_dir/conf/keycloak.conf" || die 'Distribution configuration differs from pinned public defaults'
if find -P "$release_dir" -type l ! -path "$release_dir/data" -print -quit | grep -q .; then
    die 'Unexpected distribution symlink; refusing to follow or modify it'
fi
if find -P "$release_dir" \( -type f -o -type d \) \( ! -user root -o ! -group root \) -print -quit | grep -q .; then
    die 'Unexpected distribution ownership; no permission repair permitted'
fi
if find -P "$release_dir" -type f \( -iname '*.env' -o -iname '*.key' -o -iname '*.pem' -o -iname '*.p12' -o -iname '*.pfx' -o -iname '*.jks' -o -iname '*.keystore' -o -iname '*.credential.xml' \) -print -quit | grep -q .; then
    die 'Potential private material in public distribution; manual review required'
fi
printf 'status=PlanValidated version=%s physical_root=%s\n' "$expected_version" "$release_dir"
stat -c 'mode=%a owner=%U:%G path=%n' "$release_dir" "$release_dir/bin/kc.sh"
[[ ${2:-} == --apply ]] || exit 0
# -P never follows data or any other symlink. a+rX preserves existing execute
# bits, adds traversal only for directories and adds no new write permission.
find -P "$release_dir" \( -type d -o -type f \) -exec chmod a+rX -- {} +
runuser -u keycloak -- /opt/keycloak/current/bin/kc.sh --version >/dev/null
printf '%s\n' 'status=RepairedServiceIdentityVerified service=stopped'
