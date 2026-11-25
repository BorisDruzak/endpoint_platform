#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $EUID -eq 0 ]] || { printf '%s\n' 'Run as root' >&2; exit 1; }
backup_root=/var/backups/keycloak
install -d -o root -g root -m 0700 "$backup_root"
backup_dir=$(mktemp -d "$backup_root/$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")
# Only publish a completion marker after both the consistent DB snapshot and
# secret-bearing configuration archive succeed. No automatic backup deletion.
runuser -u postgres -- pg_dump -p 5544 -Fc keycloak >"$backup_dir/keycloak.dump"
tar -czf "$backup_dir/config.tar.gz" -C / etc/keycloak \
    etc/systemd/system/keycloak.service etc/nginx/sites-available/keycloak
readlink -f /opt/keycloak/current >"$backup_dir/distribution.txt"
sha256sum "$backup_dir/keycloak.dump" "$backup_dir/config.tar.gz" >"$backup_dir/SHA256SUMS"
touch "$backup_dir/COMPLETE"
printf '%s\n' 'Keycloak backup completed; transfer encrypted backup to the approved off-host vault.'
