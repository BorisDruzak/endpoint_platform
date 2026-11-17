#!/usr/bin/env bash
# Reviewed first-install only. No existing application service is changed/restarted.
set -euo pipefail
umask 077
die() { printf '%s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die 'Run as root on the approved .19 host'
[[ $# -eq 4 || ( $# -eq 5 && ( $5 == --prepare-without-directory || $5 == --resume-before-database ) ) ]] || die 'Usage: install.sh verified.tar.gz ldap-ca.pem sso-fullchain.pem sso-key.pem [--prepare-without-directory|--resume-before-database]'
resume=false
[[ ${5:-} != --resume-before-database ]] || resume=true
archive=$(realpath "$1")
ldap_ca=$(realpath "$2")
tls_cert=$(realpath "$3")
tls_key=$(realpath "$4")
asset_dir=$(cd "$(dirname "$0")/../../deploy/keycloak" && pwd)
for dependency in python3 pg_createcluster pg_conftool pg_ctlcluster psql openssl nginx; do
    command -v "$dependency" >/dev/null || die "Missing prerequisite: $dependency"
done
for file in "$archive" "$ldap_ca" "$tls_cert" "$tls_key"; do
    [[ -f $file && ! -L $file ]] || die 'Missing or symbolic-link deployment input'
done
[[ $(stat -c '%a:%u' "$tls_key") == '600:0' ]] || die 'Input private key must be root owned mode 0600'
if ! $resume; then
    [[ ! -e /opt/keycloak && ! -e /etc/keycloak && ! -e /var/lib/keycloak ]] || die 'Existing Keycloak paths require a reviewed upgrade/backup procedure'
    [[ ! -e /etc/postgresql/16/keycloak ]] || die 'Dedicated cluster already exists'
else
    # Only the interrupted first-install phase BEFORE credentials/database and
    # service creation is recoverable here. Never rerun against an active SSO.
    [[ -d /etc/postgresql/16/keycloak && -d /etc/keycloak && -d /var/lib/keycloak ]] || die 'Incomplete first-install layout'
    [[ ! -e /etc/keycloak/keycloak.conf && ! -e /etc/systemd/system/keycloak.service ]] || die 'Database/configuration phase already ran; use reviewed upgrade procedure'
    [[ $(pg_conftool -s 16 keycloak show port) == 5544 ]] || die 'Unexpected cluster port'
    [[ $(getent passwd keycloak | cut -d: -f6) == /var/lib/keycloak ]] || die 'Unexpected Unix identity'
fi
[[ $(hostname -I) == *192.168.100.19* ]] || die 'Wrong deployment host'
[[ $(getent ahostsv4 sso.sosnadmin.local | awk 'NR==1 {print $1}') == 192.168.100.19 ]] || die 'Approve and provision exact SSO DNS first'
available_kb=$(df --output=avail /opt | tail -1)
(( available_kb >= 8388608 )) || die 'Require at least 8 GiB free before first installation'
for port in 5544 8088 9008; do
    ! ss -Hln "sport = :$port" | grep -q . || die "Port $port already in use"
done
version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$asset_dir/release.json")
digest=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sha256"])' "$asset_dir/release.json")
printf '%s  %s\n' "$digest" "$archive" | sha256sum --check --status || die 'Archive checksum mismatch'
if $resume; then
    [[ $(readlink -f /opt/keycloak/current) == /opt/keycloak/keycloak-$version ]] || die 'Unexpected interrupted distribution'
    cmp -s "$ldap_ca" /etc/keycloak/trust/ad-ca.pem || die 'Interrupted CA differs'
    cmp -s "$tls_cert" /etc/keycloak/tls/fullchain.pem || die 'Interrupted certificate differs'
    cmp -s "$tls_key" /etc/keycloak/tls/key.pem || die 'Interrupted key differs'
fi
openssl verify -purpose sslserver -verify_hostname sso.sosnadmin.local -CAfile "$ldap_ca" "$tls_cert" >/dev/null
cert_key=$(openssl x509 -in "$tls_cert" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum)
private_key=$(openssl pkey -in "$tls_key" -pubout -outform DER | sha256sum)
[[ $cert_key == "$private_key" ]] || die 'TLS key mismatch'
# Refuse plaintext LDAP and failed TLS before any mutation. This CA must validate
# both the SSO leaf and exact DC leaf, or provide a PEM bundle of both CA chains.
if [[ ${5:-} != --prepare-without-directory ]]; then
    timeout 15 openssl s_client -connect AD-MAIN.sosnadmin.local:636 \
        -servername AD-MAIN.sosnadmin.local -verify_hostname AD-MAIN.sosnadmin.local \
        -verify_return_error -CAfile "$ldap_ca" -brief </dev/null >/dev/null 2>&1 || die 'Secure LDAP prerequisite failed'
fi
if ! $resume; then
apt-get update -qq
apt-get install -y --no-install-recommends openjdk-21-jre-headless
getent passwd keycloak >/dev/null && die 'Existing keycloak Unix identity requires review'
useradd --system --user-group --home-dir /var/lib/keycloak --shell /usr/sbin/nologin keycloak
install -d -m 0755 /opt/keycloak
install -d -o keycloak -g keycloak -m 0700 /var/lib/keycloak
install -d -o root -g keycloak -m 0750 /etc/keycloak /etc/keycloak/trust
install -d -o root -g root -m 0700 /etc/keycloak/tls
tar -xzf "$archive" -C /opt/keycloak --no-same-owner --same-permissions
[[ -f /opt/keycloak/keycloak-$version/bin/kc.sh ]] || die 'Unexpected archive layout'
chown -R root:root "/opt/keycloak/keycloak-$version"
[[ ! -L /opt/keycloak/keycloak-$version/data ]] || die 'Unexpected archive data link'
if [[ -d /opt/keycloak/keycloak-$version/data ]]; then
    mv "/opt/keycloak/keycloak-$version/data" "/opt/keycloak/keycloak-$version/data.initial"
fi
ln -s /var/lib/keycloak "/opt/keycloak/keycloak-$version/data"
ln -s "keycloak-$version" /opt/keycloak/current
install -o root -g keycloak -m 0640 "$ldap_ca" /etc/keycloak/trust/ad-ca.pem
install -o root -g root -m 0644 "$tls_cert" /etc/keycloak/tls/fullchain.pem
install -o root -g root -m 0600 "$tls_key" /etc/keycloak/tls/key.pem
pg_createcluster 16 keycloak --port 5544 --start-conf=auto -- --auth-local=peer --auth-host=scram-sha-256
fi
# pg_conftool infers numeric values and misclassifies a dotted IPv4 literal;
# quoting its argument instead would escape the quotes into the hostname.
# Use a PostgreSQL-owned, explicitly quoted include and the real server parser.
pg_conftool 16 keycloak remove listen_addresses
printf "listen_addresses = '127.0.0.1'\n" | install -o root -g postgres -m 0640 /dev/stdin /etc/postgresql/16/keycloak/conf.d/10-keycloak-loopback.conf
[[ $(runuser -u postgres -- /usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/keycloak -c config_file=/etc/postgresql/16/keycloak/postgresql.conf -C listen_addresses) == 127.0.0.1 ]] || die 'PostgreSQL loopback configuration failed real parser validation'
pg_ctlcluster 16 keycloak start
[[ $(runuser -u postgres -- psql -X -At -p 5544 postgres -c "SELECT count(*) FROM pg_roles WHERE rolname='keycloak'") == 0 ]] || die 'Unexpected existing application role; do not rotate its credentials'
db_password=$(openssl rand -hex 32)
# Input is generated hex, and passed on stdin only. Never enable shell tracing.
runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -p 5544 postgres >/dev/null <<SQL
CREATE ROLE keycloak LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '$db_password';
CREATE DATABASE keycloak OWNER keycloak;
REVOKE ALL ON DATABASE keycloak FROM PUBLIC;
SQL
install -o root -g keycloak -m 0640 "$asset_dir/keycloak.conf" /etc/keycloak/keycloak.conf
printf 'db-password=%s\n' "$db_password" >>/etc/keycloak/keycloak.conf
unset db_password
# Build only non-secret options, keep the immutable optimized distribution root owned.
(
    umask 022
    /opt/keycloak/current/bin/kc.sh build --db=postgres --health-enabled=true --metrics-enabled=false --cache=local >/dev/null
)
chown -R keycloak:keycloak /var/lib/keycloak
# The actual service identity must traverse/read/execute the optimized public
# distribution; a successful root build cannot establish this contract.
runuser -u keycloak -- /opt/keycloak/current/bin/kc.sh --version >/dev/null
install -m 0644 "$asset_dir/keycloak.service" /etc/systemd/system/keycloak.service
install -m 0644 "$asset_dir/keycloak.nginx.conf" /etc/nginx/sites-available/keycloak
install -m 0644 "$asset_dir/keycloak-backup.service" /etc/systemd/system/keycloak-backup.service
install -m 0644 "$asset_dir/keycloak-backup.timer" /etc/systemd/system/keycloak-backup.timer
install -m 0700 "$(dirname "$0")/backup.sh" /usr/local/sbin/keycloak-backup
systemctl daemon-reload
printf '%s\n' 'Installed dedicated cluster and stopped Keycloak. Import pilot realm and bootstrap admin through root-only runtime secret inputs; then follow the runbook acceptance gate.'
