#!/usr/bin/env bash
# Scoped issuance on the existing corporate CA. Never export its private key.
set -euo pipefail
umask 077
[[ $EUID -eq 0 && $# -eq 2 && $2 =~ ^[a-fA-F0-9]{64}$ ]] || { echo 'Run as root with CSR path and independently verified CSR SHA256' >&2; exit 1; }
[[ $(hostname -I) == *192.168.100.5* ]] || { echo 'Wrong CA host' >&2; exit 1; }
csr=$(realpath "$1")
expected_csr=${2,,}
ca_dir=/root/sosnadmin-ca
ca_cert=$ca_dir/certs/sosnadmin-local-ca.crt.pem
expected_ca=5525ECCF01536B7F0436D96500C663F7A58EDAC463F00F0FB34A59DD8B3250BE
actual_ca=$(openssl x509 -in "$ca_cert" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':')
[[ $actual_ca == "$expected_ca" ]] || { echo 'Unapproved CA identity' >&2; exit 1; }
# Serialize this workflow's use of the shared CA index/serial. Operators must
# not run another issuance workflow concurrently against this same CA.
exec 9>"$ca_dir/sso-issuance.lock"
flock -n 9 || { echo 'Another certificate issuance is in progress' >&2; exit 1; }
[[ ! -e /home/osn-admin/ad-main-20261027.crt ]] || { echo 'Public output exists; review prior issuance' >&2; exit 1; }
install -d -m 0700 "$ca_dir/receipts"
receipt=$(mktemp -d "$ca_dir/receipts/ad-main-20261027-XXXXXX")
install -m 0600 "$csr" "$receipt/request.pem"
actual_csr=$(sha256sum "$receipt/request.pem" | cut -d' ' -f1)
[[ $actual_csr == "$expected_csr" ]] || { echo 'CSR differs from the independently verified AD request' >&2; exit 1; }
openssl req -in "$receipt/request.pem" -verify -noout >/dev/null
subject=$(openssl req -in "$receipt/request.pem" -noout -subject -nameopt RFC2253)
[[ $subject == 'subject=CN=AD-MAIN.sosnadmin.local' ]] || { echo 'Unexpected CSR subject' >&2; exit 1; }
openssl req -in "$receipt/request.pem" -pubkey -noout | openssl rsa -pubin -noout >/dev/null
bits=$(openssl req -in "$receipt/request.pem" -pubkey -noout | openssl pkey -pubin -text -noout | head -1 | tr -cd '0-9')
[[ $bits =~ ^[0-9]+$ && $bits -ge 3072 ]] || { echo 'RSA key is below 3072 bits' >&2; exit 1; }
san=$(openssl req -in "$receipt/request.pem" -text -noout | awk '/X509v3 Subject Alternative Name/{getline; gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print}')
[[ $san == 'DNS:AD-MAIN.sosnadmin.local' ]] || { echo 'Unexpected CSR SAN' >&2; exit 1; }
cp "$ca_dir/index.txt" "$receipt/index.before"
cp "$ca_dir/serial" "$receipt/serial.before"
# Preserve the canonical CA database and policy, but do not copy arbitrary CSR
# extensions. The approved hostname/EKU/key usage below are the only additions.
# The scoped copy explicitly pins signing identity and database paths instead
# of relying on a separately checked file matching an arbitrary config.
sed -e 's/^[[:space:]]*copy_extensions[[:space:]]*=.*/copy_extensions = none/' \
  -e 's|^[[:space:]]*certificate[[:space:]]*=.*|certificate = /root/sosnadmin-ca/certs/sosnadmin-local-ca.crt.pem|' \
  -e 's|^[[:space:]]*private_key[[:space:]]*=.*|private_key = /root/sosnadmin-ca/private/sosnadmin-local-ca.key.pem|' \
  -e 's|^[[:space:]]*database[[:space:]]*=.*|database = /root/sosnadmin-ca/index.txt|' \
  -e 's|^[[:space:]]*serial[[:space:]]*=.*|serial = /root/sosnadmin-ca/serial|' \
  -e 's|^[[:space:]]*new_certs_dir[[:space:]]*=.*|new_certs_dir = /root/sosnadmin-ca/newcerts|' \
  "$ca_dir/openssl-ca.cnf" >"$receipt/ca.cnf"
cat >"$receipt/extensions.cnf" <<'EXT'
[ldaps_server]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=DNS:AD-MAIN.sosnadmin.local
EXT
openssl ca -batch -notext -config "$receipt/ca.cnf" -extfile "$receipt/extensions.cnf" \
  -extensions ldaps_server -days 397 -in "$receipt/request.pem" -out "$receipt/certificate.pem"
openssl verify -purpose sslserver -verify_hostname AD-MAIN.sosnadmin.local \
  -CAfile "$ca_cert" "$receipt/certificate.pem"
openssl x509 -in "$receipt/certificate.pem" -noout -subject -issuer -serial -dates -fingerprint -sha256
# Only public certificate material leaves the root-only receipt directory.
[[ ! -e /home/osn-admin/ad-main-20261027.crt ]] || { echo 'Public output exists; use receipt without overwriting it' >&2; exit 1; }
install -o root -g root -m 0644 "$receipt/certificate.pem" /home/osn-admin/ad-main-20261027.crt
sha256sum "$receipt/request.pem" "$receipt/certificate.pem" >"$receipt/public-sha256.txt"
echo "Issuance receipt: $receipt"
