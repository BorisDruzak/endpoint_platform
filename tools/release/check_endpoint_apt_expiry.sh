#!/bin/sh
# Check both published Endpoint APT suites. Exit nonzero if either needs attention.
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
base_url=${ENDPOINT_APT_BASE_URL:-https://endpoint.sosnadmin.local/downloads}
ca=${ENDPOINT_APT_CA:-/etc/apt/keyrings/endpoint-ubuntu-ca.crt}
keyring=${ENDPOINT_APT_KEYRING:-/etc/apt/keyrings/endpoint-ubuntu-apt.gpg}
fingerprint=${ENDPOINT_APT_FINGERPRINT:-D132784F1C7F0D78BDA2842FDE5739F7FD0AFEBE}
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
GNUPGHOME=$scratch
export GNUPGHOME
index=$scratch/InRelease

failed=0
for endpoint in ubuntu/noble debian/bookworm; do
  channel=${endpoint%/*}
  codename=${endpoint#*/}
  printf '%s\n' "$endpoint"
  if ! curl --fail --silent --show-error --max-time 30 --cacert "$ca" \
    --output "$index" "$base_url/$channel/dists/$codename/InRelease" ||
    ! python3 "$script_dir/build_ubuntu_apt_repository.py" --check "$index" \
      --codename "$codename" --keyring "$keyring" --signing-fingerprint "$fingerprint"; then
    printf '<3>Endpoint APT metadata check failed for %s\n' "$endpoint" >&2
    failed=1
  fi
done
exit "$failed"
