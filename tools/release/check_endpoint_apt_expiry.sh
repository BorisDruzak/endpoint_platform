#!/bin/sh
# Check both published Endpoint APT suites. Exit nonzero if either needs attention.
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
base_url=${ENDPOINT_APT_BASE_URL:-https://endpoint.sosnadmin.local/downloads}
ca=${ENDPOINT_APT_CA:-/etc/apt/keyrings/endpoint-ubuntu-ca.crt}
keyring=${ENDPOINT_APT_KEYRING:-/etc/apt/keyrings/endpoint-ubuntu-apt.gpg}
fingerprint=${ENDPOINT_APT_FINGERPRINT:-D132784F1C7F0D78BDA2842FDE5739F7FD0AFEBE}
verify_public_keyring=${ENDPOINT_APT_VERIFY_PUBLIC_KEYRING:-0}
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
GNUPGHOME=$scratch
export GNUPGHOME
index=$scratch/InRelease
public_keyring=$scratch/endpoint-apt-transition.gpg

check_index() {
  python3 "$script_dir/build_ubuntu_apt_repository.py" --check "$index" \
    --codename "$codename" --keyring "$1" --signing-fingerprint "$channel_fingerprint"
}

failed=0
for endpoint in ubuntu/noble debian/bookworm; do
  channel=${endpoint%/*}
  codename=${endpoint#*/}
  case "$channel" in
    ubuntu) channel_fingerprint=${ENDPOINT_APT_UBUNTU_FINGERPRINT:-$fingerprint} ;;
    debian) channel_fingerprint=${ENDPOINT_APT_DEBIAN_FINGERPRINT:-$fingerprint} ;;
  esac
  printf '%s\n' "$endpoint"
  if ! curl --fail --silent --show-error --max-time 30 --cacert "$ca" \
    --output "$index" "$base_url/$channel/dists/$codename/InRelease" ||
    ! check_index "$keyring"; then
    printf '<3>Endpoint APT metadata check failed for %s\n' "$endpoint" >&2
    failed=1
    continue
  fi
  if [ "$verify_public_keyring" = 1 ]; then
    if curl --fail --silent --show-error --max-time 15 --max-filesize 65536 --cacert "$ca" \
      --output "$public_keyring" "$base_url/$channel/endpoint-apt-transition.gpg" &&
      check_index "$public_keyring"; then
      printf 'Endpoint APT published keyring verified for %s\n' "$endpoint"
    else
      printf '<3>Endpoint APT published keyring check failed for %s\n' "$endpoint" >&2
      failed=1
    fi
  fi
done
exit "$failed"
