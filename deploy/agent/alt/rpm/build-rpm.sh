#!/usr/bin/env bash
# Build an offline Endpoint Agent RPM from a reviewed Linux release bundle.
set -euo pipefail
IFS=$'\n\t'
umask 077

version=''
release=''
source_bundle=''
output=''
revision=''

die() {
    printf 'build-rpm: %s\n' "$*" >&2
    exit 2
}

usage() {
    cat <<'USAGE'
Usage:
  build-rpm.sh --version VERSION --release RELEASE --output DIRECTORY [--source BUNDLE] [--revision REVISION]

Without --source, the script runs the project Linux PyInstaller release-bundle
builder first. The command must run on Linux with PyInstaller and rpmbuild.
USAGE
}

valid_identifier() {
    [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._+~]{0,63}$ ]]
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) version=${2:-}; shift 2 ;;
        --release) release=${2:-}; shift 2 ;;
        --source) source_bundle=${2:-}; shift 2 ;;
        --output) output=${2:-}; shift 2 ;;
        --revision) revision=${2:-}; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ -n "$version" ]] || die 'missing --version'
valid_identifier "$version" || die 'version must be a bounded RPM identifier'
[[ -n "$release" ]] || die 'missing --release'
valid_identifier "$release" || die 'release must be a bounded RPM identifier'
[[ -n "$output" ]] || die 'missing --output'
command -v rpmbuild >/dev/null 2>&1 || die 'rpmbuild is required'

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
project_root=$(cd "$script_dir/../../../.." && pwd)
python_bin=${PYTHON:-python3}
[[ -n "$revision" ]] || revision=$(git -C "$project_root" rev-parse HEAD)
if [[ -n "$source_bundle" ]]; then
    [[ -d "$source_bundle" && ! -L "$source_bundle" ]] || die '--source must be a regular bundle directory'
else
    build_root=$(mktemp -d)
    trap 'rm -rf -- "$build_root"' EXIT
    "$python_bin" -m pc_agent.build_linux_release_bundle \
        --build --version "$version" --revision "$revision" --output "$build_root"
    source_bundle="$build_root/endpoint-agent-$version"
fi

topdir=$(mktemp -d)
trap 'rm -rf -- "$topdir"; [[ -n "${build_root:-}" ]] && rm -rf -- "$build_root"' EXIT
mkdir -p "$topdir/SOURCES" "$topdir/SPECS" "$output"
"$python_bin" -m pc_agent.build_alt_rpm_source \
    --source "$source_bundle" --version "$version" --revision "$revision" --output "$topdir/SOURCES"
install -m 0644 "$script_dir/endpoint-agent.spec" "$topdir/SPECS/endpoint-agent.spec"
cd "$project_root"
rpmbuild -ba "$topdir/SPECS/endpoint-agent.spec" \
    --define "_topdir $topdir" \
    --define "version $version" \
    --define "release $release"
mapfile -t artifacts < <(find "$topdir/RPMS" -type f -name "endpoint-agent-$version-$release*.rpm" -print)
[[ "${#artifacts[@]}" -eq 1 ]] || die 'RPM build did not produce exactly one x86_64 package'
install -m 0644 "${artifacts[0]}" "$output/$(basename "${artifacts[0]}")"
printf '%s\n' "$output/$(basename "${artifacts[0]}")"
