#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
project_root=$(cd -- "$script_dir/../.." && pwd -P)
release_archive=''
release_manifest=''
launcher=''
output="$project_root/output"
prepare_only=false

usage() {
    cat <<'USAGE'
Usage: build-rpm.sh [--release-archive FILE --release-manifest FILE --launcher FILE]
                    [--output DIRECTORY] [--prepare-only]

Without explicit inputs, builds the Task 8 Linux headless release and stable
Task 9 launcher before invoking rpmbuild. --prepare-only validates and stages
explicit inputs without requiring rpm-build.
USAGE
}

die() {
    printf 'endpoint-agent RPM build: %s\n' "$*" >&2
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --release-archive) release_archive=${2:-}; shift 2 ;;
        --release-manifest) release_manifest=${2:-}; shift 2 ;;
        --launcher) launcher=${2:-}; shift 2 ;;
        --output) output=${2:-}; shift 2 ;;
        --prepare-only) prepare_only=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

provided=0
[[ -n "$release_archive" ]] && ((provided += 1))
[[ -n "$release_manifest" ]] && ((provided += 1))
[[ -n "$launcher" ]] && ((provided += 1))
[[ "$provided" -eq 0 || "$provided" -eq 3 ]] || \
    die 'release archive, release manifest, and launcher must be supplied together'

python_command=${PYTHON:-python3}
command -v "$python_command" >/dev/null 2>&1 || die 'python3 is required'

temporary=$(mktemp -d "${TMPDIR:-/tmp}/endpoint-agent-rpm.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT

if [[ "$provided" -eq 0 ]]; then
    [[ "$(uname -s)" == Linux ]] || die 'default artifact builds require Linux'
    "$python_command" -m PyInstaller --noconfirm \
        --distpath "$temporary/dist" --workpath "$temporary/build-core" \
        "$project_root/pc_agent/pyinstaller_endpoint_core_linux.spec"
    "$python_command" -m PyInstaller --noconfirm \
        --distpath "$temporary/dist" --workpath "$temporary/build-launcher" \
        "$project_root/pc_agent/pyinstaller_launcher_linux.spec"
    # PyInstaller can preserve executable bits from collected shared objects.
    # Task 8 deliberately accepts only the one public entrypoint as executable,
    # so normalize this freshly generated private staging tree before it is
    # independently manifested and verified by the release builder.
    find "$temporary/dist/endpoint-agent" -type d -exec chmod 0755 {} +
    find "$temporary/dist/endpoint-agent" -type f ! -path \
        "$temporary/dist/endpoint-agent/endpoint-agent" -exec chmod 0644 {} +
    chmod 0755 "$temporary/dist/endpoint-agent/endpoint-agent" "$temporary/dist/launcher"
    version=$(
        "$python_command" -c \
            'from pc_agent.version import AGENT_VERSION; print(AGENT_VERSION)'
    )
    revision=${SOURCE_REVISION:-}
    if [[ -z "$revision" ]]; then
        revision=$(git -C "$project_root" rev-parse HEAD) || \
            die 'SOURCE_REVISION is required outside a Git checkout'
    fi
    "$python_command" "$project_root/tools/build_linux_agent.py" \
        --channel stable --source "$temporary/dist/endpoint-agent" \
        --output "$temporary/release" --version "$version" --revision "$revision"
    release_archive="$temporary/release/endpoint-agent-linux_amd64-$version.tar.gz"
    release_manifest="$temporary/release/endpoint-agent-linux_amd64-$version.manifest.json"
    launcher="$temporary/dist/launcher"
fi

[[ -f "$release_archive" && ! -L "$release_archive" ]] || die 'release archive must be a regular file'
[[ -f "$release_manifest" && ! -L "$release_manifest" ]] || die 'release manifest must be a regular file'
[[ -f "$launcher" && ! -L "$launcher" ]] || die 'launcher must be a regular file'

details=$(
    "$python_command" - "$release_archive" "$release_manifest" "$launcher" <<'PY'
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile

archive = Path(sys.argv[1])
sidecar_path = Path(sys.argv[2])
launcher = Path(sys.argv[3])
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:[-+][0-9A-Za-z.-]+)?\Z")
REVISION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PRIVATE_MARKERS = (b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN RSA PRIVATE KEY-----")

def fail(message):
    print(f"endpoint-agent RPM build: {message}", file=sys.stderr)
    raise SystemExit(1)

def load_json(path):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                fail("manifest contains duplicate keys")
            value[key] = item
        return value
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        fail("manifest is not valid UTF-8 JSON")

sidecar = load_json(sidecar_path)
required_sidecar = {
    "archive_type", "artifact_name", "build_identifier", "channel", "platform",
    "schema_version", "sha256", "size", "source_revision", "version",
}
if not isinstance(sidecar, dict) or set(sidecar) != required_sidecar:
    fail("release sidecar has an invalid schema")
version = sidecar["version"]
revision = sidecar["source_revision"]
if not isinstance(version, str) or not VERSION.fullmatch(version):
    fail("release version is invalid")
if not isinstance(revision, str) or not REVISION.fullmatch(revision):
    fail("source revision is invalid")
expected_name = f"endpoint-agent-linux_amd64-{version}.tar.gz"
if sidecar["schema_version"] != "endpoint_linux_agent_artifact_v1" or sidecar["platform"] != "linux_amd64":
    fail("release sidecar is not a Task 8 linux_amd64 artifact")
if sidecar["archive_type"] != "tar.gz" or sidecar["artifact_name"] != expected_name or archive.name != expected_name:
    fail("release archive name or type is invalid")
archive_bytes = archive.read_bytes()
if sidecar["size"] != len(archive_bytes) or sidecar["sha256"] != hashlib.sha256(archive_bytes).hexdigest():
    fail("release archive digest mismatch")
if any(marker in launcher.read_bytes() for marker in PRIVATE_MARKERS):
    fail("private key marker found in launcher")

try:
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        names = [member.name for member in members]
        if len(names) != len(set(names)):
            fail("release archive contains duplicate paths")
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
                fail("release archive contains path traversal")
            if not (member.isfile() or member.isdir()):
                fail("release archive contains a non-regular entry")
        if "manifest.json" not in names or "endpoint-agent/endpoint-agent" not in names:
            fail("release archive is missing the Task 8 manifest or entrypoint")
        manifest_stream = bundle.extractfile("manifest.json")
        if manifest_stream is None:
            fail("release archive manifest is unreadable")
        inner = json.loads(manifest_stream.read())
        if not isinstance(inner, dict) or set(inner) != {"files", "schema_version", "source_revision", "version"}:
            fail("inner release manifest has an invalid schema")
        if inner["schema_version"] != 1 or inner["version"] != version or inner["source_revision"] != revision:
            fail("inner and outer release manifests disagree")
        expected = {}
        for item in inner["files"]:
            if not isinstance(item, dict) or set(item) != {"mode", "path", "sha256"}:
                fail("inner release file entry is invalid")
            path = item["path"]
            if path in expected or not isinstance(path, str) or path == "manifest.json":
                fail("inner release file path is invalid")
            if not isinstance(item["sha256"], str) or not SHA256.fullmatch(item["sha256"]):
                fail("inner release digest is invalid")
            if not isinstance(item["mode"], str) or not re.fullmatch(r"0[0-7]{3}", item["mode"]):
                fail("inner release mode is invalid")
            expected[path] = item
        actual_files = {member.name: member for member in members if member.isfile() and member.name != "manifest.json"}
        if set(actual_files) != set(expected):
            fail("inner release manifest does not cover the payload")
        for path, member in actual_files.items():
            stream = bundle.extractfile(member)
            if stream is None:
                fail("release payload is unreadable")
            payload = stream.read()
            if hashlib.sha256(payload).hexdigest() != expected[path]["sha256"]:
                fail("inner release payload digest mismatch")
            if f"{stat.S_IMODE(member.mode):04o}" != expected[path]["mode"]:
                fail("inner release payload mode mismatch")
            if any(marker in payload for marker in PRIVATE_MARKERS):
                fail("private key marker found in release payload")
except (OSError, tarfile.TarError, UnicodeDecodeError, json.JSONDecodeError):
    fail("release archive is invalid")

print(version)
print(revision)
PY
) || exit $?
mapfile -t release_details <<< "$details"
[[ ${#release_details[@]} -eq 2 ]] || die 'release verifier returned invalid metadata'
version=${release_details[0]}
revision=${release_details[1]}

build_root="$output/rpmbuild"
[[ ! -e "$build_root" && ! -L "$build_root" ]] || die "build root already exists: $build_root"
mkdir -p \
    "$build_root/BUILD" "$build_root/BUILDROOT" "$build_root/RPMS" \
    "$build_root/SOURCES" "$build_root/SPECS" "$build_root/SRPMS"

stage_file() {
    local mode=$1 source=$2 destination=$3
    cp -- "$source" "$destination"
    if [[ "$(uname -s)" == Linux ]]; then
        chmod "$mode" "$destination"
    fi
}

if [[ "$(uname -s)" == Linux ]]; then
    chmod 0700 "$build_root" "$build_root"/*
fi
stage_file 0600 "$release_archive" "$build_root/SOURCES/endpoint-agent-linux_amd64-$version.tar.gz"
stage_file 0600 "$release_manifest" "$build_root/SOURCES/endpoint-agent-linux_amd64-$version.manifest.json"
stage_file 0755 "$launcher" "$build_root/SOURCES/launcher"
stage_file 0644 "$script_dir/endpoint-agent.spec" "$build_root/SPECS/endpoint-agent.spec"
stage_file 0644 "$script_dir/README.md" "$build_root/SOURCES/README.md"
stage_file 0644 "$script_dir/SOURCES/endpoint-agent.service" "$build_root/SOURCES/endpoint-agent.service"
stage_file 0644 "$project_root/deploy/agent/alt/endpoint-agent-update.service" "$build_root/SOURCES/endpoint-agent-update.service"
stage_file 0644 "$project_root/deploy/agent/alt/endpoint-agent-update.path" "$build_root/SOURCES/endpoint-agent-update.path"
stage_file 0755 "$project_root/deploy/agent/alt/apply-pending-alt-update.sh" "$build_root/SOURCES/apply-pending-alt-update.sh"
stage_file 0755 "$script_dir/SOURCES/check-start-prerequisites.py" "$build_root/SOURCES/check-start-prerequisites.py"
stage_file 0644 "$script_dir/SOURCES/endpoint-agent.tmpfiles" "$build_root/SOURCES/endpoint-agent.tmpfiles"
stage_file 0644 "$script_dir/SOURCES/endpoint-agent.logrotate" "$build_root/SOURCES/endpoint-agent.logrotate"

if [[ "$prepare_only" == true ]]; then
    printf 'prepared=%s\nversion=%s\nrevision=%s\n' "$build_root" "$version" "$revision"
    exit 0
fi

command -v rpmbuild >/dev/null 2>&1 || die 'rpmbuild is required on the ALT build worker'
rpmbuild -bb \
    --define "_topdir $build_root" \
    --define "agent_version $version" \
    --define "source_revision $revision" \
    "$build_root/SPECS/endpoint-agent.spec"
mapfile -t built_rpms < <(
    find "$build_root/RPMS" -type f -name 'endpoint-agent-*.rpm' \
        ! -name 'endpoint-agent-debuginfo-*.rpm' -print
)
[[ ${#built_rpms[@]} -eq 1 ]] || die 'rpmbuild did not produce exactly one binary RPM'
install -m 0644 "${built_rpms[0]}" "$output/$(basename -- "${built_rpms[0]}")"
printf 'rpm=%s\n' "$output/$(basename -- "${built_rpms[0]}")"
