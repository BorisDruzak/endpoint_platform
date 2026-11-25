"""Admit an immutable Setup transport against the signed MSI's exact Core tree."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

from endpoint_contracts.runtime_payload import (
    BUNDLE_FILENAME, MAX_MANIFEST_BYTES, PayloadConflict, read_json,
    verify_payload, verify_windows_archive,
)


def verify_reused_archive(archive: Path, runtime: Path, release: dict) -> None:
    with archive.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    identity = verify_windows_archive(archive, sha256=digest, size=archive.stat().st_size,
        version=release['version'], minimum_launcher_version=release['version'])
    # Release manifests retain the qualified build's original executable name;
    # the installed/OTA contract normalizes it to pc_agent.exe (as msi_inventory).
    original_tree = hashlib.sha256()
    for name, size, digest in sorted(
            ('endpoint_agent_core.exe' if f.path == 'pc_agent.exe' else f.path, f.size, f.sha256)
            for f in identity.files):
        original_tree.update(f'{name}\0{size}\0{digest}\n'.encode())
    if (identity.source_revision != release['source_revision']
            or original_tree.hexdigest() != release['initial_runtime_tree_sha256']):
        raise PayloadConflict()
    with zipfile.ZipFile(archive) as bundle:
        manifest = read_json(bundle.read(BUNDLE_FILENAME), MAX_MANIFEST_BYTES)
    if verify_payload(runtime, manifest,
            excluded=frozenset({'.endpoint-msi-runtime.json', BUNDLE_FILENAME})) != identity:
        raise PayloadConflict()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--release', type=Path, required=True)
    args = parser.parse_args()
    verify_reused_archive(args.archive, args.runtime, json.loads(args.release.read_bytes()))
