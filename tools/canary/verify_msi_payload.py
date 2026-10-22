"""Read-only compiled-package admission before signing an authored MSI."""
import argparse
import json
from pathlib import Path

from endpoint_contracts.runtime_payload import read_json


def verify_package(msi_path, release_path):
    from pc_agent.platform.windows.msi_inventory import read_expected_package
    with Path(release_path).open('rb') as stream:
        raw = stream.read(4097)
    release = read_json(raw, 4096)
    expected = read_expected_package(Path(msi_path), release)
    return {'version': expected.identity.version,
            'source_revision': expected.identity.source_revision,
            'foundation_schema': expected.foundation_schema,
            'foundation_file_count': len(expected.foundation_files)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--msi', required=True, type=Path)
    parser.add_argument('--release-manifest', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(verify_package(args.msi, args.release_manifest), separators=(',', ':')))


if __name__ == '__main__':
    main()
