"""Assemble an exact native ALT kit from a verified RPM pair and Setup."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import tarfile

from tools.release.linux_native_verifier import NativeRPMVerifier, PUBLISHER, snapshot


def build(core, sensor, setup, public_key, output, *, version='3.2.183', source_revision=None):
    if (not re.fullmatch(r'(?:0|[1-9][0-9]{0,4})(?:\.(?:0|[1-9][0-9]{0,4})){2}', version)
        or tuple(map(int, version.split('.'))) < (3, 2, 183)):
        raise ValueError('EXACT_NATIVE_VERSION_REQUIRED')
    if source_revision is None and version != '3.2.183':
        raise ValueError('NEW_NATIVE_KIT_REQUIRES_BOUND_SOURCE')
    if source_revision is not None and not re.fullmatch(r'[0-9a-f]{40}', source_revision):
        raise ValueError('INVALID_BOUND_SOURCE')
    verifier = NativeRPMVerifier(public_key)
    left, right = verifier(core), verifier(sensor)
    if (left.package != 'endpoint-agent' or right.package != 'endpoint-agent-user-sensor'
        or left.version != version or right.version != left.version
        or (source_revision is not None and left.source_revision != source_revision)
        or (left.source_revision, left.frozen_manifest_sha256) != (right.source_revision, right.frozen_manifest_sha256)):
        raise ValueError('EXACT_NATIVE_PAIR_REQUIRED')
    with snapshot(setup) as (_, digest):
        if digest != left.setup_sha256:
            raise ValueError('SETUP_NOT_BOUND_BY_SIGNED_CORE')
    output = Path(output)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    name = f'endpoint-alt-pilot-{version}-1'
    files = {Path(core).name: Path(core), Path(sensor).name: Path(sensor),
        'endpoint-agent-setup': Path(setup), 'endpoint-rpm-release.asc': Path(public_key)}
    manifest = {'schema_version':'endpoint_alt_native_kit_v3', 'kit_name':name,
        'agent_version':version,'agent_source_revision':left.source_revision,
        'frozen_manifest_sha256':left.frozen_manifest_sha256,'publisher_fingerprint':PUBLISHER,
        'files':{}}
    for key, path in files.items():
        with path.open('rb') as stream:
            manifest['files'][key] = {'sha256':hashlib.file_digest(stream,'sha256').hexdigest(), 'size':path.stat().st_size}
    metadata = output/(name+'.manifest.json')
    metadata.write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n',encoding='ascii')
    files['native-kit-manifest.json'] = metadata
    target = output/(name+'.tar.gz')
    with target.open('xb') as stream, gzip.GzipFile(fileobj=stream,mode='wb',filename='',mtime=0) as compressed:
        with tarfile.open(fileobj=compressed,mode='w',format=tarfile.PAX_FORMAT) as archive:
            for relative, path in sorted(files.items()):
                entry = tarfile.TarInfo(name+'/'+relative)
                entry.mode = 0o755 if relative == 'endpoint-agent-setup' else 0o644
                entry.size = path.stat().st_size
                with path.open('rb') as source:
                    archive.addfile(entry, source)
    for name, proof in manifest['files'].items():
        with files[name].open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != proof['sha256'] or files[name].stat().st_size != proof['size']:
                raise ValueError('NATIVE_KIT_INPUT_CHANGED')
    return target, metadata


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('core','sensor','setup','public-key','output'):
        parser.add_argument('--'+key,type=Path,required=True)
    parser.add_argument('--version', default='3.2.183')
    parser.add_argument('--source-revision', help='build revision returned by agent_release bind-source')
    args = parser.parse_args(argv)
    for path in build(args.core, args.sensor, args.setup, args.public_key, args.output,
                      version=args.version, source_revision=args.source_revision):
        print(path)


if __name__ == '__main__':
    main()
