"""New Linux183 kit. Signing/publication remain explicit operator operations."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import tarfile

from tools.release.linux_native_verifier import NativeRPMVerifier, PUBLISHER, snapshot


def build(core, sensor, setup, public_key, output):
    verifier = NativeRPMVerifier(public_key)
    left, right = verifier(core), verifier(sensor)
    if (left.package != 'endpoint-agent' or right.package != 'endpoint-agent-user-sensor'
        or left.version != '3.2.183' or right.version != left.version
        or (left.source_revision, left.frozen_manifest_sha256) != (right.source_revision, right.frozen_manifest_sha256)):
        raise ValueError('EXACT_NATIVE_183_PAIR_REQUIRED')
    with snapshot(setup) as (_, digest):
        if digest != left.setup_sha256:
            raise ValueError('SETUP_NOT_BOUND_BY_SIGNED_CORE')
    output = Path(output)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    name = 'endpoint-alt-pilot-3.2.183-1'
    files = {Path(core).name: Path(core), Path(sensor).name: Path(sensor),
        'endpoint-agent-setup': Path(setup), 'endpoint-rpm-release.asc': Path(public_key)}
    manifest = {'schema_version':'endpoint_alt_native_kit_v3', 'kit_name':name,
        'agent_version':'3.2.183','agent_source_revision':left.source_revision,
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
    args = parser.parse_args(argv)
    for path in build(args.core,args.sensor,args.setup,args.public_key,args.output):
        print(path)


if __name__ == '__main__':
    main()
