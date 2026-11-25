"""Assemble an exact native ALT kit from a verified RPM pair and Setup."""
import argparse
from contextlib import ExitStack
import gzip
import hashlib
import json
from pathlib import Path
import re
import tarfile
from tempfile import TemporaryDirectory

from tools.release.linux_native_verifier import NativeRPMVerifier, PUBLISHER, snapshot


def _check_build_receipt(path, proof):
    limit = 64 * 1024
    with Path(path).open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('QUALIFICATION_BUILD_RECEIPT_TOO_LARGE')
    receipt = json.loads(raw)
    expected = {
        'schema_version': 1, 'state': 'built', 'platform': 'alt', 'artifact': 'alt_native_rpm',
        'version': proof.version, 'build_revision': proof.source_revision,
        'alt_native': {'frozen_manifest_sha256': proof.frozen_manifest_sha256,
                       'setup_sha256': proof.setup_sha256},
    }
    if (not isinstance(receipt, dict) or type(receipt.get('schema_version')) is not int
            or any(receipt.get(key) != value for key, value in expected.items())):
        raise ValueError('QUALIFICATION_BUILD_RECEIPT_MISMATCH')


def build(core, sensor, setup, public_key, output, *, version='3.2.183', source_revision=None,
          build_receipt=None):
    if (not re.fullmatch(r'(?:0|[1-9][0-9]{0,4})(?:\.(?:0|[1-9][0-9]{0,4})){2}', version)
        or tuple(map(int, version.split('.'))) < (3, 2, 183)):
        raise ValueError('EXACT_NATIVE_VERSION_REQUIRED')
    if source_revision is None and version != '3.2.183':
        raise ValueError('NEW_NATIVE_KIT_REQUIRES_BOUND_SOURCE')
    if source_revision is not None and not re.fullmatch(r'[0-9a-f]{40}', source_revision):
        raise ValueError('INVALID_BOUND_SOURCE')
    paths = {Path(core).name: Path(core), Path(sensor).name: Path(sensor), 'endpoint-agent-setup': Path(setup)}
    if len(paths) != 3 or 'endpoint-rpm-release.asc' in paths:
        raise ValueError('EXACT_NATIVE_PAIR_REQUIRED')
    with ExitStack() as stack:
        files, proofs = {}, {}
        for name, path in paths.items():
            retained, digest = stack.enter_context(snapshot(path))
            files[name] = retained
            proofs[name] = {'sha256': digest, 'size': retained.stat().st_size}
        key = Path(stack.enter_context(TemporaryDirectory(prefix='endpoint-kit-key-'))) / 'publisher.asc'
        key_bytes = Path(public_key).read_bytes()
        key.write_bytes(key_bytes)
        files['endpoint-rpm-release.asc'] = key
        proofs['endpoint-rpm-release.asc'] = {'sha256': hashlib.sha256(key_bytes).hexdigest(), 'size': len(key_bytes)}
        verifier = NativeRPMVerifier(key)
        left, right = verifier(files[Path(core).name]), verifier(files[Path(sensor).name])
        if (left.package != 'endpoint-agent' or right.package != 'endpoint-agent-user-sensor'
            or left.version != version or right.version != left.version
            or (source_revision is not None and left.source_revision != source_revision)
            or (left.source_revision, left.frozen_manifest_sha256) != (right.source_revision, right.frozen_manifest_sha256)):
            raise ValueError('EXACT_NATIVE_PAIR_REQUIRED')
        if proofs['endpoint-agent-setup']['sha256'] != left.setup_sha256:
            raise ValueError('SETUP_NOT_BOUND_BY_SIGNED_CORE')
        if build_receipt is not None:
            _check_build_receipt(build_receipt, left)
        return _assemble(output, files, proofs, left)


def _assemble(output, files, proofs, verified_core):
    output = Path(output)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    name = f'endpoint-alt-pilot-{verified_core.version}-1'
    manifest = {'schema_version':'endpoint_alt_native_kit_v3', 'kit_name':name,
        'agent_version':verified_core.version,'agent_source_revision':verified_core.source_revision,
        'frozen_manifest_sha256':verified_core.frozen_manifest_sha256,'publisher_fingerprint':PUBLISHER,
        'files':proofs}
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
    return target, metadata


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('core','sensor','setup','public-key','output'):
        parser.add_argument('--'+key,type=Path,required=True)
    parser.add_argument('--version', default='3.2.183')
    parser.add_argument('--source-revision', help='build revision returned by agent_release bind-source')
    parser.add_argument('--build-receipt', type=Path, help='ALT native qualification-build.json from before signing')
    args = parser.parse_args(argv)
    for path in build(args.core, args.sensor, args.setup, args.public_key, args.output,
                      version=args.version, source_revision=args.source_revision, build_receipt=args.build_receipt):
        print(path)


if __name__ == '__main__':
    main()
