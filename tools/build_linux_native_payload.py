"""Normalize one reviewed PyInstaller Support tree without external symlinks."""
import argparse
import gzip
from pathlib import Path
import tarfile


def build_support(source, output):
    source = Path(source).resolve()
    output = Path(output)
    with output.open('xb') as target, gzip.GzipFile(fileobj=target, mode='wb', filename='', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
            for path in sorted(source.rglob('*')):
                actual = path.resolve(strict=True)
                if not actual.is_relative_to(source) or not (actual.is_file() or actual.is_dir()):
                    raise ValueError('UNSAFE_SUPPORT_FROZEN_PATH')
                name = path.relative_to(source).as_posix()
                info = tarfile.TarInfo(name)
                info.uid = info.gid = info.mtime = 0
                info.mode = 0o755 if actual.is_dir() or name == 'endpoint-support-access' else 0o644
                if actual.is_dir():
                    info.type = tarfile.DIRTYPE
                    archive.addfile(info)
                else:
                    info.size = actual.stat().st_size
                    with actual.open('rb') as stream:
                        archive.addfile(info, stream)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--support', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    build_support(args.support, args.output)
