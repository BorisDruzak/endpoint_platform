"""Build-only explicit, immutable Microsoft ZIP input for signed Support media."""
import os
from pathlib import Path


def resource_datas(repository_root: Path):
    from pc_agent.platform.windows.support_access_bundle import load_manifest,validate_archive
    from pc_agent.platform.windows.support_access_native import reject_links
    value=os.environ.get('ENDPOINT_SUPPORT_OPENSSH_ZIP')
    if not value:raise ValueError('explicit Support OpenSSH ZIP input is required')
    reject_links(Path(value))
    path=Path(value).resolve(strict=True)
    if path.name!='OpenSSH-Win64.zip':raise ValueError('Support ZIP must keep its canonical filename')
    manifest=load_manifest();validate_archive(path,manifest)
    resources=repository_root/'packaging/windows/support-openssh'
    for name in ('LICENSE.txt','NOTICE.txt'):
        import hashlib
        row=next(row for row in manifest['runtime_files'] if row['path']==name)
        if hashlib.sha256((resources/name).read_bytes()).hexdigest()!=row['sha256']:
            raise ValueError('Support vendor notices differ')
    return [(str(path),'support-openssh'),*[(str(resources/name),'support-openssh')
        for name in ('manifest.json','LICENSE.txt','NOTICE.txt','QUALIFICATION.md')]]
