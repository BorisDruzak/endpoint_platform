"""Pinned public OpenSSH code; no OS installation, service or registry mutation.

The upstream package is Preview/non-production-ready. This is the exact
artifact qualified for the requested testing channel, not vendor certification.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import time
import zipfile

MANIFEST_SHA256 = '18dfc978f8af2e79024cb2e60123c6e4a98cd54e03cb7a3750ec082a5a96c2fa'
PROFILE = 'bundled-openssh-v1'
MARKER = '.endpoint-support-runtime.json'
READ_EXECUTE = 0x1200A9


def _fail():
    raise ValueError('support_bundle_invalid')


def resources() -> Path:
    return (Path(sys._MEIPASS)/'support-openssh' if getattr(sys,'frozen',False)
            else Path(__file__).resolve().parents[3]/'packaging/windows/support-openssh')


def load_manifest() -> dict:
    path=resources()/'manifest.json'
    if not 0<path.stat().st_size<=131072:_fail()
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=MANIFEST_SHA256:_fail()
    value=json.loads(raw)
    if value['schema_version']!=1 or value['preview'] is not True:_fail()
    names={entry['path'].casefold() for entry in value['runtime_files']}
    for entry in value['runtime_files']:
        if Path(entry['path']).name!=entry['path']:_fail()
        for name in entry.get('imports',[]):
            if name.casefold() not in names and name.casefold() not in value['system_imports']:_fail()
    return value


def _hash(path: Path) -> str:
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def validate_archive(path: Path, manifest: dict) -> None:
    from .support_access_native import reject_links
    reject_links(path)
    if path.stat().st_size!=manifest['archive_size'] or _hash(path)!=manifest['archive_sha256']:_fail()
    expected={row['path']:row for row in manifest['archive_members']}
    if len(expected)!=len(manifest['archive_members']):_fail()
    with zipfile.ZipFile(path) as archive:
        entries=archive.infolist();seen=set()
        if len(entries)!=len(expected):_fail()
        for info in entries:
            name=info.filename;parts=PurePosixPath(name).parts
            if (not parts or parts[0]!='OpenSSH-Win64' or len(parts)<2 or '\\' in name
                    or ':' in name or name.startswith('/') or any(part in {'.','..'} for part in parts)
                    or name.casefold() in seen or stat.S_ISLNK(info.external_attr>>16)
                    or info.external_attr&0x400 or info.flag_bits&1):_fail()
            seen.add(name.casefold())
            row=expected.get(name)
            if row is None or info.is_dir()!=row.get('directory',False):_fail()
            if info.is_dir():continue
            if info.file_size!=row['size'] or info.file_size>32*1024*1024:_fail()
            digest=hashlib.sha256();total=0
            with archive.open(info) as source:
                for chunk in iter(lambda:source.read(65536),b''):
                    total+=len(chunk)
                    if total>row['size']:_fail()
                    digest.update(chunk)
            if total!=row['size'] or digest.hexdigest()!=row['sha256']:_fail()


def runtime_root() -> Path:
    from .support_access_native import production_roots
    return production_roots()[1].parent/'SupportRuntime'


def slot_name(manifest: dict) -> str:
    return manifest['version']+'-'+manifest['archive_sha256']


def _marker(manifest):
    return json.dumps({'schema_version':1,'manifest_sha256':MANIFEST_SHA256,
        'archive_sha256':manifest['archive_sha256'],'version':manifest['version']},sort_keys=True,separators=(',',':')).encode()


def assert_public(path: Path) -> None:
    from .support_access_native import reject_links,assert_namespace,TRUSTED_SIDS
    import win32security as security
    reject_links(path);assert_namespace(path)
    descriptor=security.GetNamedSecurityInfo(str(path),security.SE_FILE_OBJECT,
        security.OWNER_SECURITY_INFORMATION|security.DACL_SECURITY_INFORMATION)
    if security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner()) not in TRUSTED_SIDS:_fail()
    if not descriptor.GetSecurityDescriptorControl()[0]&0x1000:_fail()
    acl=descriptor.GetSecurityDescriptorDacl();public=False
    if acl is None:_fail()
    for index in range(acl.GetAceCount()):
        ace=acl.GetAce(index)
        if len(ace)!=3 or ace[0][0]!=security.ACCESS_ALLOWED_ACE_TYPE:_fail()
        sid=security.ConvertSidToStringSid(ace[2])
        if sid in TRUSTED_SIDS:continue
        if sid!='S-1-5-11' or ace[1]!=READ_EXECUTE:_fail()
        public=True
    if not public:_fail()


def _public(path):
    from .support_access_native import WindowsSupportOps
    import win32security as security
    WindowsSupportOps().protect(path)
    inherit='OICI' if path.is_dir() else ''
    descriptor=security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        f'D:P(A;{inherit};FA;;;SY)(A;{inherit};FA;;;BA)(A;{inherit};FRFX;;;AU)',1)
    security.SetNamedSecurityInfo(str(path),security.SE_FILE_OBJECT,
        security.DACL_SECURITY_INFORMATION|security.PROTECTED_DACL_SECURITY_INFORMATION,
        None,None,descriptor.GetSecurityDescriptorDacl(),None)
    assert_public(path)


def _private_directory(path):
    from .support_access_native import WindowsSupportOps,reject_links
    import win32file,win32security,pywintypes
    reject_links(path)
    attributes=pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR=win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)',1)
    win32file.CreateDirectory(str(path),attributes)
    WindowsSupportOps().protect(path)


def profile(manifest: dict) -> dict:
    slot=runtime_root()/slot_name(manifest)
    return {'profile':PROFILE,'archive_sha256':manifest['archive_sha256'],
        'manifest_sha256':MANIFEST_SHA256,**{role:str(slot/name) for role,name in
        [('ssh','ssh.exe'),('sshd','sshd.exe'),('keygen','ssh-keygen.exe')]}}


def _owned_code(path):
    from .support_access_native import assert_private
    try:assert_public(path)
    except ValueError:assert_private(path)


def _verify_files(slot: Path, manifest: dict, *, public: bool | None, partial=False) -> None:
    from .support_access_native import assert_private,reject_links
    check=_owned_code if public is None else assert_public if public else assert_private
    check(slot)
    rows={row['path']:row for row in manifest['runtime_files']}
    actual={path.name for path in slot.iterdir()};expected=set(rows)|{MARKER}
    if (not actual<=expected or MARKER not in actual or (not partial and actual!=expected)):_fail()
    for name in actual:
        path=slot/name;reject_links(path);check(path)
        info=path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:_fail()
        if name==MARKER:
            if info.st_size!=len(_marker(manifest)) or path.read_bytes()!=_marker(manifest):_fail()
        elif info.st_size!=rows[name]['size'] or _hash(path)!=rows[name]['sha256']:_fail()


def verify_profile(value: dict) -> dict:
    manifest=load_manifest();root=runtime_root();expected=profile(manifest)
    if value!=expected:_fail()
    assert_public(root)
    if {path.name for path in root.iterdir()}!={slot_name(manifest)}:_fail()
    _verify_files(root/slot_name(manifest),manifest,public=True)
    return value


def verify_signatures(slot: Path, manifest: dict) -> None:
    """Installer only; service boot authenticates these exact pinned bytes/ACLs."""
    from .support_access_native import windows_root
    rows=[row for row in manifest['runtime_files'] if row['path'].lower().endswith(('.exe','.dll'))]
    script=r'''
$ErrorActionPreference='Stop'
$out=@()
foreach($p in ($env:ENDPOINT_SUPPORT_SIGNATURE_FILES|ConvertFrom-Json)) {
 $s=Get-AuthenticodeSignature -LiteralPath $p
 if($s.Status -ne 'Valid' -or !$s.TimeStamperCertificate -or $s.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation'){throw 'signature'}
 $out+=@{name=[IO.Path]::GetFileName($p);thumbprint=$s.SignerCertificate.Thumbprint}
}
ConvertTo-Json -InputObject @($out) -Compress
'''
    env=dict(os.environ,ENDPOINT_SUPPORT_SIGNATURE_FILES=json.dumps([str(slot/row['path']) for row in rows]),
        PSModulePath=str(windows_root()/'System32/WindowsPowerShell/v1.0/Modules'))
    response=subprocess.run([str(windows_root()/'System32/WindowsPowerShell/v1.0/powershell.exe'),
        '-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(script.encode('utf-16-le')).decode()],
        env=env,capture_output=True,text=True,timeout=60,creationflags=subprocess.CREATE_NO_WINDOW)
    if response.returncode:raise ValueError('support_bundle_signature_invalid')
    values=json.loads(response.stdout)
    if (not isinstance(values,list) or len(values)!=len(rows) or
        {row['name']:row['thumbprint'] for row in values}!=
        {row['path']:row['publisher_thumbprint'] for row in rows}):
        raise ValueError('support_bundle_signature_invalid')


def install() -> dict:
    from .support_access_native import WindowsSupportOps,assert_private
    manifest=load_manifest();archive=resources()/'OpenSSH-Win64.zip'
    validate_archive(archive,manifest)
    root=runtime_root();slot=root/slot_name(manifest);stage=root/('.staging-'+manifest['archive_sha256'])
    if root.exists():
        try:assert_public(root)
        except ValueError:assert_private(root)
        if slot.exists():return verify_profile(profile(manifest))
        if {p.name for p in root.iterdir()} not in (set(),{stage.name}):_fail()
    else:_private_directory(root)
    if stage.exists():_verify_files(stage,manifest,public=False,partial=True)
    else:
        _private_directory(stage)
        (stage/MARKER).write_bytes(_marker(manifest));WindowsSupportOps().protect(stage/MARKER)
    with zipfile.ZipFile(archive) as zipped:
        for row in manifest['runtime_files']:
            path=stage/row['path']
            if path.exists():continue # Exact owned bytes already checked above.
            with zipped.open('OpenSSH-Win64/'+row['path']) as source,path.open('xb') as target:
                for chunk in iter(lambda:source.read(65536),b''):target.write(chunk)
                target.flush();os.fsync(target.fileno())
            WindowsSupportOps().protect(path)
    _verify_files(stage,manifest,public=False);verify_signatures(stage,manifest)
    os.replace(stage,slot)
    for path in slot.iterdir():_public(path)
    _public(slot);_public(root)
    return verify_profile(profile(manifest))


def remove() -> None:
    from contextlib import ExitStack
    from .support_access_native import OwnedImageProcesses,reject_links
    root=runtime_root()
    reject_links(root)
    if not root.exists():return
    manifest=load_manifest()
    _owned_code(root)
    names={path.name for path in root.iterdir()}
    if not names:root.rmdir();return
    stage='.staging-'+manifest['archive_sha256']
    if names=={slot_name(manifest)}:
        # Cleanup also admits an interrupted private-to-public ACL publication,
        # but every known byte/marker/owner and no foreign writer must still match.
        slot=root/slot_name(manifest)
    elif names=={stage}:
        slot=root/stage
    else:_fail()
    _owned_code(slot)
    if not list(slot.iterdir()):slot.rmdir();root.rmdir();return
    _verify_files(slot,manifest,public=None,partial=True)
    # Service stop precedes this call. Retain/wait exact package image handles
    # too: job termination and final DLL/image unmapping can finish afterward.
    # This never kills an unrelated user of public code; busy bytes defer cleanup.
    with ExitStack() as stack:
        deadline=time.monotonic()+15
        processes=[stack.enter_context(OwnedImageProcesses(slot/row['path']))
            for row in manifest['runtime_files'] if row['path'].endswith('.exe') and (slot/row['path']).exists()]
        for process in processes:process.wait(timeout=max(0,deadline-time.monotonic()))
        for path in sorted(slot.iterdir()):
            if path.name!=MARKER:path.unlink()
        (slot/MARKER).unlink() # Keep authority until every known byte is gone.
    slot.rmdir();root.rmdir()
