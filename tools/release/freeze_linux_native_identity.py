"""PyInstaller build-time attestation of the exact clean committed source."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def freeze_identity(root, component):
    root = Path(root)
    revision = subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()
    if subprocess.check_output(['git','-C',str(root),'status','--porcelain','--untracked-files=no'],text=True).strip():
        raise ValueError('NATIVE_FREEZE_REQUIRES_CLEAN_SOURCE')
    paths = subprocess.check_output(['git','-C',str(root),'ls-files','pc_agent','endpoint_contracts','tools/release','packaging/alt'],text=True).splitlines()
    files = {name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in paths if (root/name).is_file()}
    stage = Path(tempfile.mkdtemp(prefix='endpoint-native-source-'))
    target = stage/'linux-native-build.json'
    target.write_text(json.dumps({'schema_version':'endpoint_linux_native_build_v1','component':component,
        'version':'1.0.0' if component == 'support' else '3.2.179','source_revision':revision,
        'source_files':files},sort_keys=True,separators=(',',':')),encoding='ascii')
    return str(target)
