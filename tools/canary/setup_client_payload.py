"""Bind the immutable signed observer to reviewed source in native helpers."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re


def signed_setup_client_payload(project_root, work_root, signed_asset=None):
    asset = Path(signed_asset or os.environ['ENDPOINT_SIGNED_SETUP_CLIENT']).resolve(strict=True)
    source = (Path(project_root) / 'packaging/windows/EndpointSetupUpdater.ps1').read_text(encoding='utf-8-sig').rstrip()
    signed = asset.read_text(encoding='utf-8-sig')
    body, separator, signature = signed.partition('# SIG # Begin signature block')
    if not separator or '# SIG # End signature block' not in signature or body.rstrip() != source:
        raise ValueError('Signed Setup client differs from committed source')
    version = re.search(r"^\$script:ClientVersion='([0-9]+\.[0-9]+\.[0-9]+)'$", source, re.M)
    if version is None:
        raise ValueError('Invalid Setup client version')
    metadata = {'schema_version': 1, 'client_version': version[1],
                'script_sha256': hashlib.sha256(asset.read_bytes()).hexdigest(),
                'source_sha256': hashlib.sha256(source.encode('utf-8')).hexdigest()}
    target = Path(work_root) / 'setup-client-payload'
    target.mkdir(parents=True, exist_ok=True)
    manifest = target / 'EndpointSetupUpdater.payload.json'
    manifest.write_text(json.dumps(metadata, sort_keys=True), encoding='utf-8')
    return [(str(asset), 'setup-updater'), (str(manifest), 'setup-updater')]
