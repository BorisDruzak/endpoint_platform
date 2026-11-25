"""Bind the immutable signed observer to reviewed source in native helpers."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re


# Observer 1.0.13 shipped with Setup 3.2.245. The installed version directory
# is immutable, including the Authenticode signature and timestamp.
_CANONICAL_SHIPPED_CLIENTS = {
    '1.0.13': 'b504a8fb96ead642262494b53327c0c5a01da49a0285d9190c0364da72e399aa',
}


def stage_signed_setup_client(project_root, work_root, signed_asset=None):
    asset = Path(signed_asset or os.environ['ENDPOINT_SIGNED_SETUP_CLIENT']).resolve(strict=True)
    source = (Path(project_root) / 'packaging/windows/EndpointSetupUpdater.ps1').read_text(encoding='utf-8-sig').rstrip()
    raw = asset.read_bytes()
    signed = raw.decode('utf-8-sig').replace('\r\n', '\n').replace('\r', '\n')
    body, separator, signature = signed.partition('# SIG # Begin signature block')
    if not separator or '# SIG # End signature block' not in signature or body.rstrip() != source:
        raise ValueError('Signed Setup client differs from committed source')
    match = re.search(r"^\$script:ClientVersion='([0-9]+\.[0-9]+\.[0-9]+)'$", source, re.M)
    if match is None:
        raise ValueError('Invalid Setup client version')
    version = match[1]
    script_sha256 = hashlib.sha256(raw).hexdigest()
    canonical = _CANONICAL_SHIPPED_CLIENTS.get(version)
    if canonical is not None and script_sha256 != canonical:
        raise ValueError(f'Use the canonical signed Setup client for shipped version {version}')
    metadata = {'schema_version': 1, 'client_version': version, 'script_sha256': script_sha256,
                'source_sha256': hashlib.sha256(source.encode('utf-8')).hexdigest()}
    # Build from the same bytes that were checked. The external signing input
    # may be replaced independently after this function returns.
    target = Path(work_root) / 'setup-client-payload' / script_sha256 / 'EndpointSetupUpdater.ps1'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    return target, metadata


def signed_setup_client_payload(project_root, work_root, signed_asset=None):
    script, metadata = stage_signed_setup_client(project_root, work_root, signed_asset)
    manifest = script.with_name('EndpointSetupUpdater.payload.json')
    manifest.write_text(json.dumps(metadata, sort_keys=True), encoding='utf-8')
    return [(str(script), 'setup-updater'), (str(manifest), 'setup-updater')]
