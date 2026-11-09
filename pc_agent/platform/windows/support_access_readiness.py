"""Candidate-specific initialized readiness, separate from SCM RUNNING."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re


def dependency_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def make_record(request, *, device_id, credential_sha256, dependency_sha256, state, pid):
    if state not in {'disabled', 'tunnel_connected'}:
        return None
    if (set(request) != {'nonce', 'image_sha256'} or
            not re.fullmatch('[0-9a-f]{32}', request['nonce']) or
            not re.fullmatch('[0-9a-f]{64}', request['image_sha256'])):
        raise ValueError('support_service_not_ready')
    return dict(request, device_id=device_id, credential_sha256=credential_sha256,
        dependency_sha256=dependency_sha256, state=state, pid=pid)


def matches(record, request, *, device_id, credential_sha256, dependency_sha256, active_pids):
    if not isinstance(record, dict) or set(record) != {
            'nonce', 'image_sha256', 'device_id', 'credential_sha256',
            'dependency_sha256', 'state', 'pid'}:
        return False
    return bool(record['nonce'] == request['nonce'] and record['image_sha256'] == request['image_sha256']
        and record['device_id'] == device_id and record['credential_sha256'] == credential_sha256
        and record['dependency_sha256'] == dependency_sha256
        and record['state'] in {'disabled', 'tunnel_connected'}
        and type(record['pid']) is int and record['pid'] > 0 and record['pid'] in active_pids)


def publish_initialized(root, children, state):
    from .support_access_native import assert_private, atomic_write, WindowsSupportOps
    import sys
    request_path = root/'readiness-request.json'
    if not request_path.exists():
        return
    for path in (request_path, root/'support.json', root/'credential'):
        assert_private(path)
    if request_path.stat().st_size > 512:
        raise ValueError('support_service_not_ready')
    request = json.loads(request_path.read_text())
    with Path(sys.executable).open('rb') as stream:
        image = hashlib.file_digest(stream, 'sha256').hexdigest()
    if image != request['image_sha256']:
        return
    config = json.loads((root/'support.json').read_text())
    record = make_record(request, device_id=config['device_id'],
        credential_sha256=hashlib.sha256((root/'credential').read_bytes()).hexdigest(),
        dependency_sha256=dependency_digest(children.dependencies),
        state=state if getattr(children,'dependencies_validated',False) else 'dependency_unavailable',pid=os.getpid())
    if record is not None:
        path = root/'readiness.json'
        atomic_write(path, json.dumps(record, sort_keys=True))
        WindowsSupportOps().protect(path)
    else:
        path=root/'readiness.json'
        atomic_write(path,json.dumps(dict(request,state='not_ready',pid=os.getpid()),sort_keys=True))
        WindowsSupportOps().protect(path)
