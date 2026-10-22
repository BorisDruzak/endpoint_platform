"""Preserve a build interpreter's explicit TLS policy in frozen artifacts.

Some interpreter distributions require this adjacent public policy resource
when constructing SSLContext. Collect it unchanged; never edit stdlib SSL,
replace trust stores, or relax certificate verification to make a build run.
"""
import ast
import hashlib
from pathlib import Path
import stat

from endpoint_contracts.runtime_payload import reject_reparse_ancestors

POLICY_NAME = 'codex-rejected-cas.pem'


def _read_regular(path, maximum):
    reject_reparse_ancestors(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
        raise ValueError('invalid TLS policy resource input')
    data = path.read_bytes()
    after = path.lstat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError('TLS policy resource input changed')
    return data


def configure_ssl_resources(analysis):
    modules = [row for row in analysis.pure if row[0] == 'ssl']
    if not modules:
        return None  # In particular, keep the offline updater networkless.
    if len(modules) != 1:
        raise ValueError('ambiguous TLS policy resource source')
    try:
        source = Path(modules[0][1])
        raw = _read_regular(source, 1024 * 1024)
        tree = ast.parse(raw)
        if not any(isinstance(node, ast.Constant) and node.value == POLICY_NAME for node in ast.walk(tree)):
            return None
        resource = source.with_name(POLICY_NAME)
        data = _read_regular(resource, 64 * 1024)
        if any(row[0].replace('\\', '/').casefold() == POLICY_NAME for row in analysis.datas):
            raise ValueError('duplicate TLS policy resource')
    except (OSError, SyntaxError) as error:
        raise ValueError('required TLS policy resource unavailable') from error
    analysis.datas.append((POLICY_NAME, str(resource), 'DATA'))
    return {'ssl_source_sha256': hashlib.sha256(raw).hexdigest(),
            'resource_sha256': hashlib.sha256(data).hexdigest()}
