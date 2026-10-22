"""Stable MSI bindings for authenticated shared Foundation dependencies."""
import hashlib

from endpoint_contracts.runtime_payload import safe_path

SHARED_DIRECTORY = '_foundation-runtime'


def shared_binding(path):
    safe_path(path)
    if not path.startswith(SHARED_DIRECTORY + '/'):
        raise ValueError('invalid shared Foundation path')
    suffix = hashlib.sha256(path.casefold().encode('utf-8')).hexdigest()[:20]
    return 'filFoundation_' + suffix, 'cmpFoundation_' + suffix
