import hashlib
import io
import json

import pytest


def test_digest_only_and_header_only_are_not_native_signatures():
    from tools.release import linux_native_verifier as v
    good = 'Header V4 RSA/SHA256 Signature, key ID 48370631: OK\n V4 RSA/SHA256 Signature, key ID 48370631: OK\n'
    v.require_signatures(good)
    for invalid in ('MD5 digest: OK', good.splitlines()[0], good.replace('48370631', '12345678'), good + 'BAD signature'):
        with pytest.raises(v.VerificationError):
            v.require_signatures(invalid)


def test_signed_source_manifest_covers_exact_package_bytes_and_common_source():
    from tools.release import linux_native_verifier as v
    raw = b'hello'
    manifest = {'schema_version': 'endpoint_linux_native_source_v1', 'version': '3.2.178',
        'source_revision': 'a' * 40, 'core_manifest_sha256': 'b' * 64,
        'packages': {'endpoint-agent': {'/opt/a': {'sha256': hashlib.sha256(raw).hexdigest(), 'mode': '0755'}},
                     'endpoint-agent-user-sensor': {}}}
    metadata = json.dumps(manifest).encode()
    payload = {'/opt/a': {'sha256': hashlib.sha256(raw).hexdigest(), 'mode': '0755'}}
    result = v.inspect_source(metadata, 'endpoint-agent', '3.2.178', payload, core_manifest_digest='b' * 64)
    assert result == ('a' * 40, hashlib.sha256(metadata).hexdigest())
    for changed in ({}, {**payload, '/foreign': payload['/opt/a']}, {'/opt/a': {**payload['/opt/a'], 'mode': '0777'}}):
        with pytest.raises(v.VerificationError):
            v.inspect_source(metadata, 'endpoint-agent', '3.2.178', changed, core_manifest_digest='b' * 64)


def test_cpio_reader_rejects_symlink_and_traversal_without_extracting():
    from tools.release import linux_native_verifier as v
    def archive(name, mode):
        encoded = name.encode() + b'\0'
        fields = [1, mode, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(encoded), 0]
        header = b'070701' + ''.join(f'{x:08x}' for x in fields).encode()
        return io.BytesIO(header + encoded + b'\0' * (-(110 + len(encoded)) % 4))
    for name, mode in (('./../../etc/passwd', 0o100644), ('./opt/link', 0o120777)):
        with pytest.raises(v.VerificationError):
            v.read_cpio(archive(name, mode))
