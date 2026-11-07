"""Strict, stdlib-only RPM verifier shared by native Setup and publication.

Never installs packages or extracts a payload into the host filesystem. Requires
RPM4.13-compatible RSA/SHA256 signatures covering BOTH header and payload.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
import time

PUBLISHER = 'BC24B8EE43DBB05A748E11A4343B5DA748370631'
KEY_SHA256 = '12175df39caa5a67336aeb002b5c71d3a9d3047961f5ad90cf959650044b456c'
MAX_RPM = 512 * 1024 * 1024
MAX_PAYLOAD = 1024 * 1024 * 1024
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/nonexistent'}
NATIVE_PATHS = {'endpoint-agent': '/usr/share/endpoint-agent/native-source.json',
                'endpoint-agent-user-sensor': '/usr/share/endpoint-agent-user-sensor/native-source.json'}
LEGACY_SOURCE = '6ed41cd01d494e46111a452c2ae3a844f723175b'
LEGACY_MANIFEST = 'cc1037497712cbd741ea04916794bdd436af510895dd1b58ebcbe404f5f8f658'
LEGACY_RPMS = {'endpoint-agent': '0287f55321b7f69ce5f3036c866ff416af376c907a087052afb0f833cade0e9b',
    'endpoint-agent-user-sensor': '5688d7270c647fe87b2ce3ff37150c867d08dccc358b320e65e8fb58ef126daa'}


class VerificationError(ValueError):
    """Fixed public diagnostic; tool output and private inputs are never echoed."""


@dataclass(frozen=True)
class VerifiedNativeRPM:
    nevra: str
    signer_fingerprint: str
    source_revision: str
    frozen_manifest_sha256: str
    sha256: str
    version: str
    package: str
    setup_sha256: str | None = None


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise VerificationError('duplicate_json_key')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError):
        raise VerificationError('invalid_manifest') from None


def run(argv, *, limit=65536, timeout=30, output_file=None):
    """Bound output while the process runs; no unbounded communicate buffer."""
    with tempfile.TemporaryFile() as output:
        sink = output_file or output
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=sink,
            stderr=subprocess.DEVNULL, env=ENV, start_new_session=True)
        started = time.monotonic()
        try:
            while process.poll() is None:
                if time.monotonic() - started > timeout or os.fstat(sink.fileno()).st_size > limit:
                    raise VerificationError('native_tool_bound')
                time.sleep(.02)
            if process.returncode or os.fstat(sink.fileno()).st_size > limit:
                raise VerificationError('native_tool_failed')
            sink.seek(0)
            return b'' if output_file else sink.read(limit + 1)
        finally:
            if process.poll() is None:
                import signal
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)


def require_signatures(output):
    suffix = re.escape(PUBLISHER[-8:].lower())
    if (not re.search(r'(?m)^\s*Header V4 RSA/SHA256 Signature, key ID ' + suffix + r': OK\s*$', output)
        or not re.search(r'(?m)^\s*V4 RSA/SHA256 Signature, key ID ' + suffix + r': OK\s*$', output)
        or re.search(r'BAD|NOT OK|NOKEY|NOTTRUSTED', output)):
        raise VerificationError('both_native_signatures_required')


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_mode, info.st_uid, info.st_gid, info.st_nlink)


@contextmanager
def snapshot(path):
    """Retain verified execution bytes; reject replaced/changed source nodes."""
    path = Path(path).absolute()
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
            raise VerificationError('unsafe_input_parent')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022
            or before.st_nlink != 1 or not 0 < before.st_size <= MAX_RPM):
            raise VerificationError('unsafe_native_input')
        with tempfile.TemporaryDirectory(prefix='endpoint-native-verified-') as directory:
            target = Path(directory) / 'input.rpm'
            digest = hashlib.sha256()
            with target.open('xb') as stream:
                while chunk := os.read(fd, 1024 * 1024):
                    digest.update(chunk)
                    stream.write(chunk)
                stream.flush()
                os.fsync(stream.fileno())
            target.chmod(0o400)
            if _identity(before) != _identity(os.fstat(fd)) or _identity(before) != _identity(path.lstat()):
                raise VerificationError('native_input_changed')
            yield target, digest.hexdigest()
            if _identity(before) != _identity(os.fstat(fd)) or _identity(before) != _identity(path.lstat()):
                raise VerificationError('native_input_changed')
    finally:
        os.close(fd)


def read_cpio(stream):
    """Read newc into bounded digests and selected metadata, never extract code."""
    files, selected, names, hardlinks = {}, {}, set(), {}
    consumed = 0
    while True:
        header = stream.read(110)
        if len(header) != 110 or header[:6] not in (b'070701', b'070702'):
            raise VerificationError('invalid_cpio')
        try:
            fields = [int(header[i:i+8], 16) for i in range(6, 110, 8)]
        except ValueError:
            raise VerificationError('invalid_cpio') from None
        inode, mode, uid, gid, links, _, size, major, minor, _, _, length, _ = fields
        if not 1 <= length <= 4096 or size > MAX_PAYLOAD or consumed + size > MAX_PAYLOAD:
            raise VerificationError('payload_bound')
        name_raw = stream.read(length)
        if len(name_raw) != length or not name_raw.endswith(b'\0'):
            raise VerificationError('invalid_cpio')
        stream.read(-(110 + length) % 4)
        name = name_raw[:-1].decode('utf-8', errors='strict')
        if name == 'TRAILER!!!':
            break
        clean = name[2:] if name.startswith('./') else name
        path = PurePosixPath(clean)
        if path.is_absolute() or any(x in ('', '.', '..') for x in clean.split('/')):
            raise VerificationError('unsafe_payload_path')
        name = '/' + clean
        if name in names or len(names) > 30000 or uid != 0 or gid != 0:
            raise VerificationError('unsafe_payload_entry')
        names.add(name)
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)) or (stat.S_ISREG(mode) and not 1 <= links <= 128):
            raise VerificationError('unsafe_payload_type')
        if mode & 0o7022:
            raise VerificationError('unsafe_payload_mode')
        keep = name in NATIVE_PATHS.values() or re.fullmatch(r'/opt/endpoint-agent/versions/[0-9.]+/manifest.json', name)
        if keep and size > 4 * 1024 * 1024:
            raise VerificationError('manifest_bound')
        digest, content, left = hashlib.sha256(), bytearray(), size
        while left:
            chunk = stream.read(min(left, 1024 * 1024))
            if not chunk:
                raise VerificationError('truncated_payload')
            left -= len(chunk)
            digest.update(chunk)
            if keep:
                content.extend(chunk)
        stream.read(-size % 4)
        consumed += size + 110 + length
        if stat.S_ISREG(mode):
            files[name] = {'sha256': digest.hexdigest(), 'mode': f'{stat.S_IMODE(mode):04o}'}
            if links > 1:
                if keep:
                    raise VerificationError('linked_source_metadata')
                hardlinks.setdefault((major, minor, inode), []).append((name, links, size, digest.hexdigest()))
            if keep:
                selected[name] = bytes(content)
    for entries in hardlinks.values():
        if any(count != len(entries) for _, count, _, _ in entries):
            raise VerificationError('external_payload_hardlink')
        populated = [digest for _, _, size, digest in entries if size]
        if len(set(populated)) > 1:
            raise VerificationError('conflicting_payload_hardlink')
        digest = populated[0] if populated else hashlib.sha256(b'').hexdigest()
        for name, _, _, _ in entries:
            files[name]['sha256'] = digest
    return files, selected


def inspect_source(raw, package, version, files, *, core_manifest_digest=None):
    data = _json(raw)
    if (not isinstance(data, dict) or set(data) != {'schema_version', 'version', 'source_revision', 'core_manifest_sha256', 'packages'}
        or data['schema_version'] != 'endpoint_linux_native_source_v1' or data['version'] != version
        or not re.fullmatch('[0-9a-f]{40}', str(data['source_revision']))
        or not re.fullmatch('[0-9a-f]{64}', str(data['core_manifest_sha256']))
        or set(data['packages']) != set(NATIVE_PATHS) or data['packages'][package] != files
        or (package == 'endpoint-agent' and data['core_manifest_sha256'] != core_manifest_digest)):
        raise VerificationError('signed_source_closure_mismatch')
    return data['source_revision'], hashlib.sha256(raw).hexdigest()


class NativeRPMVerifier:
    def __init__(self, public_key, *, legacy_manifest=None, legacy_signature=None, legacy_core=None):
        self.public_key = Path(public_key)
        self.legacy_manifest, self.legacy_signature, self.legacy_core = legacy_manifest, legacy_signature, legacy_core

    def _legacy_proof(self, directory, package, digest, version, release, metadata, path):
        if (version != '3.2.156' or release != 'alt5' or LEGACY_RPMS.get(package) != digest
            or self.legacy_manifest is None or self.legacy_signature is None):
            raise VerificationError('native_source_missing')
        # Existing immutable signed KIT is the only legacy Sensor source adapter.
        with snapshot(self.legacy_manifest) as (manifest, _), snapshot(self.legacy_signature) as (signature, _):
            output = run(['/usr/bin/gpg', '--homedir', str(Path(directory)/'gpg'), '--batch', '--status-fd', '1',
                '--verify', str(signature), str(manifest)]).decode()
            if not re.search(r'(?m)^\[GNUPG:\] VALIDSIG ' + PUBLISHER + r' ', output):
                raise VerificationError('legacy_kit_signature')
            kit = _json(manifest.read_bytes())
        if (kit.get('schema_version') != 'endpoint_alt_pilot_kit_v2'
            or kit.get('agent_version') != '3.2.156' or kit.get('agent_source_revision') != LEGACY_SOURCE
            or kit.get('publisher_fingerprint') != PUBLISHER
            or any(kit.get('files', {}).get(name+'-3.2.156-alt5.x86_64.rpm', {}).get('sha256') != sha
                   for name, sha in LEGACY_RPMS.items())):
            raise VerificationError('legacy_kit_pair_binding')
        if package == 'endpoint-agent':
            core = metadata.get('/opt/endpoint-agent/versions/3.2.156/manifest.json')
            if core is None or hashlib.sha256(core).hexdigest() != LEGACY_MANIFEST or _json(core).get('source_revision') != LEGACY_SOURCE:
                raise VerificationError('legacy_core_manifest')
        else:
            if self.legacy_core is None:
                raise VerificationError('legacy_paired_core_required')
            core = self(self.legacy_core)
            if core.sha256 != LEGACY_RPMS['endpoint-agent']:
                raise VerificationError('legacy_core_digest')
            requirements = run(['/usr/bin/rpm', '-qp', '--requires', str(path)]).decode().splitlines()
            if 'endpoint-agent = 3.2.156-alt5' not in requirements:
                raise VerificationError('legacy_sensor_dependency')
        return LEGACY_SOURCE, LEGACY_MANIFEST

    def _keyring(self, directory):
        raw = self.public_key.read_bytes()
        if hashlib.sha256(raw).hexdigest() != KEY_SHA256:
            raise VerificationError('publisher_key_digest')
        key = Path(directory) / 'publisher.asc'
        key.write_bytes(raw)
        home = Path(directory) / 'gpg'
        home.mkdir(mode=0o700)
        run(['/usr/bin/gpg', '--homedir', str(home), '--batch', '--import', str(key)])
        listing = run(['/usr/bin/gpg', '--homedir', str(home), '--batch', '--with-colons', '--fingerprint', '--list-keys']).decode()
        fingerprints = [line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')]
        if fingerprints != [PUBLISHER]:
            raise VerificationError('publisher_full_fingerprint')
        database = Path(directory) / 'rpmdb'
        database.mkdir(mode=0o700)
        run(['/usr/bin/rpm', '--dbpath', str(database), '--initdb'])
        run(['/usr/bin/rpm', '--dbpath', str(database), '--import', str(key)])
        return database

    def _verify_snapshot(self, path, digest):
        with tempfile.TemporaryDirectory(prefix='endpoint-native-trust-') as directory:
            database = self._keyring(directory)
            output = run(['/usr/bin/rpm', '--dbpath', str(database), '--checksig', '--verbose', str(path)]).decode()
            require_signatures(output)
            identity = run(['/usr/bin/rpm', '-qp', '--qf', '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{EPOCH}', str(path)]).decode().split('\t')
            if len(identity) != 5:
                raise VerificationError('native_identity')
            package, version, release, arch, epoch = identity
            if (package not in NATIVE_PATHS or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version)
                or not re.fullmatch(r'[A-Za-z0-9._]+', release) or arch != 'x86_64' or epoch not in ('(none)', '0')):
                raise VerificationError('native_identity')
            with tempfile.TemporaryFile() as payload:
                run(['/usr/bin/rpm2cpio', str(path)], output_file=payload, limit=MAX_PAYLOAD, timeout=90)
                files, metadata = read_cpio(payload)
            source = metadata.get(NATIVE_PATHS[package])
            if source is None:
                revision, manifest = self._legacy_proof(directory, package, digest, version, release, metadata, path)
            else:
                files.pop(NATIVE_PATHS[package])
                core_raw = metadata.get(f'/opt/endpoint-agent/versions/{version}/manifest.json')
                core_digest = hashlib.sha256(core_raw).hexdigest() if core_raw else None
                revision, manifest = inspect_source(source, package, version, files, core_manifest_digest=core_digest)
                if core_raw and _json(core_raw).get('source_revision') != revision:
                    raise VerificationError('core_source_mismatch')
            setup = _json(source)['packages']['endpoint-agent'].get('/usr/lib/endpoint-agent-setup/endpoint-agent-setup', {}).get('sha256') if source else None
            return VerifiedNativeRPM(f'{package}-{version}-{release}.{arch}', PUBLISHER, revision, manifest, digest, version, package, setup)

    def __call__(self, path, expected_full_signer=PUBLISHER):
        if expected_full_signer != PUBLISHER:
            raise VerificationError('untrusted_publisher')
        with snapshot(path) as (retained, digest):
            return self._verify_snapshot(retained, digest)


def publication_verifier(public_key, **legacy_inputs):
    """Narrow adapter: server imports no pc_agent/Core/runtime modules."""
    verifier = NativeRPMVerifier(public_key, **legacy_inputs)
    def verify(path, expected_full_signer):
        from endpoint_server.installation_lifecycle.linux_sources import VerifiedRPM
        value = verifier(path, expected_full_signer)
        return VerifiedRPM(value.nevra, value.signer_fingerprint, value.source_revision, value.frozen_manifest_sha256)
    return verify
