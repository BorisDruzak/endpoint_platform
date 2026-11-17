"""Catch authorization widening and stale-lease survival in the privileged broker."""
import base64
import importlib.util
import json
import struct
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest


SOURCE = Path(__file__).parents[2] / 'deploy/server/support_access_broker.py'


def broker():
    assert SOURCE.exists(), 'independent privileged support broker is missing'
    spec = importlib.util.spec_from_file_location('support_access_broker_test', SOURCE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


NOW = datetime(2026, 11, 6, 10, 0, tzinfo=UTC)
DEVICE = '943c87ef-f121-40b9-a31f-003e9459e292'
KEY = 'ssh-ed25519 ' + base64.b64encode(struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + bytes(range(32))).decode()


def snapshot():
    return dict(schema_version=1, generated_at=NOW.isoformat(), valid_until=(NOW+timedelta(seconds=60)).isoformat(),
                leases=[dict(device_id=DEVICE, tunnel_user='eps-943c87eff12140b9a31f003e', remote_port=32000,
                             tunnel_public_key=KEY, host_public_key=KEY, expires_at=(NOW+timedelta(minutes=10)).isoformat())])


def test_authorized_key_cannot_open_another_listener_or_shell():
    module = broker()
    lease, = module.validate_snapshot(snapshot(), now=NOW)
    assert module.authorized_key(lease) == 'restrict,port-forwarding,permitlisten="127.0.0.1:32000" ' + KEY + '\n'
    config = module.render_gateway_config('192.168.100.19')
    assert 'AllowTcpForwarding remote\n' in config
    assert 'PermitOpen none\n' in config
    assert 'GatewayPorts no\n' in config
    assert 'MaxSessions 0\n' in config
    assert 'PasswordAuthentication no\n' in config
    assert 'ListenAddress 192.168.100.19\n' in config
    assert 'Port 2222\n' in config
    assert 'AuthorizedKeysCommand none\n' in config
    assert 'TrustedUserCAKeys none\n' in config
    assert 'UsePAM yes\n' in config
    assert 'Include ' not in config
    assert 'Match ' not in config


@pytest.mark.parametrize('address',['0.0.0.0','::','8.8.8.8','192.168.100.19\nPermitRootLogin yes'])
def test_gateway_transport_cannot_bind_public_or_wildcard_address(address):
    with pytest.raises(ValueError): broker().render_gateway_config(address)


@pytest.mark.parametrize('change', ['stale','future','long_ttl','expired','wrong_user','external_port','injected_key','duplicate_port','duplicate_device','bad_blob'])
def test_malformed_or_stale_input_never_grants_access(change):
    module = broker()
    data = snapshot()
    if change == 'stale': data['valid_until'] = NOW.isoformat()
    elif change == 'future': data['generated_at'] = (NOW+timedelta(minutes=1)).isoformat()
    elif change == 'long_ttl': data['valid_until'] = (NOW+timedelta(hours=1)).isoformat()
    elif change == 'expired': data['leases'][0]['expires_at'] = NOW.isoformat()
    elif change == 'wrong_user': data['leases'][0]['tunnel_user'] = 'root'
    elif change == 'external_port': data['leases'][0]['remote_port'] = 22
    elif change == 'injected_key': data['leases'][0]['tunnel_public_key'] += '\ncommand="bash" ' + KEY
    elif change == 'bad_blob': data['leases'][0]['tunnel_public_key'] = 'ssh-ed25519 YWJjZA=='
    elif change == 'duplicate_device': data['leases'].append(dict(data['leases'][0], remote_port=32001))
    elif change == 'duplicate_port': data['leases'].append(dict(data['leases'][0], device_id='143c87ef-f121-40b9-a31f-003e9459e292', tunnel_user='eps-143c87eff12140b9a31f003e'))
    with pytest.raises(ValueError): module.validate_snapshot(data, now=NOW)


def test_expired_lease_removes_key_and_disconnects_only_owned_user(tmp_path):
    module = broker()
    lease, = module.validate_snapshot(snapshot(), now=NOW)
    keys = tmp_path / 'keys'; keys.mkdir()
    state = tmp_path / 'state.json'
    events = []
    module.reconcile((lease,), state_path=state, keys_root=keys,
                     ensure_user=lambda item: events.append(('ensure', item.tunnel_user)),
                     disconnect=lambda item: events.append(('kill', item)))
    assert (keys/lease.tunnel_user).read_text() == module.authorized_key(lease)
    module.reconcile((), state_path=state, keys_root=keys,
                     ensure_user=lambda item: pytest.fail('must not create user on revoke'),
                     disconnect=lambda item: events.append(('kill', item)))
    assert not (keys/lease.tunnel_user).exists()
    assert events[-1] == ('kill', lease.tunnel_user)
    assert json.loads(state.read_text()) == {}


def test_key_rotation_closes_existing_authenticated_connection(tmp_path):
    module = broker()
    lease, = module.validate_snapshot(snapshot(), now=NOW)
    keys = tmp_path/'keys'; keys.mkdir(); state=tmp_path/'state.json'; events=[]
    module.reconcile((lease,), state_path=state, keys_root=keys, ensure_user=lambda _:None, disconnect=events.append)
    data = snapshot(); data['leases'][0]['tunnel_public_key'] = 'ssh-ed25519 '+base64.b64encode(struct.pack('>I',11)+b'ssh-ed25519'+struct.pack('>I',32)+bytes(range(1,33))).decode()
    changed, = module.validate_snapshot(data, now=NOW)
    module.reconcile((changed,), state_path=state, keys_root=keys, ensure_user=lambda _:None, disconnect=events.append)
    assert events == [lease.tunnel_user]
    assert changed.tunnel_public_key in (keys/lease.tunnel_user).read_text()


def test_symlink_key_file_cannot_overwrite_unrelated_file(tmp_path):
    module = broker()
    lease, = module.validate_snapshot(snapshot(), now=NOW)
    keys=tmp_path/'keys'; keys.mkdir(); target=tmp_path/'admin_keys'; target.write_text('untouched')
    try: (keys/lease.tunnel_user).symlink_to(target)
    except OSError: pytest.skip('symlink privilege unavailable')
    with pytest.raises(ValueError):
        module.reconcile((lease,), state_path=tmp_path/'state', keys_root=keys, ensure_user=lambda _:None, disconnect=lambda _:None)
    assert target.read_text() == 'untouched'


def test_crash_before_state_commit_still_revokes_orphan_authorization(tmp_path):
    module=broker(); lease,=module.validate_snapshot(snapshot(),now=NOW)
    keys=tmp_path/'keys';keys.mkdir();(keys/lease.tunnel_user).write_text(module.authorized_key(lease))
    events=[]
    module.reconcile((),state_path=tmp_path/'state',keys_root=keys,ensure_user=lambda _:None,disconnect=events.append)
    assert not (keys/lease.tunnel_user).exists()
    assert events==[lease.tunnel_user]


def test_interrupted_orphan_revoke_retries_disconnect_after_key_was_cleared(tmp_path):
    module=broker();lease,=module.validate_snapshot(snapshot(),now=NOW)
    keys=tmp_path/'keys';keys.mkdir();(keys/lease.tunnel_user).write_text(module.authorized_key(lease))
    def fail_disconnect(_): raise RuntimeError('termination interrupted')
    with pytest.raises(RuntimeError):
        module.reconcile((),state_path=tmp_path/'state',keys_root=keys,ensure_user=lambda _:None,disconnect=fail_disconnect)
    assert (keys/lease.tunnel_user).read_text()==''
    events=[]
    module.reconcile((),state_path=tmp_path/'state',keys_root=keys,ensure_user=lambda _:None,disconnect=events.append)
    assert events==[lease.tunnel_user]
    assert not (keys/lease.tunnel_user).exists()
