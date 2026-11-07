"""Safety boundaries for independent Linux Support (no live host required)."""
import base64
from datetime import datetime, timezone, timedelta
from pathlib import PurePosixPath as Path

import pytest

from pc_agent.platform.linux import support_access as s

DEVICE = 'e46fc348-c48c-415c-a86a-1dd60ef14e1a'
NOW = datetime(2026, 11, 7, 10, tzinfo=timezone.utc)
ORIGIN = 'https://endpoint.sosnadmin.local'


def key(n):
    return 'ssh-ed25519 ' + base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0 ' + bytes([n])*32).decode()


def policy(**changes):
    return dict(platform='linux_amd64', device_id=DEVICE, enabled=True, revision=3,
        expires_at=(NOW+timedelta(hours=1)).isoformat(), gateway_host='endpoint.sosnadmin.local',
        gateway_port=2222, gateway_host_public_key=key(3), tunnel_user='eps-e46fc348c48c415ca86a1dd6',
        remote_port=32001, local_port=22222, linux_admin_username='root', linux_admin_uid=0,
        operator_public_keys=[key(4)], poll_after_seconds=30) | changes


def parse(raw):
    return s.SupportPolicy.parse(raw, device_id=DEVICE, origin=ORIGIN, host_key=key(1), tunnel_key=key(2))


@pytest.mark.parametrize('change', [
    {'platform':'windows_amd64'}, {'gateway_host':'evil.example'}, {'gateway_port':22},
    {'linux_admin_uid':True}, {'linux_admin_uid':-1}, {'linux_admin_username':'root\nPermitRootLogin yes'},
    {'operator_public_keys':[key(1)]}, {'operator_public_keys':[key(2)]},
    {'operator_public_keys':[key(3)]}, {'operator_public_keys':[key(4),key(4)]},
    {'gateway_host_public_key':key(1)}, {'tunnel_user':'-oProxyCommand=evil'},
    {'local_port':22}, {'revision':True}, {'windows_admin_username':'root'},
    {'expires_at':'2026-11-07T11:00:00'}, {'operator_public_keys':[key(4)+' command=x']},
])
def test_policy_rejects_cross_role_keys_and_option_or_identity_confusion(change):
    with pytest.raises(s.SupportError):
        parse(policy(**change))


def test_policy_binds_environment_and_disabled_masks_authority():
    assert parse(policy()).uid == 0
    disabled = parse(policy(enabled=False, expires_at=None, linux_admin_username=None,
        linux_admin_uid=None, operator_public_keys=[]))
    assert disabled.username is None
    with pytest.raises(s.SupportError):
        parse(policy(enabled=False))
    with pytest.raises(s.SupportError):
        parse(policy(gateway_host='endpoint-staging.sosnadmin.local'))


def test_repeated_policy_clock_rollback_and_restart_never_extend_original_deadline():
    state = s.LeaseState()
    p = parse(policy())
    assert state.accept(p, wall=NOW.timestamp(), server=NOW.timestamp(), boot=10, boot_id='a') == 3610
    assert state.accept(p, wall=NOW.timestamp()-600, server=NOW.timestamp()+30, boot=40, boot_id='a') == 3610
    restored = s.LeaseState.from_json(state.to_json())
    assert restored.accept(p, wall=NOW.timestamp()-600, server=NOW.timestamp()+40, boot=50, boot_id='a') == 3610
    assert restored.accept(p, wall=NOW.timestamp()-600, server=NOW.timestamp()+100, boot=5, boot_id='b') == 3505


def test_expiry_stale_revision_and_same_revision_mutation_fail_closed():
    state = s.LeaseState()
    state.accept(parse(policy()), wall=NOW.timestamp(), server=NOW.timestamp(), boot=10, boot_id='a')
    for raw in (policy(revision=2), policy(linux_admin_username='admin',linux_admin_uid=1000)):
        with pytest.raises(s.SupportError):
            state.accept(parse(raw), wall=NOW.timestamp(), server=NOW.timestamp(), boot=20, boot_id='a')
    with pytest.raises(s.SupportError):
        state.accept(parse(policy()), wall=NOW.timestamp()-3600, server=NOW.timestamp()+3601, boot=5, boot_id='b')


def test_masked_availability_preserves_original_authority_and_deadline_after_restart():
    disabled = parse(policy(enabled=False, expires_at=None, linux_admin_username=None,
        linux_admin_uid=None, operator_public_keys=[]))
    state = s.LeaseState()
    assert state.accept(disabled, wall=NOW.timestamp(), server=NOW.timestamp(), boot=1, boot_id='a') == 0
    assert state.accept(parse(policy()), wall=NOW.timestamp(), server=NOW.timestamp(), boot=10, boot_id='a') == 3610
    assert state.accept(disabled, wall=NOW.timestamp(), server=NOW.timestamp()+30, boot=40, boot_id='a') == 0
    restored = s.LeaseState.from_json(state.to_json())
    for changed in (policy(operator_public_keys=[key(5)]), policy(linux_admin_uid=1),
                    policy(expires_at=(NOW+timedelta(hours=2)).isoformat())):
        with pytest.raises(s.SupportError, match='stale_policy'):
            restored.accept(parse(changed), wall=NOW.timestamp(), server=NOW.timestamp(), boot=50, boot_id='a')
    assert restored.accept(parse(policy()), wall=NOW.timestamp()-600, server=NOW.timestamp()+40, boot=50, boot_id='a') == 3610
    assert restored.accept(disabled, wall=NOW.timestamp(), server=NOW.timestamp()+50, boot=60, boot_id='a') == 0
    assert restored.accept(parse(policy()), wall=NOW.timestamp()-600, server=NOW.timestamp()+100, boot=5, boot_id='b') == 3505
    with pytest.raises(s.SupportError, match='expired_policy'):
        restored.accept(parse(policy()), wall=NOW.timestamp(), server=NOW.timestamp()+3601, boot=3506, boot_id='b')


def test_administrator_revision_discards_old_readiness_authority_and_rejects_replay():
    state=s.LeaseState()
    state.accept(parse(policy()),wall=NOW.timestamp(),server=NOW.timestamp(),boot=10,boot_id='a')
    saved=state.to_json()
    saved['authority']['operator_keys']=[key(5)]
    with pytest.raises(s.SupportError,match='invalid_lease_state'):
        s.LeaseState.from_json(saved)
    disabled=parse(policy(revision=4,enabled=False,expires_at=None,linux_admin_username=None,
        linux_admin_uid=None,operator_public_keys=[]))
    assert state.accept(disabled,wall=NOW.timestamp(),server=NOW.timestamp(),boot=20,boot_id='a')==0
    assert state.authority_policy() is None and state.deadline==0
    with pytest.raises(s.SupportError,match='stale_policy'):
        state.accept(parse(policy()),wall=NOW.timestamp(),server=NOW.timestamp(),boot=30,boot_id='a')


def test_expiry_does_not_wait_for_http_worker():
    stopped = []
    gate = s.LeaseGate(lambda: stopped.append(True))
    gate.arm(absolute_deadline=1000, boot=10)
    assert gate.tick(69)
    assert not gate.tick(70)
    assert stopped == [True]


def test_paths_cannot_inject_sshd_configuration():
    with pytest.raises(s.SupportError):
        s.sshd_config(Path('/safe\nHostKey /evil'), Path('/public'), parse(policy()))
    text = s.sshd_config(Path('/private'), Path('/public'), parse(policy()))
    assert 'AuthorizedKeysFile /public/%U' in text
    assert 'DisableForwarding yes' in text
    command = s.tunnel_command(Path('/private'), parse(policy()))
    assert command[-1] == 'endpoint.sosnadmin.local'
    assert 'StrictHostKeyChecking=yes' in command
    assert '-F' in command and '/dev/null' in command


def test_tunnel_master_does_not_report_forwarding_before_mux_ack():
    command=s.tunnel_command(Path('/private'),parse(policy()))
    assert '-M' in command and '-S' in command and '/private/mux' in command
    assert '-R' not in command
    forward=s.forward_command(Path('/private'),parse(policy()))
    assert forward[forward.index('-O')+1]=='forward'
    assert forward[forward.index('-R')+1]=='127.0.0.1:32001:127.0.0.1:22222'
    assert '-F' in forward and '/dev/null' in forward
