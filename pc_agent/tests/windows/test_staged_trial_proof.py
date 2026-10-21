"""A native success is provisional until a fresh connected runtime proves health."""
from types import SimpleNamespace
import json
from uuid import uuid4

import pytest
from dataclasses import replace

from pc_agent.platform.windows import durable_state, installer_fence
from pc_agent.tests.windows.test_staged_update_state import staged, begin, move, native_protected_root


@pytest.fixture
def trial(staged, monkeypatch):
    from pc_agent.platform.windows import staged_trial_proof as proof
    from pc_agent.platform.windows import installation_provenance as provenance
    state, paths, binding, owner = staged
    begin(staged)
    move(staged, 'preparing', 'prepared')
    move(staged, 'prepared', 'switching')
    clock = [100_000_000_000]
    monkeypatch.setattr(proof.time, 'monotonic_ns', lambda: clock[0])
    monkeypatch.setattr(provenance, 'verified_foundation_release', lambda _: binding.new_release)
    identity = SimpleNamespace(version=binding.candidate_version,
        source_revision=binding.candidate_source_revision, tree_sha256=binding.candidate_tree_sha256)
    monkeypatch.setattr(provenance, '_inspect_core_value', lambda *_: SimpleNamespace(identity=identity))
    monkeypatch.setattr(proof, '_running_candidate', lambda *_: True)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        attempt = proof.begin_staged_trial(paths, binding.operation_id)
    writer = proof.StagedTrialProofWriter(paths)
    return proof, paths, binding, attempt, writer, clock


def decide(trial, elapsed, stable):
    proof, paths, binding, attempt, _, clock = trial
    clock[0] = int((100 + elapsed) * 1e9)
    return proof.staged_trial_decision(paths, binding.operation_id, attempt,
        elapsed_seconds=elapsed, stable_seconds=stable)


def test_fresh_trial_retires_previous_proof_before_waiting_for_handshake(trial):
    from pc_agent.platform.windows import staged_update_state as state
    proof, paths, binding, first, writer, _clock = trial
    assert writer.record_handshake()
    old_proof = (paths.updates_root / 'staged-trial-proof.json').read_bytes()
    record = state.read_staged_update(paths)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        state._write(paths, replace(record, phase='native-settled', attempt_id=None))
        second = proof.begin_staged_trial(paths, binding.operation_id)
    assert first != second
    assert proof.staged_trial_decision(paths, binding.operation_id, second, elapsed_seconds=0, stable_seconds=0) == 'waiting'
    # Replay introduced after the fresh attempt still causes rejection.
    (paths.updates_root / 'staged-trial-proof.json').write_bytes(old_proof)
    assert proof.staged_trial_decision(paths, binding.operation_id, second, elapsed_seconds=1, stable_seconds=0) == 'rollback'


def test_first_trial_does_not_require_an_existing_update_directory(trial):
    from pc_agent.platform.windows import staged_update_state as state
    proof, paths, binding, _attempt, _writer, _clock = trial
    paths.updates_root.rmdir()
    record = state.read_staged_update(paths)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        state._write(paths, replace(record, phase='native-settled', attempt_id=None))
        attempt = proof.begin_staged_trial(paths, binding.operation_id)
    assert proof.staged_trial_decision(paths, binding.operation_id, attempt, elapsed_seconds=0, stable_seconds=0) == 'waiting'


def test_no_acceptance_before_60_seconds_and_fresh_heartbeat(trial):
    _, _, _, _, writer, _ = trial
    assert writer.record_handshake()
    assert decide(trial, 59, 59) == 'waiting'
    assert writer.record_policy_ack(SimpleNamespace(status='APPLIED'))
    assert decide(trial, 60, 60) == 'waiting'
    assert writer.record_heartbeat()
    assert decide(trial, 60, 60) == 'accept'


def test_trial_deadline_is_180_seconds(trial):
    assert decide(trial, 180, 0) == 'rollback'


def test_delayed_handshake_does_not_shorten_health_window(trial):
    _, _, _, _, writer, _ = trial
    assert decide(trial, 61, 0) == 'waiting'
    assert writer.record_handshake()
    assert writer.record_heartbeat()
    assert writer.record_policy_ack(SimpleNamespace(status='APPLIED'))
    assert decide(trial, 120, 59) == 'waiting'
    assert writer.record_heartbeat()
    assert decide(trial, 121, 60) == 'accept'


@pytest.mark.parametrize('defect', ['operation', 'attempt', 'source', 'foundation', 'future', 'stale', 'extra'])
def test_trial_clock_rollback_and_replay(trial, defect):
    proof, paths, binding, attempt, writer, clock = trial
    writer.record_handshake()
    writer.record_heartbeat()
    writer.record_policy_ack(SimpleNamespace(status='APPLIED'))
    if defect in {'operation', 'attempt'}:
        assert proof.staged_trial_decision(paths, str(uuid4()) if defect == 'operation' else binding.operation_id,
            str(uuid4()) if defect == 'attempt' else attempt, elapsed_seconds=60, stable_seconds=60) == 'rollback'
        return
    leaf = paths.updates_root / 'staged-trial-proof.json'
    value = json.loads(leaf.read_bytes())
    if defect in {'source', 'foundation'}: value['request_sha256'] = 'f' * 64
    elif defect == 'future': value['heartbeat_ns'] = clock[0] + int(1000e9)
    elif defect == 'extra': value['arbitrary'] = True
    leaf.write_text(json.dumps(value))
    assert decide(trial, 120 if defect == 'stale' else 60, 60) != 'accept'


def test_reconnect_and_disconnect_reset_all_proof(trial):
    proof, paths, _, _, writer, _ = trial
    writer.record_handshake(); writer.record_heartbeat()
    writer.record_policy_ack(SimpleNamespace(status='APPLIED'))
    assert writer.record_disconnected()
    assert decide(trial, 60, 60) == 'waiting'
    writer.record_handshake()
    assert not proof.read_staged_trial_proof(paths)['policy_ack']
    assert decide(trial, 60, 60) == 'waiting'
    writer.record_heartbeat(); writer.record_policy_ack(SimpleNamespace(status='APPLIED'))
    assert decide(trial, 60, 0) == 'waiting'


def test_trial_does_not_unblock_ota_or_other_runtime(trial):
    from pc_agent.platform.windows import staged_update_state as state
    from pc_agent.platform.windows.update_transaction import UpdateInProgress
    _, paths, binding, _, _, _ = trial
    state.assert_staged_update_allowed(paths, purpose='launch', runtime_tree_sha256=binding.candidate_tree_sha256)
    for purpose in ('ota', 'setup', 'cleanup'):
        with pytest.raises(UpdateInProgress): state.assert_staged_update_allowed(paths, purpose=purpose)
    with pytest.raises(UpdateInProgress): state.assert_staged_update_allowed(paths, purpose='launch', runtime_tree_sha256='0' * 64)


def test_service_launcher_enforces_journal_after_full_tree_verification(trial):
    from pc_agent.platform.windows import service_launcher, staged_update_state as state
    from pc_agent.platform.windows.update_transaction import UpdateInProgress
    _, paths, binding, _, _, _ = trial
    selector = json.loads(paths.current_path.read_bytes())
    service_launcher._verify_selected_runtime(paths, selector)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        state.advance_staged_update(paths, binding.operation_id, 'trial', 'rolling-back')
    with pytest.raises(UpdateInProgress): service_launcher._verify_selected_runtime(paths, selector)


def test_browser_companion_cannot_run_during_compensation(trial, monkeypatch):
    from pc_agent.platform.windows import browser_policy_service_entry as browser, staged_update_state as state
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    from pc_agent.platform.windows.update_transaction import UpdateInProgress
    _, paths, binding, _, _, _ = trial
    monkeypatch.setattr(WindowsUpdatePaths, 'production', classmethod(lambda _: paths))
    browser._assert_installer_allows_policy()
    with durable_state.installer_mutation_checkpoints(lambda: None):
        state.advance_staged_update(paths, binding.operation_id, 'trial', 'rolling-back')
    with pytest.raises(UpdateInProgress): browser._assert_installer_allows_policy()


def test_writer_failure_is_nonfatal(trial, monkeypatch):
    proof, _, _, _, writer, _ = trial
    def denied(*_, **__): raise PermissionError('denied')
    monkeypatch.setattr(proof, '_write_proof', denied)
    assert writer.record_handshake() is False
    assert writer.record_heartbeat() is False


def test_accepted_is_durable_before_cleanup(trial, monkeypatch):
    from pc_agent.platform.windows import staged_update_state as state
    proof, paths, binding, attempt, writer, _ = trial
    writer.record_handshake()
    decide(trial, 60, 60)
    writer.record_heartbeat(); writer.record_policy_ack(SimpleNamespace(status='APPLIED'))
    with durable_state.installer_mutation_checkpoints(lambda: None):
        proof.accept_staged_trial(paths, binding.operation_id, attempt, elapsed_seconds=60, stable_seconds=60)
    assert state.read_staged_update(paths).phase == 'accepted'
    state.assert_staged_update_allowed(paths, purpose='ota')


def test_live_trial_bridge_cannot_accept_without_current_proof(trial):
    from pc_agent.platform.windows import installer_transaction_bridge as bridge, staged_update_state as state
    _, paths, binding, _, writer, _ = trial
    record = state.read_staged_update(paths)
    sent = []
    client = SimpleNamespace(phase='observe-staged-trial', checkpoint=lambda: None,
        capability={'operation': 'install', 'recovery': False, 'uninstall_finalization': False,
                    'transaction_id': binding.operation_id, 'owner': record.owner, 'package': binding.new_release},
        request=lambda action, result: sent.append((action, result)))
    assert bridge.execute_staged_trial_phase(client, paths)['decision'] == 'waiting'
    client.phase = 'accept-staged-trial'
    with pytest.raises(ValueError): bridge.execute_staged_trial_phase(client, paths)
    writer.record_handshake()
    decide(trial, 60, 60)
    writer.record_heartbeat(); writer.record_policy_ack(SimpleNamespace(status='APPLIED'))
    assert bridge.execute_staged_trial_phase(client, paths)['result'] == 'staged-accepted'
    assert state.read_staged_update(paths).phase == 'accepted'
