"""A native success is provisional until a fresh connected runtime proves health."""
from types import SimpleNamespace
import json
from contextlib import contextmanager
import threading
from uuid import uuid4

import pytest
from dataclasses import replace

from pc_agent.platform.windows import durable_state, installer_fence
from pc_agent.platform.windows.staged_trial_gate import live_candidate as retained_candidate
from pc_agent.tests.windows.test_staged_update_state import staged, begin, move, native_protected_root


@pytest.fixture
def fake_gates(monkeypatch):
    """Explicit OS-boundary double; production has no file/POSIX fallback."""
    from pc_agent.platform.windows import staged_trial_gate as gate
    objects = {}
    class FakeGate:
        def __init__(self, shared): self.shared = shared
        @contextmanager
        def locked(self, **_):
            with self.shared.lock:
                self.shared.depth += 1
                try: yield self
                finally: self.shared.depth -= 1
        def reset(self): self.shared.ready = False
        def publish(self): self.shared.ready = True
        def ready(self): return self.shared.ready
        def close(self): pass
    def create(request, owner):
        objects[gate._names(request)] = SimpleNamespace(lock=threading.RLock(), depth=0, ready=False)
    def opened(request):
        try: return FakeGate(objects[gate._names(request)])
        except KeyError: raise FileNotFoundError('missing fake gate') from None
    @contextmanager
    def candidate(paths, binding, pid, created):
        assert created == 123
        yield SimpleNamespace(assert_alive=lambda: None)
    monkeypatch.setattr(gate, 'create_trial_gate', create)
    monkeypatch.setattr(gate, 'open_gate', opened)
    monkeypatch.setattr(gate, 'process_created', lambda: 123)
    monkeypatch.setattr(gate, 'live_candidate', candidate)
    return objects


@pytest.fixture
def trial(staged, monkeypatch, fake_gates):
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


@pytest.mark.parametrize('negotiated,readiness,expected', [
    (True, 'not_required', 'accept'),
    (True, 'required', 'waiting'),
    (True, None, 'waiting'),
    (False, 'not_required', 'waiting'),
])
def test_trial_requires_explicit_negotiated_policy_readiness(trial, negotiated, readiness, expected):
    _, _, _, _, writer, _ = trial
    hello = SimpleNamespace(protocol_features=['endpoint.policy-readiness.v1'] if negotiated else [],
                            policy_readiness=readiness)
    assert writer.record_handshake(hello)
    assert decide(trial, 59, 59) == 'waiting'
    assert writer.record_heartbeat()
    assert decide(trial, 60, 60) == expected


def test_policy_delivery_revokes_not_required_before_an_applied_ack(trial):
    _, _, _, _, writer, _ = trial
    assert writer.record_handshake(SimpleNamespace(protocol_features=['endpoint.policy-readiness.v1'],
                                                  policy_readiness='not_required'))
    assert decide(trial, 60, 60) == 'waiting'
    assert writer.record_heartbeat()
    assert decide(trial, 60, 60) == 'accept'
    assert writer.record_policy_delivery()
    assert decide(trial, 60, 60) == 'waiting'
    assert writer.record_policy_ack(SimpleNamespace(status='ERROR'))
    assert decide(trial, 60, 60) == 'waiting'
    assert writer.record_policy_ack(SimpleNamespace(status='APPLIED'))
    assert decide(trial, 60, 60) == 'accept'


def test_reconnect_to_legacy_provider_drops_not_required_proof(trial):
    _, _, _, _, writer, _ = trial
    assert writer.record_handshake(SimpleNamespace(protocol_features=['endpoint.policy-readiness.v1'],
                                                  policy_readiness='not_required'))
    assert decide(trial, 60, 60) == 'waiting'
    assert writer.record_heartbeat()
    assert decide(trial, 60, 60) == 'accept'
    assert writer.record_disconnected()
    assert writer.record_handshake()
    assert writer.record_heartbeat()
    assert decide(trial, 120, 60) == 'waiting'


def test_policy_arrival_hook_runs_before_failed_policy_application():
    import asyncio
    from pc_agent.runtime.lifecycle import _handle_inbound
    calls = []
    async def received(): calls.append('received')
    async def apply(_):
        calls.append('apply')
        raise RuntimeError('owned policy application failure')
    async def send(_): calls.append('ack')
    inbound = SimpleNamespace(root=SimpleNamespace(kind='endpoint_policy_delivery', payload=object()))
    with pytest.raises(RuntimeError, match='owned policy application failure'):
        asyncio.run(_handle_inbound(SimpleNamespace(send_policy_ack=send), object(), inbound,
                                    policy_handler=apply, after_policy_delivery=received))
    assert calls == ['received', 'apply']


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
    writer = proof.StagedTrialProofWriter(paths)
    assert writer.record_handshake()
    assert writer.record_heartbeat()
    assert writer.record_policy_ack(SimpleNamespace(status='APPLIED'))


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


@pytest.mark.parametrize('transition', ['policy_delivery', 'disconnected', 'required_handshake'])
def test_failed_revocation_cannot_accept_previous_durable_proof(trial, monkeypatch, transition):
    proof, paths, _, _, writer, _ = trial
    assert writer.record_handshake(SimpleNamespace(protocol_features=['endpoint.policy-readiness.v1'],
                                                  policy_readiness='not_required'))
    assert decide(trial, 58, 58) == 'waiting'
    assert writer.record_heartbeat()
    previous = (paths.updates_root / 'staged-trial-proof.json').read_bytes()
    assert decide(trial, 59, 59) == 'waiting'
    def denied(*_, **__): raise PermissionError('publication denied')
    monkeypatch.setattr(proof, '_write_proof', denied)
    if transition == 'policy_delivery': assert not writer.record_policy_delivery()
    elif transition == 'disconnected': assert not writer.record_disconnected()
    else: assert not writer.record_handshake(SimpleNamespace(protocol_features=[], policy_readiness=None))
    assert (paths.updates_root / 'staged-trial-proof.json').read_bytes() == previous
    assert decide(trial, 60, 60) != 'accept'


@pytest.mark.parametrize('transition', ['policy_delivery', 'disconnected', 'required_handshake'])
def test_gate_revocation_precedes_even_request_read_failure(trial, monkeypatch, transition):
    proof, _, _, _, writer, _ = trial
    writer.record_handshake(SimpleNamespace(protocol_features=['endpoint.policy-readiness.v1'],
                                           policy_readiness='not_required'))
    decide(trial, 58, 58)
    writer.record_heartbeat()
    request = proof._request
    def denied(*_):
        assert writer.gate.shared.depth == 1
        assert not writer.gate.ready()
        raise PermissionError('request denied')
    monkeypatch.setattr(proof, '_request', denied)
    if transition == 'policy_delivery': assert not writer.record_policy_delivery()
    elif transition == 'disconnected': assert not writer.record_disconnected()
    else: assert not writer.record_handshake()
    monkeypatch.setattr(proof, '_request', request)
    assert decide(trial, 60, 60) != 'accept'


def _ready(trial):
    writer = trial[4]
    assert writer.record_handshake()
    decide(trial, 60, 60)
    assert writer.record_heartbeat()
    assert writer.record_policy_ack(SimpleNamespace(status='APPLIED'))
    assert decide(trial, 60, 60) == 'accept'


def test_valid_file_without_os_gate_cannot_authorize(trial, fake_gates):
    _ready(trial)
    fake_gates.clear()
    assert decide(trial, 60, 60) == 'waiting'


def test_busy_publication_withholds_snapshot_without_premature_rollback(trial, monkeypatch):
    proof, paths, _, _, _, _ = trial
    _ready(trial)
    opened = proof.gate.open_gate
    @contextmanager
    def busy():
        raise proof.gate.GateBusy('publication still holds mutex')
        yield
    def contended(request):
        boundary = opened(request)
        boundary.locked = busy
        return boundary
    monkeypatch.setattr(proof.gate, 'open_gate', contended)
    assert proof.read_staged_trial_proof(paths) is None
    assert decide(trial, 60, 60) == 'waiting'
    assert decide(trial, 180, 60) == 'rollback'
    monkeypatch.setattr(proof.gate, 'open_gate', opened)
    assert decide(trial, 61, 61) == 'accept'


def test_stale_pid_or_untrusted_candidate_cannot_authorize(trial, monkeypatch):
    proof, _, _, _, _, _ = trial
    _ready(trial)
    @contextmanager
    def rejected(*_):
        raise proof.gate.GateUnavailable('candidate process has died or changed')
        yield
    monkeypatch.setattr(proof.gate, 'live_candidate', rejected)
    assert decide(trial, 60, 60) == 'rollback'


def test_old_file_shape_without_process_creation_cannot_authorize(trial):
    _, paths, _, _, _, _ = trial
    _ready(trial)
    leaf = paths.updates_root / 'staged-trial-proof.json'
    value = json.loads(leaf.read_bytes())
    del value['process_created']
    leaf.write_text(json.dumps(value))
    assert decide(trial, 60, 60) == 'rollback'


def test_accept_rechecks_gate_and_holds_lock_through_state_advance(trial, monkeypatch):
    proof, paths, binding, attempt, writer, _ = trial
    _ready(trial)
    advance = proof.state.advance_staged_update
    calls = []
    def checked(*args, **kwargs):
        assert writer.gate.shared.depth == 1
        assert writer.gate.ready()
        calls.append('accepted under gate')
        return advance(*args, **kwargs)
    monkeypatch.setattr(proof.state, 'advance_staged_update', checked)
    writer.record_policy_delivery()
    with durable_state.installer_mutation_checkpoints(lambda: None):
        with pytest.raises(ValueError):
            proof.accept_staged_trial(paths, binding.operation_id, attempt, elapsed_seconds=60, stable_seconds=60)
        assert not calls
        writer.record_policy_ack(SimpleNamespace(status='APPLIED'))
        proof.accept_staged_trial(paths, binding.operation_id, attempt, elapsed_seconds=60, stable_seconds=60)
    assert calls == ['accepted under gate']


def test_runtime_lifetime_cannot_publish_under_a_later_attempt(trial):
    from pc_agent.platform.windows import staged_update_state as state
    proof, paths, binding, first, writer, _ = trial
    assert writer.record_handshake()
    with durable_state.installer_mutation_checkpoints(lambda: None):
        record = state.read_staged_update(paths)
        state._write(paths, replace(record, phase='native-settled', attempt_id=None))
        second = proof.begin_staged_trial(paths, binding.operation_id)
    assert first != second
    assert not writer.record_handshake()
    assert not (paths.updates_root / 'staged-trial-proof.json').exists()


def test_candidate_exit_after_accepted_write_cannot_retract_receipt(trial, monkeypatch):
    proof, paths, binding, attempt, writer, _ = trial
    candidate = SimpleNamespace(value={'created': 123, 'hash': 'a' * 64}, closed=False,
        image_path=paths.versions_root / binding.candidate_version / 'pc_agent.exe')
    def alive():
        if candidate.closed: raise proof.gate.GateUnavailable('candidate exited after commit')
    candidate.assert_alive = alive
    candidate.close = lambda: None
    from pc_agent.platform.windows import installation_provenance as provenance
    core = SimpleNamespace(version=binding.candidate_version, source_revision=binding.candidate_source_revision,
        tree_sha256=binding.candidate_tree_sha256, files=(SimpleNamespace(path='pc_agent.exe', sha256='a' * 64),))
    monkeypatch.setattr(proof.gate, '_CandidateProcess', lambda _: candidate)
    monkeypatch.setattr(proof.gate, 'live_candidate', retained_candidate)
    monkeypatch.setattr(provenance, '_inspect_core_value', lambda *_: SimpleNamespace(identity=core))
    _ready(trial)
    advance = proof.state.advance_staged_update
    def accepted_then_exit(*args, **kwargs):
        result = advance(*args, **kwargs)
        assert result.phase == 'accepted'
        candidate.closed = True
        return result
    monkeypatch.setattr(proof.state, 'advance_staged_update', accepted_then_exit)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        receipt = proof.accept_staged_trial(paths, binding.operation_id, attempt, elapsed_seconds=60, stable_seconds=60)
    assert receipt.phase == 'accepted'
    assert proof.state.read_staged_update(paths).phase == 'accepted'


def test_failed_accept_commit_still_raises_and_retains_trial(trial, monkeypatch):
    proof, paths, binding, attempt, _, _ = trial
    _ready(trial)
    def denied(*_, **__): raise PermissionError('journal commit denied')
    monkeypatch.setattr(proof.state, 'advance_staged_update', denied)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        with pytest.raises(PermissionError, match='journal commit denied'):
            proof.accept_staged_trial(paths, binding.operation_id, attempt, elapsed_seconds=60, stable_seconds=60)
    assert proof.state.read_staged_update(paths).phase == 'trial'


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


def test_missing_trial_directory_rejects_untrusted_parent_before_creation(trial, monkeypatch):
    from pc_agent.platform.windows import staged_update_state as state, update_transaction
    proof, paths, binding, _attempt, _writer, _clock = trial
    paths.updates_root.rmdir()
    with durable_state.installer_mutation_checkpoints(lambda: None):
        state._write(paths, replace(state.read_staged_update(paths), phase='native-settled', attempt_id=None))
        def reject(path):
            assert path == paths.updates_root.parent
            raise ValueError('untrusted parent')
        monkeypatch.setattr(update_transaction, '_assert_state_security', reject)
        with pytest.raises(ValueError, match='untrusted parent'):
            proof.begin_staged_trial(paths, binding.operation_id)
    assert not paths.updates_root.exists()
    assert state.read_staged_update(paths).phase == 'native-settled'
