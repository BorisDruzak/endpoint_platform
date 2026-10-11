"""Real sealed-packet execution and admission; never dispatch the comparator."""
import base64
import copy
import json
import os
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.canary.task13_continuation import sources, transport
from tools.canary.task13_continuation.codec import sha256
from tools.canary.task13_continuation.history import verify_historical_prefix

pytestmark = pytest.mark.no_db
windows_only = pytest.mark.skipif(os.name != 'nt', reason='native Windows protected-store admission')


@pytest.fixture(scope="module")
def historical():
    if not os.environ.get('TASK13_HISTORICAL_ROOT'):
        pytest.skip('private retained prefix input')
    return verify_historical_prefix(os.environ["TASK13_HISTORICAL_ROOT"])


def validate(argv, **kwargs):
    fn = getattr(transport, "validate_command", None)
    assert callable(fn), "exact UTF-16 command admission is missing"
    return fn(argv, **kwargs)


def delivery(prefix, script, data=b""):
    fn = getattr(sources, "build_stdin_delivery", None)
    assert callable(fn), "sealed stdin delivery is missing"
    return fn(prefix, script, data)


def execute(bootstrap, wire):
    return subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                           base64.b64encode(bootstrap.decode().encode("utf-16-le")).decode()],
                          input=wire, capture_output=True, timeout=15)


def test_historical_34172_command_rejected_with_stable_code():
    # Fixed synthetic total including quotes and NUL, without private argv.
    argv = ["ssh.exe", "x" * 34163]
    assert len(subprocess.list2cmdline(argv)) + 1 == 34172
    with pytest.raises(ValueError, match="COMMAND_LINE_TOO_LONG"):
        validate(argv)


def test_utf16_quoting_and_nul_are_counted():
    value = validate(["tool", "a b", "\U0001f600"])
    assert value["utf16_units_with_nul"] == 14
    assert value["command_sha256"] == sha256('tool "a b" \U0001f600'.encode("utf-16-le"))
    validate(["x" * 8190])
    with pytest.raises(ValueError, match="COMMAND_LINE_TOO_LONG"):
        validate(["x" * 8191])
    with pytest.raises(ValueError):
        validate(["x\0y"])


def test_remote_shell_layer_is_checked():
    with pytest.raises(ValueError, match="COMMAND_LINE_TOO_LONG"):
        validate(["ssh", "host", "short"], remote_command="x" * 8191)


def test_long_payload_short_bootstrap_and_original_inner_stdin(historical):
    # Source is well over the old command limit; only stdin receives it.
    script = ("#" + "payload" * 12000 + "\n"
              "$s=[Console]::In.ReadToEnd();@{status='SYNTHETIC_PASS';inner=$s;ps=$PSVersionTable.PSVersion.ToString()}|ConvertTo-Json -Compress")
    bootstrap, wire, binding = delivery(historical, script, b"QUJDRA==")
    argv = transport.powershell_argv(["ssh", "test-vm"], bootstrap.decode())
    assert validate(argv, remote_command=argv[-1])["utf16_units_with_nul"] < 8192
    assert binding["wire_bytes"] == len(wire) and binding["wire_sha256"] == sha256(wire)
    result = execute(bootstrap, wire)
    assert result.returncode == 0 and not result.stderr
    value = json.loads(result.stdout)
    assert value["status"] == "SYNTHETIC_PASS" and value["inner"] == "QUJDRA=="
    assert value["ps"].startswith("5.1.")


@pytest.mark.parametrize("kind", ["truncated", "extra", "wire-sha", "wire-length", "body-sha", "body-length", "source-pin", "parameter-pin"])
def test_bad_packet_fails_before_script_side_effect(historical, tmp_path, kind):
    sentinel = tmp_path / "must-not-exist"
    source = "[IO.File]::WriteAllText('" + str(sentinel) + "','bad');Write-Output 'invoked'"
    bootstrap, wire, binding = delivery(historical, source)
    if kind == "truncated": wire = wire[:-4]
    elif kind == "extra": wire += b"A"
    else:
        fn = getattr(sources, "delivery_bootstrap", None)
        assert callable(fn), "packet verifier binding is missing"
        binding = copy.deepcopy(binding)
        if kind == "wire-sha": binding["wire_sha256"] = "0" * 64
        elif kind == "wire-length": binding["wire_bytes"] += 4
        elif kind == "body-sha": binding["body_utf8_sha256"] = "0" * 64
        elif kind == "body-length": binding["body_utf8_bytes"] -= 1
        elif kind == "source-pin": binding["helper_sha256"] = "0" * 64
        elif kind == "parameter-pin": binding["parameter_hashes"]["RunId"] = "0" * 64
        bootstrap = fn(binding)
    result = execute(bootstrap, wire)
    assert result.returncode == 2
    assert not result.stdout and not sentinel.exists()


@windows_only
def test_command_refuses_before_transport_intent_or_spawn(tmp_path, monkeypatch):
    from tools.canary.task13_continuation.storage import ProtectedStore
    store = ProtectedStore.create_root(tmp_path / "transport")
    auth = SimpleNamespace(check=lambda: None, capsule={"deadline_mono_ns": time.monotonic_ns() + 100 * 10**9})
    def forbidden(*args, **kwargs): raise AssertionError("process must not launch")
    monkeypatch.setattr(transport.subprocess, "Popen", forbidden)
    with pytest.raises(ValueError, match="COMMAND_LINE_TOO_LONG"):
        transport.ContinuationTransport(store, auth).call("oversized", ["x" * 8191])
    assert list(store.root.iterdir()) == []


@windows_only
def test_final_binding_rechecked_before_spawn(tmp_path, monkeypatch):
    from tools.canary.task13_continuation.storage import ProtectedStore
    store = ProtectedStore.create_root(tmp_path / "transport")
    auth = SimpleNamespace(check=lambda: None, capsule={"deadline_mono_ns": time.monotonic_ns() + 100 * 10**9})
    argv = ["short"]
    def guard():
        return lambda when: argv.append("x" * 8191)
    def forbidden(*args, **kwargs): raise AssertionError("process must not launch")
    monkeypatch.setattr(transport.subprocess, "Popen", forbidden)
    with pytest.raises(ValueError, match="COMMAND_LINE_TOO_LONG"):
        transport.ContinuationTransport(store, auth).call("final", argv, pre_dispatch=guard)


@windows_only
def test_short_command_substitution_refuses_before_spawn(tmp_path, monkeypatch):
    from tools.canary.task13_continuation.storage import ProtectedStore
    store = ProtectedStore.create_root(tmp_path / 'changed')
    auth = SimpleNamespace(check=lambda: None, capsule={'deadline_mono_ns':time.monotonic_ns()+100*10**9})
    argv = ['short']
    def guard(): return lambda when: argv.append('substitution')
    def forbidden(*args, **kwargs): raise AssertionError('substituted command must not launch')
    monkeypatch.setattr(transport.subprocess,'Popen',forbidden)
    with pytest.raises(ValueError,match='command binding changed'):
        transport.ContinuationTransport(store,auth).call('changed',argv,pre_dispatch=guard)


def short_plan():
    names = ('guest','inventory','current','process_identity','clock_guest','prepare','workload','collect')
    return ({'management_argv':['python','-c','pass'],'provider_argv':['ssh','host','true'],
             'guest_ssh':['ssh','host']},
            {'delivery-'+name+'.ps1':b"Write-Output 'synthetic'" for name in names})


@windows_only
@pytest.mark.parametrize('layer',['root','prepare','workload','provider','management','global'])
def test_preclaim_plan_refusal_preserves_all_claims(tmp_path,monkeypatch,layer):
    import sys
    from contextlib import contextmanager
    from tools.canary.task13_continuation import supervisor,loader,authorized_execution
    from tools.canary.task13_continuation.storage import ProtectedStore
    store = ProtectedStore.create_root(tmp_path/'bundle')
    history = ProtectedStore.create_root(tmp_path/'history')
    prefix = SimpleNamespace(root=history.root,binding={'original_run_seal_sha256':'1'*64,'original_tip':'2'*64})
    request={'scope':'seq04-after-readonly-recovery','record_sha256':'3'*64,'gate_admission_sha256':'4'*64}
    operations,entries=short_plan()
    executable=sys._base_executable
    if layer in ('prepare','workload'): entries['delivery-'+layer+'.ps1']=b'x'*20000
    elif layer in ('provider','management'): operations[layer+'_argv']=['x'*8191]
    elif layer=='root': executable=str(Path('C:/'+('x'*8191)).absolute())
    elif layer=='global': operations['management_argv']=['x'*8191]
    closure={'continuation_id':'11111111-1111-4111-8111-111111111111','runtime':{executable:{}}}
    @contextmanager
    def reviewed(*args):
        yield store,closure,{},{},entries,prefix,request,operations,{'root_interpreter':executable}
    target=loader if layer=='global' else supervisor
    monkeypatch.setattr(target,'reviewed_bundle',reviewed)
    monkeypatch.setattr(target,'require_seq04_permission',lambda value:None)
    flag='--execute-reviewed-seq04-child' if layer=='global' else '--execute-reviewed-seq04'
    monkeypatch.setattr(sys,'argv',[str(store.root/'bootstrap.py'),flag])
    def forbidden(*args,**kwargs): raise AssertionError('oversized plan must not launch')
    monkeypatch.setattr(supervisor.subprocess,'Popen',forbidden)
    with pytest.raises(ValueError,match='COMMAND_LINE_TOO_LONG'):
        if layer=='global':loader.run_seq04({'bootstrap_root':str(store.root)}, {})
        else:supervisor.supervise(store.root)
    assert not authorized_execution.launch_path(prefix,request).exists()
    assert list(history.root.iterdir())==[] and list(store.root.iterdir())==[]


def test_actual_historical_builder_and_new_sealed_commands(historical):
    root = Path.home()/'.codex/task-evidence/task13-authorized-seq04-review-20261011-e'
    operations = json.loads((root/'operations.json').read_bytes())
    encoded = base64.b64encode((root/'entry-prepare.ps1').read_text().encode('utf-16-le')).decode()
    old = [*operations['guest_ssh'],'powershell.exe -NoProfile -NonInteractive -EncodedCommand '+encoded]
    assert len(subprocess.list2cmdline(old).encode('utf-16-le'))//2+1 == 34172
    with pytest.raises(ValueError,match='COMMAND_LINE_TOO_LONG'): validate(old)
    from tools.canary.task13_continuation.operations import build_operations
    from uuid import uuid4
    cid = str(uuid4())
    entries = sources.build_execution_sources(historical,cid,'C:\\Task13Continuation-'+cid.replace('-',''))
    wrapper,wire=entries['wrapper.ps1'],entries['wire.bin']
    operations=build_operations(historical,cid,entries,Path('C:/Task13OwnedOfflineBundle'))
    plan=transport.validate_command_plan(operations,entries)
    assert max(row['utf16_units_with_nul'] for row in plan.values()) < 8192
    assert entries['wrapper.ps1']==wrapper and entries['wire.bin']==wire
    closure=sources.seal_sources(entries)
    sources.verify_sources(closure,entries)
    with pytest.raises(ValueError):
        sources.verify_sources(closure,{**entries,'packet-prepare.bin':entries['packet-prepare.bin']+b'A'})


@pytest.mark.parametrize('complete',[False,True])
def test_open_stdin_is_bounded_without_invocation(historical,tmp_path,monkeypatch,complete):
    real_read=sources.read_file
    def read(path):
        raw=real_read(path)
        if Path(path).name=='Read-Task13SealedPacket.ps1':
            # Scale the fixed production input deadline for this owned native test.
            raw=raw.replace(b'120000',b'1000').replace(b'10000',b'1000')
        return raw
    monkeypatch.setattr(sources,'read_file',read)
    sentinel=tmp_path/'must-not-exist'
    bootstrap,wire,_=delivery(historical,"[IO.File]::WriteAllText('"+str(sentinel)+"','bad')")
    argv=['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(bootstrap.decode().encode('utf-16-le')).decode()]
    process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        process.stdin.write(wire if complete else wire[:4]);process.stdin.flush()
        assert process.wait(timeout=4)==2
        assert not sentinel.exists()
        assert process.stdout.read()==b''
    finally:
        if process.poll() is None:process.kill();process.wait(timeout=2)
        process.stdin.close();process.stdout.close();process.stderr.close()
