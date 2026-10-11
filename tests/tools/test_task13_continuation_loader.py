"""Loader safety tests never dispatch to a host."""
import subprocess
import os
import sys
import time
from types import SimpleNamespace
from pathlib import Path

import pytest
from tools.canary.task13_continuation.loader import check_operations, run_seq04
from tools.canary.task13_continuation.codec import digest

pytestmark = pytest.mark.no_db


def test_cli_default_refuses_without_loading_targets():
    path = Path(__file__).resolve().parents[2] / "tools/canary/run_task13_continuation.py"
    result = subprocess.run([sys.executable, str(path)],capture_output=True,timeout=10)
    assert result.returncode == 2
    assert b"NONOPERATIONAL" in result.stdout


def test_missing_independently_protected_bootstrap_refuses():
    with pytest.raises(ValueError):
        run_seq04({}, {})


def test_operations_never_authorize_marker_or_restore():
    with pytest.raises(ValueError):
        check_operations({"allowed_seq":5,"allowed_step":"marker"})


@pytest.mark.parametrize("code,seconds,success", [
    ("import sys,json; print(json.dumps({'received':len(sys.stdin.buffer.read())}))",5,True),
    ("print('not json')",5,False),
    ("import sys;sys.stderr.write('E'*16384)",5,False),
    ("import time;time.sleep(30)",1,False),
    ("raise SystemExit(2)",5,False),
])
@pytest.mark.skipif(os.name != "nt",reason="owned native Windows transport storage")
def test_owned_transport_retains_raw_and_never_retries(tmp_path,code,seconds,success):
    from tools.canary.task13_continuation.transport import ContinuationTransport
    from tools.canary.task13_continuation.storage import ProtectedStore
    from tools.canary.task13_continuation.codec import parse_json
    store = ProtectedStore.create_root(tmp_path/"transport")
    store.create("dispatch-claim.json",b"permanent")
    auth = SimpleNamespace(check=lambda:None,capsule={"deadline_mono_ns":time.monotonic_ns()+150*10**9})
    transport = ContinuationTransport(store,auth)
    args = [sys.executable,"-I","-B","-c",code]
    if success:
        assert transport.call("owned",args,b"abc",seconds)["observation"] == {"received":3}
    else:
        with pytest.raises(ValueError,match="UNKNOWN"):
            transport.call("owned",args,b"abc",seconds)
    results = list(store.root.glob("*-result.json"))
    assert len(results) == 1
    result = parse_json(store.read(results[0].name))
    assert result["status"] == ("TRANSPORT_COMPLETE" if success else "UNKNOWN")
    assert store.read("dispatch-claim.json") == b"permanent"
