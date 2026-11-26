import json
from subprocess import TimeoutExpired
from types import SimpleNamespace

import pytest


UUID = "b9fce33b-ab0a-432c-a17f-2608bff246a8"
CONFIG = (f"name: endpoint-alt-native-stock487\nsmbios1: uuid={UUID}\n"
          "agent: enabled=1\nonboot: 0\nboot: order=scsi0\n"
          "scsi0: local-lvm:vm-487-disk-0,iothread=1,size=50G\n")
TARGET = SimpleNamespace(vmid=487, guest_uuid=UUID, expected_name="endpoint-alt-native-stock487",
                         snapshot="before-alt274-factory-verifier", snapshot_sha256="a" * 64)


@pytest.mark.parametrize("change", [
    "net0: virtio=00:00:00:00:00:00,bridge=vmbr0\n",
    "args: -nic user\n",
    "hostpci0: 0000:01:02.0\n",
    "scsi1: local-lvm:vm-488-disk-0,size=50G\n",
    "vmstate: local-lvm:vm-487-state-snapshot\n",
    "lock: snapshot\n",
])
def test_nonisolated_or_uncertain_lab_configs_hold(change):
    from tools.canary.run_alt_factory_offline import _verify_config

    assert _verify_config(CONFIG, TARGET)["name"] == TARGET.expected_name
    with pytest.raises(ValueError):
        _verify_config(CONFIG + change, TARGET)


def test_native_dispatch_timeout_preserves_marker_and_does_not_redispatch(tmp_path):
    from tools.canary.run_alt_factory_offline import _install

    called = []

    def submit(_source):
        called.append("submit")
        raise TimeoutExpired("qm guest exec", timeout=20)

    machine = SimpleNamespace(submit=submit)
    with pytest.raises(TimeoutExpired):
        _install(machine, tmp_path, "native")
    assert (tmp_path / "install-dispatched.json").is_file()
    with pytest.raises(FileExistsError):
        _install(machine, tmp_path, "native")
    assert called == ["submit"]


def test_native_wait_is_bound_to_one_handle(tmp_path):
    from tools.canary.run_alt_factory_offline import _install

    observed = []
    handle = b'{"pid":1730}\n'
    completed = b'{"exited":1,"exitcode":0,"out-data":"setup_install_exit=21"}\n'

    def wait(pid, *, seconds):
        observed.append((pid, seconds))
        return completed

    machine = SimpleNamespace(submit=lambda _: handle, wait=wait)
    _install(machine, tmp_path, "native")
    assert observed == [(1730, 240)]
    assert json.loads((tmp_path / "install-handle.json").read_bytes()) == {"pid": 1730}
    assert (tmp_path / "install.json").read_bytes() == completed


def test_unconfirmed_native_result_reaches_neither_reboot_nor_restore(tmp_path, monkeypatch):
    from tools.canary import run_alt_factory_offline as runner

    calls = []
    machine = SimpleNamespace(inspect=lambda **_: {}, start=lambda: calls.append("start"),
                              guest=lambda _: b'{"exited":1,"exitcode":0,"out-data":"staged"}',
                              submit=lambda _: calls.append("reboot"), restore=lambda: calls.append("restore"))
    candidate = {"request_id": "trial", "version": "3.2.274", "build_revision": "b" * 40,
                 "artifacts": {"archive": {"sha256": "d" * 64}},
                 "members": {"endpoint-agent-3.2.274-alt6.x86_64.rpm": {"sha256": "e" * 64},
                             "endpoint-agent-user-sensor-3.2.274-alt6.x86_64.rpm": {"sha256": "f" * 64},
                             "endpoint-agent-setup": {}, "endpoint-rpm-release.asc": {}}}
    check_fields = {"interfaces": ["lo"], "default_ipv4_route": False, "default_ipv6_route": False,
                    "identity_present": False, "credential_present": False, "claim_present": False,
                    "config_present": False, "installation_events": 0, "installation_sequence": 0,
                    "installation_ack": 0, "receipts": 0, "support_ssh_listener": False,
                    "support_policy_failure_journal_count": 0}
    installed = {**check_fields, "source": runner.recorded_source(candidate),
                 "selector": {"schema_version": 1, "source_revision": "b" * 40, "version": "3.2.274"},
                 "native": {"id": UUID, "action": "install", "phase": "invocation_possible", "exit_code": None}}
    monkeypatch.setattr(runner, "check_factory_baseline", lambda _: None)
    monkeypatch.setattr(runner, "_observe", lambda _machine, _output, name, _source:
                        {"ca_sha256": None} if name == "before" else installed)
    monkeypatch.setattr(runner, "_install", lambda *_: calls.append("install"))
    with pytest.raises(ValueError, match="durable native RPM zero"):
        runner.execute(SimpleNamespace(output_dir=tmp_path / "trial", guest_uuid=UUID), candidate, machine, [])
    assert calls == ["start", "install"]
