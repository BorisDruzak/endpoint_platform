import json
from uuid import UUID

import pytest

from tools import provision_ubuntu_server_pilot as pilot


INSTALLATION_ID = UUID(int=3)
FINGERPRINT = "sha256:" + "0" * 64


@pytest.mark.parametrize(("target", "ssh_host", "hostname"), [
    ("openvpn", "openvpn-100-30", "openvpn"),
    ("endpoint", "endpoint-platform-server", "endpointplatform"),
])
def test_web_request_sends_binding_over_ssh_stdin(monkeypatch, target, ssh_host, hostname):
    def run(command, *, host, input):
        assert command == "sudo -n /usr/bin/python3 -"
        assert host == ssh_host
        assert repr(hostname).encode("ascii") in input
        assert FINGERPRINT.encode("ascii") in input
        return json.dumps({"request_id": str(INSTALLATION_ID), "status": "waiting_approval"}).encode("ascii")

    monkeypatch.setattr(pilot, "_ssh", run)
    assert pilot.web_enrollment("request", pilot.TARGETS[target], FINGERPRINT) == {
        "request_id": str(INSTALLATION_ID), "status": "waiting_approval",
    }
