import json
from uuid import UUID

from tools import provision_ubuntu_server_pilot as pilot


INSTALLATION_ID = UUID(int=3)
FINGERPRINT = "sha256:" + "0" * 64


def test_web_request_sends_binding_over_ssh_stdin(monkeypatch):
    def run(command, *, input):
        assert command == "sudo -n /usr/bin/python3 -"
        assert FINGERPRINT.encode("ascii") in input
        return json.dumps({"request_id": str(INSTALLATION_ID), "status": "waiting_approval"}).encode("ascii")

    monkeypatch.setattr(pilot, "_ssh", run)
    assert pilot.web_enrollment("request", FINGERPRINT) == {
        "request_id": str(INSTALLATION_ID), "status": "waiting_approval",
    }
