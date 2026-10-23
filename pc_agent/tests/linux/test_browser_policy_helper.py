"""The root helper checks the kernel service UID before reading any request."""
import json
import os
import struct
import socket

import pytest

from pc_agent.browser_policy_protocol import encode_policy_request
from pc_agent.platform.linux.browser_policy_helper import handle_connection
from pc_agent.platform.linux.seqpacket import LocalIpcRejected


class Applicator:
    def __init__(self):
        self.called = []
    def apply(self, family):
        self.called.append(('apply', family)); return 'APPLIED'
    def relinquish(self, family):
        self.called.append(('relinquish', family)); return 'EXTERNALLY_MANAGED'


def test_unapproved_uid_is_rejected_before_parsing_or_file_access(monkeypatch):
    monkeypatch.setattr(socket, 'SO_PEERCRED', 17, raising=False)
    class Connection:
        def getsockopt(self, *_args):
            return struct.pack('iII', 123, 2000, 2000)
        def recvmsg(self, *_args):
            pytest.fail('unapproved peer read a policy request')
    applicator = Applicator()
    with pytest.raises(LocalIpcRejected):
        handle_connection(Connection(), applicator, agent_uid=1000)
    assert not applicator.called


@pytest.mark.skipif(os.name != 'posix', reason='native Linux socket credentials')
def test_root_helper_uses_the_common_closed_request_and_typed_reply():
    from pc_agent.platform.linux.seqpacket import read_frame, write_frame
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        client.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        applicator = Applicator()
        write_frame(client, encode_policy_request('apply', 'chrome'))
        handle_connection(server, applicator, agent_uid=os.getuid())
        reply = json.loads(read_frame(client, expected_peer=(os.getpid(), os.getuid(), os.getgid())))
        assert reply == {'schema_version':'endpoint_browser_policy_reply_v1', 'status':'APPLIED'}
        assert applicator.called == [('apply', 'chrome')]
    finally:
        client.close(); server.close()
