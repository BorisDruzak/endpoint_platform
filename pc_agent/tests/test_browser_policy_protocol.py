"""The privileged browser helper accepts the same closed protocol on every OS."""
import pytest

from pc_agent.browser_policy_protocol import (
    BrowserPolicyRequestError, decode_policy_request, encode_policy_request,
    decode_policy_reply, encode_policy_reply,
)


def test_common_browser_policy_request_and_reply_roundtrip():
    assert decode_policy_request(encode_policy_request('apply', 'chrome')) == ('apply', 'chrome')
    assert decode_policy_request(encode_policy_request('relinquish', 'yandex')) == ('relinquish', 'yandex')
    assert decode_policy_reply(encode_policy_reply('EXTERNALLY_MANAGED')) == 'EXTERNALLY_MANAGED'


@pytest.mark.parametrize('payload', [
    b'{"schema_version":"endpoint_browser_policy_request_v1","operation":"apply","operation":"relinquish","browser_family":"chrome"}',
    b'{"schema_version":"endpoint_browser_policy_request_v1","operation":"apply","browser_family":"chrome","path":"/etc/passwd"}',
    b'x' * 1025,
])
def test_privileged_request_rejects_duplicate_or_arbitrary_fields(payload):
    with pytest.raises(BrowserPolicyRequestError):
        decode_policy_request(payload)


def test_reply_rejects_duplicate_status_and_unrecognized_status():
    with pytest.raises(BrowserPolicyRequestError):
        decode_policy_reply(b'{"schema_version":"endpoint_browser_policy_reply_v1","status":"APPLIED","status":"HELPER_ERROR"}')
    with pytest.raises(BrowserPolicyRequestError):
        encode_policy_reply('unexpected')
    with pytest.raises(BrowserPolicyRequestError):
        decode_policy_reply(b'{"schema_version":"endpoint_browser_policy_reply_v1","status":[]}')
