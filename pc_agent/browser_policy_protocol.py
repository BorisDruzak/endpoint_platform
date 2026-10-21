"""Closed, stdlib-only protocol shared by privileged Windows/Linux helpers."""
from __future__ import annotations

import json
from typing import Literal

Operation = Literal['apply', 'relinquish']
BrowserFamily = Literal['chrome', 'yandex']
MAX_REQUEST_BYTES = 1024
REQUEST_SCHEMA = 'endpoint_browser_policy_request_v1'
REPLY_SCHEMA = 'endpoint_browser_policy_reply_v1'
REPLY_STATUSES = frozenset({'APPLIED', 'EXTERNALLY_MANAGED', 'POLICY_CONFLICT', 'INVALID_REQUEST', 'HELPER_ERROR'})


class BrowserPolicyRequestError(ValueError):
    """A helper message exceeds the closed privileged operation contract."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BrowserPolicyRequestError('duplicate browser policy field')
        result[key] = value
    return result


def _decode(payload: bytes, encoding: str):
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_REQUEST_BYTES:
        raise BrowserPolicyRequestError('invalid browser policy message size')
    try:
        return json.loads(payload.decode(encoding), object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError) as error:
        raise BrowserPolicyRequestError('invalid browser policy message') from error


def decode_policy_request(payload: bytes) -> tuple[Operation, BrowserFamily]:
    request = _decode(payload, 'utf-8')
    if (not isinstance(request, dict) or set(request) != {'schema_version', 'operation', 'browser_family'}
        or request['schema_version'] != REQUEST_SCHEMA
        or request['operation'] not in ('apply', 'relinquish')
        or request['browser_family'] not in ('chrome', 'yandex')):
        raise BrowserPolicyRequestError('invalid browser policy request')
    return request['operation'], request['browser_family']


def encode_policy_request(operation: Operation, family: BrowserFamily) -> bytes:
    payload = json.dumps(dict(schema_version=REQUEST_SCHEMA, operation=operation, browser_family=family),
                         sort_keys=True, separators=(',', ':')).encode('ascii')
    decode_policy_request(payload)
    return payload


def decode_policy_reply(payload: bytes) -> str:
    reply = _decode(payload, 'ascii')
    if (not isinstance(reply, dict) or set(reply) != {'schema_version', 'status'}
        or reply['schema_version'] != REPLY_SCHEMA or not isinstance(reply['status'], str)
        or reply['status'] not in REPLY_STATUSES):
        raise BrowserPolicyRequestError('invalid browser policy reply')
    return reply['status']


def encode_policy_reply(status: str) -> bytes:
    payload = json.dumps(dict(schema_version=REPLY_SCHEMA, status=status),
                         sort_keys=True, separators=(',', ':')).encode('ascii')
    decode_policy_reply(payload)
    return payload
