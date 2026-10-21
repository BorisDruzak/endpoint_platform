"""Unprivileged client for the single fixed root browser-policy socket."""
from pc_agent.browser_policy_protocol import encode_policy_request, decode_policy_reply
from .browser_policy_helper import SOCKET_PATH
from .local_ipc import exchange_with_service


def send_policy_request(operation: str, family: str) -> str:
    return decode_policy_reply(exchange_with_service(
        encode_policy_request(operation, family), socket_path=SOCKET_PATH, service_uid=0,
    ))
