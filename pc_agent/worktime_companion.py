"""Existing authenticated sensor IPC carries one narrow WorkTime interaction.

The Core derives login from OS peer facts. No user-supplied identity, URL,
credentials, executable path or command can pass this protocol.
"""
from __future__ import annotations

import json
import logging
from pydantic import ValidationError

from endpoint_contracts.worktime_companion import CompanionActionV1, CompanionPollV1, CompanionReplyV1
from pc_agent.local_sensor_protocol import _unique_object

logger = logging.getLogger(__name__)


async def _wait_retry(seconds):
    import asyncio
    await asyncio.sleep(seconds)


def parse_request(payload):
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= 2048:
        return None
    try:
        raw = json.loads(payload, object_pairs_hook=_unique_object)
        if not isinstance(raw, dict):
            return None
        version = raw.get('schema_version')
        if version == 'worktime_companion_poll_v1':
            return CompanionPollV1.model_validate(raw)
        if version == 'worktime_companion_action_v1':
            return CompanionActionV1.model_validate(raw)
    except (ValueError, TypeError, ValidationError):
        pass
    return None


def handle_request(payload, *, user_login, handler):
    message = parse_request(payload)
    if message is None:
        return None
    if not user_login or handler is None:
        return CompanionReplyV1()
    try:
        return CompanionReplyV1.model_validate(handler(message, user_login))
    except Exception:
        return CompanionReplyV1()


class CoreCompanionBridge:
    """Sync listener callback bounded by an async Core-only HTTPS exchange."""
    def __init__(self):
        self._exchange = None
        self._loop = None
        self._poll_after = {}

    def handle(self, message, user_login):
        import asyncio
        import time
        if self._exchange is None or self._loop is None:
            return CompanionReplyV1()
        if isinstance(message, CompanionPollV1):
            now = time.monotonic()
            if self._poll_after.get(user_login, 0) > now:
                return CompanionReplyV1()
            # Active sessions are bounded by native listener authorization.
            if len(self._poll_after) > 128:
                self._poll_after.clear()
            self._poll_after[user_login] = now + 30
        future = asyncio.run_coroutine_threadsafe(self._exchange(message, user_login), self._loop)
        try:
            return future.result(timeout=2.5)
        except Exception:
            future.cancel()
            return CompanionReplyV1()

    async def serve(self, settings, credential):
        """An optional notification transport cannot end the technical WSS agent."""
        import asyncio
        delay = 5
        while True:
            try:
                await self._serve_once(settings, credential)
            except asyncio.CancelledError:
                raise
            except Exception as error:
                logger.warning('WorkTime companion transport unavailable',
                    extra={'error_type': type(error).__name__})
            finally:
                self._exchange = self._loop = None
            await _wait_retry(delay)
            delay = min(delay * 2, 300)

    async def _serve_once(self, settings, credential):
        import asyncio
        import ssl
        import aiohttp
        from endpoint_contracts.worktime_companion import CompanionDeviceActionV1, CompanionDevicePollV1
        from pc_agent.transport.http_pull import reject_endpoint_redirect, validate_endpoint_origin
        validate_endpoint_origin(settings.endpoint_origin)
        context = ssl.create_default_context(cafile=str(settings.ca_file))
        trace = aiohttp.TraceConfig()
        trace.on_request_redirect.append(reject_endpoint_redirect)
        connector = aiohttp.TCPConnector(ssl=context)
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=2),
                    connector=connector, trace_configs=[trace]) as session:
                async def exchange(message, user_login):
                    if isinstance(message, CompanionPollV1):
                        body = CompanionDevicePollV1(user_login=user_login)
                        route = 'next'
                    else:
                        body = CompanionDeviceActionV1(**message.model_dump(), user_login=user_login)
                        route = 'ack'
                    async with session.post(f'{settings.endpoint_origin}/agent/v1/gateway/worktime/{route}',
                            json=body.model_dump(mode='json'), headers={'Authorization': f'Bearer {credential}'},
                            allow_redirects=False) as response:
                        if response.status != 200:
                            return CompanionReplyV1()
                        if response.content_length is not None and response.content_length > 4096:
                            return CompanionReplyV1()
                        raw = await response.content.read(4097)
                        if len(raw) > 4096:
                            return CompanionReplyV1()
                        reply = CompanionReplyV1.model_validate_json(raw)
                        if reply.portal_url is not None:
                            from urllib.parse import urlsplit
                            if urlsplit(reply.portal_url).netloc != urlsplit(settings.endpoint_origin).netloc:
                                return CompanionReplyV1()
                        return reply
                self._loop = asyncio.get_running_loop()
                self._exchange = exchange
                try:
                    await asyncio.Future()
                finally:
                    self._exchange = self._loop = None
        finally:
            # A constructor/context-entry failure has not transferred ownership
            # to ClientSession. Closing again after ordinary exit is harmless.
            close = getattr(connector, 'close', None)
            if close is not None:
                import inspect
                try:
                    outcome = close()
                    if inspect.isawaitable(outcome):
                        await outcome
                except Exception as error:
                    logger.warning('WorkTime companion connector cleanup unavailable',
                        extra={'error_type': type(error).__name__})
