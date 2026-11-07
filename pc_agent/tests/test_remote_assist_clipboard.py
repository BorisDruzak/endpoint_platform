from __future__ import annotations

import asyncio

from pc_agent.remote_assist.clipboard import ClipboardConfig, ClipboardSyncBridge, MemoryClipboardBackend, clipboard_hash


def test_clipboard_remote_update_writes_backend() -> None:
    async def scenario() -> None:
        sent: list[dict] = []
        backend = MemoryClipboardBackend("old")
        bridge = ClipboardSyncBridge(
            config=ClipboardConfig(enabled=True, max_bytes=1024),
            send=sent.append,
            backend=backend,
        )
        await bridge.handle_message({"type": "clipboard.update", "payload": {"text": "new", "hash": clipboard_hash("new")}})
        assert backend.text == "new"
        assert backend.writes == ["new"]
        await bridge.stop()

    asyncio.run(scenario())


def test_clipboard_poll_sends_local_changes_without_echo() -> None:
    async def scenario() -> None:
        sent: list[dict] = []
        updated = asyncio.Event()

        def send(message: dict) -> None:
            sent.append(message)
            if message["type"] == "clipboard.update":
                updated.set()

        backend = MemoryClipboardBackend("initial")
        bridge = ClipboardSyncBridge(
            config=ClipboardConfig(enabled=True, max_bytes=1024, poll_interval_sec=0.01),
            send=send,
            backend=backend,
        )
        await bridge.start()
        try:
            backend.text = "operator visible text"
            # Wait for the observable result, including Windows thread scheduling.
            await asyncio.wait_for(updated.wait(), timeout=1)
        finally:
            await bridge.stop()

        updates = [item for item in sent if item["type"] == "clipboard.update"]
        assert updates
        assert updates[-1]["payload"]["text"] == "operator visible text"

    asyncio.run(scenario())
