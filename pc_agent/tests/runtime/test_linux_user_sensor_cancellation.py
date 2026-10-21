"""User logoff must stop a silent helper without waiting for its read timeout."""
import asyncio
import os

import pytest


@pytest.mark.skipif(os.name != 'posix', reason='Linux helper subprocess')
@pytest.mark.asyncio
async def test_stop_interrupts_a_silent_native_helper(tmp_path):
    from pc_agent.platform.linux.user_sensor_runtime import run_user_sensor

    helper = tmp_path / 'silent-helper'
    helper.write_text('#!/usr/bin/python3\nimport sys\nsys.stdin.buffer.read(1)\n')
    helper.chmod(0o700)
    stop = asyncio.Event()
    task = asyncio.create_task(run_user_sensor(stop=stop, probe_path=helper))
    await asyncio.sleep(0.1)
    stop.set()
    await asyncio.wait_for(task, 1.5)
