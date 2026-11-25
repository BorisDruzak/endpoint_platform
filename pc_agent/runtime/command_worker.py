"""Run one allowlisted Gateway command in an owned subprocess."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import json
import os
import signal
import subprocess
import sys

from endpoint_contracts import AgentCommandV1, AgentResultV1
from pc_agent.primitives.network.policy import AgentNetworkProbePolicy


_MAX_FRAME = 128 * 1024
_CLEANUP_SECONDS = 2


def _worker_arguments() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, "--gateway-command-worker"]
    return [sys.executable, "-m", "pc_agent.runtime.main", "--gateway-command-worker"]


def _assign_windows_job(pid: int):
    import win32api
    import win32con
    import win32job
    from pywintypes import error as WindowsError

    job = None
    try:
        job = win32job.CreateJobObject(None, "")
        limits = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
        limits["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, limits)
        process = win32api.OpenProcess(
            win32con.PROCESS_SET_QUOTA | win32con.PROCESS_TERMINATE, False, pid,
        )
        try:
            win32job.AssignProcessToJobObject(job, process)
        finally:
            process.Close()
    except WindowsError as error:
        if job is not None:
            job.Close()
        raise OSError("cannot contain command worker in a Windows Job") from error
    return job


async def run_command_worker(
    command: AgentCommandV1, policy: AgentNetworkProbePolicy, timeout: float,
) -> AgentResultV1:
    request = json.dumps({
        "command": command.model_dump(mode="json"),
        "allowed_cidrs": [str(cidr) for cidr in policy.allowed_cidrs],
        "allowed_suffixes": policy.allowed_suffixes,
    }, ensure_ascii=False).encode() + b"\n"
    if len(request) > _MAX_FRAME:
        raise ValueError("command worker request exceeds limit")

    if command.deadline_at <= datetime.now(UTC):
        raise TimeoutError("command worker deadline elapsed before spawn")
    windows = os.name == "nt"
    spawn_options = (
        {"creationflags": subprocess.CREATE_NO_WINDOW} if windows else {"start_new_session": True}
    )
    spawning = asyncio.create_task(asyncio.create_subprocess_exec(
        *_worker_arguments(), stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        limit=_MAX_FRAME, **spawn_options,
    ))
    process = None
    job = None
    request_sent = False
    try:
        async with asyncio.timeout(timeout):
            process = await asyncio.shield(spawning)
            assert process.stdin is not None and process.stdout is not None
            if windows:
                job = _assign_windows_job(process.pid)
            # The worker cannot dispatch a handler before receiving its request.
            if command.deadline_at <= datetime.now(UTC):
                raise TimeoutError("command worker deadline elapsed before dispatch")
            request_sent = True
            process.stdin.write(request)
            await process.stdin.drain()
            reply = await process.stdout.readline()
            if not reply.endswith(b"\n") or len(reply) > _MAX_FRAME:
                raise ValueError("command worker reply exceeds limit or is incomplete")
            result = AgentResultV1.model_validate_json(reply)
            if (result.command_id, result.device_id) != (command.command_id, command.device_id):
                raise ValueError("command worker result identity mismatch")
            return result
    finally:
        if process is None:
            process = await spawning
        try:
            if job is not None:
                job.Close()
            elif windows:
                if process.returncode is None:
                    process.kill()
            elif process.returncode is None or request_sent:
                os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        finally:
            if process.stdin is not None:
                process.stdin.close()
            # Drain in bounded chunks to resume a paused stdout transport and
            # release the process waiter even after an oversized reply.
            async with asyncio.timeout(_CLEANUP_SECONDS):
                if process.stdout is not None:
                    while await process.stdout.read(4096):
                        pass
                await process.wait()


def worker_main() -> int:
    """Serve one fixed typed request on inherited pipes, then wait for teardown."""
    from pc_agent.runtime.command_executor import execute_worker_command, failed_result

    source = sys.stdin.buffer
    try:
        frame = source.readline(_MAX_FRAME + 1)
        if len(frame) > _MAX_FRAME or not frame.endswith(b"\n"):
            return 1
        request = json.loads(frame)
        if not isinstance(request, dict) or set(request) != {"command", "allowed_cidrs", "allowed_suffixes"}:
            return 1
        command = AgentCommandV1.model_validate(request["command"])
        policy = AgentNetworkProbePolicy.from_values(
            allowed_cidrs=request["allowed_cidrs"], allowed_suffixes=request["allowed_suffixes"],
        )
    except (TypeError, ValueError):
        return 1
    try:
        if command.deadline_at <= datetime.now(UTC):
            result = failed_result(command, "AGENT_COMMAND_DEADLINE_EXCEEDED", status="expired")
        else:
            result = execute_worker_command(command, policy).model_copy(
                update={"completed_at": datetime.now(UTC)},
            )
        reply = result.model_dump_json().encode() + b"\n"
        if len(reply) > _MAX_FRAME:
            raise ValueError("command worker reply exceeds limit")
    except Exception:
        reply = failed_result(command, "AGENT_COMMAND_WORKER_FAILED").model_dump_json().encode() + b"\n"
    sys.stdout.buffer.write(reply)
    sys.stdout.buffer.flush()
    # Keep ownership of the process group until the caller tears it down.
    source.read(1)
    return 0
