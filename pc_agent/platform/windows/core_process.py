"""Own the selected Windows Core before it can start any descendants."""

from __future__ import annotations

from contextlib import ExitStack
import msvcrt
import os
from pathlib import Path
import subprocess

import _winapi
import win32job
import win32process


_FORCED_EXIT = 75
_EXTENDED_STARTUPINFO_PRESENT = 0x00080000


class WindowsCoreProcess:
    def __init__(self, command: list[str]) -> None:
        resources = ExitStack()
        with resources:
            read_fd, write_fd = os.pipe()
            resources.callback(os.close, read_fd)
            try:
                pipe = os.fdopen(write_fd, "wb", buffering=0)
            except BaseException:
                os.close(write_fd)
                raise
            with ExitStack() as owned:
                owned.enter_context(pipe)
                self.stdin = pipe
                input_handle = msvcrt.get_osfhandle(read_fd)
                null = resources.enter_context(open(os.devnull, "wb"))
                output_handle = msvcrt.get_osfhandle(null.fileno())
                startup = subprocess.STARTUPINFO(
                    dwFlags=subprocess.STARTF_USESTDHANDLES,
                    hStdInput=input_handle, hStdOutput=output_handle, hStdError=output_handle,
                    lpAttributeList={"handle_list": [input_handle, output_handle]},
                )
                job = win32job.CreateJobObject(None, "")
                owned.callback(job.Close)
                limits = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
                limits["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, limits)
                for handle in (input_handle, output_handle):
                    os.set_handle_inheritable(handle, True)
                process, thread, _pid, _tid = _winapi.CreateProcess(
                    command[0], subprocess.list2cmdline(command), None, None, True,
                    _EXTENDED_STARTUPINFO_PRESENT | win32process.CREATE_SUSPENDED
                    | subprocess.CREATE_NO_WINDOW, None, str(Path(command[0]).parent), startup,
                )
                resources.callback(_winapi.CloseHandle, thread)
                owned.callback(_winapi.CloseHandle, process)
                try:
                    win32job.AssignProcessToJobObject(job, process)
                    win32process.ResumeThread(thread)
                except BaseException:
                    _winapi.TerminateProcess(process, _FORCED_EXIT)
                    raise
                self._job = job
                self._process = process
                self._resources = owned.pop_all()

    def wait(self, timeout: float) -> int:
        if _winapi.WaitForSingleObject(self._process, int(timeout * 1000)) == _winapi.WAIT_TIMEOUT:
            raise subprocess.TimeoutExpired("EndpointAgent Core", timeout)
        return _winapi.GetExitCodeProcess(self._process)

    def terminate_tree(self) -> None:
        win32job.TerminateJobObject(self._job, _FORCED_EXIT)

    def active_processes(self) -> int:
        info = win32job.QueryInformationJobObject(self._job, win32job.JobObjectBasicAccountingInformation)
        return info["ActiveProcesses"]

    def close(self) -> None:
        self._resources.close()
