"""Own the selected Windows Core before it can start any descendants."""

from __future__ import annotations

from contextlib import ExitStack
import ctypes
from ctypes import wintypes
from functools import cache
import msvcrt
import os
from pathlib import Path
import subprocess
import threading
import time

import _winapi
from pywintypes import error as Win32Error
import win32job
import win32process


_FORCED_EXIT = 75
_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
_JOB_ACTIVE_LIMIT = 128
_JOB_ADMISSION_LIMIT = 4096
_PROCESS_WAIT_ACCESS = 0x00101000  # SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION


class _JobProcessIds(ctypes.Structure):
    _fields_ = [
        ("assigned", wintypes.DWORD),
        ("listed", wintypes.DWORD),
        ("pids", ctypes.c_size_t * _JOB_ACTIVE_LIMIT),
    ]


@cache
def _job_query():
    query = ctypes.WinDLL("kernel32", use_last_error=True).QueryInformationJobObject
    query.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p)
    query.restype = wintypes.BOOL
    return query


def _job_pids(job) -> tuple[int, ...]:
    query = _job_query()
    members = _JobProcessIds()
    if not query(int(job), win32job.JobObjectBasicProcessIdList, ctypes.byref(members), ctypes.sizeof(members), None):
        raise ctypes.WinError(ctypes.get_last_error())
    if not members.assigned == members.listed <= _JOB_ACTIVE_LIMIT:
        raise ValueError("incomplete Core Job membership")
    listed = tuple(members.pids[:members.listed])
    if not all(listed) or len(set(listed)) != len(listed):
        raise ValueError("invalid Core Job membership")
    return listed


@cache
def _process_times_query():
    query = ctypes.WinDLL("kernel32", use_last_error=True).GetProcessTimes
    query.argtypes = (wintypes.HANDLE,) + (ctypes.POINTER(wintypes.FILETIME),) * 4
    query.restype = wintypes.BOOL
    return query


def _creation_time(process) -> int:
    query = _process_times_query()
    times = [wintypes.FILETIME() for _ in range(4)]
    if not query(process, *(ctypes.byref(value) for value in times)):
        raise ctypes.WinError(ctypes.get_last_error())
    created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
    if not created:
        raise ValueError("invalid Core process creation time")
    return created


class _CompletionAssociation(ctypes.Structure):
    _fields_ = [("key", ctypes.c_void_p), ("port", wintypes.HANDLE)]


@cache
def _completion_api():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateIoCompletionPort
    create.argtypes = (wintypes.HANDLE, wintypes.HANDLE, ctypes.c_size_t, wintypes.DWORD)
    create.restype = wintypes.HANDLE
    associate = kernel.SetInformationJobObject
    associate.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
    associate.restype = wintypes.BOOL
    read = kernel.GetQueuedCompletionStatus
    read.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(ctypes.c_size_t),
                     ctypes.POINTER(ctypes.c_void_p), wintypes.DWORD)
    read.restype = wintypes.BOOL
    return create, associate, read


class _JobAdmissionNotifications:
    """Observe admissions promptly, without treating the hints as exit evidence."""

    def __init__(self, job):
        create, self._associate, self._read = _completion_api()
        self._job = int(job)
        self._binding_lock = threading.Lock()
        self._attached = False
        self._port = create(wintypes.HANDLE(-1), None, 0, 1)
        if not self._port:
            raise ctypes.WinError(ctypes.get_last_error())
        binding = _CompletionAssociation(1, self._port)
        if not self._set_binding(binding):
            error = ctypes.WinError(ctypes.get_last_error())
            _winapi.CloseHandle(self._port)
            raise error
        self._attached = True
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._thread = None

    def start(self, evidence):
        thread = threading.Thread(target=self._observe, args=(evidence,), daemon=True)
        try:
            thread.start()
        except RuntimeError:
            return  # Bounded polling still handles runtime if a reader cannot start.
        self._thread = thread
        self._ready.wait(0.1)

    def _set_binding(self, binding):
        return self._associate(self._job, win32job.JobObjectAssociateCompletionPortInformation,
                               ctypes.byref(binding), ctypes.sizeof(binding))

    def _detach(self, *, owner_closing=False):
        with self._binding_lock:
            if not self._attached:
                return True
            detached = bool(self._set_binding(_CompletionAssociation(None, None)))
            if detached or owner_closing:
                self._attached = False  # The owner may now release the Job HANDLE.
            return detached

    def _observe(self, evidence):
        code = wintypes.DWORD()
        key = ctypes.c_size_t()
        pid = ctypes.c_void_p()
        self._ready.set()
        collecting = True
        try:
            while not self._stop.is_set():
                if not self._read(self._port, ctypes.byref(code), ctypes.byref(key), ctypes.byref(pid), 50):
                    if ctypes.get_last_error() == _winapi.WAIT_TIMEOUT:
                        continue
                    return
                if collecting and key.value == 1 and code.value == win32job.JOB_OBJECT_MSG_NEW_PROCESS and pid.value:
                    collecting = evidence.observe_admission(pid.value)
                    if not collecting and self._detach():
                        return
                # If detach failed, drain without acquiring more process handles.
        finally:
            self._detach()
            _winapi.CloseHandle(self._port)

    def close(self):
        self._stop.set()
        self._detach(owner_closing=True)
        if self._thread is None:
            _winapi.CloseHandle(self._port)
        else:
            self._thread.join(0.15)  # The reader still owns the port after a timeout.


class _JobExitEvidence:
    def __init__(self, job, core_pid, core_handle):
        self._job = job
        self._core_handle = core_handle
        self._lock = threading.Lock()
        self._live = {}
        self._completed = set()
        self._unknown = False
        try:
            self._live[core_pid] = (core_handle, _creation_time(core_handle))
        except (OSError, ValueError, Win32Error):
            self._unknown = True

    def close(self):
        with self._lock:
            self._unknown = True
            self._close_handles()

    def _close_handles(self):
        for handle, _ in self._live.values():
            if handle != self._core_handle:
                _winapi.CloseHandle(handle)
        self._live.clear()

    def _at_limit(self):
        return (len(self._live) >= _JOB_ACTIVE_LIMIT
                or len(self._live) + len(self._completed) >= _JOB_ADMISSION_LIMIT)

    def _record_member(self, pid):
        if self._at_limit():
            raise ValueError("Core Job evidence bound exhausted")
        handle = _winapi.OpenProcess(_PROCESS_WAIT_ACCESS, False, pid)
        try:
            if not win32job.IsProcessInJob(handle, self._job):
                raise ValueError("process does not belong to the Core Job")
            stamp = _creation_time(handle)
            if (pid, stamp) in self._completed:
                if _winapi.WaitForSingleObject(handle, 0) != _winapi.WAIT_OBJECT_0:
                    raise ValueError("Core process identity reused without proof")
                return
            self._live[pid] = (handle, stamp)
            handle = None
        finally:
            if handle is not None:
                _winapi.CloseHandle(handle)

    def _reap(self):
        for pid, (handle, stamp) in tuple(self._live.items()):
            result = _winapi.WaitForSingleObject(handle, 0)
            if result == _winapi.WAIT_TIMEOUT:
                continue
            if result != _winapi.WAIT_OBJECT_0:
                raise ValueError("invalid Core process wait result")
            self._completed.add((pid, stamp))
            del self._live[pid]
            if handle != self._core_handle:
                _winapi.CloseHandle(handle)
        return not self._live

    def observe_admission(self, pid) -> bool:
        with self._lock:
            if self._unknown:
                return False
            if pid in self._live:
                return True
            if self._at_limit():
                self._unknown = True
                self._close_handles()
                return False
            try:
                self._record_member(pid)
            except (OSError, ValueError, Win32Error):
                # A delayed notification can name a recycled or exited PID.
                # It provides no credit; completeness remains mandatory.
                pass
            return True

    def observe(self):
        with self._lock:
            if self._unknown:
                return
            try:
                # A signalled process can still appear in the accounting snapshot.
                # Keep its verified handle through that snapshot.
                for pid in _job_pids(self._job):
                    if pid not in self._live:
                        self._record_member(pid)
                self._reap()
            except (OSError, ValueError, Win32Error):
                self._unknown = True
                self._close_handles()

    def verify_exited(self, deadline):
        try:
            while True:
                with self._lock:
                    if self._unknown:
                        return False
                    if self._reap():
                        info = win32job.QueryInformationJobObject(
                            self._job, win32job.JobObjectBasicAccountingInformation,
                        )
                        return info["ActiveProcesses"] == 0 and info["TotalProcesses"] == len(self._completed)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                time.sleep(min(0.01, remaining))
        except (OSError, ValueError, Win32Error):
            return False

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
                try:
                    notifications = _JobAdmissionNotifications(job)
                except OSError:
                    notifications = None
                if notifications is not None:
                    owned.callback(notifications.close)
                for handle in (input_handle, output_handle):
                    os.set_handle_inheritable(handle, True)
                process, thread, pid, _tid = _winapi.CreateProcess(
                    command[0], subprocess.list2cmdline(command), None, None, True,
                    _EXTENDED_STARTUPINFO_PRESENT | win32process.CREATE_SUSPENDED
                    | subprocess.CREATE_NO_WINDOW, None, str(Path(command[0]).parent), startup,
                )
                resources.callback(_winapi.CloseHandle, thread)
                owned.callback(_winapi.CloseHandle, process)
                try:
                    win32job.AssignProcessToJobObject(job, process)
                    self._evidence = _JobExitEvidence(job, pid, process)
                    owned.callback(self._evidence.close)
                    if notifications is not None:
                        notifications.start(self._evidence)
                    win32process.ResumeThread(thread)
                except BaseException:
                    _winapi.TerminateProcess(process, _FORCED_EXIT)
                    raise
                self._job = job
                self._process = process
                self._resources = owned.pop_all()

    def wait(self, timeout: float) -> int:
        self._evidence.observe()
        result = _winapi.WaitForSingleObject(self._process, int(timeout * 1000))
        if result == _winapi.WAIT_TIMEOUT:
            raise subprocess.TimeoutExpired("EndpointAgent Core", timeout)
        if result != _winapi.WAIT_OBJECT_0:
            raise OSError("invalid Core process wait result")
        return _winapi.GetExitCodeProcess(self._process)

    def terminate_tree(self) -> None:
        self._evidence.observe()
        win32job.TerminateJobObject(self._job, _FORCED_EXIT)

    def active_processes(self) -> int | None:
        try:
            info = win32job.QueryInformationJobObject(self._job, win32job.JobObjectBasicAccountingInformation)
            return info["ActiveProcesses"]
        except (OSError, Win32Error):
            return None

    def verify_tree_exited(self, deadline: float) -> bool:
        return self._evidence.verify_exited(deadline)

    def close(self) -> None:
        self._resources.close()
