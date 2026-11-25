import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows Job API")


@pytest.fixture
def job_api(monkeypatch):
    import pywintypes
    from pc_agent.platform.windows import core_process as native

    facts = {"pids": [10], "handles": {10: 110}, "stamps": {110: 1000},
             "signalled": set(), "closed": [], "accounting": {"ActiveProcesses": 0, "TotalProcesses": 1}}
    monkeypatch.setattr(native, "_job_pids", lambda job: facts["pids"])
    monkeypatch.setattr(native, "_creation_time", lambda handle: facts["stamps"][handle])
    monkeypatch.setattr(native._winapi, "OpenProcess", lambda access, inherit, pid: facts["handles"][pid])
    monkeypatch.setattr(native._winapi, "CloseHandle", facts["closed"].append)
    monkeypatch.setattr(
        native._winapi, "WaitForSingleObject", lambda handle, timeout:
        native._winapi.WAIT_OBJECT_0 if handle in facts["signalled"] else native._winapi.WAIT_TIMEOUT,
    )
    def in_job(handle, job):
        if facts.get("membership_error"):
            raise pywintypes.error(5, "IsProcessInJob", "denied")
        return handle in facts["stamps"] and job == 1
    monkeypatch.setattr(native.win32job, "IsProcessInJob", in_job)
    monkeypatch.setattr(native.win32job, "QueryInformationJobObject", lambda *_: facts["accounting"])
    return native, facts


def test_accounts_for_finished_worker_and_two_simultaneous_exits_without_pid_alias(job_api):
    native, f = job_api
    evidence = native._JobExitEvidence(1, 10, 110)
    f["pids"] = [10, 20]
    f["handles"][20] = 120
    f["stamps"][120] = 2000
    evidence.observe()
    f["signalled"].add(120)
    f["pids"] = [10]
    evidence.observe()
    assert f["closed"] == [120]  # keep only the completed admission, not its handle
    f["pids"] = [10, 20]
    f["handles"][20] = 121
    f["stamps"][121] = 2001
    evidence.observe()
    f["accounting"]["TotalProcesses"] = 3
    assert not evidence.verify_exited(0)
    f["signalled"].update((110, 121))
    assert evidence.verify_exited(0)
    assert f["closed"] == [120, 121]


def test_omitted_transient_admission_never_authorizes_empty_job(job_api):
    native, f = job_api
    evidence = native._JobExitEvidence(1, 10, 110)
    f["signalled"].add(110)
    f["accounting"]["TotalProcesses"] = 2
    assert not evidence.verify_exited(0)


def test_native_membership_error_is_sticky_and_closes_process_handle(job_api):
    native, f = job_api
    evidence = native._JobExitEvidence(1, 10, 110)
    f["pids"] = [10, 33]
    f["handles"][33] = 133
    f["stamps"][133] = 2000
    f["membership_error"] = True
    evidence.observe()
    f["membership_error"] = False
    f["signalled"].add(110)
    assert not evidence.verify_exited(0)
    assert f["closed"] == [133]


def test_fast_root_exit_does_not_reopen_stale_job_pid(job_api, monkeypatch):
    native, f = job_api
    evidence = native._JobExitEvidence(1, 10, 110)
    # The list still contains the root while its retained handle already signals.
    f["signalled"].add(110)
    def unavailable(*args):
        raise OSError("exited process is no longer openable by PID")
    monkeypatch.setattr(native._winapi, "OpenProcess", unavailable)
    evidence.observe()
    assert evidence.verify_exited(0)


def test_job_notification_tracks_worker_that_never_appears_in_poll(job_api):
    native, f = job_api
    evidence = native._JobExitEvidence(1, 10, 110)
    f["handles"][33] = 133
    f["stamps"][133] = 2000
    evidence.observe_admission(33)
    f["signalled"].update((110, 133))
    f["accounting"]["TotalProcesses"] = 2
    assert evidence.verify_exited(0)
    assert f["closed"] == [133]


def test_exhausted_admission_limit_stops_observer_without_more_handle_opens(job_api, monkeypatch):
    native, _ = job_api
    evidence = native._JobExitEvidence(1, 10, 110)
    monkeypatch.setattr(native, "_JOB_ADMISSION_LIMIT", 1)
    monkeypatch.setattr(native._winapi, "OpenProcess", lambda *_: pytest.fail("opened at evidence limit"))
    assert not evidence.observe_admission(22)
    assert not evidence.observe_admission(33)
    assert not evidence.verify_exited(0)


def test_reader_keeps_port_until_its_own_exit_after_bounded_join(job_api, monkeypatch):
    native, facts = job_api
    associations = []
    def associate(job, info, binding, size):
        item = native.ctypes.cast(binding, native.ctypes.POINTER(native._CompletionAssociation)).contents
        associations.append(item.port)
        return 1
    monkeypatch.setattr(native, "_completion_api", lambda: (lambda *_: 25, associate, None))
    port = native._JobAdmissionNotifications(1)
    class DelayedThread:
        def join(self, timeout):
            assert timeout == 0.15
    port._thread = DelayedThread()
    port.close()
    assert facts["closed"] == []
    port._observe(None)
    assert facts["closed"] == [25]
    assert associations == [25, None]
