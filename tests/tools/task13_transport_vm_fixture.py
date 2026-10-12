"""Stdlib-only synthetic child witness. Input is supplied by a reviewed harness."""
import base64
import ctypes as ct
import hashlib
import json
import subprocess
import sys
import time


def main():
    assert sys.version_info[:2] == (3, 12)
    request = json.loads(sys.stdin.buffer.read(8 * 1024 * 1024 + 1))
    kernel = ct.WinDLL('kernel32', use_last_error=True)
    kernel.GetProcessTimes.argtypes = [ct.c_void_p] * 5
    kernel.GetProcessTimes.restype = ct.c_int
    kernel.WaitForSingleObject.argtypes = [ct.c_void_p, ct.c_uint32]
    kernel.WaitForSingleObject.restype = ct.c_uint32
    kernel.GetExitCodeProcess.argtypes = [ct.c_void_p, ct.POINTER(ct.c_uint32)]
    kernel.GetExitCodeProcess.restype = ct.c_int
    rows = []
    for case in request['cases']:
        script = base64.b64decode(case['bootstrap_b64'], validate=True)
        wire = base64.b64decode(case['wire_b64'], validate=True)
        assert hashlib.sha256(script).hexdigest() == case['bootstrap_sha256']
        assert hashlib.sha256(wire).hexdigest() == case['wire_sha256']
        argv = ['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',
                base64.b64encode(script.decode('utf-8').encode('utf-16-le')).decode('ascii')]
        units = len(subprocess.list2cmdline(argv).encode('utf-16-le')) // 2 + 1
        assert units < 8192
        start = time.monotonic()
        process = subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                   creationflags=0x08000000)
        handle = ct.c_void_p(int(process._handle))
        times = [ct.c_ulonglong() for _ in range(4)]
        assert kernel.GetProcessTimes(handle,*(ct.byref(v) for v in times))
        birth = times[0].value
        try:
            if case['open_stdin']:
                process.stdin.write(wire);process.stdin.flush()
                process.wait(timeout=15)
                process.stdin.close();process.stdin=None
                stdout,stderr=process.communicate(timeout=2)
            else:
                stdout,stderr=process.communicate(wire,timeout=15)
            wait = kernel.WaitForSingleObject(handle,0)
            native = ct.c_uint32()
            assert wait == 0 and kernel.GetExitCodeProcess(handle,ct.byref(native))
            final = [ct.c_ulonglong() for _ in range(4)]
            assert kernel.GetProcessTimes(handle,*(ct.byref(v) for v in final)) and final[0].value == birth
            assert native.value == process.returncode == case['exit_code'] and not stderr
            observation = None
            if case['exit_code'] == 0:
                observation=json.loads(stdout)
                assert observation['status']=='SYNTHETIC_PASS' and observation['inner']=='QUJDRA=='
                assert observation['ps'].startswith('5.1.')
            else: assert stdout == b''
            rows.append(dict(name=case['name'],pid=process.pid,birth=birth,wait_result=wait,
                             exit_code=native.value,seconds=time.monotonic()-start,
                             command_utf16_units_with_nul=units,bootstrap_sha256=case['bootstrap_sha256'],
                             wire_sha256=case['wire_sha256'],observation=observation))
        finally:
            if process.poll() is None: process.kill();process.wait(timeout=2)
    print(json.dumps(dict(status='SYNTHETIC_TRANSPORT_PASS',python=sys.version,passed=len(rows),
                          cases=rows,seq04_dispatched=False,runtime_changed=False),separators=(',',':')))


if __name__ == '__main__':
    main()
