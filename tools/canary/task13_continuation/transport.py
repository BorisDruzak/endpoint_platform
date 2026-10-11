"""One bounded raw-retaining local transport; timeout is UNKNOWN, never retried."""
import base64
import os
import subprocess
import threading
import time
from datetime import datetime, timezone

from .codec import canonical, digest, parse_json, require, sha256


def utc():
    return datetime.now(timezone.utc).isoformat()


class TransportUnknown(ValueError):
    def __init__(self,result):
        super().__init__("UNKNOWN transport; dispatch claim remains consumed")
        self.result = result


def envelope(stdout, stderr, code, start_utc, start_ns, end_utc, end_ns, stdin_confirmed):
    parsed = {"status":"UNKNOWN"}
    complete = code == 0 and not stderr and stdin_confirmed
    if complete:
        try:
            parsed = parse_json(stdout.strip())
        except ValueError:
            complete = False
    return {"status":"TRANSPORT_COMPLETE" if complete else "UNKNOWN",
            "exit_code":code, "stdin_confirmed":stdin_confirmed,
            "stdout_b64":base64.b64encode(stdout).decode(), "stderr_b64":base64.b64encode(stderr).decode(),
            "stdout_sha256":sha256(stdout), "stderr_sha256":sha256(stderr),
            "dispatch_utc":start_utc,"dispatch_mono_ns":start_ns,"finished_utc":end_utc,"finished_mono_ns":end_ns,
            "observation":parsed}


class ContinuationTransport:
    def __init__(self, store, authorization):
        self.store, self.authorization, self.counter = store, authorization, 0
        self._lock = threading.Lock()

    def call(self, tag, argv, data=b"", seconds=25, *, pre_dispatch=None):
        require(type(seconds) is int and 1 <= seconds <= 145 and type(data) is bytes, "bounded transport request")
        self.authorization.check()
        with self._lock:
            self.counter += 1
            name = f"transport-{self.counter:03d}-{tag}"
        self.store.create(name+"-intent.json",canonical({"argv_sha256":digest(argv),"stdin_sha256":sha256(data),
                                                       "stdin_bytes":len(data),"seconds":seconds}))
        self.authorization.check()
        start_utc, start_ns = utc(), time.monotonic_ns()
        require(start_ns + seconds*10**9 < self.authorization.capsule["deadline_mono_ns"] - 2*10**9,
                "insufficient continuation budget")
        if pre_dispatch is not None: pre_dispatch()
        self.authorization.check()
        start_utc,start_ns=utc(),time.monotonic_ns()
        env = {k:v for k,v in os.environ.items() if k.upper() not in ("PYTHONPATH","PYTHONHOME")}
        process = subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                   env=env,cwd=self.store.root,creationflags=0x08000000 if os.name == "nt" else 0)
        outputs = [bytearray(),bytearray()]
        failures, sent = [], []

        def drain(stream, slot, limit):
            try:
                while block := stream.read(4096):
                    if len(outputs[slot])+len(block)>limit:
                        failures.append("output bound")
                        break
                    outputs[slot].extend(block)
            except Exception:
                failures.append("output read")

        def feed():
            try:
                count = process.stdin.write(data)
                process.stdin.flush()
                process.stdin.close()
                require(count == len(data), "stdin incomplete")
                sent.append(True)
            except Exception:
                failures.append("stdin write")

        threads = [threading.Thread(target=drain,args=(process.stdout,0,8*1024*1024),daemon=True),
                   threading.Thread(target=drain,args=(process.stderr,1,8192),daemon=True),
                   threading.Thread(target=feed,daemon=True)]
        for thread in threads:
            thread.start()
        uncertain = False
        try:
            while process.poll() is None or any(thread.is_alive() for thread in threads):
                self.authorization.check()
                if failures or time.monotonic_ns()-start_ns >= seconds*10**9:
                    uncertain = True
                    break
                time.sleep(.05)
        except Exception:
            uncertain = True
        finally:
            if uncertain and process.poll() is None:
                process.kill()  # Local SSH only. Independent guest watchdog owns settlement.
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                uncertain = True
            for thread in threads:
                thread.join(timeout=.1)
                uncertain |= thread.is_alive()
        code = process.returncode if not uncertain and not failures else None
        result = envelope(bytes(outputs[0]),bytes(outputs[1]),code,start_utc,start_ns,utc(),
                          time.monotonic_ns(),sent == [True] and not uncertain)
        self.store.create(name+"-result.json",canonical(result))
        self.authorization.check()
        if result["status"] != "TRANSPORT_COMPLETE":
            raise TransportUnknown(result)
        return result

    def powershell(self, prefix, script, tag, seconds=25, data=b"", *, pre_dispatch=None):
        encoded = base64.b64encode(script.encode("utf-16-le")).decode()
        argv = [*prefix,"powershell.exe -NoProfile -NonInteractive -EncodedCommand "+encoded]
        require(len(subprocess.list2cmdline(argv))+1<=32767,"Windows command-line bound")
        return self.call(tag,argv,data,seconds,pre_dispatch=pre_dispatch)
