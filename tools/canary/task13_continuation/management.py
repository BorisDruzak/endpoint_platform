"""Fixed read-only management child. No mutation command or old authorization."""
import ast
import base64
import json
import time
import types
from pathlib import Path

from .codec import canonical, parse_json, require, sha256
from .history import read_file, MANIFEST_SHA
from .transport import envelope, utc


def sealed_module(root, name, manifest):
    raw = read_file(root/name)
    entry = next(v for v in manifest["entries"] if v["name"] == name)
    require(sha256(raw) == entry["sha256"] and len(raw) == entry["bytes"], "management source pin")
    module = types.ModuleType("sealed_readonly_"+name.replace(".","_"))
    module.__file__ = str(root/name)
    exec(compile(raw,module.__file__,"exec"),module.__dict__)
    return module


def validate_checkpoint_config(policy,config,request):
    # Current VM parent advanced at snapshot creation; the snapshot's saved
    # configuration keeps its older parent and is validated by saved_guard.
    return policy.validate_config(config,request['snapshot'],request['generation'])


def main():
    import sys
    request = parse_json(sys.stdin.buffer.read(65537),limit=65536)
    require(set(request) == {"root","action","run_id","snapshot","generation"}
            and request["action"] in ("state","clock"), "read-only management request")
    root = Path(request["root"])
    manifest_raw = read_file(root/"source-closure-manifest.json")
    require(sha256(manifest_raw) == MANIFEST_SHA, "original management closure")
    manifest = parse_json(manifest_raw)
    auth = sealed_module(root,"hypervisor_readonly.py",manifest)
    policy = sealed_module(root,"task13_vm100_recovery.draft.py",manifest)
    worker_name = "task13_zero_owner_management_worker.py"
    worker_raw = read_file(root/worker_name)
    entry = next(v for v in manifest["entries"] if v["name"] == worker_name)
    require(sha256(worker_raw) == entry["sha256"], "original saved-config guard")
    nodes = [node for node in ast.parse(worker_raw).body
             if isinstance(node,ast.FunctionDef) and node.name in {"require","saved_guard"}]
    namespace = {}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),worker_name,"exec"),namespace)
    # Same strict local host-key store as the audited original auth entry point.
    client = auth.paramiko.SSHClient()
    client.load_host_keys(str(Path.home()/".ssh/known_hosts"))
    client.set_missing_host_key_policy(auth.paramiko.RejectPolicy())
    deadline = time.monotonic()+25
    receipts = {}

    def command(tag, text):
        require(time.monotonic()<deadline, "management child deadline")
        sent_utc,sent_ns = utc(),time.monotonic_ns()
        stdin,stdout,stderr = client.exec_command(text,timeout=max(.1,min(10,deadline-time.monotonic())),get_pty=False)
        stdin.close()
        channel = stdout.channel
        out,err = bytearray(),bytearray()
        try:
            while True:
                require(time.monotonic()<deadline, "management command UNKNOWN")
                if channel.recv_ready(): out.extend(channel.recv(4096))
                if channel.recv_stderr_ready(): err.extend(channel.recv_stderr(4096))
                require(len(out)<=262144 and len(err)<=8192,"management output bound")
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready() and channel.eof_received:
                    break
                time.sleep(.01)
            code = channel.recv_exit_status()
            require(type(code) is int and code == 0 and not err,"management native exit")
            receipts[tag] = {"command_sha256":sha256(text.encode()),"stdout_b64":base64.b64encode(out).decode(),
                             "stderr_b64":base64.b64encode(err).decode(),"exit_code":code,
                             "dispatch_utc":sent_utc,"dispatch_mono_ns":sent_ns,
                             "finished_utc":utc(),"finished_mono_ns":time.monotonic_ns()}
            return bytes(out).decode("utf-8")
        finally:
            channel.close()

    try:
        client.connect(auth.HOST,username="root",password=auth.supplied_password(),look_for_keys=False,
                       allow_agent=False,timeout=5,auth_timeout=5,banner_timeout=5)
        if request["action"] == "clock":
            value = {"status":"CLOCK_OBSERVED","kind":"management","run_id":request["run_id"],
                     "utc":command("clock","date -u +%Y-%m-%dT%H:%M:%S.%NZ").strip()}
        else:
            require(__import__("re").fullmatch(r"pre82-real81-staged-[0-9a-f]{16}",request["snapshot"]),"fixed snapshot selector")
            status = command("status","qm status 100")
            config = policy.parse_config(command("config","qm config 100"))
            validate_checkpoint_config(policy,config,request)
            snapshots = json.loads(command("snapshots","pvesh get /nodes/pve1/qemu/100/snapshot --output-format json"))
            metadata = next(row for row in snapshots if row["name"] == request["snapshot"])
            raw_lvs = json.loads(command("lvs","lvs --reportformat json -a -o lv_name,lv_uuid,origin,lv_attr,lv_size -S 'lv_name=~vm-100' pve"))
            lvs = [{k:str(v[k]).strip() for k in ("lv_name","lv_uuid","origin","lv_attr","lv_size")}
                   for v in raw_lvs["report"][0]["lv"]]
            saved = json.loads(command("saved","pvesh get /nodes/pve1/qemu/100/snapshot/"+request["snapshot"]+"/config --output-format json"))
            normalized = namespace["saved_guard"](saved,metadata,policy,request["generation"])
            active = json.loads(command("active","pvesh get /nodes/pve1/tasks --vmid 100 --source active --output-format json"))
            value = {"status":"CONTINUATION_MANAGEMENT_OBSERVED","run_id":request["run_id"],
                     "state":{"status":status,"config":config,"lvs":lvs},"metadata":metadata,
                     "saved_config_normalized":normalized,"volumes":[v for v in lvs if v["lv_name"].endswith("_"+request["snapshot"])],
                     "active_tasks":active,"command_receipts":receipts}
        sys.stdout.buffer.write(canonical(value))
    finally:
        client.close()
