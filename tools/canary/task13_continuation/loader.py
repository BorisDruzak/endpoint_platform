"""Canonical additive one-step loader. Trust comes from fixed protected slots."""
import base64
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack,contextmanager
from pathlib import Path

from .authority import create_capsule, LiveAuthorization, REVIEW_SCOPE
from .codec import canonical, digest, parse_json, require, sha256, uuid
from .history import verify_historical_prefix, MANIFEST_SHA, _relative
from .permission import verify_permission
from .recovery import hold_recovery,launch_owner
from .receipt import make_receipt, verify_continuation_receipt, publication_ack, raw_bytes, observation
from .reconciliation import validate_state,dispatch_freshness
from .sources import seal_sources
from .storage import ProtectedStore
from .transport import ContinuationTransport, TransportUnknown, envelope, utc
from . import windows


def check_operations(value):
    require(type(value) is dict and value.get("schema") == "task13_fixed_operations_v1"
            and type(value.get("allowed_seq")) is int and value["allowed_seq"] == 4
            and value.get("allowed_step") == "compare-after-start", "only seq04 operations")
    uuid(value["continuation_id"])
    require(value["guest_root"] == "C:\\Task13Continuation-"+value["continuation_id"].replace("-",""), "fixed guest root")
    for argv in (value["guest_ssh"],value["provider_argv"]):
        require(type(argv) is list and "StrictHostKeyChecking=yes" in argv and "BatchMode=yes" in argv,
                "strict fixed SSH required")


def _hold_file(stack, path, expected, *, protected=False, runtime=False):
    links = expected.get("hardlink_count",1)
    require(type(links) is int and 1 <= links <= 32
            and (links == 1 or runtime and path in windows.system_core_paths()),"only pinned installed system hardlinks")
    handle = stack.enter_context(windows.retained(path,protected=protected,security=protected,expected_links=links))
    raw = windows.read_handle(handle,path,expected_links=links)
    require(len(raw) == expected["bytes"] and sha256(raw) == expected["sha256"], "held source closure changed")
    return raw


def _hold_history(stack, root):
    manifest_raw = ProtectedStore(root).read("source-closure-manifest.json")
    require(sha256(manifest_raw) == MANIFEST_SHA, "historical native source manifest")
    manifest = parse_json(manifest_raw)
    dirs = {root,root/"zero-owner-recovery-records"}
    for group,field,base in (("entries","name",root),("prerequisites","relative_path",root.parent)):
        for spec in manifest[group]:
            path = base/_relative(spec[field])
            dirs.update(path.parents)
    dirs.update(root.parents)
    for path in sorted(dirs,key=lambda p:len(p.parts)):
        stack.enter_context(windows.retained(path,directory=True,security=False))
    for group,field,base in (("entries","name",root),("prerequisites","relative_path",root.parent)):
        for spec in manifest[group]:
            _hold_file(stack,base/_relative(spec[field]),spec)
    for path in (root/"zero-owner-recovery-records").glob("*.json"):
        stack.enter_context(windows.retained(path,protected=False,security=True))


def _reconcile(prefix, auth, transport, operations, entries):
    sent_utc,sent_ns = utc(),time.monotonic_ns()
    def ps(name,seconds=25):
        return transport.powershell(operations["guest_ssh"],entries["entry-"+name+".ps1"].decode(),name,seconds)
    def management(action):
        return transport.call("management-"+action,operations["management_argv"],
                              canonical({**operations["management_request"],"action":action}),30 if action=="state" else 5)
    work = {"management":lambda:management("state"),"provider":lambda:transport.call("provider",operations["provider_argv"],entries["provider-stdin.bin"],25),
            "guest":lambda:ps("guest"),"inventory":lambda:ps("inventory"),"current":lambda:ps("current")}
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {name:pool.submit(fn) for name,fn in work.items()}
        constituents = {name:future.result() for name,future in futures.items()}
    with ThreadPoolExecutor(max_workers=2) as pool:
        guest_clock = pool.submit(ps,"clock_guest",5)
        management_clock = pool.submit(management,"clock")
        constituents.update(clock_guest=guest_clock.result(),clock_management=management_clock.result())
    state = {"schema":"task13_reconciled_state_v1","predicate_version":"task13_readonly_reconciliation_v1",
             "status":"PASS","original":prefix.binding,"constituents":constituents,"constituent_sha256":digest(constituents)}
    done_utc,done_ns = utc(),time.monotonic_ns()
    validate_state(prefix,auth.capsule,state,done_utc)
    # This is a root aggregation of independently retained real transports.
    result = envelope(canonical(state),b"",0,sent_utc,sent_ns,done_utc,done_ns,True)
    result["kind"] = "ROOT_VALIDATED_RECONCILIATION"
    auth.check()
    return result


def guard_dispatch(prefix,auth,preflight):
    auth.check()
    state=observation(preflight,auth.capsule,maximum=60)
    validate_state(prefix,auth.capsule,state,utc())
    return dispatch_freshness(state)


@contextmanager
def reviewed_bundle(root,trust=None):
    store = ProtectedStore(root)
    with ExitStack() as held:
        for path in reversed((root,*root.parents)):
            held.enter_context(windows.retained(path,directory=True,protected=path==root,security=path==root))
        closure = parse_json(store.read("closure.json"))
        review = parse_json(store.read("review.json"))
        detached = parse_json(store.read("trust.json"))
        require((trust is None or trust == detached) and set(detached) == {"schema","source_closure_sha256","review_sha256","bootstrap_sha256","request_sha256","reviewer_controller"}
                and detached["schema"] == "task13_independent_review_trust_v1"
                and digest(closure) == detached["source_closure_sha256"] == review["source_closure_sha256"]
                and digest(review) == detached["review_sha256"] and review["status"] == "PASS"
                and review["scope"] == REVIEW_SCOPE,"independent final source review PASS required")
        require(closure["schema"] == "task13_reviewed_closure_v1", "exact reviewed closure schema")
        entries = {}
        for name,spec in closure["execution"]["entries"].items():
            path = root/_relative(name)
            if path.parent != root:
                for parent in reversed(path.parent.parents):
                    if root in (parent,*parent.parents) and parent != root:
                        held.enter_context(windows.retained(parent,directory=True,protected=True))
                held.enter_context(windows.retained(path.parent,directory=True,protected=True))
            entries[name] = _hold_file(held,path,spec,protected=True)
        require(seal_sources(entries) == closure["execution"], "exact bundle source closure")
        require(sha256(entries["bootstrap.py"]) == detached["bootstrap_sha256"]
                and digest(parse_json(entries["operator-request.json"])) == detached["request_sha256"],"reviewed bootstrap/operator pins")
        runtime_dirs = {parent for name in closure["runtime"] for parent in Path(name).parents}
        for parent in sorted(runtime_dirs,key=lambda p:len(p.parts)):
            held.enter_context(windows.retained(parent,directory=True,security=False))
        for path,spec in closure["runtime"].items():
            _hold_file(held,Path(path),spec,runtime=True)
        control = parse_json(entries["control.json"])
        require(control["schema"] == "task13_bootstrap_control_v1", "fixed control schema")
        original_root = Path(control["original_root"])
        require(Path(control["claim_home"]) == original_root/"continuation-v1-claims", "canonical original-step claim home")
        _hold_history(held,original_root)
        prefix = verify_historical_prefix(original_root)
        require(prefix.binding == control["original_binding"] == closure["original_binding"], "reviewed prefix changed")
        request = parse_json(entries["operator-request.json"])
        verify_permission(request)
        hold_recovery(held,parse_json(entries['recovery.json']),prefix,launch_owner(prefix,closure),
                      require_launch=sys.argv[1:]==['--execute-reviewed-seq04-child'])
        operations = parse_json(entries["operations.json"])
        check_operations(operations)
        require(operations["continuation_id"] == closure["continuation_id"], "reviewed execution identity")
        yield store,closure,review,detached,entries,prefix,request,operations,control


def run_seq04(config, trust):
    require(type(config) is dict and set(config) == {"bootstrap_root"}, "fixed native bootstrap required")
    root = Path(config["bootstrap_root"]).absolute()
    require(Path(sys.argv[0]).absolute() == root/"bootstrap.py" and sys.argv[1:]==['--execute-reviewed-seq04-child'],
            'run only the supervised protected reviewed bootstrap')
    with reviewed_bundle(root,trust) as (store,closure,review,detached,entries,prefix,request,operations,control):
        identity = windows.observe_controller()
        require(detached["reviewer_controller"]["pid"] != identity["pid"]
                or detached["reviewer_controller"]["birth"] != identity["birth"],"independent reviewer process required")
        authority = {"schema":"task13_operator_authority_v1","original":prefix.binding,
                     "allowed_seq":4,"allowed_step":"compare-after-start","controller":identity,
                     "source_closure_sha256":digest(closure),"bootstrap_sha256":detached["bootstrap_sha256"],
                     "request_sha256":detached["request_sha256"],"request_reference":"actual-app-session-message"}
        capsule = create_capsule(prefix,closure,authority,review,identity)
        attestation = {"schema":"task13_creator_attestation_v1","capsule_sha256":digest(capsule),
                       "authority_sha256":digest(authority),"controller":identity}
        trusted = {"authority_sha256":digest(authority),"attestation_sha256":digest(attestation),
                   **{k:detached[k] for k in ("review_sha256","bootstrap_sha256","source_closure_sha256","request_sha256")}}
        auth = LiveAuthorization(capsule,authority,attestation,review,trusted,identity)
        auth.check()
        for name,value in (("authority",authority),("capsule",capsule),("attestation",attestation),("live-trust",trusted)):
            store.create(name+".json",canonical(value))
        transport = ContinuationTransport(store,auth)
        # Fresh preflight can refuse without claiming workload dispatch.
        preflight = _reconcile(prefix,auth,transport,operations,entries)
        store.create("preflight.json",canonical(preflight))
        auth.check();verify_permission(request)
        claims_root = Path(control["claim_home"])
        try:
            claims = ProtectedStore.create_root(claims_root)
        except OSError:
            claims = ProtectedStore(claims_root)
        claim = claims.claim(prefix,capsule["continuation_id"])
        store.create("dispatch-claim.json",canonical(claim))
        try:
            auth.check()
            ready = transport.powershell(operations["guest_ssh"],entries["entry-prepare.ps1"].decode(),"prepare",25)
            value = observation(ready,capsule,maximum=25)
            require(value["status"] == "INDEPENDENT_WATCHDOG_READY" and value["run"] == capsule["continuation_id"]
                    and value["watchdog_sha256"] == sha256(entries["Watch-Task13DiagnosticProcess.ps1"]),"independent watchdog preparation")
            preflight=_reconcile(prefix,auth,transport,operations,entries)
            store.create('dispatch-preflight.json',canonical(preflight))
            try:
                guest = transport.powershell(operations["guest_ssh"],entries["entry-workload.ps1"].decode(),"compare-after-start",145,entries["wire.bin"],
                                            pre_dispatch=lambda:guard_dispatch(prefix,auth,preflight))
            except TransportUnknown:
                # Settlement reads are part of this same dispatch, never a workload
                # retry. Authority must still be live; otherwise leave guest artifacts.
                try:
                    failure_collection = transport.powershell(operations["guest_ssh"],entries["entry-collect.ps1"].decode(),"failure-settlement",15)
                    store.create("failure-retained-collection.json",canonical(failure_collection))
                except Exception:
                    pass
                raise
            collected = transport.powershell(operations["guest_ssh"],entries["entry-collect.ps1"].decode(),"settlement",15)
            result = observation(collected,capsule,maximum=15)
            require(result["status"] == "RETAINED_CONTINUATION_EVIDENCE" and result["run"] == capsule["continuation_id"]
                    and result["root"] == operations["guest_root"],"retained evidence root")
            files = {name:raw_bytes(raw) for name,raw in result["files"].items()}
            identity_row = parse_json(files["identity.json"])
            process_identity = {k:identity_row[k] for k in ("run","pid","birth")}
            watchdog_row = parse_json(files["exit-confirmed.json"])
            require(watchdog_row["pid"] == process_identity["pid"] and watchdog_row["birth"] == process_identity["birth"],"watchdog identity")
            watchdog = envelope(canonical({**watchdog_row,"run":process_identity["run"]}),b"",0,
                                collected["dispatch_utc"],collected["dispatch_mono_ns"],
                                collected["finished_utc"],collected["finished_mono_ns"],True)
            watchdog["retained_transport_sha256"] = digest(collected)
            postflight = _reconcile(prefix,auth,transport,operations,entries)
            evidence = {"schema":"task13_execution_evidence_v1","continuation_id":capsule["continuation_id"],
                        "source_closure_sha256":digest(closure),"preflight":preflight,"postflight":postflight,
                        "guest":guest,"watchdog":watchdog,"identity":process_identity,
                        "journal_b64":base64.b64encode(files["stages.jsonl"]).decode(),
                        "journal_sha256":sha256(files["stages.jsonl"]),"retained_collection":collected,"watchdog_preparation":ready}
            evidence['dispatch_claim']=claim
            auth.check();verify_permission(request)
            receipt = make_receipt(prefix,capsule,evidence)
            require(parse_json(claims.read('claim-'+digest({k:claim[k] for k in ('original_run_seal_sha256','original_tip','seq')})+'.json'))==claim,
                    'durable dispatch claim unchanged')
            require(verify_historical_prefix(prefix.root).binding == prefix.binding,"history changed after workload")
            store.create("execution-evidence.json",canonical(evidence))
            auth.check()
            store.publish("receipt-04-compare-after-start.json",canonical(receipt))
            auth.check()
            store.create("resume-gate.json",canonical(publication_ack(capsule,receipt)))
            from .receipt import verify_receipt_candidate
            verify_receipt_candidate(prefix,capsule,parse_json(store.read("receipt-04-compare-after-start.json")),evidence,
                                     parse_json(store.read("resume-gate.json")))
            auth.check()
            return {"status":"ROOT_PUBLICATION_READY","continuation_id":capsule["continuation_id"],"continuation_sha256":digest(capsule),
                    "receipt_sha256":digest(receipt),"source_closure_sha256":digest(closure),"resume_gate":"STOP_BEFORE_SEQ05"}
        except Exception as error:
            store.create("unknown.json",canonical({"status":"UNKNOWN","error_type":type(error).__name__,
                                                   "dispatch_claim_consumed":True,"retry_allowed":False}))
            raise


def bootstrap_entry(root):
    if sys.argv[1:] not in (["--execute-reviewed-seq04"],['--execute-reviewed-seq04-child']):
        print('{"status":"NONOPERATIONAL","reason":"explicit reviewed bootstrap required"}')
        raise SystemExit(2)
    if sys.argv[1:] == ['--execute-reviewed-seq04-child']:
        trust = parse_json(ProtectedStore(root).read("trust.json"))
        result = run_seq04({"bootstrap_root":str(root)},trust)
    else:
        from .supervisor import supervise
        result=supervise(root)
    print(canonical(result).decode("ascii"))
