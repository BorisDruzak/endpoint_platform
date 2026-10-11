"""A reviewed observation entry, with no workload claim or execution capsule."""
import threading
import time
from datetime import datetime,timedelta,timezone
from pathlib import Path

from .codec import canonical,digest,instant,parse_json,require
from .permission import verify_permission
from .process_identity import identity_states
from .storage import ProtectedStore
from .transport import ContinuationTransport,utc
from . import windows


class ReadOnlyWindow:
    def __init__(self,identity):
        self.identity=canonical(identity)
        now,mono=datetime.now(timezone.utc),time.monotonic_ns()
        self._window=canonical(dict(schema='task13_readonly_gate_window_v1',controller=identity,
            created_utc=now.isoformat(),expires_utc=(now+timedelta(seconds=1200)).isoformat(),
            created_mono_ns=mono,deadline_mono_ns=mono+1200*10**9))
        self.last_utc,self.last_ns=now,mono
        self.lock=threading.RLock()

    @property
    def capsule(self):
        # Transport bracket format only; this schema is rejected by seq04 authority.
        return parse_json(self._window)

    def check(self):
        with self.lock:
            require(canonical(windows.observe_controller())==self.identity,'read-only controller changed')
            window=self.capsule
            now,mono=datetime.now(timezone.utc),time.monotonic_ns()
            start,end=instant(window['created_utc']),instant(window['expires_utc'])
            require(start<=now<end and window['created_mono_ns']<=mono<window['deadline_mono_ns']-2*10**9,'read-only observation expired')
            require(abs((now-start).total_seconds()-(mono-window['created_mono_ns'])/10**9)<=5,'read-only clock divergence')
            require(now>=self.last_utc and mono>=self.last_ns,'read-only clock rollback')
            self.last_utc,self.last_ns=now,mono


def observe_reviewed_guard(root):
    from .loader import reviewed_bundle,_reconcile
    import sys
    root=Path(root).absolute()
    require(Path(sys.argv[0]).absolute()==root/'bootstrap.py' and sys.argv[1:]==['--observe-reviewed-guard'],'fixed read-only reviewed entry')
    with reviewed_bundle(root) as (_,closure,review,trust,entries,prefix,request,operations,control):
        identity=windows.observe_controller()
        require((trust['reviewer_controller']['pid'],trust['reviewer_controller']['birth'])!=(identity['pid'],identity['birth']),
                'independent reviewer required')
        store=ProtectedStore.create_root(root/'read-only-guard')
        auth=ReadOnlyWindow(identity)
        store.create('window.json',canonical(auth.capsule))
        transport=ContinuationTransport(store,auth)
        verdict=dict(schema='task13_readonly_gate_verdict_v1',status='BLOCKED',source_closure_sha256=digest(closure),
            original=prefix.binding,seq04_dispatched=False,claims_consumed=False,checked_utc=None)
        try:
            result=_reconcile(prefix,auth,transport,operations,entries)
            store.create('preflight.json',canonical(result))
            auth.check();verify_permission(request)
            status='READ_ONLY_CANONICAL_PREFLIGHT_PASS' if request.get('scope')=='readonly-unknown-recovery' else 'READY_FOR_SEPARATE_SEQ04'
            verdict.update(status=status,preflight_sha256=digest(result))
        except ValueError as error:
            # Messages are fixed source predicates, never raw SSH exceptions/args.
            verdict.update(error_type=type(error).__name__,predicate=str(error)[:256])
        for path in store.root.glob('transport-*-process_identity-result.json'):
            raw=parse_json(store.read(path.name))
            if raw['status']=='TRANSPORT_COMPLETE':
                states=identity_states(prefix,raw['observation'])
                verdict['identity_state_counts']={state:list(states.values()).count(state) for state in sorted(set(states.values()))}
        verdict['checked_utc']=utc()
        if request.get('scope')=='readonly-unknown-recovery':
            from .readonly_recovery import capture_readonly_recovery
            record=parse_json(entries['recovery.json']);fresh=capture_readonly_recovery(prefix)
            require({k:v for k,v in record.items() if k!='creator_termination_observation'}
                    =={k:v for k,v in fresh.items() if k!='creator_termination_observation'},'read-only recovery evidence changed')
            verdict.update(historical_rca='UNKNOWN',seq04_authorized=False,consumed_claim_unchanged=True)
        store.create('verdict.json',canonical(verdict))
        return verdict
