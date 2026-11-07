"""Standalone Linux Support entry point and one-time native enrollment bootstrap.

The service loads only its own token/CA/config; it never reads device credentials.
HTTP runs in one daemon worker. Expiry and cgroup lifetime never wait for HTTP.
"""
from __future__ import annotations

from email.utils import parsedate_to_datetime
import http.client
import json
import math
import queue
import re
import signal
import ssl
import threading
import time
from uuid import UUID

from pc_agent.platform.linux.support_access import (COMPONENT_VERSION, ORIGINS,
    SupportError, SupportPolicy, LeaseState, LeaseGate)
from pc_agent.platform.linux.support_access_native import (SupportPaths, PrivateStore,
    NativeChildren, boot_time, boot_id, validate_account)

PREFIX = '/agent/v1/support-access/linux/'


def _public_status_error(error):
    """Map private failures to the frozen status vocabulary without DTO imports.

    This must match LinuxSupportStatusReport's inherited seven-code contract;
    internal diagnostics or arbitrary exception text never go on the wire.
    """
    code = str(error) if isinstance(error,(SupportError,str)) else None
    return {
        'https_unavailable':'policy_unavailable',
        'https_timeout':'policy_unavailable',
        'expired_policy':'policy_unavailable',
        'stale_policy':'policy_unavailable',
        'invalid_policy':'configuration_conflict',
        'invalid_key':'configuration_conflict',
        'account_not_authorized':'configuration_conflict',
        'unsafe_path':'configuration_conflict',
        'unsafe_file':'configuration_conflict',
        'unsafe_control_socket':'configuration_conflict',
        'key_mismatch':'key_conflict',
        'key_role_conflict':'key_conflict',
        'child_start_failed':'tunnel_failed',
        'master_unavailable':'tunnel_failed',
        'master_changed':'tunnel_failed',
    }.get(code,'service_failed')


class SupportHTTPS:
    def __init__(self, origin, ca_file):
        if origin not in ORIGINS:
            raise SupportError('invalid_origin')
        self.host = ORIGINS[origin]
        try:
            self.ssl = ssl.create_default_context(cafile=str(ca_file))
            self.ssl.minimum_version = ssl.TLSVersion.TLSv1_2
        except Exception:
            raise SupportError('invalid_ca') from None

    def request(self, action, token, payload=None):
        if action not in ('register','policy','status','unregister'):
            raise SupportError('invalid_action')
        if not isinstance(token,str) or not 1 <= len(token) <= 4096 or not re.fullmatch(r'[A-Za-z0-9_.-]+',token):
            raise SupportError('invalid_credential')
        connection = http.client.HTTPSConnection(self.host,443,timeout=5,context=self.ssl)
        started = time.monotonic()
        try:
            body = None if payload is None else json.dumps(payload,separators=(',',':')).encode()
            if body is not None and len(body)>65536:
                raise SupportError('request_bound')
            connection.connect()
            if time.monotonic()-started >= 10:
                raise SupportError('https_timeout')
            connection.request('GET' if action == 'policy' else 'POST',PREFIX+action,body=body,
                headers={'Authorization':'Bearer '+token,'Content-Type':'application/json','Accept':'application/json'})
            response = connection.getresponse()
            if response.status not in ((204,) if action=='unregister' else (200,201)):
                raise SupportError('https_rejected')
            date = parsedate_to_datetime(response.getheader('Date',''))
            if date.tzinfo is None:
                raise SupportError('missing_server_time')
            data = bytearray()
            while True:
                if time.monotonic()-started >= 12:
                    raise SupportError('https_timeout')
                chunk = response.read1(4096)
                if not chunk:
                    break
                data.extend(chunk)
                if len(data)>65536:
                    raise SupportError('response_bound')
            # Conservatively consume transit time and Date's one-second precision.
            server_time = date.timestamp()+math.ceil(time.monotonic()-started)+1
            return (None if action=='unregister' else json.loads(data),server_time)
        except Exception:
            raise SupportError('https_unavailable') from None
        finally:
            connection.close()


class PolicyWorker:
    """At most one request/result, no durable secret queue or blocking shutdown."""
    def __init__(self, request):
        self.request = request
        self.results = queue.Queue(maxsize=1)
        self.thread = None
        self.closed = False

    def submit(self,payload):
        if self.closed or self.thread is not None:
            return False
        def perform():
            try:
                value = ('ok',self.request(payload))
            except Exception:
                value = ('error','https_unavailable')
            if not self.closed:
                self.results.put_nowait(value)
        self.thread = threading.Thread(target=perform,daemon=True,name='support-https')
        self.thread.start()
        return True

    def result(self):
        try:
            value = self.results.get_nowait()
            self.thread = None
            return value
        except queue.Empty:
            return None

    def close(self):
        self.closed = True


def bounded_request(request):
    worker = PolicyWorker(lambda _:request())
    try:
        worker.submit(None)
        limit=time.monotonic()+15
        while time.monotonic()<limit:
            result=worker.result()
            if result is not None:
                if result[0]!='ok':
                    raise SupportError('https_unavailable')
                return result[1]
            time.sleep(.05)
        raise SupportError('https_timeout')
    finally:
        worker.close()


def validate_config(raw):
    try:
        if set(raw) != {'device_id','credential_id','support_token','origin','environment'}:
            raise ValueError
        for field in ('device_id','credential_id'):
            if str(UUID(raw[field])) != raw[field]:
                raise ValueError
        if not re.fullmatch(r'eps1[._-][A-Za-z0-9_.-]{32,2048}',raw['support_token']):
            raise ValueError
        expected = 'https://endpoint.sosnadmin.local' if raw['environment']=='production' else 'https://endpoint-staging.sosnadmin.local'
        if raw['environment'] not in ('production','staging') or raw['origin'] != expected:
            raise ValueError
        return raw
    except Exception:
        raise SupportError('invalid_config') from None


def install_from_enrollment(*, device_id, credential_reader, endpoint_origin, ca_bytes,
                            environment=None, paths=SupportPaths(), register_retained=False):
    """Called under coordinator ownership, with Support service stopped.

    credential_reader is invoked ONCE only when registration is needed; returns
    the canonical retained device bearer in memory. No Core imports/credential
    path inference. Does not install RPMs, systemd units or start services.
    Retained credentials/keys are never automatically rotated or unregistered.
    """
    from pc_agent.platform.linux.enrollment_origin import configured_endpoint_origin
    try:
        if endpoint_origin != configured_endpoint_origin(environment):
            raise SupportError('invalid_origin')
        if str(UUID(device_id)) != device_id or not isinstance(ca_bytes,bytes) or not 1 <= len(ca_bytes)<=65536:
            raise SupportError('invalid_bootstrap')
        store = PrivateStore(paths)
        store.prepare()
        with store.locked():
            existing = store.json('config.json',missing=True)
            if existing is not None:
                existing = validate_config(existing)
                if existing['device_id'] != device_id or existing['origin'] != endpoint_origin or store.read('ca.crt') != ca_bytes:
                    raise SupportError('bootstrap_conflict')
                store.keys()
                if not register_retained:
                    return {'installed':True,'component_version':COMPONENT_VERSION}
            old_ca = store.read('ca.crt',missing=True)
            if old_ca is not None and old_ca != ca_bytes:
                raise SupportError('bootstrap_conflict')
            store.write('ca.crt',ca_bytes)
            client = SupportHTTPS(endpoint_origin,paths.private/'ca.crt')
            host,tunnel = store.keys(create=True)
            credential = credential_reader()
            response,_ = bounded_request(lambda: client.request('register',credential,
                dict(platform='linux_amd64',component_version=COMPONENT_VERSION,
                     host_public_key=host,tunnel_public_key=tunnel)))
            config = validate_config(dict(device_id=response['device_id'],credential_id=response['credential_id'],
                support_token=response['support_token'],origin=endpoint_origin,
                environment='production' if endpoint_origin=='https://endpoint.sosnadmin.local' else 'staging'))
            if config['device_id'] != device_id:
                raise SupportError('registration_identity_mismatch')
            # Registration never opens SSH. Fresh healthy running status owns grant.
            store.save('config.json',config)
            return {'installed':True,'component_version':COMPONENT_VERSION}
    except SupportError:
        raise
    except Exception:
        raise SupportError('bootstrap_pending') from None


def uninstall(*, paths=SupportPaths()):
    """Bounded notification AFTER coordinator stops own service; retain identity.

    Return pending on HTTPS/ownership failure. Never remove keys/config, claim
    native success, replay RPM or touch Core/global SSH. Task4 owns event order.
    """
    worker = None
    try:
        store = PrivateStore(paths)
        with store.locked():
            NativeChildren(store).stop()
            config = validate_config(store.json('config.json'))
            store.read('ca.crt')
            client = SupportHTTPS(config['origin'],paths.private/'ca.crt')
            worker = PolicyWorker(lambda _: client.request('unregister',config['support_token']))
            worker.submit(None)
            limit = time.monotonic()+15
            while time.monotonic()<limit:
                result = worker.result()
                if result is not None:
                    return {'unregistered':result[0]=='ok','pending':result[0]!='ok'}
                time.sleep(.05)
    except Exception:
        pass
    finally:
        if worker:
            worker.close()
    return {'unregistered':False,'pending':True}


def finalize_removal(*, known_native_exit_code, paths=SupportPaths()):
    """Erase ONLY owned Support secrets after coordinator-observed native0.

    Caller MUST have stopped/disabled the Support parent and own the native
    operation. Package code/unit removal and canonical identity/outbox are the
    coordinator's separate responsibility. Unregister uncertainty stays visible.
    Never call this for upgrades, retries or unknown native outcomes.
    """
    if type(known_native_exit_code) is not int or known_native_exit_code != 0:
        raise SupportError('native_removal_unconfirmed')
    import subprocess
    from pc_agent.platform.linux.support_access import SERVICE_NAME
    from pc_agent.platform.linux.support_access_native import remove_owned_state
    result = subprocess.run(['/usr/bin/systemctl','show','--property=ActiveState','--value',SERVICE_NAME],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=3)
    if result.returncode != 0 or result.stdout.strip() not in (b'inactive',b'failed'):
        raise SupportError('support_parent_not_stopped')
    notification = uninstall(paths=paths)
    store = PrivateStore(paths)
    with store.locked():
        NativeChildren(store).stop()
        remove_owned_state(store)
    return notification | {'private_state_removed':True}


def run_service(*, paths=SupportPaths(), stop_event=None):
    """Independent root service. API failure closes access within60sec.

    Hard systemd child expiry also survives service death, stopped Core/updater,
    blocked HTTP, detached process sessions, and ordinary service restarts.
    """
    stop_event = stop_event or threading.Event()
    store = PrivateStore(paths)
    try:
        with store.locked():
            _run_service_locked(store,paths,stop_event)
    except Exception:
        raise SupportError('service_unavailable') from None


def _run_service_locked(store,paths,stop_event):
    worker = None
    children = NativeChildren(store)
    try:
        children.stop()  # Never inherit children or cached effective authority.
        config = validate_config(store.json('config.json'))
        store.read('ca.crt')
        client = SupportHTTPS(config['origin'],paths.private/'ca.crt')
        host,tunnel = store.keys()
        raw_state = store.json('lease.json',missing=True)
        state = LeaseState() if raw_state is None else LeaseState.from_json(raw_state)
        worker = PolicyWorker(lambda body: client.request('status',config['support_token'],body))
        gate = LeaseGate(children.stop)
        next_poll = 0
        current = None
        error = None
        while not stop_event.is_set():
            now = boot_time()
            gate.tick(now)
            result = worker.result()
            if result is not None:
                if result[0] == 'ok':
                    try:
                        raw,server = result[1]
                        policy = SupportPolicy.parse(raw,device_id=config['device_id'],origin=config['origin'],host_key=host,tunnel_key=tunnel)
                        deadline = state.accept(policy,wall=time.time(),server=server,boot=boot_time(),boot_id=boot_id())
                        store.save('lease.json',state.to_json())
                        if not policy.enabled:
                            children.stop()
                            gate.deadline = 0
                        else:
                            validate_account(policy.username,policy.uid)
                            if current != policy or not children.alive():
                                children.stop()
                                children.start(policy,deadline)
                            gate.arm(absolute_deadline=deadline,boot=boot_time())
                        current,error = policy,None
                    except Exception as failure:
                        children.stop()
                        gate.deadline = 0
                        error = _public_status_error(failure)
                else:
                    error = _public_status_error(result[1])
            if now >= next_poll:
                # Positive only after remote forwarding acknowledgement on the
                # same root-owned master/socket, never administrator attestation.
                if worker.submit(dict(platform='linux_amd64',component_version=COMPONENT_VERSION,
                    installed=True,tunnel_connected=children.connected(),last_error_code=error)):
                    next_poll = now+30
            stop_event.wait(.2)
    finally:
        if worker:
            worker.close()
        children.stop()


def main():
    import sys
    if sys.argv[1:] == ['--version']:
        print(COMPONENT_VERSION)
        return 0
    if sys.argv[1:] != ['run']:
        return 2
    stop = threading.Event()
    for sig in (signal.SIGTERM,signal.SIGINT):
        signal.signal(sig,lambda *_:stop.set())
    try:
        run_service(stop_event=stop)
        return 0
    except Exception:
        print('support_service_unavailable',file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
