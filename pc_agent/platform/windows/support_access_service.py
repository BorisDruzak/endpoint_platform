"""Frozen SCM entrypoint, independent of Agent/Core/observer/update runtime."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from queue import Empty, Queue
from threading import Event, Thread
import time
import sys

from pc_agent.platform.windows.support_access import SERVICE_NAME, SupportHTTPClient, SupportHTTPError, SupportSupervisor, install_support_access, uninstall_support_access
from pc_agent.platform.windows.support_access_native import SupportChildren, assert_private, assert_bootstrap_file, production_roots, verify_dependencies


def run_supervisor(device_id, client, children, stop: Event, *, publish=lambda state: None):
    """Keep the lease cutoff responsive while DNS/TLS/policy requests block."""
    supervisor = SupportSupervisor(device_id,children)
    incoming = Queue(maxsize=8)

    def policy_worker():
        while not stop.is_set():
            delay = 10
            try:
                policy = client.policy()
                incoming.put(('policy',policy))
                delay = max(5,min(30,policy.get('poll_after_seconds',30)))
                connected = supervisor.state == 'tunnel_connected'
                error = {'process_failed':'tunnel_failed','invalid_policy':'configuration_conflict',
                         'expired':'policy_unavailable'}.get(supervisor.state)
                policy = client.status(connected=connected,error=error)
                incoming.put(('policy',policy))
            except SupportHTTPError as error:
                if error.status in {401,403,404,410}:
                    incoming.put(('revoked',None))
            except Exception:
                # Never log raw exceptions, HTTP bodies, tokens or machine data.
                pass
            stop.wait(delay)

    worker = Thread(target=policy_worker,name='support-policy',daemon=True)
    worker.start()
    previous = None
    try:
        while not stop.is_set():
            try:
                kind, value = incoming.get(timeout=.25)
            except Empty:
                pass
            else:
                if kind == 'revoked':
                    supervisor.stop('revoked')
                else:
                    try:
                        supervisor.accept(value,now=datetime.now(timezone.utc),monotonic_now=time.monotonic())
                    except ValueError:
                        pass
            supervisor.tick(monotonic_now=time.monotonic())
            if previous != supervisor.state:
                previous = supervisor.state
                publish(previous)
    finally:
        supervisor.stop()
        stop.set()
        worker.join(timeout=1)


def load_service(root: Path):
    assert_private(root)
    for name in ('support.json','credential','ca.pem'):
        assert_private(root/name)
    if (root/'support.json').stat().st_size>16384 or (root/'credential').stat().st_size>128 or (root/'ca.pem').stat().st_size>65536:
        raise ValueError('invalid_support_configuration')
    config = json.loads((root/'support.json').read_text(encoding='utf-8'))
    verify_dependencies(config['dependencies'])
    client = SupportHTTPClient(config['origin'],root/'ca.pem',(root/'credential').read_text().strip())
    return config['device_id'],client,SupportChildren(root,config['dependencies'])


def install_from_enrollment():
    # Installer path only. Service startup never reads Agent files or credential.
    from pc_agent.device_credential import read_device_credential
    from pc_agent.enrollment_identity import read_enrollment_device_id
    root,program = production_roots()
    agent = root.parent/'Agent'
    for name in ('device-credential','endpoint-origin','endpoint-ca.crt','enrollment-identity.json'):
        assert_bootstrap_file(agent/name)
    return install_support_access(agent,program.parent/'Agent',
        origin=(agent/'endpoint-origin').read_text(encoding='ascii').strip(),
        ca_pem=(agent/'endpoint-ca.crt').read_text(encoding='ascii'),
        device_id=str(read_enrollment_device_id(agent/'enrollment-identity.json')),
        device_token=read_device_credential(agent/'device-credential'),
        service_executable=Path(sys.executable))


def main():
    if sys.argv[1:] == ['--install']:
        try:
            result = install_from_enrollment()
        except Exception as error:
            known = {'support_dependency_install_failed','support_dependency_reboot_required',
                     'support_process_identity_unavailable','support_process_exit_timeout',
                     'support_dependency_firewall_conflict',
                     'support_dependency_signature_invalid','support_dependency_changed',
                     'support_identity_conflict','support_key_role_conflict','support_key_generation_failed',
                     'support_key_read_failed','support_enrollment_unavailable','unsafe_support_acl'}
            code = str(error) if str(error) in known else 'support_install_failed'
            print(json.dumps({'installed':False,'error':code}))
            return 1
        print(json.dumps(result))
        return 0
    if sys.argv[1:] == ['--uninstall']:
        try:
            result = uninstall_support_access()
        except Exception:
            print(json.dumps({'installed':True,'error':'support_remove_failed'}))
            return 1
        print(json.dumps(result))
        return 0
    if sys.argv[1:]:
        return 2
    import servicemanager
    import win32service
    import win32serviceutil

    class SupportWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = 'Endpoint Support Access'
        _svc_description_ = 'Independent policy-bound outbound support access'

        def __init__(self,args):
            super().__init__(args)
            self.stop_event = Event()

        def SvcDoRun(self):
            root,_ = production_roots()
            try:
                device,client,children = load_service(root)
            except Exception:
                servicemanager.LogInfoMsg('EndpointSupportAccess: configuration_unavailable; disabled')
                self.stop_event.wait()
                return
            run_supervisor(device,client,children,self.stop_event,
                publish=lambda state:servicemanager.LogInfoMsg('EndpointSupportAccess: '+state))

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.stop_event.set()

        def SvcShutdown(self):
            self.SvcStop()

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(SupportWindowsService)
    servicemanager.StartServiceCtrlDispatcher()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
