import json,subprocess,os
from pathlib import Path
import pytest

pytestmark=pytest.mark.skipif(os.name!='nt',reason='Windows PowerShell/OpenSSH operator tool')

ROOT=Path(__file__).resolve().parents[2]
SCRIPT=ROOT/'tools/support/Connect-EndpointSupport.ps1'
DEVICE='943c87ef-f121-40b9-a31f-003e9459e292'
KEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIgFQz1c8VYxtONq+OBXahV6OD7ZCdk1dpomZu1EoUjA'

def invoke(tmp_path,*extra):
 params={'-DeviceId':DEVICE,'-RemotePort':'32000','-WindowsAdminUsername':r'SOSNADM\admin-2','-HostPublicKey':KEY,'-KnownHostsDirectory':str(tmp_path/'pins with spaces')}
 assert len(extra)%2==0
 params.update(zip(extra[::2],extra[1::2]))
 args=[item for pair in params.items() for item in pair]
 return subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(SCRIPT),*args,'-InspectOnly'],capture_output=True,text=True)

def test_inspection_builds_strict_uuid_bound_connection_without_network_or_writes(tmp_path):
 r=invoke(tmp_path);assert r.returncode==0,r.stderr
 p=json.loads(r.stdout);a=p['arguments']
 assert p['device_id']==DEVICE and p['windows_admin_username']==r'sosnadm\admin-2'
 assert 'StrictHostKeyChecking=yes' in a and 'HostKeyAlias=endpoint-device-'+DEVICE in a
 assert '-F' in a and 'NUL' in a and 'ForwardAgent=no' in a and 'PermitLocalCommand=no' in a
 proxy=next(x for x in a if x.startswith('ProxyCommand='));assert 'StrictHostKeyChecking=yes' in proxy and 'endpoint-platform-server' in proxy
 assert p['host_pin_line']=='endpoint-device-'+DEVICE+' '+KEY
 assert not (tmp_path/'pins with spaces').exists()

@pytest.mark.parametrize('name,value',[('-GatewayAlias','bad;whoami'),('-WindowsAdminUsername','admin*'),('-HostPublicKey',KEY+'\nssh-ed25519 bad'),('-RemotePort','31999')])
def test_connection_rejects_unbounded_inputs_before_writes(tmp_path,name,value):
 r=invoke(tmp_path,name,value);assert r.returncode!=0
 assert not (tmp_path/'pins with spaces').exists()

def test_existing_mismatched_device_pin_is_preserved_and_rejected(tmp_path):
 d=tmp_path/'pins with spaces';d.mkdir();p=d/('endpoint-device-'+DEVICE+'.known_hosts');p.write_text('endpoint-device-'+DEVICE+' ssh-ed25519 different\n')
 r=invoke(tmp_path);assert r.returncode!=0 and 'changed' in r.stderr.lower()
 assert p.read_text().endswith(' different\n')

def test_existing_matching_pin_is_accepted_without_modification(tmp_path):
 d=tmp_path/'pins with spaces';d.mkdir();p=d/('endpoint-device-'+DEVICE+'.known_hosts');raw='endpoint-device-'+DEVICE+' '+KEY+'\n';p.write_text(raw)
 r=invoke(tmp_path);assert r.returncode==0,r.stderr;assert p.read_text()==raw
