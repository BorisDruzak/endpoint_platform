"""Bounded successor approval; retained history remains its original authority."""
import hashlib
import json
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import installation_provenance as provenance, runtime_identity
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

MSI79 = '2f7d778799f1e32645af7936dfaf3f090d6ad4df5bb883827ea8a0a5d859f72a'
MSI81 = 'ad4dc49703513d6dee6fd3e51ac94a09c5967112d58aed4e60a63cf6966251f5'
SOURCE79 = 'd9b0fea2b14e34b05e25058e4ee004ea61643ca6'


def test_foundation158_approves_only_exact79_without_rewriting_historical_contract():
    historical = json.dumps(runtime_identity._LEGACY_MSI_CONTRACTS,sort_keys=True)
    assert runtime_identity.legacy_foundation_compatible(MSI79,'3.2.158')
    for foundation in ('3.2.157','3.2.159','3.2.158.0','03.2.158','4.0.0'):
        assert not runtime_identity.legacy_foundation_compatible(MSI79,foundation)
    for media in (MSI81,'0'*64,MSI79.upper(),MSI79[:-1]+'b'):
        assert not runtime_identity.legacy_foundation_compatible(media,'3.2.158')
    assert runtime_identity._LEGACY_MSI_CONTRACTS[MSI79] == {
        'version':'3.2.79','source_revision':SOURCE79,'file_count':2543,
        'tree_sha256':'06200efd1ee8b2914828e71eef65db8e6dd803318b44047672b8b9dc40c950c4',
        'component_guid':'F15DDAF9-80BC-4944-921C-D2561CE923F9','approved_foundations':('3.2.82',)}
    assert json.dumps(runtime_identity._LEGACY_MSI_CONTRACTS,sort_keys=True) == historical


@pytest.mark.parametrize('foundation,media,accepted',[
    ('3.2.158',MSI79,True),('3.2.157',MSI79,False),('3.2.159',MSI79,False),
    ('3.2.158',MSI81,False),('3.2.158','0'*64,False),
])
def test_verified_retained_evidence_still_controls_provenance_guard(tmp_path,monkeypatch,foundation,media,accepted):
    # The archive verifier is a boundary here: its hash/tree/ACL tests live in
    # test_installation_provenance; no fake tree is blessed as genuine media.
    paths = WindowsUpdatePaths(tmp_path/'Agent',tmp_path/'data/updates/pending_update.json')
    core = paths.versions_root/'3.2.79'
    core.mkdir(parents=True)
    (core/'.endpoint-retained-msi.json').write_bytes(b'protected link fixture')
    selector = {'version':'3.2.79','schema_version':1,'source_revision':SOURCE79}
    selector_bytes = json.dumps(selector).encode()
    owner_bytes = json.dumps({'package':{'sha256':media},'compatibility_foundations':['3.2.82']}).encode()
    identity = SimpleNamespace(version='3.2.79',source_revision=SOURCE79,minimum_launcher_version=None)
    retained = SimpleNamespace(identity=identity,record={'original_manifest_bytes':b'original manifest'.hex(),
        'compatibility_foundations':['3.2.82']},link_bytes=b'original link',record_bytes=owner_bytes)
    inspected=[]
    def verify(actual,version):
        assert actual is paths and version=='3.2.79'
        inspected.append(True)
        return retained
    monkeypatch.setattr(runtime_identity,'verify_retained_runtime',verify)
    monkeypatch.setattr(provenance,'_assert_security',lambda *_:None)
    from pc_agent.platform.windows import staged_foundation_rollback
    monkeypatch.setattr(staged_foundation_rollback,'original_foundation_runtime_allowed',lambda *_:False)
    before = hashlib.sha256(selector_bytes+owner_bytes+retained.link_bytes).hexdigest()
    if accepted:
        evidence = provenance._inspect_core_value(paths,selector_bytes,selector,foundation)
        assert evidence.identity is identity
        assert evidence.compatibility_foundations == ('3.2.82',)
        assert evidence.selector_bytes == selector_bytes and evidence.owner_bytes == owner_bytes
    else:
        with pytest.raises(provenance.ProvenanceConflict):
            provenance._inspect_core_value(paths,selector_bytes,selector,foundation)
    assert inspected == [True]
    assert hashlib.sha256(selector_bytes+owner_bytes+retained.link_bytes).hexdigest() == before


def test_new_optional_companion_tolerates_pre_capability_core_ack(tmp_path):
    from pc_agent.platform.worktime_user import UserCompanion
    events=[]
    companion=UserCompanion(lambda _:b'{"schema_version":"browser_bridge_ack_v1","accepted":false,"error_code":"INVALID_PAYLOAD"}',
        lambda:events.append('notice'),state_path=tmp_path/'receipt',open_url=lambda _:events.append('browser'))
    # Real optional worker containment, including release for subsequent samples.
    for _ in range(2):
        assert companion._lock.acquire(blocking=False)
        companion._run()
        assert not companion._lock.locked()
    assert not events and not companion.state_path.exists()


def test_foundation158_launcher_command_parses_with_immutable79_cli(tmp_path,monkeypatch):
    from pc_agent.platform.windows import service_launcher
    from pc_agent.tests.windows.fixtures.core_3_2_79_parser import _parser
    paths = WindowsUpdatePaths(tmp_path/'Agent',tmp_path/'data/updates/pending_update.json')
    core = paths.versions_root/'3.2.79'/'pc_agent.exe'
    core.parent.mkdir(parents=True)
    core.write_bytes(b'CLI-only fixture, never executed')
    paths.current_path.write_text(json.dumps({'version':'3.2.79'}))
    monkeypatch.setattr(service_launcher,'AGENT_VERSION','3.2.158')
    # Ownership and full-byte verifier paths are separately tested above and in
    # test_installation_provenance; this exercises the actual launcher CLI ABI.
    monkeypatch.setattr(service_launcher,'_verify_selected_runtime',lambda *_:None)
    command = service_launcher.build_agent_child_command(paths)
    arguments = _parser().parse_args(command[1:])
    assert command[0] == str(core) and '--launcher-version' not in command
    assert arguments.windows_service_child and arguments.transport_mode=='gateway_wss'
    assert arguments.migration_http_pull_fallback is False
    assert arguments.data_dir == str(paths.pending_path.parents[1])
    assert arguments.ca_file == str(paths.pending_path.parents[1]/'endpoint-ca.crt')
