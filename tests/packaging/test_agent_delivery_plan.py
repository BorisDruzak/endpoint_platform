import json
from pathlib import Path
import subprocess
import sys

import pytest


CLI = Path(__file__).resolve().parents[2] / 'tools/release/release_plan.py'


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()


def write(root, name, content):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')


def commit(root):
    git(root, 'add', '.')
    git(root, 'commit', '-m', 'test: release path')
    return git(root, 'rev-parse', 'HEAD')


@pytest.fixture
def source(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    git(root, 'init', '-q')
    git(root, 'config', 'user.email', 'fixture@example.test')
    git(root, 'config', 'user.name', 'Fixture')
    for name, entry in (
        ('pyinstaller_endpoint_core_windows.spec', 'runtime/main.py'),
        ('pyinstaller_endpoint_core_linux.spec', 'runtime/main.py'),
        ('pyinstaller_launcher_win.spec', 'launcher/launcher_main.py'),
        ('pyinstaller_launcher_linux.spec', 'launcher/launcher_main.py'),
    ):
        write(root, 'pc_agent/' + name, 'a = Analysis([str(pc_agent_root / ' + repr(entry) +
              ')], hiddenimports=[], runtime_hooks=[], excludes=[])\n')
    write(root, 'pc_agent/runtime/main.py', 'from pc_agent.runtime.reconnect import run\n')
    write(root, 'pc_agent/runtime/reconnect.py', 'from pc_agent.logic.backoff import delay\n')
    write(root, 'pc_agent/launcher/launcher_main.py', 'from pc_agent.logic.native import guard\n')
    write(root, 'pc_agent/logic/native.py', 'from pc_agent.logic.codec import decode\n')
    write(root, 'pc_agent/logic/codec.py', 'from pc_agent.logic.shared import marker\n')
    write(root, 'pc_agent/runtime/liveness.py', 'from pc_agent.logic.shared import marker\n')
    write(root, 'pc_agent/logic/shared.py', 'marker = 1\n')
    write(root, 'pc_agent/logic/backoff.py', 'delay = 1\n')
    write(root, 'pc_agent/version.py', 'AGENT_VERSION = "3.2.205"\nEXIT_UPDATE_PENDING = 42\n')
    return root, commit(root)


def plan(source, head, platform='windows', *args):
    root, base = source
    result = subprocess.run([sys.executable, str(CLI), '--repo-root', str(root), '--base', base,
                             '--target', head, '--platform', platform, *args], capture_output=True, text=True,
                            encoding='utf-8', timeout=25)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_transitive_runtime_change_can_use_core_with_bound_floor(source, tmp_path):
    root, base = source
    write(root, 'pc_agent/logic/backoff.py', 'delay = 2\n')
    write(root, 'pc_agent/version.py', 'AGENT_VERSION = "3.2.276"\nEXIT_UPDATE_PENDING = 42\n')
    head = commit(root)
    contract = tmp_path / 'endpoint-runtime-contract.json'
    contract.write_text(json.dumps({'schema_version': 1, 'version': '3.2.276', 'source_revision': head,
                                    'minimum_launcher_version': '3.2.205'}), encoding='utf-8')
    options = ('--runtime-contract', str(contract), '--observed-launcher')
    ready = plan(source, head, 'windows', *options, '3.2.205')
    assert ready['artifacts'] == ['windows_core_zip']
    assert ready['state'] == 'planned'
    assert ready['core_compatibility']['minimum_launcher_version'] == '3.2.205'
    assert ready['source_revision'] == head and ready['baseline_revision'] == base
    blocked = plan(source, head, 'windows', *options, '3.2.204')
    assert blocked['state'] == 'hold'
    assert blocked['core_compatibility']['status'] == 'below_minimum'


def test_shared_transitive_native_dependency_prevents_core_only(source):
    root, _ = source
    write(root, 'pc_agent/runtime/main.py', 'from pc_agent.runtime.liveness import alive\n')
    write(root, 'pc_agent/logic/shared.py', 'marker = 4\n')
    head = commit(root)
    windows = plan(source, head)
    alt = plan(source, head, 'alt')
    assert windows['artifacts'] == ['windows_full_setup']
    assert alt['artifacts'] == ['alt_native_rpm']
    assert windows['artifact_reasons'] == {'windows_full_setup': ['windows_foundation']}
    assert {'windows_core', 'windows_foundation'} <= set(windows['changed_components'])
    assert {'alt_core', 'alt_native'} <= set(alt['changed_components'])


def test_provider_change_reports_contracts_and_migration_without_agent_build(source):
    root, _ = source
    write(root, 'endpoint_server/gateway/ws_routes.py', 'SCHEMA = 2\n')
    write(root, 'endpoint_server/db/migrations/versions/0057_sample.py', 'revision: str = "0057_sample"\n')
    write(root, 'contracts/openapi/endpoint-platform-v1.yaml', 'openapi: 3.1.0\n')
    write(root, 'pc_agent/AGENTS.md', 'Agent development guidance.\n')
    result = plan(source, commit(root), 'alt')
    assert result['state'] == 'planned'
    assert result['unclassified'] == []
    assert result['artifacts'] == ['provider']
    assert result['provider_migrations'] == ['0057_sample']
    assert result['changed_contracts'] == ['contracts/openapi/endpoint-platform-v1.yaml']


def test_unknown_dependency_does_not_default_to_core(source):
    root, _ = source
    write(root, 'pc_agent/logic/unclassified.py', 'release_switch = 1\n')
    result = plan(source, commit(root))
    assert result['state'] == 'hold'
    assert result['unclassified'] == ['pc_agent/logic/unclassified.py']


def test_standalone_lab_tooling_stays_out_of_agent_release(source):
    root, _ = source
    tools = ('install_alt_factory_offline.py', 'observe_alt_factory_offline.py', 'run_alt_factory_offline.py',
             'staged_windows_update.py')
    for path in tools:
        write(root, 'tools/canary/' + path, 'lab_only = True\n')
    baseline = commit(root)
    for platform in ('windows', 'alt'):
        result = plan(source, baseline, platform)
        assert result['state'] == 'planned'
        assert result['unclassified'] == []
        assert result['artifacts'] == []

    path = 'tools/canary/run_alt_factory_offline.py'
    write(root, path, 'lab_only = False\n')
    write(root, 'pc_agent/launcher/launcher_main.py', 'from tools.canary.run_alt_factory_offline import lab_only\n')
    result = plan((root, baseline), commit(root), 'alt')
    assert result['artifacts'] == ['alt_native_rpm']
    assert path in result['changed_components']['alt_native']


def test_alt_core_floor_is_checked_against_bound_build_receipt(source, tmp_path):
    root, base = source
    write(root, 'pc_agent/logic/backoff.py', 'delay = 2\n')
    head = commit(root)
    receipt = {
        'source_revision': head,
        'build': {
            'schema_version': 'update_build_manifest_v1', 'platform': 'linux_amd64',
            'archive_type': 'tar.gz', 'version': '3.2.205', 'minimum_launcher_version': '3.2.183',
        },
    }
    contract = tmp_path / 'receipt.json'
    contract.write_text(json.dumps(receipt), encoding='utf-8')
    options = ('--runtime-contract', str(contract))
    waiting = plan(source, head, 'alt', *options)
    assert waiting['core_compatibility']['status'] == 'current_launcher_unknown'
    assert waiting['state'] == 'hold'
    ready = plan(source, head, 'alt', *options, '--observed-launcher', '3.2.183')
    assert ready['artifacts'] == ['alt_core_ota']
    assert ready['state'] == 'planned'
    receipt['source_revision'] = base
    contract.write_text(json.dumps(receipt), encoding='utf-8')
    rejected = subprocess.run([sys.executable, str(CLI), '--repo-root', str(root), '--base', base,
                               '--target', head, '--platform', 'alt', *options], check=False,
                              capture_output=True, text=True, encoding='utf-8', timeout=25)
    assert rejected.returncode == 1
    assert 'must bind the target version, Git SHA and launcher minimum' in rejected.stderr


def test_hidden_import_and_browser_package_have_distinct_owners(source):
    root, _ = source
    write(root, 'pc_agent/pyinstaller_launcher_win.spec',
          'native_modules = ["pc_agent.logic.native_adapter"]\n'
          'a = Analysis([str(pc_agent_root / "launcher/launcher_main.py")], hiddenimports=native_modules)\n')
    write(root, 'pc_agent/logic/native_adapter.py', 'value = 1\n')
    baseline = commit(root)
    write(root, 'pc_agent/logic/native_adapter.py', 'value = 2\n')
    write(root, 'browser_sensor/extension/manifest.json', '{}\n')
    target = commit(root)
    windows = plan((root, baseline), target)
    alt = plan((root, baseline), target, 'alt')
    assert windows['artifacts'] == ['browser_sensor', 'windows_full_setup']
    assert windows['changed_components']['windows_foundation'] == ['pc_agent/logic/native_adapter.py']
    assert alt['artifacts'] == ['browser_sensor']


def test_linux_archive_builder_is_shared_with_alt_rpm(source):
    root, _ = source
    write(root, 'tools/build_linux_agent.py', 'archive_format = 2\n')
    target = commit(root)
    alt = plan(source, target, 'alt')
    assert alt['artifacts'] == ['alt_native_rpm']
    assert set(alt['changed_components']) == {'alt_core', 'alt_native'}
    assert alt['unclassified'] == []
    assert plan(source, target)['artifacts'] == []
