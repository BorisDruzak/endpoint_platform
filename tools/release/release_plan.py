"""Plan agent and service delivery from the inputs of the existing builders."""

from argparse import ArgumentParser
import ast
from collections import defaultdict
from io import BytesIO
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile


SPEC_GROUPS = {
    'windows_core': ('endpoint_core_windows',),
    'windows_foundation': ('launcher_win', 'windows_service_launcher', 'windows_installer_host',
                           'windows_provision', 'windows_updater', 'windows_setup', 'windows_tray',
                           'windows_user_sensor', 'windows_browser_bridge', 'windows_browser_policy_service'),
    'windows_support': ('windows_support_access',),
    'alt_core': ('endpoint_core_linux',),
    'alt_native': ('launcher_linux', 'linux_setup'),
    'alt_support': ('linux_support_access',),
}
DEB_PLATFORMS = ('ubuntu', 'debian')
DEB_DELIVERY_COMPONENTS = ('deb_core', 'deb_package', 'apt_repository')
PACKAGED_INPUTS = {
    'windows_foundation': ('packaging/windows/', 'requirements/build-windows.txt', 'requirements/agent-core.txt'),
    'windows_observer': ('packaging/windows/EndpointSetupUpdater.ps1', 'tools/canary/setup_client_payload.py'),
    'windows_support': ('packaging/windows/support-openssh/',),
    'windows_core': ('packaging/windows/build-update-zip.ps1',),
    'alt_core': ('tools/build_linux_agent.py',),
    'alt_native': ('packaging/alt/', 'deploy/agent/alt/', 'pc_agent/platform/linux/kde_probe/',
                   'pc_agent/platform/linux/browser_policy.py', 'pc_agent/platform/linux/seqpacket.py',
                   'pc_agent/platform/linux/browser_policy_helper.py', 'pc_agent/browser_policy_protocol.py',
                   'tools/build_linux_native_manifest.py', 'tools/build_linux_native_payload.py',
                   'tools/build_linux_agent.py', 'tools/build_alt_native_kit.py', 'tools/build_alt_pilot_kit.py',
                   'tools/release/freeze_linux_native_identity.py', 'tools/release/linux_native_verifier.py',
                   'requirements/build-linux.txt', 'requirements/agent-core.txt', 'browser_sensor/extension-id.txt'),
    'deb_core': ('requirements/build-linux.txt', 'requirements/agent-core.txt'),
    'deb_package': ('packaging/ubuntu/', 'tools/build_ubuntu_agent_deb.py'),
    'debian_package': ('packaging/debian/',),
    'apt_repository': ('tools/release/build_ubuntu_apt_repository.py', 'tools/release/check_endpoint_apt_expiry.sh',
                       'tools/release/prepare_endpoint_apt_windows.ps1', 'tools/release/prepare_external_apt_renewal.py',
                       'tools/release/sign_endpoint_apt_release.ps1', 'deploy/server/endpoint-apt-expiry.service',
                       'deploy/server/endpoint-apt-expiry.timer', 'deploy/server/endpoint-apt-expiry.zabbix.yaml',
                       'deploy/server/endpoint-apt-prepare-renewal@.service',
                       'deploy/server/endpoint-apt-prepare-renewal@.timer'),
    'python_sdk': ('sdk/python/',),
    'browser_sensor': ('browser_sensor/', 'tools/register_browser_sensor_release.py', 'requirements/browser-sensor-release.txt'),
    'provider': ('endpoint_server/', 'deploy/server/', 'webapp/', 'alembic.ini', 'endpoint_contracts/', 'contracts/'),
}
REVIEW_ONLY = ('docs/', 'tests/', 'pc_agent/docs/', 'pc_agent/tests/', 'tools/release/', 'tools/contracts/',
               'tools/keycloak/', 'tools/provision_ubuntu_server_pilot.py', 'tools/provision_ubuntu_server_pilot.sh',
               'tools/ubuntu_console_enrollment.py', 'tools/register_windows_setup_release.py', '.github/', 'PLANS.md', 'AGENTS.md', 'README.md',
               'pc_agent/AGENTS.md', 'pytest.ini', 'requirements-ci.txt',
               'tools/canary/install_alt_factory_offline.py', 'tools/canary/observe_alt_factory_offline.py',
               'tools/canary/run_alt_factory_offline.py', 'tools/canary/staged_windows_update.py')
WINDOWS_PACKAGING_DOCS = ('packaging/windows/README.md', 'packaging/windows/support-openssh/QUALIFICATION.md')
REVISION = re.compile(r'[0-9a-f]{40}')
VERSION = re.compile(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)')
VERSION_FILE = 'pc_agent/version.py'


def _git(root, *args):
    return subprocess.check_output(['git', '--no-replace-objects', '-C', str(root), *args], timeout=60)


def _revision(root, value):
    result = _git(root, 'rev-parse', '--verify', '--end-of-options', value + '^{commit}').decode().strip()
    if not REVISION.fullmatch(result):
        raise ValueError('A Git commit with a 40-character SHA is required')
    return result


def _sources(root, revision):
    archive = BytesIO(_git(root, 'archive', '--format=tar', revision))
    sources = {}
    with tarfile.open(fileobj=archive, mode='r:') as files:
        for file in files:
            if (file.isfile() and file.name.endswith(('.py', '.spec'))
                    and file.name.startswith(('pc_agent/', 'endpoint_contracts/', 'tools/', 'shared/', 'endpoint_server/'))
                    and not file.name.startswith(('pc_agent/tests/', 'pc_agent/docs/'))):
                with files.extractfile(file) as source:
                    sources[file.name] = source.read()
    return sources


def _imports(tree, package):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (item.name for item in node.names)
        if isinstance(node, ast.ImportFrom):
            if node.level:
                parts = package.split('.') if package else []
                if node.level > len(parts):
                    continue
                parent = '.'.join(parts[:len(parts) - node.level + 1])
                module = '.'.join(part for part in (parent, node.module) if part)
            else:
                module = node.module
            if module:
                yield module
                yield from (f'{module}.{item.name}' for item in node.names if item.name != '*')
        if isinstance(node, ast.Call) and node.args:
            function = getattr(node.func, 'id', None) or getattr(node.func, 'attr', None)
            if function in ('__import__', 'import_module') and isinstance(node.args[0], ast.Constant):
                name = node.args[0].value
                if isinstance(name, str) and not name.startswith('.'):
                    yield name


def _spec_path(expression):
    if isinstance(expression, ast.Name):
        return {'pc_agent_root': 'pc_agent', 'project_root': '', 'root': ''}.get(expression.id)
    if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Div):
        parent = _spec_path(expression.left)
        if parent is not None and isinstance(expression.right, ast.Constant) and isinstance(expression.right.value, str):
            return str(PurePosixPath(parent) / expression.right.value)
    return None


def _string_items(node):
    if isinstance(node, (ast.List, ast.Tuple)):
        return {item.value for item in node.elts if isinstance(item, ast.Constant) and isinstance(item.value, str)}
    return set()


def _dependencies(sources):
    modules = {}
    for path in sources:
        if path.endswith('.py'):
            module = path[:-3].removesuffix('/__init__').replace('/', '.')
            modules[module] = path
    parsed = {}
    groups = defaultdict(set)
    for component, specs in SPEC_GROUPS.items():
        for name in specs:
            path = f'pc_agent/pyinstaller_{name}.spec'
            if path not in sources:
                continue
            tree = ast.parse(sources[path], filename=path)
            direct = {label for call in ast.walk(tree) if isinstance(call, ast.Call)
                      and isinstance(call.func, ast.Name) and call.func.id == 'str' and call.args
                      for label in (_spec_path(call.args[0]),) if label}
            literals = {node.targets[0].id: node.value for node in tree.body if isinstance(node, ast.Assign)
                        and isinstance(node.targets[0], ast.Name)}
            pending = list(_imports(tree, 'pc_agent'))
            excluded = set()
            for call in ast.walk(tree):
                if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name) or call.func.id != 'Analysis':
                    continue
                for keyword in call.keywords:
                    value = keyword.value
                    if isinstance(value, ast.Name):
                        value = literals.get(value.id)
                    if keyword.arg == 'hiddenimports':
                        pending.extend(_string_items(value))
                    if keyword.arg == 'excludes':
                        excluded |= _string_items(value)
            for filename in direct:
                if filename.endswith('.py'):
                    pending.append(filename[:-3].replace('/', '.'))
            closure = groups[component]
            closure.update(direct | {path})
            seen = set()
            while pending:
                name = pending.pop()
                if name in seen or any(name == prefix or name.startswith(prefix + '.') for prefix in excluded):
                    continue
                seen.add(name)
                mod = modules.get(name)
                parent = name.rpartition('.')[0]
                if parent in modules:
                    pending.append(parent)
                if mod is None:
                    continue
                closure.add(mod)
                if mod not in parsed:
                    package = name if mod.endswith('/__init__.py') else parent
                    parsed[mod] = tuple(_imports(ast.parse(sources[mod], filename=mod), package))
                pending.extend(parsed[mod])
    return groups


def _matches(path, patterns):
    return any(path.startswith(pattern) if pattern.endswith('/') else path == pattern for pattern in patterns)


def _assignment(tree, name):
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            return node
    return None


def _version_source(source):
    tree = ast.parse(source)
    assignment = _assignment(tree, 'AGENT_VERSION')
    if assignment is None or not isinstance(assignment.value, ast.Constant):
        raise ValueError('Agent version must be a literal value in the source revision')
    version = assignment.value.value
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ValueError('Agent version must be a numeric version triplet')
    assignment.value = ast.Constant(value=None)
    return version, ast.dump(tree)


def _core_compatibility(platform, revision, version, contract, observed_launcher):
    result = {'minimum_launcher_version': None, 'observed_launcher': observed_launcher}
    if contract is None:
        return {**result, 'status': 'bound_core_contract_required'}
    if platform == 'alt':
        # ALT supplies the source-bound build receipt, with the canonical update manifest in build.
        build = contract['build']
        if (build['platform'] != 'linux_amd64' or build['archive_type'] != 'tar.gz'
                or build['schema_version'] != 'update_build_manifest_v1'):
            raise ValueError('Expected the exact ALT OTA update build manifest')
        bound = (contract['source_revision'], build['version'])
        minimum = build['minimum_launcher_version']
    else:
        if type(contract['schema_version']) is not int or contract['schema_version'] != 1:
            raise ValueError('Expected the authored Windows Core runtime contract')
        bound = (contract['source_revision'], contract['version'])
        minimum = contract['minimum_launcher_version']
    if bound != (revision, version) or not isinstance(minimum, str) or not VERSION.fullmatch(minimum):
        raise ValueError('Core compatibility evidence must bind the target version, Git SHA and launcher minimum')
    result['minimum_launcher_version'] = minimum
    if observed_launcher is None:
        return {**result, 'status': 'current_launcher_unknown'}
    observed_version = tuple(map(int, observed_launcher.split('.')))
    minimum_version = tuple(map(int, minimum.split('.')))
    status = 'below_minimum' if observed_version < minimum_version else 'within_minimum'
    return {**result, 'status': status}


def plan(root, base, target, platform, *, contract=None, observed_launcher=None):
    baseline, revision = _revision(root, base), _revision(root, target)
    changed = sorted(path for path in _git(root, 'diff', '--no-ext-diff', '--no-renames', '--name-only',
                                         '-z', baseline, revision, '--').decode().split('\0') if path)
    before, after = _sources(root, baseline), _sources(root, revision)
    left, right = _dependencies(before), _dependencies(after)
    reachable = {name: left[name] | right[name] for name in SPEC_GROUPS}
    version, normalized = _version_source(after[VERSION_FILE])
    _, old_normalized = _version_source(before[VERSION_FILE])
    deb = platform in DEB_PLATFORMS
    if deb and (contract is not None or observed_launcher is not None):
        raise ValueError('A Core OTA contract does not apply to a native DEB package')
    if deb:
        reachable['deb_core'] = reachable['alt_core']
    selected_prefix = platform + '_'
    opposite_platform = 'linux' if platform == 'windows' else 'windows'
    components = defaultdict(list)
    unclassified = []
    for path in changed:
        if path == VERSION_FILE and normalized == old_normalized:
            continue
        if path in WINDOWS_PACKAGING_DOCS or path.startswith(f'pc_agent/platform/{opposite_platform}/'):
            continue
        owners = {name for name, paths in reachable.items() if path in paths}
        owners.update(name for name, patterns in PACKAGED_INPUTS.items() if _matches(path, patterns))
        if path == 'packaging/windows/build-update-zip.ps1':
            owners.discard('windows_foundation')
        if 'apt_repository' in owners:
            owners.discard('provider')
        if platform == 'debian' and 'debian_package' in owners:
            owners.add('deb_package')
        relevant = {name for name in owners if name in ('provider', 'browser_sensor', 'python_sdk')
                    or (name in DEB_DELIVERY_COMPONENTS if deb else name.startswith(selected_prefix))}
        for name in sorted(relevant):
            components[name].append(path)
        if not owners and not _matches(path, REVIEW_ONLY):
            unclassified.append(path)

    artifacts = [name for name in ('provider', 'browser_sensor') if name in components]
    reasons = {name: [name] for name in artifacts}
    compatibility = None
    if deb:
        deb_components = [name for name in DEB_DELIVERY_COMPONENTS if name in components]
        if deb_components:
            artifact = f'{platform}_deb_apt'
            artifacts.append(artifact)
            reasons[artifact] = deb_components
    else:
        native = 'windows_full_setup' if platform == 'windows' else 'alt_native_rpm'
        core = 'windows_core_zip' if platform == 'windows' else 'alt_core_ota'
        native_components = sorted(name for name in components
                                   if name.startswith(selected_prefix) and name != selected_prefix + 'core')
        if native_components:
            artifacts.append(native)
            reasons[native] = native_components
        elif selected_prefix + 'core' in components:
            artifacts.append(core)
            reasons[core] = [selected_prefix + 'core']
            compatibility = _core_compatibility(platform, revision, version, contract, observed_launcher)
    migrations = []
    for path in changed:
        if path.startswith('endpoint_server/db/migrations/versions/') and path.endswith('.py'):
            source = after.get(path) or before.get(path)
            assignment = _assignment(ast.parse(source), 'revision') if source else None
            value = assignment.value.value if assignment is not None and isinstance(assignment.value, ast.Constant) else None
            migrations.append(value if isinstance(value, str) else path)
    return {
        'schema_version': 1, 'platform': platform, 'baseline_revision': baseline, 'source_revision': revision,
        'version': version, 'artifacts': artifacts, 'artifact_reasons': reasons,
        'changed_components': dict(components), 'unclassified': unclassified,
        'changed_contracts': [path for path in changed if path.startswith(('endpoint_contracts/', 'contracts/'))],
        'provider_migrations': sorted(migrations), 'core_compatibility': compatibility,
        'state': 'hold' if unclassified or (compatibility and compatibility['status'] != 'within_minimum') else 'planned',
    }


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--base', required=True, help='Reviewed baseline for the selected platform')
    parser.add_argument('--target', default='HEAD', help='Committed candidate source')
    parser.add_argument('--platform', required=True, choices=('windows', 'alt', *DEB_PLATFORMS))
    parser.add_argument('--runtime-contract', type=Path, help='Authored Windows runtime contract or source-bound ALT OTA receipt')
    parser.add_argument('--observed-launcher', help='Latest verified launcher version of the source profile')
    args = parser.parse_args()
    try:
        if args.observed_launcher is not None and not VERSION.fullmatch(args.observed_launcher):
            raise ValueError('Observed launcher must be a numeric version triplet')
        result = plan(args.repo_root, args.base, args.target, args.platform,
                      contract=json.loads(args.runtime_contract.read_bytes()) if args.runtime_contract else None,
                      observed_launcher=args.observed_launcher)
    except (OSError, KeyError, SyntaxError, TypeError, ValueError, subprocess.SubprocessError, tarfile.TarError) as exc:
        parser.exit(1, f'Release plan failed: {exc}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
