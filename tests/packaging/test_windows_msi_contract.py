"""Static contracts for the machine-wide Windows Endpoint Agent MSI."""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
WINDOWS_PACKAGING = PROJECT_ROOT / "packaging" / "windows"
WIX_ROOT = WINDOWS_PACKAGING / "wix"


@pytest.mark.skipif(os.name != "nt", reason="generated WiX helper requires Windows URI/path semantics")
def test_generated_runtime_directory_cleanup_belongs_to_runtime_components(tmp_path):
    import subprocess
    runtime=tmp_path/'runtime';(runtime/'nested/deep').mkdir(parents=True)
    for name in ['pc_agent.exe','endpoint-runtime-contract.json','nested/a.dll','nested/deep/b.dll','nested/deep/c.dll']:
        (runtime/name).write_bytes(b'payload')
    output=tmp_path/'payload.wxs'
    script=tmp_path/'generate.ps1';script.write_text(r'''param($Source,$Runtime,$Output)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
foreach($node in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){Invoke-Expression $node.Extent.Text}
Write-GeneratedPayloadWix $Runtime $Output | Out-Null
''',encoding='utf-8')
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(script),
        str(WINDOWS_PACKAGING/'build-msi.ps1'),str(runtime),str(output)],capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr
    tree=ET.parse(output).getroot()
    namespace={'w':'http://wixtoolset.org/schemas/v4/wxs'}
    directories={d.attrib['Id'] for d in tree.findall('.//w:Directory',namespace)}
    group=tree.find('.//w:ComponentGroup',namespace)
    assert group.attrib['Id']=='EndpointAgentGeneratedPayload'
    removals=group.findall('.//w:RemoveFolder',namespace)
    assert len(removals)==len(directories)==2
    assert {r.attrib['Directory'] for r in removals}==directories
    assert {r.attrib['On'] for r in removals}=={'uninstall'}
    assert len(group.findall('.//w:File',namespace))==4


def test_synthetic_wix4_package_links_with_finalization_audit(tmp_path):
    """Compile dummy bytes only; never execute MSI, ICEs, services or release tools."""
    import shutil
    import subprocess
    wix=shutil.which('wix') or str(Path.home()/'.dotnet/tools/wix.exe')
    if not Path(wix).is_file(): pytest.skip('WiX4 authoring compiler unavailable')
    version=subprocess.run([wix,'--version'],capture_output=True,text=True,timeout=15)
    assert version.returncode==0 and version.stdout.startswith('4.0.6'),version.stdout
    stage=tmp_path/'dummy';stage.mkdir()
    variables={'StagingDir':str(stage),'PackageVersion':'0.0.1','InitialRuntimeVersion':'0.0.1',
        'InitialRuntimeComponentGuid':str(uuid.uuid4()),'InitialRuntimeTransitionApproved':'0',
        'BaselineInitialRuntimeVersion':'0.0.0','SourceRevision':'a'*40,
        'InitialRuntimeInventoryPath':str(stage/'dummy-inventory.json')}
    sources=[]
    fixture_upgrade=str(uuid.uuid4()).upper()
    for name in WIX_FILES:
        source=(WIX_ROOT/name).read_text()
        for key,value in variables.items(): source=source.replace('$(var.'+key+')',value)
        source=source.replace(STABLE_UPGRADE_CODE,fixture_upgrade)
        root=ET.fromstring(source)
        for node in root.iter():
            if node.tag.endswith('}Package'):
                node.set('Name','Task7 Synthetic Authoring Only');node.set('Manufacturer','Synthetic Test')
            if node.tag.endswith('}Component') and node.get('Guid')!='*': node.set('Guid',str(uuid.uuid4()))
            if node.tag.endswith('}Directory') and node.get('Id') in {'VENDORFOLDER','PROGRAMDATAVENDOR'}: node.set('Name','Task7 Synthetic Authoring Only')
            for key in ('Source','SourceFile'):
                if key in node.attrib:
                    path=Path(node.attrib[key].replace('\\','/'))
                    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'NONEXECUTABLE SYNTHETIC AUTHORING FIXTURE')
        target=tmp_path/name;ET.ElementTree(root).write(target,encoding='utf-8',xml_declaration=True);sources.append(target)
    generated=tmp_path/'empty-payload.wxs'
    generated.write_text('<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs"><Fragment><ComponentGroup Id="EndpointAgentGeneratedPayload" /></Fragment></Wix>')
    output=tmp_path/'synthetic-authoring-only.msi'
    # wix.exe build only links; ICE execution is the separate msi validate verb.
    result=subprocess.run([wix,'build','-arch','x64','-ext','WixToolset.Util.wixext/4.0.6',
        '-out',str(output),*map(str,sources),str(generated)],capture_output=True,text=True,timeout=60)
    assert result.returncode==0,result.stdout+result.stderr
    script=tmp_path/'inspect.ps1';inspection=tmp_path/'inspection.json'
    script.write_text(r'''param($Source,$Msi,$Output)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
foreach($node in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){Invoke-Expression $node.Extent.Text}
Export-MsiInspection $Msi $Output
''',encoding='utf-8')
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(script),
        str(WINDOWS_PACKAGING/'build-msi.ps1'),str(output),str(inspection)],capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stdout+result.stderr
    rows=json.loads(inspection.read_text())['execute_sequence']
    assert not any(row['action']=='Wix4RemoveFoldersEx_X64' for row in rows)
    cleanup=next(row for row in rows if row['action']=='ScheduleEndpointRootCleanup')
    assert cleanup['condition']=='NOT ENDPOINT_UNINSTALL_FINALIZE'


@pytest.mark.parametrize('defect',['none','unknown','condition','feature','guard_type','guard_order'])
def test_compiled_finalization_sequence_rejects_unreviewed_reachable_actions(tmp_path,defect):
    import subprocess
    powershell = shutil.which("powershell.exe") or shutil.which("pwsh")
    if powershell is None:
        pytest.skip("PowerShell is required to execute the extracted finalization audit; static WXS checks still run")
    sequence=[{'action':name,'condition':'','sequence':number} for name,number in
        [('CostFinalize',1000),('InstallerOwnerPreflight',1002),('InstallInitialize',1500),
         ('InstallerOwnerEnter',1501),('InstallerOwnerComplete',6599),('InstallFinalize',6600)]]
    for name,number in [('ProcessComponents',1600),('StopServices',1900),('RemoveFiles',3500),
                        ('RegisterUser',6000),('RegisterProduct',6100),('PublishFeatures',6300),('PublishProduct',6400),('RemoveExistingProducts',6501)]:
        sequence.append({'action':name,'condition':'NOT ENDPOINT_UNINSTALL_FINALIZE','sequence':number})
    inspection={'execute_sequence':sequence,
        'features':[{'feature':name,'level':'1'} for name in ['EndpointAgentFeature','EndpointAgentInitialRuntimeFeature']],
        'feature_conditions':[{'feature':name,'level':'0','condition':'ENDPOINT_UNINSTALL_FINALIZE = 1'} for name in ['EndpointAgentFeature','EndpointAgentInitialRuntimeFeature']],
        'custom_actions':[{'action':name,'type':kind,'source':'EndpointInstallerHost'} for name,kind in
            [('InstallerOwnerPreflight',8194),('InstallerOwnerEnter',11266),('InstallerOwnerComplete',11778)]]}
    if defect=='unknown': sequence.append({'action':'UnreviewedMutation','condition':'','sequence':3000})
    elif defect=='condition': sequence[6]['condition']='NOT ENDPOINT_UNINSTALL_FINALIZE OR 1'
    elif defect=='feature': inspection['feature_conditions'].pop()
    elif defect=='guard_type': inspection['custom_actions'][1]['type']=1154
    elif defect=='guard_order': sequence[3]['sequence']=4000
    data=tmp_path/'inspection.json';data.write_text(json.dumps(inspection))
    script=tmp_path/'audit.ps1';script.write_text(r'''param($Source,$Data)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Assert-UninstallFinalizationSequence'},$true)
if($null -eq $node){throw 'compiled audit missing'}
Invoke-Expression $node.Extent.Text
Assert-UninstallFinalizationSequence ([IO.File]::ReadAllText($Data) | ConvertFrom-Json)
''',encoding='utf-8')
    result=subprocess.run([powershell,'-NoProfile','-NonInteractive','-File',str(script),
        str(WINDOWS_PACKAGING/'build-msi.ps1'),str(data)],capture_output=True,text=True,timeout=30)
    assert (result.returncode==0)==(defect=='none'),result.stderr

WIX_FILES = (
    "Package.wxs",
    "Directories.wxs",
    "Components.wxs",
    "Services.wxs",
    "Upgrade.wxs",
)
WIX_NS = "http://wixtoolset.org/schemas/v4/wxs"
UTIL_NS = "http://wixtoolset.org/schemas/v4/wxs/util"
NS = {"w": WIX_NS, "util": UTIL_NS}
STABLE_UPGRADE_CODE = "D4F3045C-51CF-49D9-AF9C-3AEBF206ED1F"


def test_privileged_foundation_uses_patched_bootloader_and_forced_parent_check():
    requirements = (PROJECT_ROOT / "requirements/build-windows.txt").read_text()
    assert "PyInstaller==6.22.3" in requirements
    assert "pyinstaller-hooks-contrib==2026.8" in requirements
    for name in ("windows_service_launcher", "windows_updater", "windows_setup", "windows_provision", "windows_browser_policy_service", "launcher_win"):
        tree = ast.parse((PROJECT_ROOT / "pc_agent" / f"pyinstaller_{name}.spec").read_text())
        executables = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == "EXE"]
        assert len(executables) == 1
        options = [node for argument in executables[0].args for node in ast.walk(argument)
            if isinstance(node, ast.Tuple)]
        assert any(ast.literal_eval(node) == ("pyi-enable-onefile-parent-verification", None, "OPTION")
            for node in options), name


def test_initial_runtime_has_separate_default_feature_and_owner_started_agent():
    trees = _trees()
    features = {node.attrib['Id']:node for node in trees['Package.wxs'].findall('.//w:Feature', NS)}
    assert features['EndpointAgentInitialRuntimeFeature'].attrib['Level'] == '1'
    runtime_groups = {node.attrib['Id'] for node in features['EndpointAgentInitialRuntimeFeature'].findall('w:ComponentGroupRef', NS)}
    assert runtime_groups == {'EndpointAgentInitialRuntimeComponents', 'EndpointAgentGeneratedPayload'}
    foundation_groups = {node.attrib['Id'] for node in features['EndpointAgentFeature'].findall('w:ComponentGroupRef', NS)}
    assert 'EndpointAgentGeneratedPayload' not in foundation_groups
    anchor = trees['Components.wxs'].find(".//w:ComponentGroup[@Id='EndpointAgentInitialRuntimeComponents']/w:Component[@Id='cmpInitialRuntimeAnchor']", NS)
    assert anchor is not None and anchor.find('w:RemoveFolder', NS) is not None
    control = trees['Services.wxs'].find(".//w:ServiceControl[@Name='EndpointAgent']", NS)
    assert 'Start' not in control.attrib
    cleanup = trees['Components.wxs'].find('.//w:CustomTable/w:Row/w:Data[@Column="Condition"]', NS)
    assert cleanup.attrib['Value'] == 'REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE'


def _trees() -> dict[str, ET.Element]:
    return {
        name: ET.parse(WIX_ROOT / name).getroot()  # noqa: S314 - repository XML only
        for name in WIX_FILES
    }


def _all_elements(trees: dict[str, ET.Element], local_name: str) -> list[ET.Element]:
    return [
        element
        for root in trees.values()
        for element in root.iter()
        if element.tag.rsplit("}", 1)[-1] == local_name
    ]


def _by_id(elements: list[ET.Element], identifier: str) -> ET.Element:
    return next(element for element in elements if element.get("Id") == identifier)


def _python_string_literals(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }


def test_wix_sources_are_wix4_documents() -> None:
    """Dropping or corrupting any authored source makes the MSI unbuildable."""
    trees = _trees()

    assert set(trees) == set(WIX_FILES)
    assert all(root.tag == f"{{{WIX_NS}}}Wix" for root in trees.values())


def test_package_is_stable_machine_wide_x64() -> None:
    """A per-user, 32-bit, or unrelated product cannot replace the deployed agent."""
    packages = _all_elements(_trees(), "Package")
    assert len(packages) == 1
    package = packages[0]

    assert package.get("UpgradeCode") == STABLE_UPGRADE_CODE
    assert package.get("Scope") == "perMachine"
    assert package.get("Compressed") == "yes"
    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")
    assert 'ValidateSet("x64")' in script
    assert '"-arch", "x64"' in script


def test_every_component_is_explicitly_64_bit() -> None:
    """A default-bit component can be redirected into the 32-bit registry/filesystem view."""
    components = _all_elements(_trees(), "Component")

    assert components
    assert {component.get("Bitness") for component in components} == {"always64"}


def test_binding_manifest_lists_every_authored_wix_component() -> None:
    """Release binding must account for every authored MSI component."""
    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")
    declaration = re.search(
        r"\$componentManifest\s*=\s*@\((.*?)\)\s*\+\s*@\(",
        script,
        re.S,
    )
    assert declaration is not None
    declared = set(re.findall(r"'(?P<id>cmp[A-Za-z0-9]+)'", declaration.group(1)))
    authored = {
        component.get("Id")
        for component in _all_elements(_trees(), "Component")
    }
    assert declared == authored


def test_installer_defines_no_enrollment_or_device_secret_property() -> None:
    """Enrollment claims and permanent bearer credentials must arrive after MSI install."""
    trees = _trees()
    properties = _all_elements(trees, "Property")
    forbidden = re.compile(r"(claim|campaign|device.?token|credential|enroll)", re.I)

    assert not [item.get("Id") for item in properties if forbidden.search(item.get("Id", ""))]
    custom_actions = _all_elements(trees, "CustomAction")
    assert not [
        action.get("Id")
        for action in custom_actions
        if forbidden.search(" ".join(action.attrib.values()))
    ]


def test_services_use_fixed_accounts_start_modes_and_recovery() -> None:
    """Changing an SCM identity or updater start mode crosses the reviewed privilege boundary."""
    trees = _trees()
    services = _all_elements(trees, "ServiceInstall")
    core = _by_id(services, "svcEndpointAgent")
    updater = _by_id(services, "svcEndpointAgentUpdater")

    assert core.get("Name") == "EndpointAgent"
    assert core.get("Account") == "NT AUTHORITY\\LocalService"
    assert core.get("Start") == "disabled"
    assert core.get("Vital") == "yes"
    assert core.get("Arguments") == "--agent-service"
    assert updater.get("Name") == "EndpointAgentUpdater"
    assert updater.get("Account") == "LocalSystem"
    assert updater.get("Start") == "disabled"
    assert updater.get("Vital") == "yes"
    assert updater.get("Arguments") == "--updater-service"

    service_component = next(
        component for component in _all_elements(trees, "Component")
        if core in list(component)
    )
    service_key_path = next(
        child for child in service_component if child.tag == f"{{{WIX_NS}}}File"
    )
    assert service_component.get("Directory") == "INSTALLFOLDER"
    assert service_key_path.get("Id") == "filServiceHost"
    assert service_key_path.get("Name") == "endpoint-agent-service.exe"
    assert "versions" not in service_key_path.get("Source", "").lower()

    assert not [
        item
        for item in _all_elements(trees, "ServiceConfig")
        if item.tag == f"{{{WIX_NS}}}ServiceConfig"
    ]

    assert not _all_elements(trees, "ServiceConfig")


def test_service_components_remove_services_and_fail_the_transaction_on_error() -> None:
    """A failed service registration must roll back and uninstall must not orphan services."""
    trees = _trees()
    controls = _all_elements(trees, "ServiceControl")

    assert {item.get("Name") for item in controls} == {
        "EndpointAgent",
        "EndpointAgentUpdater",
        "EndpointBrowserPolicy",
    }
    core_control = _by_id(controls, "ctlEndpointAgent")
    updater_control = _by_id(controls, "ctlEndpointAgentUpdater")
    browser_control = _by_id(controls, "ctlEndpointBrowserPolicy")
    assert core_control.get("Start") is None
    assert updater_control.get("Start") is None
    assert browser_control.get("Start") == "install"
    assert all(item.get("Remove") == "uninstall" for item in controls)
    assert all(item.get("Wait") == "yes" for item in controls)
    assert all(item.get("Vital") == "yes" for item in _all_elements(trees, "ServiceInstall"))
    actions = _all_elements(trees, "CustomAction")
    configure = _by_id(actions, "ConfigureFoundation")
    assert configure.get("BinaryRef") == "EndpointInstallerHost"
    assert configure.get("ExeCommand") == '--installer-phase foundation-config --installer-session "[ENDPOINT_INSTALLER_SESSION]"'
    assert configure.get("Execute") == "deferred"
    assert configure.get("Impersonate") == "no"
    assert configure.get("Return") == "check"
    sequence = next(item for item in _all_elements(trees, "Custom") if item.get("Action") == "ConfigureFoundation")
    assert sequence.get("After") == "InstallServices"
    assert sequence.get("Condition") == 'NOT ENDPOINT_UNINSTALL_FINALIZE AND &EndpointAgentFeature = 3 AND NOT ENDPOINT_RUNTIME_RETIRE AND NOT REMOVE~="ALL"'
    assert not any(item.get("FileRef") == "filServiceHost" for item in actions)


def test_updater_acl_custom_action_reaches_only_the_fixed_no_argument_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The MSI must not synthesize a caller-controlled service ACL command."""
    from pc_agent.runtime import main as runtime_main

    observed: list[str] = []
    monkeypatch.setattr(
        "pc_agent.platform.windows.service_control.restrict_updater_start_permissions",
        lambda: observed.append("restricted"),
    )

    with pytest.raises(SystemExit):
        runtime_main.main(["--windows-restrict-updater-start"])
    assert observed == []


def test_programdata_acl_is_replaced_by_fixed_elevated_action() -> None:
    """Ordinary users must not gain a writable Program Files tree or credential access."""
    trees = _trees()
    components = _all_elements(trees, "Component")
    data = _by_id(components, "cmpProgramDataRoot")
    assert data.get("Directory") == "DATAROOT"
    assert data.get("Permanent") == "yes"
    assert not list(data.iter(f"{{{UTIL_NS}}}PermissionEx"))
    actions = _all_elements(trees, "CustomAction")
    action = _by_id(actions, "ConfigureFoundation")
    assert action.get("BinaryRef") == "EndpointInstallerHost"
    assert action.get("ExeCommand") == '--installer-phase foundation-config --installer-session "[ENDPOINT_INSTALLER_SESSION]"'
    assert action.get("Execute") == "deferred"
    assert action.get("Impersonate") == "no"
    assert action.get("Return") == "check"
    assert action.get("HideTarget") == "yes"
    program_files_components = [
        item for item in components if item.get("Directory") != "DATAROOT"
    ]
    assert not any(
        descendant.tag == f"{{{UTIL_NS}}}PermissionEx"
        for component in program_files_components
        for descendant in component.iter()
    )


def test_tray_status_directory_is_prepared_by_a_fixed_elevated_action() -> None:
    """The service must never inherit a user-writable public status directory."""
    actions = _all_elements(_trees(), "CustomAction")
    action = _by_id(actions, "ConfigureFoundation")
    sequence = next(
        item
        for item in _all_elements(_trees(), "Custom")
        if item.get("Action") == "ConfigureFoundation"
    )

    assert action.get("BinaryRef") == "EndpointInstallerHost"
    assert action.get("ExeCommand") == '--installer-phase foundation-config --installer-session "[ENDPOINT_INSTALLER_SESSION]"'
    assert action.get("Execute") == "deferred"
    assert action.get("Impersonate") == "no"
    assert action.get("Return") == "check"
    assert sequence.get("After") == "InstallServices"


def test_payload_has_launcher_immutable_core_config_documentation_and_selector() -> None:
    """Removing an operational payload boundary creates an incomplete package."""
    files = _all_elements(_trees(), "File")
    by_id = {item.get("Id"): item for item in files}

    assert by_id["filLauncher"].get("Name") == "launcher.exe"
    assert by_id["filInitialCore"].get("Name") == "pc_agent.exe"
    assert by_id["filConfigTemplate"].get("Name") == "agent-config.yaml"
    assert by_id["filPublicReadme"].get("Name") == "README.md"
    assert by_id["filCurrentSelector"].get("Name") == "current.json"


def test_msi_includes_a_separate_provisioning_executable_without_secret_inputs() -> None:
    """Post-install enrollment needs an executable boundary, never an MSI property."""
    files = _all_elements(_trees(), "File")
    by_id = {item.get("Id"): item for item in files}
    provisioner = by_id["filProvisioner"]

    assert provisioner.get("Name") == "endpoint-agent-provision.exe"
    assert "ProgramFiles\\endpoint-agent-provision.exe" in provisioner.get("Source", "")

    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")
    assert "pyinstaller_windows_provision.spec" in script
    assert "endpoint-agent-provision.exe" in script

    spec = PROJECT_ROOT / "pc_agent" / "pyinstaller_windows_provision.spec"
    assert spec.is_file()
    assert '"provision_entry.py"' in spec.read_text(encoding="utf-8")
    entry = PROJECT_ROOT / "pc_agent" / "platform" / "windows" / "provision_entry.py"
    assert entry.read_text(encoding="utf-8") == (
        "from pc_agent.platform.windows.provision import main\n\n"
        "\nif __name__ == \"__main__\":\n"
        "    raise SystemExit(main())\n"
    )


def test_msi_owns_windowed_tray_binary_and_machine_logon_entry() -> None:
    """The companion starts in each interactive user session, never from service session 0."""
    files = _all_elements(_trees(), "File")
    by_id = {item.get("Id"): item for item in files}
    tray = by_id["filEndpointAgentTray"]
    values = _all_elements(_trees(), "RegistryValue")
    logon = _by_id(values, "regEndpointAgentTray")

    assert tray.get("Name") == "EndpointAgentTray.exe"
    assert "ProgramFiles\\EndpointAgentTray.exe" in tray.get("Source", "")
    assert logon.get("Root") == "HKLM"
    assert logon.get("Key") == "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    assert logon.get("Name") == "EndpointAgentTray"
    assert "filEndpointAgentTray" in logon.get("Value", "")


def test_build_script_builds_and_stages_the_tray_before_wix_binding() -> None:
    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")

    assert "pyinstaller_windows_tray.spec" in script
    assert "EndpointAgentTray.exe" in script
    assert script.index("pyinstaller_windows_tray.spec") < script.index("$generatedWix")


def test_msi_starts_unprivileged_user_sensor_at_each_logon() -> None:
    files = {item.get("Id"): item for item in _all_elements(_trees(), "File")}
    values = _all_elements(_trees(), "RegistryValue")
    sensor = files["filEndpointUserSensor"]
    logon = _by_id(values, "regEndpointUserSensor")

    assert sensor.get("Name") == "EndpointUserSensor.exe"
    assert "ProgramFiles\\EndpointUserSensor.exe" in sensor.get("Source", "")
    assert logon.get("Root") == "HKLM"
    assert logon.get("Key") == "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    assert logon.get("Name") == "EndpointUserSensor"
    assert "filEndpointUserSensor" in logon.get("Value", "")

    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")
    assert "pyinstaller_windows_user_sensor.spec" in script
    assert "EndpointUserSensor.exe" in script
    assert script.index("pyinstaller_windows_user_sensor.spec") < script.index("$generatedWix")


def test_msi_registers_pinned_native_host_for_chrome_and_yandex() -> None:
    extension_id = (PROJECT_ROOT / "browser_sensor" / "extension-id.txt").read_text(
        encoding="ascii"
    ).strip()
    manifest = json.loads(
        (WINDOWS_PACKAGING / "assets" / "ru.sosnadmin.endpoint.browser.json").read_text(
            encoding="utf-8"
        )
    )
    assert manifest == {
        "name": "ru.sosnadmin.endpoint.browser",
        "description": "Endpoint Browser Sensor bridge",
        "path": "EndpointBrowserBridge.exe",
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{extension_id}/"],
    }
    files = {item.get("Id"): item for item in _all_elements(_trees(), "File")}
    values = _all_elements(_trees(), "RegistryValue")
    assert files["filEndpointBrowserBridge"].get("Name") == "EndpointBrowserBridge.exe"
    assert files["filEndpointBrowserManifest"].get("Name") == "ru.sosnadmin.endpoint.browser.json"
    registration = _by_id(values, "regEndpointChromeNativeHost")
    assert registration.get("Root") == "HKLM"
    assert registration.get("Key") == (
        "Software\\Google\\Chrome\\NativeMessagingHosts\\ru.sosnadmin.endpoint.browser"
    )
    assert registration.get("Name") is None
    assert registration.get("Value") == "[#filEndpointBrowserManifest]"
    chromium_registration = _by_id(values, "regEndpointChromiumNativeHost")
    assert chromium_registration.get("Root") == "HKLM"
    assert chromium_registration.get("Key") == (
        "Software\\Chromium\\NativeMessagingHosts\\ru.sosnadmin.endpoint.browser"
    )
    assert chromium_registration.get("Name") is None
    assert chromium_registration.get("Value") == "[#filEndpointBrowserManifest]"
    assert {
        item.get("Id")
        for item in values
        if "NativeMessagingHosts" in item.get("Key", "")
    } == {"regEndpointChromeNativeHost", "regEndpointChromiumNativeHost"}
    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")
    assert "pyinstaller_windows_browser_bridge.spec" in script
    assert "EndpointBrowserBridge.exe" in script
    assert "NativeMessagingBlocklist" not in script


def test_browser_bridge_component_has_stable_unique_guid() -> None:
    """WiX cannot derive a GUID for the bridge EXE and unversioned manifest pair."""
    components = _all_elements(_trees(), "Component")
    bridge = _by_id(components, "cmpBrowserBridge")
    assert len(bridge.findall(f"{{{WIX_NS}}}File")) == 2
    guid = str(uuid.UUID(bridge.get("Guid", ""))).upper()
    assert guid == bridge.get("Guid")
    assert sum(component.get("Guid") == guid for component in components) == 1


def test_msi_excludes_the_universal_setup_bootstrapper() -> None:
    """The release Setup executable owns the MSI; the MSI must not contain a nested setup."""
    files = _all_elements(_trees(), "File")
    by_id = {item.get("Id"): item for item in files}

    assert "filUniversalSetup" not in by_id

    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")
    assert "pyinstaller_windows_setup.spec" not in script
    assert "EndpointAgentSetup.exe" not in script
    assert "ENROLLMENT" not in (WINDOWS_PACKAGING / "wix" / "Package.wxs").read_text(
        encoding="utf-8"
    )


def test_selector_never_overwrite_is_authored_on_the_wix4_component() -> None:
    """WiX 4 emits MSI's NeverOverwrite component bit, not an invalid File attribute."""
    components = _all_elements(_trees(), "Component")
    selector_component = next(
        component
        for component in components
        if any(child.get("Id") == "filCurrentSelector" for child in component)
    )

    assert selector_component.get("NeverOverwrite") == "yes"


def test_major_upgrade_preserves_state_and_requires_explicit_runtime_transition() -> None:
    """A routine major upgrade must not reset identity, credential, or selected runtime."""
    trees = _trees()
    assert not _all_elements(trees, "MajorUpgrade")
    versions = _all_elements(trees, "UpgradeVersion")
    assert len(versions) == 2
    assert {v.get('Property') for v in versions} == {'WIX_UPGRADE_DETECTED','WIX_DOWNGRADE_DETECTED'}
    removal = _all_elements(trees, 'RemoveExistingProducts')
    assert len(removal) == 1 and removal[0].get('After') == 'InstallExecute'
    assert removal[0].get('Condition') == 'NOT ENDPOINT_UNINSTALL_FINALIZE'

    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")
    assert "ApproveInitialRuntimeTransition" in script
    assert "ApproveInitialRuntimeSourceChange" in script
    assert "initial-runtime.json" in script
    assert "InitialRuntimeComponentGuid" in script


def test_approved_runtime_transition_migrates_selector_before_service_start() -> None:
    """Removing an old initial component must not leave current.json dangling."""
    trees = _trees()
    properties = _all_elements(trees, "Property")
    transition_property = _by_id(
        properties, "ENDPOINT_AGENT_INITIAL_RUNTIME_TRANSITION"
    )
    assert transition_property.get("Value") == "$(var.InitialRuntimeTransitionApproved)"

    actions = _all_elements(trees, "CustomAction")
    guard = _by_id(actions, "InstallerOwnerEnter")
    assert guard.get("BinaryRef") == "EndpointInstallerHost"
    assert guard.get("Execute") == "deferred"
    assert guard.get("Impersonate") == "no"
    assert guard.get("Return") == "check"
    sequence = next(item for item in _all_elements(trees, "Custom") if item.get("Action") == "InstallerOwnerEnter")
    assert sequence.get("After") == "InstallInitialize"
    assert not any(item.get("Id") == "MigrateInitialSelector" for item in actions)

    registry_values = [
        item for item in _all_elements(trees, "RegistryValue")
        if item.get("Key", "").endswith("InitialRuntimeTransition")
    ]
    assert {item.get("Name"): item.get("Value") for item in registry_values} == {
        "Approved": "$(var.InitialRuntimeTransitionApproved)",
        "FromVersion": "$(var.BaselineInitialRuntimeVersion)",
        "SourceRevision": "$(var.SourceRevision)",
        "ToVersion": "$(var.InitialRuntimeVersion)",
    }

    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")
    assert "InitialRuntimeTransitionApproved" in script
    assert "BaselineInitialRuntimeVersion" in script


def test_owner_guards_are_embedded_and_have_no_unowned_rollback_writer() -> None:
    actions = _all_elements(_trees(), "CustomAction")
    assert not any(item.get("Id") in {"RollbackInitialSelector", "FinalizeInitialSelectorMigration"} for item in actions)
    for name,execution in (("InstallerOwnerPreflight","immediate"),("InstallerOwnerEnter","deferred"),("InstallerOwnerComplete","commit")):
        action=_by_id(actions,name)
        assert action.get("BinaryRef")=="EndpointInstallerHost"
        assert action.get("Execute")==execution
        assert action.get("Return")=="check"
        assert action.get("HideTarget")=="yes"
    sequence=_all_elements(_trees(),"Custom")
    preflight=next(item for item in sequence if item.get("Action")=="InstallerOwnerPreflight")
    assert preflight.get("After")=="ClassifyRuntimeRetirement"
    classifier=next(item for item in sequence if item.get("Action")=="ClassifyRuntimeRetirement")
    assert classifier.get("After")=="CostFinalize"
    assert "&EndpointAgentInitialRuntimeFeature = 2" in classifier.get("Condition")
    assert "&EndpointAgentFeature = 3" in classifier.get("Condition")
    complete=next(item for item in sequence if item.get("Action")=="InstallerOwnerComplete")
    assert complete.get("Before")=="InstallFinalize"


def test_initial_runtime_marker_is_staged_for_msi_ownership_provenance() -> None:
    """A valid executable alone cannot distinguish an old MSI core from an updater release."""
    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")

    assert ".endpoint-msi-runtime.json" in script
    assert "initial_runtime_component_guid" in script


def test_msi_builder_seals_the_initial_selector_to_the_exact_source_revision() -> None:
    """A Windows canary must reject an MSI whose selector cannot prove its staged SHA."""
    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")

    assert "function Get-SourceRevision" in script
    assert "function Assert-CleanSourceTree" in script
    assert "git -C $RepositoryRoot status --porcelain --untracked-files=all" in script
    assert "[string]$InitialRuntimeStageRoot" in script
    assert "[string]$InitialRuntimeStageEvidence" in script
    assert "Initial runtime stage evidence is required for a schema-v5 manifest." in script
    assert "'--stage-root', $InitialRuntimeStageRoot" in script
    assert "'--stage-evidence', $InitialRuntimeStageEvidence" in script
    assert "$initialRuntimeSourceRevision = [string]$initialRuntimeIdentity.source_revision" in script
    assert "$initialRuntimeSourceRevision = [string]$manifestPreview.source_revision" not in script
    assert "merge-base --is-ancestor $initialRuntimeSourceRevision $checkedOutSourceRevision" in script
    assert script.count("source_revision = $initialRuntimeSourceRevision") == 2
    assert "schema_version = 1" in script


def test_msi_builder_preserves_the_legacy_baseline_source_revision_fallback() -> None:
    """A schema-v2 baseline stays buildable while schema-v5 seals staged bytes."""
    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")

    assert "if ([int]$manifestPreview.schema_version -ge 5)" in script
    assert "$initialRuntimeSourceRevision = $checkedOutSourceRevision" in script


def test_initial_runtime_payload_is_validated_before_msi_provenance_marker() -> None:
    """The immutable runtime manifest covers frozen payload bytes, not generated MSI metadata."""
    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")

    marker_write = "Write-Utf8NoBom (Join-Path $runtimeStage '.endpoint-msi-runtime.json')"
    artifact_validation = "$artifactValidationJson = & $python"
    assert script.index(artifact_validation) < script.index(marker_write)


def test_initial_runtime_manifest_uses_the_verified_staged_payload() -> None:
    """Schema-v5 MSI builds retain the exact payload tied to stage evidence."""
    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")

    stage_selection = "$runtimePayload = [IO.Path]::GetFullPath($InitialRuntimeStageRoot)"
    artifact_validation = "$artifactValidationJson = & $python @($validationArguments + @('--artifact-root', $runtimePayload))"
    copy_core = "Get-ChildItem -LiteralPath $runtimePayload | ForEach-Object {"
    rename_core = "Move-Item -LiteralPath (Join-Path $runtimeStage 'endpoint_agent_core.exe')"

    assert stage_selection in script
    assert script.index(stage_selection) < script.index(artifact_validation) < script.index(copy_core) < script.index(rename_core)


def test_default_uninstall_retains_programdata_and_documents_admin_purge() -> None:
    """Repair/reinstall identity must survive default uninstall while purge remains deliberate."""
    components = _all_elements(_trees(), "Component")
    data = _by_id(components, "cmpProgramDataRoot")
    readme = (WINDOWS_PACKAGING / "README.md").read_text(encoding="utf-8")

    assert data.get("Permanent") == "yes"
    assert "Remove-Item" in readme
    assert r"C:\ProgramData\Endpoint Platform\Agent" in readme
    assert "administrator" in readme.lower()


def test_uninstall_cleanup_uses_the_resolved_install_folder_not_a_registry_search() -> None:
    """RemoveFolderEx must still receive a path after uninstall removes registry values."""
    cleanup = _by_id(_all_elements(_trees(), "CustomTable"), "Wix4RemoveFolderEx")
    values = {item.get('Column'):item.get('Value') for item in cleanup.findall('w:Row/w:Data',NS)}
    assert values['Property'] == "ENDPOINT_AGENT_REMEMBERED_INSTALLROOT"
    assert not cleanup.findall('w:Column',NS)
    root = _all_elements(_trees(), "Property")
    remembered = next(item for item in root if item.get("Id") == "ENDPOINT_AGENT_REMEMBERED_INSTALLROOT")
    assert remembered.get("Value") == "C:\\Program Files\\Endpoint Platform\\Agent\\"
    assert not _all_elements(_trees(), "RegistrySearch")


def test_msi_builder_keeps_a_versioned_copy_for_repair() -> None:
    """A later build may clean staging/output but must not lose older repair media."""
    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")
    assert "$releaseRoot = Join-Path $wixBuildRoot 'releases'" in script
    assert "Copy-Item -LiteralPath $msiPath -Destination" in script


def test_msi_inspection_releases_com_handles_before_hashing_and_signing() -> None:
    """The Windows Installer automation database must not lock the MSI release file."""
    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")

    inspection = script.index("function Export-MsiInspection")
    hash_msi = script.index("$packageSha256 = (Get-FileHash")

    assert "$database.Close()" not in script[inspection:hash_msi]
    assert "[Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)" in script[
        inspection:hash_msi
    ]
    assert "[Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)" in script[
        inspection:hash_msi
    ]


def test_windows_release_builder_selects_only_headless_core_specs() -> None:
    """The canonical Windows release must not regress to the Helpdesk/GUI PyInstaller spec."""
    literals = _python_string_literals(PROJECT_ROOT / "pc_agent" / "build_windows_release_v2.py")

    assert "pyinstaller_endpoint_core_windows.spec" in literals
    assert "pyinstaller_launcher_win.spec" in literals
    assert "pyinstaller_agent_win_release.spec" not in literals
    assert "pyinstaller_launcher_win_release.spec" not in literals


def test_msi_builder_is_compatible_with_windows_powershell_51() -> None:
    """The documented command runs in the workspace's Windows PowerShell host."""
    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")

    assert "utf8NoBOM" not in script
    assert "[IO.Path]::GetRelativePath" not in script
    assert "::HashData" not in script


def test_msi_builder_passes_wix_preprocessor_defines_as_separate_arguments() -> None:
    """WiX 4 must receive each `-d` switch separately from its name/value pair."""
    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")

    assert '"-d", "StagingDir=$stagingRoot"' in script
    assert '"-dStagingDir=$stagingRoot"' not in script


def test_msi_builder_pins_python_hash_ordering_for_reproducible_runtime_bytes() -> None:
    """PyInstaller must not inherit a random hash seed into base_library.zip."""
    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")

    assert '$env:PYTHONHASHSEED = "0"' in script
    assert 'python_hash_seed' in script


def test_msi_builder_can_isolate_wix_payloads_in_a_safe_short_build_root() -> None:
    """WiX cabinet source paths must be relocatable without moving repository sources."""
    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")

    assert '[string]$WixBuildRoot' in script
    assert 'Assert-SafeWixBuildRoot' in script
    assert 'Get-ReparsePointInPath' in script
    assert 'Refusing to use a filesystem root for WiX build output.' in script
    assert 'Refusing to use a WiX build directory inside the repository.' in script
    assert '$repository + [IO.Path]::DirectorySeparatorChar' in script
    assert '$stagingRoot = Join-Path $wixBuildRoot' in script
    assert '$outputRoot = Join-Path $wixBuildRoot' in script


def test_msi_inspection_discards_com_method_output_before_filtering_rows() -> None:
    """COM Execute/Close return values must not become strict-mode table rows."""
    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")

    assert '[void]$view.Execute()' in script
    assert '[void]$view.Close()' in script


@pytest.mark.parametrize(
    "forbidden",
    ("enrollment-claim", "campaign-token", "device-token", "device-credential"),
)
def test_msi_binding_inputs_never_name_secret_payloads(forbidden: str) -> None:
    """A secret-named source file must never enter the MSI binding surface."""
    authored = "\n".join(
        (WIX_ROOT / name).read_text(encoding="utf-8") for name in WIX_FILES
    ).lower()

    assert forbidden not in authored
