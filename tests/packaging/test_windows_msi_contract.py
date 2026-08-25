"""Static contracts for the machine-wide Windows Endpoint Agent MSI."""

from __future__ import annotations

import ast
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
WINDOWS_PACKAGING = PROJECT_ROOT / "packaging" / "windows"
WIX_ROOT = WINDOWS_PACKAGING / "wix"
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
    assert core.get("Start") == "auto"
    assert core.get("Vital") == "yes"
    assert core.get("Arguments") == "--agent-service"
    assert updater.get("Name") == "EndpointAgentUpdater"
    assert updater.get("Account") == "LocalSystem"
    assert updater.get("Start") == "demand"
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
    }
    assert all(item.get("Remove") == "uninstall" for item in controls)
    assert all(item.get("Wait") == "yes" for item in controls)
    assert all(item.get("Vital") == "yes" for item in _all_elements(trees, "ServiceInstall"))
    custom_actions = _all_elements(trees, "CustomAction")
    restrict = _by_id(custom_actions, "RestrictUpdaterServiceStart")
    configure_sids = _by_id(custom_actions, "ConfigureServiceSids")
    assert configure_sids.get("FileRef") == "filServiceHost"
    assert configure_sids.get("ExeCommand") == "--configure-service-sids"
    assert configure_sids.get("Execute") == "deferred"
    assert configure_sids.get("Impersonate") == "no"
    assert configure_sids.get("Return") == "check"
    assert restrict.get("Execute") == "deferred"
    assert restrict.get("Impersonate") == "no"
    assert restrict.get("Return") == "check"

    configure_sequence = next(
        item
        for item in _all_elements(trees, "Custom")
        if item.get("Action") == "ConfigureServiceSids"
    )
    restrict_sequence = next(
        item
        for item in _all_elements(trees, "Custom")
        if item.get("Action") == "RestrictUpdaterServiceStart"
    )
    assert configure_sequence.get("After") == "ApplyProgramDataAcl"
    assert restrict_sequence.get("After") == "ConfigureServiceSids"


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

    assert runtime_main.main(["--windows-restrict-updater-start"]) == 0
    assert observed == ["restricted"]


def test_programdata_acl_is_replaced_by_fixed_elevated_action() -> None:
    """Ordinary users must not gain a writable Program Files tree or credential access."""
    trees = _trees()
    components = _all_elements(trees, "Component")
    data = _by_id(components, "cmpProgramDataRoot")
    assert data.get("Directory") == "DATAROOT"
    assert data.get("Permanent") == "yes"
    assert not list(data.iter(f"{{{UTIL_NS}}}PermissionEx"))
    actions = _all_elements(trees, "CustomAction")
    action = _by_id(actions, "ApplyProgramDataAcl")
    assert action.get("FileRef") == "filServiceHost"
    assert action.get("ExeCommand") == "--apply-programdata-acl"
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
    upgrade = _all_elements(trees, "MajorUpgrade")
    assert len(upgrade) == 1
    assert upgrade[0].get("Schedule") == "afterInstallExecute"
    assert upgrade[0].get("DowngradeErrorMessage")

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
    migration = _by_id(actions, "MigrateInitialSelector")
    assert migration.get("FileRef") == "filServiceHost"
    assert migration.get("ExeCommand") == "--migrate-initial-selector"
    assert migration.get("Execute") == "deferred"
    assert migration.get("Impersonate") == "no"
    assert migration.get("Return") == "check"

    sequence = next(
        item for item in _all_elements(trees, "Custom")
        if item.get("Action") == "MigrateInitialSelector"
    )
    assert sequence.get("Action") == "MigrateInitialSelector"
    assert sequence.get("After") == "RestrictUpdaterServiceStart"
    assert "ENDPOINT_AGENT_INITIAL_RUNTIME_TRANSITION = 1" in sequence.get(
        "Condition", ""
    )

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


def test_selector_migration_has_a_no_argument_rollback_pair() -> None:
    """A later MSI failure must restore current.json before old components are removed."""
    actions = _all_elements(_trees(), "CustomAction")
    rollback = _by_id(actions, "RollbackInitialSelector")
    finalize = _by_id(actions, "FinalizeInitialSelectorMigration")
    for action, command, execution in (
        (rollback, "--rollback-initial-selector", "rollback"),
        (finalize, "--finalize-initial-selector", "commit"),
    ):
        assert action.get("FileRef") == "filServiceHost"
        assert action.get("ExeCommand") == command
        assert action.get("Execute") == execution
        assert action.get("Impersonate") == "no"
        assert action.get("Return") == "check"
        assert action.get("HideTarget") == "yes"

    sequence = _all_elements(_trees(), "Custom")
    rollback_sequence = next(item for item in sequence if item.get("Action") == "RollbackInitialSelector")
    migrate_sequence = next(item for item in sequence if item.get("Action") == "MigrateInitialSelector")
    finalize_sequence = next(item for item in sequence if item.get("Action") == "FinalizeInitialSelectorMigration")
    assert rollback_sequence.get("Before") == "MigrateInitialSelector"
    assert migrate_sequence.get("After") == "RestrictUpdaterServiceStart"
    assert finalize_sequence.get("After") == "MigrateInitialSelector"
    assert all(
        "ENDPOINT_AGENT_INITIAL_RUNTIME_TRANSITION = 1" in item.get("Condition", "")
        for item in (rollback_sequence, migrate_sequence, finalize_sequence)
    )


def test_initial_runtime_marker_is_staged_for_msi_ownership_provenance() -> None:
    """A valid executable alone cannot distinguish an old MSI core from an updater release."""
    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")

    assert ".endpoint-msi-runtime.json" in script
    assert "initial_runtime_component_guid" in script


def test_msi_builder_seals_the_initial_selector_to_the_exact_source_revision() -> None:
    """A Windows canary must reject an MSI whose selector cannot prove its source SHA."""
    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")

    assert "function Get-SourceRevision" in script
    assert "function Assert-CleanSourceTree" in script
    assert "git -C $RepositoryRoot status --porcelain --untracked-files=all" in script
    assert "source_revision = $sourceRevision" in script
    assert "schema_version = 1" in script


def test_initial_runtime_payload_is_validated_before_msi_provenance_marker() -> None:
    """The immutable runtime manifest covers frozen payload bytes, not generated MSI metadata."""
    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")

    marker_write = "Write-Utf8NoBom (Join-Path $runtimeStage '.endpoint-msi-runtime.json')"
    artifact_validation = "$artifactValidationJson = & $python"
    assert script.index(artifact_validation) < script.index(marker_write)


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
    cleanup = _by_id(_all_elements(_trees(), "RemoveFolderEx"), "RemoveEndpointAgentBinaries")
    assert cleanup.get("Property") == "ENDPOINT_AGENT_REMEMBERED_INSTALLROOT"
    root = _all_elements(_trees(), "Property")
    remembered = next(item for item in root if item.get("Id") == "ENDPOINT_AGENT_REMEMBERED_INSTALLROOT")
    assert remembered.get("Value") == "C:\\Program Files\\Endpoint Platform\\Agent\\"
    assert not _all_elements(_trees(), "RegistrySearch")


def test_msi_builder_keeps_a_versioned_copy_for_repair() -> None:
    """A later build may clean staging/output but must not lose older repair media."""
    script = (WINDOWS_PACKAGING / "build-msi.ps1").read_text(encoding="utf-8")
    assert "$releaseRoot = Join-Path $wixBuildRoot 'releases'" in script
    assert "Copy-Item -LiteralPath $msiPath -Destination" in script


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
