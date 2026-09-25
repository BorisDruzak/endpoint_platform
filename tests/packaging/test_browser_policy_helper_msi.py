"""The privileged browser-policy writer is a separate fixed MSI service."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_msi_builds_and_installs_fixed_browser_policy_service() -> None:
    build = (ROOT / "packaging/windows/build-msi.ps1").read_text(encoding="utf-8")
    wix = (ROOT / "packaging/windows/wix/Services.wxs").read_text(encoding="utf-8")
    spec = ROOT / "pc_agent/pyinstaller_windows_browser_policy_service.spec"
    assert spec.is_file()
    assert "pyinstaller_windows_browser_policy_service.spec" in build
    assert "EndpointBrowserPolicy.exe" in build
    assert 'Name="EndpointBrowserPolicy"' in wix
    assert 'Account="LocalSystem"' in wix
    assert 'Arguments="--agent-service"' in wix  # Agent remains LocalService.
    assert 'Account="NT AUTHORITY\\LocalService"' in wix
    assert "EndpointBrowserPolicy.exe" in wix
    assert "NativeMessagingBlocklist" not in wix


def test_service_sid_configuration_includes_fixed_helper_name() -> None:
    source = (ROOT / "pc_agent/platform/windows/service_control.py").read_text(
        encoding="utf-8"
    )
    assert 'BROWSER_POLICY_SERVICE_NAME = "EndpointBrowserPolicy"' in source
    assert (
        "SERVICE_SID_NAMES = (SERVICE_NAME, UPDATER_SERVICE_NAME, BROWSER_POLICY_SERVICE_NAME)"
        in source
    )
