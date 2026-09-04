from pathlib import Path


def _assert_endpoint_core_spec_collects_core_builtin_modules(spec_name: str) -> None:
    root = Path(__file__).resolve().parents[1]
    text = (root / spec_name).read_text(encoding="utf-8")

    for module_name in (
        "pc_agent.context_profiles.command_execution",
        "pc_agent.context_profiles.probe",
        "pc_agent.context_profiles.registry",
    ):
        assert f'"{module_name}"' in text

    assert '"pc_agent.endpoint_gateway"' in text
    assert '"pc_agent.gateway_update_runtime"' in text


def test_linux_endpoint_core_spec_collects_core_builtin_modules() -> None:
    _assert_endpoint_core_spec_collects_core_builtin_modules("pyinstaller_endpoint_core_linux.spec")


def test_linux_endpoint_core_spec_collects_the_systemd_gateway_transport() -> None:
    root = Path(__file__).resolve().parents[1]
    text = (root / "pyinstaller_endpoint_core_linux.spec").read_text(encoding="utf-8")

    assert '"pc_agent.endpoint_gateway"' in text
    assert '"pc_agent.gateway_update_runtime"' in text


def test_linux_launcher_spec_collects_the_immutable_alt_updater() -> None:
    root = Path(__file__).resolve().parents[1]
    text = (root / "pyinstaller_launcher_linux.spec").read_text(encoding="utf-8")

    assert '"pc_agent.alt_update_installer"' in text


def test_windows_endpoint_core_spec_collects_core_builtin_modules() -> None:
    _assert_endpoint_core_spec_collects_core_builtin_modules("pyinstaller_endpoint_core_windows.spec")
