"""Privileged frozen entrypoints must not run build-tool hooks before SCM."""
from __future__ import annotations

import runpy
import hashlib
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINTS = (
    "windows_service_launcher", "windows_updater", "windows_setup",
    "windows_provision", "windows_browser_policy_service", "launcher_win", "windows_installer_host",
)
BUILD_MODULES = {"setuptools", "pkg_resources", "_distutils_hack"}


def _analyze_spec(name, tmp_path, monkeypatch, *, bad_module=None, bad_script=None, timezone_rows=False):
    monkeypatch.syspath_prepend(str(ROOT))
    for variable, filename in {
        "ENDPOINT_SETUP_MSI": "EndpointAgent.msi",
        "ENDPOINT_SETUP_CORE_ARCHIVE": "EndpointCore.zip",
        "ENDPOINT_SETUP_CA_FILE": "endpoint-ca.crt",
        "ENDPOINT_SETUP_CONFIG": "setup-config.json",
        "ENDPOINT_SETUP_MSI_RELEASE_MANIFEST": "EndpointAgent.release.json",
        "ENDPOINT_SETUP_VERSION_FILE": "setup-version-info.txt",
    }.items():
        path = tmp_path / filename
        path.write_bytes(b"public fixture for spec evaluation only")
        monkeypatch.setenv(variable, str(path))
    observed = {}

    class Analysis:
        def __init__(self, *args, **kwargs):
            observed["excludes"] = set(kwargs["excludes"])
            observed["hiddenimports"] = set(kwargs["hiddenimports"])
            observed["runtime_hooks"] = kwargs["runtime_hooks"]
            observed["analysis"] = self
            self.pure = [(module, "public-fixture.py", "PYMODULE") for module in
                         ("os", "win32service", "pc_agent.platform.windows.installer_fence")]
            self.binaries = []
            self.zipfiles = []
            self.scripts = [("entry", "public-fixture.py", "PYSOURCE")]
            # Simulate a builder regression despite requested exclusions. The
            # spec must refuse its actual analysis before producing an EXE.
            if bad_module:
                self.pure.append((bad_module, "public-fixture.py", "PYMODULE"))
            if bad_script:
                self.scripts.append((bad_script, "public-fixture.py", "PYSOURCE"))
            self.datas = []
            if timezone_rows:
                self.pure.append(('tzdata.zoneinfo','timezone.py','PYMODULE'))
                self.datas.append(('tzdata/zoneinfo/UTC','old-resource','DATA'))

    def executable(*args, **kwargs):
        observed["exe_created"] = True
        return object()

    runpy.run_path(str(ROOT / "pc_agent" / f"pyinstaller_{name}.spec"), init_globals={
        "SPECPATH": str(ROOT / "pc_agent"), "workpath": str(tmp_path/'work'), "Analysis": Analysis,
        "PYZ": lambda *args, **kwargs: object(), "EXE": executable,
        "COLLECT": lambda *args, **kwargs: object(),
    })
    return observed


@pytest.mark.parametrize('entrypoint',[*ENTRYPOINTS,'windows_tray','windows_user_sensor',
                                    'windows_browser_bridge','endpoint_core_windows'])
def test_every_windows_artifact_replaces_loose_timezone_resources(entrypoint,tmp_path,monkeypatch):
    result=_analyze_spec(entrypoint,tmp_path,monkeypatch,timezone_rows=True)
    analysis=result['analysis']
    assert not any(row[0]=='tzdata' or row[0].startswith('tzdata.') for row in analysis.pure)
    assert not any(row[0].replace('\\','/').startswith('tzdata/') for row in analysis.datas)
    assert sum(row[0]=='tzdata-runtime.zip' for row in analysis.datas)==1
    assert str(ROOT/'pc_agent/runtime_hook_tzdata_zip.py') in result['runtime_hooks']


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
def test_privileged_spec_accepts_ordinary_runtime_modules(entrypoint, tmp_path, monkeypatch):
    assert _analyze_spec(entrypoint, tmp_path, monkeypatch)["exe_created"]


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
def test_privileged_spec_requests_build_module_exclusions(entrypoint, tmp_path, monkeypatch):
    observed = _analyze_spec(entrypoint, tmp_path, monkeypatch)
    assert BUILD_MODULES <= observed["excludes"]


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
@pytest.mark.parametrize("module", sorted(BUILD_MODULES))
def test_privileged_spec_refuses_build_modules_in_actual_analysis(entrypoint, module, tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="Build tools in privileged Windows runtime"):
        _analyze_spec(entrypoint, tmp_path, monkeypatch, bad_module=module)


def test_browser_service_refuses_setuptools_runtime_hook(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="Build tools in privileged Windows runtime"):
        _analyze_spec("windows_browser_policy_service", tmp_path, monkeypatch,
                      bad_script="pyi_rth_setuptools")


def test_browser_service_refuses_vendored_build_tool_modules(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="Build tools in privileged Windows runtime"):
        _analyze_spec("windows_browser_policy_service", tmp_path, monkeypatch,
                      bad_module="setuptools._vendor.jaraco.context")


def _archive_cli(tmp_path, monkeypatch, *, modules, members=("PYZ.pyz", "entry"), mutate=False):
    artifact = tmp_path / "public-fixture.exe"
    artifact.write_bytes(b"public archive fixture bytes")
    output = tmp_path / "inspection.json"

    class Reader:
        def __init__(self, path):
            assert path == str(artifact)
            self.toc = dict.fromkeys(members)

        def open_embedded_archive(self, name):
            assert name == "PYZ.pyz"
            if mutate:
                artifact.write_bytes(b"different public fixture bytes")
            return SimpleNamespace(toc=dict.fromkeys(modules))

    for name in ("PyInstaller", "PyInstaller.archive", "PyInstaller.archive.readers"):
        monkeypatch.setitem(sys.modules, name, ModuleType(name))
    sys.modules["PyInstaller.archive.readers"].CArchiveReader = Reader
    monkeypatch.setattr(sys, "argv", ["bootstrap-inspection", str(artifact), "--output", str(output)])
    runpy.run_path(str(ROOT / "tools/canary/privileged_bootstrap_contract.py"), run_name="__main__")


@pytest.mark.parametrize("module", ("setuptools._vendor.jaraco.context", "pkg_resources", "_distutils_hack"))
def test_finished_archive_cli_refuses_build_modules(module, tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="Build tools in privileged Windows runtime"):
        _archive_cli(tmp_path, monkeypatch, modules=("os", module))


def test_finished_archive_cli_refuses_runtime_hook_even_without_build_modules(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="Build tools in privileged Windows runtime"):
        _archive_cli(tmp_path, monkeypatch, modules=("os",), members=("PYZ.pyz", "pyi_rth_setuptools"))


def test_finished_archive_cli_refuses_uninspectable_python_payload(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="no inspectable Python archive"):
        _archive_cli(tmp_path, monkeypatch, modules=(), members=("entry",))


def test_finished_archive_cli_binds_success_to_exact_public_bytes(tmp_path, monkeypatch):
    with pytest.raises(SystemExit) as exited:
        _archive_cli(tmp_path, monkeypatch, modules=("os", "setuptools_scm", "pc_agent.platform.windows.installer_fence"))
    assert exited.value.code == 0
    inspection = json.loads((tmp_path / "inspection.json").read_text())
    result = inspection["executables"][0]
    assert result["sha256"] == hashlib.sha256(b"public archive fixture bytes").hexdigest()
    assert result["build_tools_absent"] is True
    assert result["python_module_count"] == 3


def test_finished_archive_cli_refuses_artifact_changed_during_inspection(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="changed during bootstrap inspection"):
        _archive_cli(tmp_path, monkeypatch, modules=("os",), mutate=True)


@pytest.mark.parametrize('entrypoint,modules', [
    ('windows_service_launcher', {'staged_update_state','staged_trial_proof','staged_foundation_rollback','staged_recovery','retained_storage'}),
    ('windows_setup', {'staged_update_state','staged_recovery'}),
    ('windows_updater', {'staged_update_state'}),
])
def test_staged_fixed_entrypoint_closure_is_explicit(entrypoint, modules, tmp_path, monkeypatch):
    observed = _analyze_spec(entrypoint,tmp_path,monkeypatch)
    assert {'pc_agent.platform.windows.'+name for name in modules} <= observed['hiddenimports']


def test_staged_trial_writer_is_explicit_in_windows_core():
    import ast
    tree = ast.parse((ROOT / 'pc_agent/pyinstaller_endpoint_core_windows.spec').read_text(encoding='utf-8'))
    imports = next(node.value for node in ast.walk(tree) if isinstance(node,ast.keyword) and node.arg == 'hiddenimports')
    assert {'pc_agent.platform.windows.staged_trial_proof','pc_agent.platform.windows.staged_update_state'} <= set(ast.literal_eval(imports))
