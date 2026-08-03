"""Linux build contracts for the neutral Endpoint Agent artifact."""

from __future__ import annotations

import hashlib
import json
import os
import runpy
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
from PyInstaller.archive.readers import CArchiveReader

from tools import build_linux_agent


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SPEC_PATH = PROJECT_ROOT / "pc_agent" / "pyinstaller_endpoint_core_linux.spec"
BUILD_TOOL = PROJECT_ROOT / "tools" / "build_linux_agent.py"

REQUIRED_EMBEDDED_MODULES = {
    "pc_agent.context_profiles.baseline",
    "pc_agent.context_profiles.diagnostic",
    "pc_agent.context_profiles.health",
    "pc_agent.context_profiles.network",
    "pc_agent.context_profiles.registry",
    "pc_agent.transport.websocket",
}
FORBIDDEN_MODULE_PREFIXES = {
    "pc_agent.ui_gui",
    "pc_agent.ui_bridge",
    "pc_agent.ws_agent",
}
FORBIDDEN_PATH_PARTS = {"qt", "qt6", "ui_gui", "ui_bridge"}
GUI_ASSET_SUFFIXES = (".ico", ".png", ".qss", ".svg")


def _capture_spec_outputs() -> dict[str, object]:
    captured: dict[str, object] = {}

    def analysis(scripts: list[str], **kwargs: object) -> object:
        captured["scripts"] = scripts
        captured.update(kwargs)
        return type(
            "AnalysisResult",
            (),
            {"pure": [], "scripts": [], "binaries": [], "datas": []},
        )()

    def executable(*args: object, **kwargs: object) -> tuple[object, ...]:
        captured["executable_name"] = kwargs.get("name")
        return args

    def collect(*args: object, **kwargs: object) -> tuple[object, ...]:
        captured["collect_name"] = kwargs.get("name")
        return args

    runpy.run_path(
        str(SPEC_PATH),
        init_globals={
            "SPECPATH": str(SPEC_PATH.parent),
            "Analysis": analysis,
            "PYZ": lambda pure: pure,
            "EXE": executable,
            "COLLECT": collect,
        },
    )
    return captured


def _embedded_module_names(executable: Path) -> set[str]:
    archive = CArchiveReader(executable)
    pyz = archive.open_embedded_archive("PYZ.pyz")
    return {name.lower() for name in pyz.toc}


def _artifact_path_parts(root: Path) -> set[str]:
    return {
        part.lower()
        for path in root.rglob("*")
        for part in path.relative_to(root).parts
    }


def _valid_verify_state(tmp_path: Path) -> tuple[Path, Path, Path]:
    data_root = tmp_path / "data"
    install_root = tmp_path / "install"
    data_root.mkdir()
    install_root.mkdir()
    ca_file = tmp_path / "endpoint-ca.crt"
    ca_file.write_text("test-only CA fixture", encoding="ascii")
    (data_root / "device-credential").write_text("c" * 43, encoding="ascii")
    (data_root / "enrollment-identity.json").write_text(
        '{"device_id":"00000000-0000-4000-8000-000000000801",'
        '"schema_version":"endpoint_enrollment_identity_v1"}',
        encoding="utf-8",
    )
    (install_root / "current.json").write_text(
        '{"schema_version":1,"source_revision":"dc8182f","version":"3.1.76"}',
        encoding="utf-8",
    )
    return data_root, install_root, ca_file


def _write_fixture_artifact(root: Path) -> None:
    root.mkdir(parents=True)
    executable = root / "endpoint-agent"
    executable.write_bytes(b"headless-core\n")
    executable.chmod(0o755)
    internal = root / "_internal" / "runtime.dat"
    internal.parent.mkdir()
    internal.write_bytes(b"runtime\n")
    internal.chmod(0o644)


def _run_builder(source: Path, output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(BUILD_TOOL),
            "--channel",
            "canary",
            "--source",
            str(source),
            "--output",
            str(output),
            "--version",
            "3.1.76",
            "--revision",
            "dc8182f",
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_release_builder_rejects_a_label_that_differs_from_compiled_agent_version(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A release label must not claim a version the frozen agent cannot report."""
    with pytest.raises(SystemExit) as exited:
        build_linux_agent.main(["--channel", "canary", "--version", "3.1.84"])

    assert exited.value.code == 1
    assert "must match compiled AGENT_VERSION" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("relative", "source_mode", "expected_mode"),
    [
        (Path("endpoint-agent"), 0o700, 0o755),
        (Path("_internal/runtime.dat"), 0o600, 0o644),
        (Path("_internal/native-extension.so"), 0o755, 0o644),
    ],
)
def test_release_builder_normalizes_safe_source_modes(
    relative: Path, source_mode: int, expected_mode: int
) -> None:
    assert build_linux_agent._normalized_payload_mode(relative, source_mode) == expected_mode


@pytest.mark.parametrize(
    ("relative", "source_mode"),
    [
        (Path("_internal/runtime.dat"), 0o666),
        (Path("endpoint-agent"), 0o777),
        (Path("_internal/runtime.dat"), 0o757),
        (Path("endpoint-agent"), 0o644),
    ],
)
def test_release_builder_rejects_unsafe_or_non_entrypoint_source_modes(
    relative: Path, source_mode: int
) -> None:
    with pytest.raises(ValueError):
        build_linux_agent._normalized_payload_mode(relative, source_mode)


def _build_pyinstaller_artifact(build_root: Path) -> Path:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--distpath",
            str(build_root / "dist"),
            "--workpath",
            str(build_root / "build"),
            str(SPEC_PATH),
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return build_root / "dist" / "endpoint-agent"


@pytest.fixture(scope="module")
def built_artifact_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if not sys.platform.startswith("linux"):
        pytest.skip("Linux artifact build")
    return _build_pyinstaller_artifact(
        tmp_path_factory.mktemp("linux-headless-artifact")
    )


def test_linux_spec_names_the_new_headless_artifact_and_core_executable() -> None:
    """Keeping the transitional core name would break the supported artifact path."""
    captured = _capture_spec_outputs()

    assert captured["scripts"] == [
        str(PROJECT_ROOT / "pc_agent" / "runtime" / "main.py")
    ]
    assert captured["executable_name"] == "endpoint-agent"
    assert captured["collect_name"] == "endpoint-agent"


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="Linux artifact inspection"
)
def test_built_artifact_contains_context_collectors_and_wss_without_gui_or_ticket_code(
    built_artifact_root: Path,
) -> None:
    """A Linux build that regains Qt/GUI/Ticket code or loses WSS/context is invalid."""
    core_executable = built_artifact_root / "endpoint-agent"
    assert core_executable.is_file()
    assert os.access(core_executable, os.X_OK)

    embedded = _embedded_module_names(core_executable)
    assert REQUIRED_EMBEDDED_MODULES.issubset(embedded)
    assert not {
        forbidden
        for forbidden in FORBIDDEN_MODULE_PREFIXES
        if any(
            name == forbidden or name.startswith(f"{forbidden}.") for name in embedded
        )
    }
    assert "pc_agent.ui_gui.server_api" not in embedded
    artifact_names = _artifact_path_parts(built_artifact_root)
    assert not FORBIDDEN_PATH_PARTS.intersection(artifact_names)
    assert not {
        name
        for name in artifact_names
        if name.startswith("libqt")
        or "pyside" in name
        or name.endswith(GUI_ASSET_SUFFIXES)
    }


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux binary smoke")
def test_built_artifact_supports_network_free_verify(
    built_artifact_root: Path, tmp_path: Path
) -> None:
    """The shipped entrypoint must retain a successful network-free --verify path."""
    data_root, install_root, ca_file = _valid_verify_state(tmp_path)
    environment = dict(os.environ)
    environment["ENDPOINT_AGENT_CA_FILE"] = str(ca_file)
    core_executable = built_artifact_root / "endpoint-agent"
    assert core_executable.is_file()

    result = subprocess.run(
        [
            str(core_executable),
            "--verify",
            "--data-dir",
            str(data_root),
            "--install-root",
            str(install_root),
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert (data_root / "storage.db").is_file()


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="Linux release assembly"
)
def test_release_builder_writes_a_deterministic_immutable_linux_artifact(
    tmp_path: Path,
) -> None:
    """Changing content must change metadata, while an exact rebuild stays byte-identical."""
    source = tmp_path / "endpoint-agent"
    output = tmp_path / "release"
    _write_fixture_artifact(source)

    first = _run_builder(source, output)

    assert first.returncode == 0, first.stderr
    archive = output / "endpoint-agent-linux_amd64-3.1.76.tar.gz"
    manifest_path = output / "endpoint-agent-linux_amd64-3.1.76.manifest.json"
    first_archive = archive.read_bytes()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest == {
        "archive_type": "tar.gz",
        "artifact_name": archive.name,
        "build_identifier": "endpoint-agent-linux_amd64-3.1.76",
        "channel": "canary",
        "platform": "linux_amd64",
        "schema_version": "endpoint_linux_agent_artifact_v1",
        "sha256": hashlib.sha256(first_archive).hexdigest(),
        "size": len(first_archive),
        "source_revision": "dc8182f",
        "version": "3.1.76",
    }

    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        assert [member.name for member in members] == [
            "endpoint-agent",
            "endpoint-agent/_internal",
            "endpoint-agent/_internal/runtime.dat",
            "endpoint-agent/endpoint-agent",
            "manifest.json",
        ]
        assert all(member.mtime == 0 for member in members)
        assert all(member.uid == 0 and member.gid == 0 for member in members)
        executable = bundle.getmember("endpoint-agent/endpoint-agent")
        assert stat.S_IMODE(executable.mode) == 0o755
        extracted = bundle.extractfile(executable)
        assert extracted is not None
        assert extracted.read() == b"headless-core\n"

    second = _run_builder(source, output)

    assert second.returncode == 0, second.stderr
    assert archive.read_bytes() == first_archive
    assert json.loads(manifest_path.read_text(encoding="utf-8")) == manifest


def test_release_archive_embeds_the_strict_alt_per_file_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Omitting the inner manifest would make the headless tar unverifiable by ALT."""
    source = tmp_path / "endpoint-agent"
    output = tmp_path / "release"
    _write_fixture_artifact(source)

    if not sys.platform.startswith("linux"):
        executable = source / "endpoint-agent"
        internal = source / "_internal" / "runtime.dat"
        path_type = type(executable)
        original_stat = path_type.stat
        original_lstat = path_type.lstat

        def stat_with_fixture_execute_bit(path: Path, *args, **kwargs):
            details = original_stat(path, *args, **kwargs)
            if path == executable:
                values = list(details)
                values[0] |= 0o111
                return os.stat_result(values)
            return details

        def lstat_with_fixture_modes(path: Path, *args, **kwargs):
            details = original_lstat(path, *args, **kwargs)
            if path in {executable, internal}:
                values = list(details)
                values[0] = (values[0] & ~0o777) | (
                    0o755 if path == executable else 0o644
                )
                return os.stat_result(values)
            return details

        monkeypatch.setattr(path_type, "stat", stat_with_fixture_execute_bit)
        monkeypatch.setattr(path_type, "lstat", lstat_with_fixture_modes)

    archive, _ = build_linux_agent.build_release(
        source=source,
        output=output,
        version="3.1.76",
        channel="canary",
        revision="dc8182f",
    )

    archive = output / "endpoint-agent-linux_amd64-3.1.76.tar.gz"
    with tarfile.open(archive, "r:gz") as bundle:
        manifest_member = bundle.getmember("manifest.json")
        manifest_stream = bundle.extractfile(manifest_member)
        assert manifest_stream is not None
        manifest = json.loads(manifest_stream.read())
    assert stat.S_IMODE(manifest_member.mode) == 0o644
    assert manifest == {
        "files": [
            {
                "mode": "0644",
                "path": "endpoint-agent/_internal/runtime.dat",
                "sha256": hashlib.sha256(b"runtime\n").hexdigest(),
            },
            {
                "mode": "0755",
                "path": "endpoint-agent/endpoint-agent",
                "sha256": hashlib.sha256(b"headless-core\n").hexdigest(),
            },
        ],
        "schema_version": 1,
        "source_revision": "dc8182f",
        "version": "3.1.76",
    }


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="Linux release assembly"
)
def test_release_builder_refuses_to_replace_an_existing_immutable_build(
    tmp_path: Path,
) -> None:
    """Reusing a build identity for changed bytes must not overwrite its artifact."""
    source = tmp_path / "endpoint-agent"
    output = tmp_path / "release"
    _write_fixture_artifact(source)
    first = _run_builder(source, output)
    assert first.returncode == 0, first.stderr
    archive = output / "endpoint-agent-linux_amd64-3.1.76.tar.gz"
    original = archive.read_bytes()
    (source / "_internal" / "runtime.dat").write_bytes(b"changed\n")

    changed = _run_builder(source, output)

    assert changed.returncode != 0
    assert "immutable build already exists" in changed.stderr
    assert archive.read_bytes() == original


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux clean builds")
def test_two_clean_pyinstaller_builds_produce_identical_release_bytes(
    tmp_path: Path,
) -> None:
    """A clean rebuild of one revision must not conflict with its immutable identity."""
    first_source = _build_pyinstaller_artifact(tmp_path / "first-build")
    second_source = _build_pyinstaller_artifact(tmp_path / "second-build")
    first_output = tmp_path / "first-release"
    second_output = tmp_path / "second-release"

    first_result = _run_builder(first_source, first_output)
    second_result = _run_builder(second_source, second_output)

    assert first_result.returncode == 0, first_result.stderr
    assert second_result.returncode == 0, second_result.stderr
    archive_name = "endpoint-agent-linux_amd64-3.1.76.tar.gz"
    manifest_name = "endpoint-agent-linux_amd64-3.1.76.manifest.json"
    assert (first_output / archive_name).read_bytes() == (
        second_output / archive_name
    ).read_bytes()
    assert (first_output / manifest_name).read_bytes() == (
        second_output / manifest_name
    ).read_bytes()
