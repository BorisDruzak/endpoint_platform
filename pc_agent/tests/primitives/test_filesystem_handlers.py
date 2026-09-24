"""Fixed local volume and logical Endpoint path reads."""

from __future__ import annotations

from endpoint_contracts.filesystem_primitives import (
    FileMetadataParametersV1,
    FreeSpaceParametersV1,
    PathExistsParametersV1,
)


def test_free_space_returns_fixed_system_volume_without_path() -> None:
    from pc_agent.primitives.filesystem.handlers import free_space

    result = free_space(FreeSpaceParametersV1(schema_version="filesystem_free_space_parameters_v1"))
    assert result.status == "succeeded"
    assert result.volumes[0].volume_key == "system"
    assert result.volumes[0].total_bytes >= result.volumes[0].free_bytes
    assert "mountpoint" not in str(result.model_dump(mode="json"))


def test_free_space_fails_if_system_volume_cannot_be_proven_local(monkeypatch) -> None:
    from pc_agent.primitives.filesystem import handlers

    monkeypatch.setattr(handlers.psutil, "disk_partitions", lambda all=False: [])
    result = handlers.free_space(FreeSpaceParametersV1(schema_version="filesystem_free_space_parameters_v1"))
    assert result.status == "failed" and result.volumes == []


def test_logical_path_result_does_not_reveal_resolved_path(tmp_path) -> None:
    from pc_agent.primitives.filesystem.handlers import file_metadata, path_exists

    manifest = tmp_path / "current.json"
    manifest.write_text("{}", encoding="utf-8")
    resolver = lambda key: manifest
    exists = path_exists(
        PathExistsParametersV1(schema_version="filesystem_path_exists_parameters_v1", path_key="endpoint_runtime_manifest"),
        resolve_path=resolver,
    )
    metadata = file_metadata(
        FileMetadataParametersV1(schema_version="filesystem_file_metadata_parameters_v1", path_key="endpoint_runtime_manifest"),
        resolve_path=resolver,
    )
    assert exists.exists and exists.kind == "file"
    assert metadata.exists and metadata.size == 2
    assert str(tmp_path) not in str(exists.model_dump(mode="json"))
    assert str(tmp_path) not in str(metadata.model_dump(mode="json"))
