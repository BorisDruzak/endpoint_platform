"""Filesystem contracts expose logical keys and safe metadata only."""

from __future__ import annotations

import pytest
from pydantic import ValidationError


def test_filesystem_paths_are_closed_logical_keys() -> None:
    from endpoint_contracts.filesystem_primitives import PathExistsParametersV1, FileMetadataParametersV1

    with pytest.raises(ValidationError):
        PathExistsParametersV1(schema_version="filesystem_path_exists_parameters_v1", path_key="C:\\Users\\person\\secret.txt")
    with pytest.raises(ValidationError):
        PathExistsParametersV1(schema_version="filesystem_path_exists_parameters_v1", path_key="endpoint_install_root", path="C:\\secret")
    with pytest.raises(ValidationError):
        FileMetadataParametersV1(schema_version="filesystem_file_metadata_parameters_v1", path_key="endpoint_data_root")


def test_free_space_takes_no_path_input() -> None:
    from endpoint_contracts.filesystem_primitives import FreeSpaceParametersV1

    with pytest.raises(ValidationError):
        FreeSpaceParametersV1(schema_version="filesystem_free_space_parameters_v1", path="/")


def test_filesystem_catalog_has_fixed_policy() -> None:
    from endpoint_contracts.capabilities import MODULE_CAPABILITY_REGISTRY

    for capability in ("filesystem.free_space", "filesystem.path_exists", "filesystem.file_metadata"):
        assert capability in MODULE_CAPABILITY_REGISTRY
        assert MODULE_CAPABILITY_REGISTRY[capability].metadata.category == "filesystem"
