"""Machine software inventory exposes only fixed safe metadata."""

from __future__ import annotations

import pytest
from pydantic import ValidationError


def test_software_parameters_reject_shell_patterns_and_execution_fields() -> None:
    from endpoint_contracts.software_primitives import SoftwareFindParametersV1

    with pytest.raises(ValidationError):
        SoftwareFindParametersV1(schema_version="software_find_parameters_v1", name="CryptoPro", command="reg query")
    with pytest.raises(ValidationError):
        SoftwareFindParametersV1(schema_version="software_find_parameters_v1", name="x" * 129)


def test_software_fact_rejects_keys_and_install_paths() -> None:
    from endpoint_contracts.software_primitives import SoftwareFactV1

    safe = dict(name="CryptoPro", version="5.0", publisher="Vendor", source="windows_registry", architecture="x64")
    assert SoftwareFactV1.model_validate(safe).name == "CryptoPro"
    for private in ({"product_key": "secret"}, {"install_path": "C:\\secret"}, {"license_key": "secret"}):
        with pytest.raises(ValidationError):
            SoftwareFactV1.model_validate({**safe, **private})


def test_software_result_rejects_more_than_thirty_two_products() -> None:
    from datetime import UTC, datetime
    from endpoint_contracts.software_primitives import SoftwareFactV1, SoftwareListResultV1

    facts = [SoftwareFactV1(name=f"Product {index}", source="windows_registry") for index in range(33)]
    with pytest.raises(ValidationError):
        SoftwareListResultV1(
            schema_version="software_list_result_v1", software=facts,
            status="succeeded", collected_at=datetime.now(UTC),
        )


def test_software_catalog_group_is_default_disabled() -> None:
    from endpoint_contracts.capabilities import MODULE_CAPABILITY_REGISTRY

    for capability in ("software.list", "software.find"):
        assert MODULE_CAPABILITY_REGISTRY[capability].metadata.feature_flag == "endpoint_software_primitives_enabled"
