"""Software list/find deduplicates fixed machine inventory safely."""

from __future__ import annotations

from endpoint_contracts.software_primitives import SoftwareFindParametersV1, SoftwareListParametersV1


def test_software_list_deduplicates_and_bounds_safe_fields() -> None:
    from pc_agent.primitives.software.handlers import software_list

    records = [
        {"name": "CryptoPro", "version": "5.0", "publisher": "Vendor", "source": "windows_registry", "architecture": "x64", "product_key": "secret", "install_path": "C:\\private"},
    ] * 50
    result = software_list(
        SoftwareListParametersV1(schema_version="software_list_parameters_v1"),
        query_inventory=lambda: records,
    )
    assert result.status == "succeeded"
    assert len(result.software) == 1
    assert "secret" not in str(result.model_dump(mode="json"))
    assert "private" not in str(result.model_dump(mode="json"))


def test_software_find_is_plain_case_insensitive_text() -> None:
    from pc_agent.primitives.software.handlers import software_find

    records = [
        {"name": "CryptoPro CSP", "version": "5.0", "source": "alt_rpm"},
        {"name": "Unrelated", "version": "1", "source": "alt_rpm"},
    ]
    result = software_find(
        SoftwareFindParametersV1(schema_version="software_find_parameters_v1", name="cryptopro"),
        query_inventory=lambda: records,
    )
    assert result.present
    assert [item.name for item in result.matches] == ["CryptoPro CSP"]


def test_software_list_caps_many_distinct_products() -> None:
    from pc_agent.primitives.software.handlers import software_list

    result = software_list(
        SoftwareListParametersV1(schema_version="software_list_parameters_v1"),
        query_inventory=lambda: [
            {"name": f"Product {index}", "version": "1", "source": "alt_rpm"}
            for index in range(100)
        ],
    )
    assert result.status == "succeeded"
    assert len(result.software) == 32
