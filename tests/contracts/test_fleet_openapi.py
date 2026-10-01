from tools.contracts.generate_contract_artifacts import _service_operation_openapi


def test_fleet_is_in_published_contract_with_both_scopes():
    operation = _service_operation_openapi()["paths"]["/api/v1/devices/context-summary"]["get"]
    assert operation["x-required-scopes"] == ["devices.read", "context.read"]
    assert operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith("ServiceFleetResponse")
    assert "503" in operation["responses"]
