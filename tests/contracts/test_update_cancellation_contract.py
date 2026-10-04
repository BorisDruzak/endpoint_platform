"""The admin cancellation contract has its own minimal generated boundary."""

from pathlib import Path

from fastapi import FastAPI
import yaml

from endpoint_server.updates.admin_routes import router
from tools.contracts.generate_contract_artifacts import render_artifacts

ROOT = Path(__file__).resolve().parents[2]
ADMIN = Path("contracts/openapi/endpoint-platform-admin-v1.yaml")
PATHS = {"/api/admin/updates/rollouts/{rollout_id}/cancellation-context",
    "/api/admin/updates/rollouts/{rollout_id}/cancel"}


def references(value):
    if isinstance(value, dict):
        if "$ref" in value: yield value["$ref"]
        for child in value.values(): yield from references(child)
    elif isinstance(value, list):
        for child in value: yield from references(child)


def test_admin_cancellation_openapi_matches_runtime_models_and_security():
    rendered = render_artifacts(ROOT)
    assert ADMIN in rendered
    published = yaml.safe_load(rendered[ADMIN])
    app = FastAPI()
    app.include_router(router)
    runtime = app.openapi()
    assert set(published["paths"]) == PATHS
    for path in PATHS:
        assert published["paths"][path] == runtime["paths"][path]
        operation = next(iter(published["paths"][path].values()))
        assert operation["security"] == [{"UpdateAdminCookie": []}]
        assert {"200", "401", "403", "404", "409", "422", "503"} <= set(operation["responses"])
    schemes = published["components"]["securitySchemes"]
    assert set(schemes) == {"UpdateAdminCookie"}
    assert schemes["UpdateAdminCookie"]["name"] == "endpoint_admin_session"
    assert schemes["UpdateAdminCookie"]["in"] == "cookie"
    post = published["paths"]["/api/admin/updates/rollouts/{rollout_id}/cancel"]["post"]
    assert any(p["name"] == "x-csrf-token" and p["in"] == "header" and p["required"] for p in post["parameters"])
    assert "updates:write" in post["description"]
    for ref in references(published):
        assert ref.startswith("#/components/schemas/")
        name = ref.rsplit("/", 1)[1]
        assert published["components"]["schemas"][name] == runtime["components"]["schemas"][name]
    assert "operation_id" not in published["components"]["schemas"]["UpdateRolloutCancellationContextV1"]["properties"]


def test_admin_cancellation_does_not_change_public_operation_cancel_contract():
    rendered = render_artifacts(ROOT)
    public = Path("contracts/openapi/endpoint-platform-v1.yaml")
    assert rendered[public].encode() == (ROOT / public).read_bytes()
    assert not set(yaml.safe_load(rendered[public])["paths"]) & PATHS
