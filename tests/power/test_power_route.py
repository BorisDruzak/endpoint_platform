from uuid import uuid4
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from endpoint_server.auth.admin_sessions import require_admin
from endpoint_server.power.routes import router
from endpoint_server.db.models import DeviceInstance, DeviceSession
from .test_power_provider import db as db, batch, event, send_batch


async def test_power_route_auth_cache_pagination_and_missing_device(db):
    async with db[0].kw["bind"].begin() as connection:
        await connection.run_sync(
            lambda sync: [
                t.create(sync)
                for t in (DeviceInstance.__table__, DeviceSession.__table__)
            ]
        )
    app = FastAPI()
    app.include_router(router)
    app.state.session_provider = db[0]
    # Actual require_admin rejects an unauthenticated request before reading evidence.
    app.state.settings = type(
        "Settings", (), {"allowed_admin_cidrs": (), "trusted_proxy_cidrs": ()}
    )()
    await send_batch(db, batch([event()]))
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        path = f"/api/admin/console/devices/{db[1]}/power"
        assert (await client.get(path)).status_code == 401
        app.dependency_overrides[require_admin] = lambda: object()
        result = await client.get(path + "?limit=1")
        assert result.status_code == 200, result.text
        assert result.headers["Cache-Control"] == "no-store"
        assert result.json()["total"] == 1 and len(result.json()["data"]) == 1
        assert (await client.get(path + "?offset=1")).json()["data"] == []
        assert (await client.get(path + "?limit=101")).status_code == 422
        assert (
            await client.get(f"/api/admin/console/devices/{uuid4()}/power")
        ).status_code == 404
    app.dependency_overrides.clear()
    assert any(
        d.call is require_admin
        for route in app.routes
        if hasattr(route, "dependant")
        for d in route.dependant.dependencies
    )
