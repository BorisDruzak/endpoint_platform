"""Read-only platform discovery from the same canonical admission evidence."""
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from endpoint_contracts.support_console import SupportPlatform
from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.db.models import Device
from .models import SupportAccess
from .platforms import verified_platform
from sqlalchemy import select

router = APIRouter(prefix='/api/admin/support-access', tags=['admin-support-access'])


@router.get('/devices/{device_id}/platform', response_model=SupportPlatform)
async def platform(device_id: UUID, request: Request, response: Response,
                   _: Annotated[AdminPrincipal, Depends(require_admin)]):
    response.headers['Cache-Control'] = 'no-store'
    async with request.app.state.session_provider() as session:
        if await session.get(Device, device_id) is None:
            raise HTTPException(404, 'Device not found')
        value = await verified_platform(session, device_id)
        registered = await session.scalar(select(SupportAccess.platform).where(SupportAccess.device_id == device_id))
        if registered is not None and registered != value:
            value = None
        return SupportPlatform(device_id=device_id, platform=value)
