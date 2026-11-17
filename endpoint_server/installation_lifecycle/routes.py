from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from endpoint_contracts.installation_lifecycle import InstallationEventV1, InstallationEventAckV1
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.db.models import Device
from endpoint_server.updates.agent_routes import _authenticate_device, _revalidate_device_principal
from .models import InstallationEvent
from .service import accept_event, InstallationConflict, projection_data

router=APIRouter(tags=['installation-lifecycle'])


@router.post('/agent/v1/installation-events',response_model=InstallationEventAckV1,
    openapi_extra={'security':[{'AgentBearer':[]}]})
async def installation_event(body:InstallationEventV1,request:Request,response:Response):
    response.headers['Cache-Control']='no-store'
    async with request.app.state.session_provider() as session:
        principal=await _authenticate_device(session,request)
        await _revalidate_device_principal(session,request,principal)
        try:
            ack=await accept_event(session,principal,body,request_id=audit_request_id(request))
        except InstallationConflict as error:
            raise HTTPException(409,str(error)) from None
        except IntegrityError:
            await session.rollback()
            raise HTTPException(409,"Event conflicts with the committed stream") from None
        await _revalidate_device_principal(session,request,principal)
        await session.commit()
        return ack


@router.get('/api/admin/console/devices/{device_id}/installation-events')
async def installation_history(device_id:UUID,request:Request,response:Response,
    _:Annotated[AdminPrincipal,Depends(require_admin)],limit:int=Query(50,ge=1,le=100),offset:int=Query(0,ge=0,le=100000)):
    response.headers['Cache-Control']='no-store'
    async with request.app.state.session_provider() as session:
        if await session.get(Device,device_id) is None:
            raise HTTPException(404,'Device not found')
        rows=(await session.scalars(select(InstallationEvent).where(InstallationEvent.device_id==device_id)
            .order_by(InstallationEvent.sequence.desc()).offset(offset).limit(limit+1))).all()
        return {'installation':await projection_data(session,device_id,include_parent=True),
            'data':[{'event':row.payload,'acknowledgement':row.acknowledgement} for row in rows[:limit]],
            'limit':limit,'offset':offset,'has_more':len(rows)>limit}
