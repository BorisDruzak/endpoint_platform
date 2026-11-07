from fastapi import APIRouter, HTTPException, Request, Response
from sqlalchemy.exc import IntegrityError
from endpoint_contracts.linux_installation_lifecycle import LinuxInstallationEventV1 as InstallationEventV1
from endpoint_contracts.installation_lifecycle import InstallationEventAckV1
from endpoint_server.support_access.platforms import verified_platform,LINUX
from .linux_sources import resolve_linux_source
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.updates.agent_routes import _authenticate_device, _revalidate_device_principal
from .service import accept_event, InstallationConflict

router=APIRouter(tags=['installation-lifecycle'])


@router.post('/agent/v1/installation/linux/events',response_model=InstallationEventAckV1,
    openapi_extra={'security':[{'AgentBearer':[]}]})
async def installation_event(body:InstallationEventV1,request:Request,response:Response):
    response.headers['Cache-Control']='no-store'
    async with request.app.state.session_provider() as session:
        principal=await _authenticate_device(session,request)
        await _revalidate_device_principal(session,request,principal)
        if await verified_platform(session,principal.device.id)!=LINUX:
            raise HTTPException(409,'Verified Linux platform unavailable')
        try:
            ack=await accept_event(session,principal,body,request_id=audit_request_id(request),source_resolver=resolve_linux_source)
        except InstallationConflict as error:
            raise HTTPException(409,str(error)) from None
        except IntegrityError:
            await session.rollback()
            raise HTTPException(409,"Event conflicts with the committed stream") from None
        await _revalidate_device_principal(session,request,principal)
        await session.commit()
        return ack
