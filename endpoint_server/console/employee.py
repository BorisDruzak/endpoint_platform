"""Public employee sign-in shell; personnel and DLP APIs own their authority."""
from fastapi import APIRouter, HTTPException, Request
from endpoint_server.console.routes import _index

router = APIRouter(tags=['employee-portal'])


@router.get('/employee',include_in_schema=False)
@router.get('/employee/{path:path}',include_in_schema=False)
@router.get('/dlp',include_in_schema=False)
@router.get('/dlp/{path:path}',include_in_schema=False)
async def employee_shell(request: Request,path: str=''):
    if not request.app.state.settings.oidc.enabled:
        raise HTTPException(404,'Employee portal unavailable')
    return _index()
