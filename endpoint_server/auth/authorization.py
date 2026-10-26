"""Explicit personnel grants; technical administration grants no personnel access."""
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from endpoint_server.db.models.identity import ConfirmedIdentity, ScopedRoleGrant
from endpoint_server.auth.employee_sessions import require_privileged_assurance


async def authorize_person(session, principal, person_id: UUID, action: str) -> ConfirmedIdentity:
    target = await session.scalar(select(ConfirmedIdentity).where(ConfirmedIdentity.person_id == person_id, ConfirmedIdentity.state == 'active', ConfirmedIdentity.revoked_at.is_(None)))
    if target is None or principal.identity.state != 'active' or principal.identity.revoked_at is not None:
        raise HTTPException(403, 'Personnel permission required')
    client=getattr(principal,'authority_client',None)
    if client is None:
        raise HTTPException(503,'Personnel identity authority unavailable')
    try:
        current=await client.resolve(target.issuer,target.subject,target.ad_object_guid)
        if current.person_id!=target.person_id:
            raise ValueError('Person binding changed')
        target.department_id=current.department_id
    except Exception:
        raise HTTPException(503,'Personnel identity authority unavailable') from None
    if action in {'worktime.read','worktime.write'} and principal.identity.person_id == person_id:
        return target
    require_privileged_assurance(principal)
    grants = (await session.scalars(select(ScopedRoleGrant).where(ScopedRoleGrant.identity_id == principal.identity.id, ScopedRoleGrant.revoked_at.is_(None)))).all()
    allowed = {
        'manager': {'worktime.read','worktime.approve'},
        'hr': {'worktime.read','worktime.write','worktime.approve','worktime.hr'},
        'worktime_admin': {'worktime.read','worktime.write','worktime.approve','worktime.hr','worktime.admin'},
    }
    for grant in grants:
        if grant.revoked_at is not None or action not in allowed.get(grant.role, set()):
            continue
        if grant.role == 'manager' and grant.department_id is None:
            continue
        if grant.department_id is None or grant.department_id == target.department_id:
            if action == 'worktime.approve' and principal.identity.person_id == person_id:
                continue
            return target
    raise HTTPException(403, 'Personnel permission required')
