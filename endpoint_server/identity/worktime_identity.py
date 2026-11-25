"""Serialize one canonical person across local handoff and verified AD adoption."""
from datetime import UTC, datetime
from sqlalchemy import select, text
from fastapi import HTTPException
from endpoint_server.db.models.identity import ConfirmedIdentity


async def lock_person_identity(session,person_id):
    await session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key,0))"),{'key':'worktime-person:'+str(person_id)})


async def local_worktime_identity(session,verified,issuer):
    await lock_person_identity(session,verified.person_id)
    identity=await session.scalar(select(ConfirmedIdentity).where(ConfirmedIdentity.person_id==verified.person_id).with_for_update())
    if identity is None:
        identity=ConfirmedIdentity(person_id=verified.person_id,department_id=verified.department_id,issuer=issuer,
            subject=str(verified.person_id),authority_kind='helpdesk',ad_object_guid=None,state='active',confirmed_at=datetime.now(UTC))
        session.add(identity);await session.flush()
    if identity.state!='active' or identity.revoked_at is not None:raise HTTPException(401,'Employee identity inactive')
    if identity.authority_kind=='helpdesk' and (identity.issuer!=issuer or identity.subject!=str(verified.person_id)):
        raise HTTPException(401,'Employee identity mismatch')
    identity.department_id=verified.department_id
    return identity
