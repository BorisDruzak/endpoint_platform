"""Additive migration roundtrip in the existing guarded disposable PG fixture."""
import asyncio
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address

import pytest
from alembic import command
from tests.server.test_update_postgresql import update_migration_database_urls, _alembic_config, _fetch

pytestmark = pytest.mark.usefixtures('preserve_migration_loggers')


def test_linux_enrollment_roundtrip_and_retained_authority_guard(update_migration_database_urls):
    url, plain = update_migration_database_urls
    config = _alembic_config(url)
    command.upgrade(config,'head')
    command.downgrade(config,'0049_linux_support_lifecycle')
    command.upgrade(config,'head')
    async def insert():
        from endpoint_server.db.session import AsyncSessionProvider
        from endpoint_server.installation_lifecycle.linux_sources import LinuxNativeRelease
        from endpoint_server.enrollment.linux_requests import build_linux_request
        from endpoint_server.enrollment.requests import CampaignSelection
        from endpoint_contracts.linux_enrollment import LinuxPreEnrollmentRequestCreateV1
        from tests.server.test_linux_enrollment_requests import body, source_data, PEPPER
        provider=AsyncSessionProvider(url)
        try:
            async with provider() as session:
                source=LinuxNativeRelease(**source_data(),signer_fingerprint='A'*40,frozen_manifest_sha256='c'*64,reviewed_by='fixture')
                session.add(source)
                await session.flush()
                request,binding=build_linux_request(LinuxPreEnrollmentRequestCreateV1.model_validate(body()),source_id=source.id,
                    selection=CampaignSelection('review_required',None,'NO_MATCHING_CAMPAIGN'),source_address=ip_address('127.0.0.1'),
                    pepper=PEPPER,now=datetime.now(UTC))
                session.add(request)
                await session.flush()
                session.add(binding)
                await session.commit()
        finally:
            await provider.close()
    asyncio.run(insert())
    with pytest.raises(RuntimeError,match='authority must be preserved'):
        command.downgrade(config,'0049_linux_support_lifecycle')
    assert asyncio.run(_fetch(plain,'SELECT count(*) AS count FROM linux_enrollment_bindings'))[0]['count']==1
