from endpoint_server.setup_updates.service import assign_setup,record_presence
from tests.server.test_setup_update_service import db,state,NOW


async def test_assignment_retains_initial_client_source_after_presence_changes(db,state):
    device,release,*_=state
    await record_presence(db,device.id,dict(client_version='1.0.5',ready=True,
        core_version='3.2.158',foundation_version='3.2.158'),now=NOW)
    job=await assign_setup(db,device.id,release.id,'Capture actual qualified source',
        actor='test-admin',request_id='source-snapshot',now=NOW)
    assert job.source_foundation_version=='3.2.158'
    assert job.source_core_version=='3.2.158'
    assert job.source_client_version=='1.0.5'
    await record_presence(db,device.id,dict(client_version='1.0.5',ready=True,
        core_version='3.2.169',foundation_version='3.2.169'),now=NOW)
    await db.refresh(job)
    assert (job.source_foundation_version,job.source_core_version,job.source_client_version)==('3.2.158','3.2.158','1.0.5')
