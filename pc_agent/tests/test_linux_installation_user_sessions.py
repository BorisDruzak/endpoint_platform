import pytest


def test_only_existing_active_graphical_user_session_is_eligible():
    from pc_agent.platform.linux.installation_user_sessions import session_uid
    good = {'Active':'yes','Remote':'no','Class':'user','Type':'x11','User':'1000','State':'active'}
    assert session_uid(good) == 1000
    for changes in ({'Remote':'yes'}, {'Class':'greeter'}, {'Type':'tty'}, {'User':'0'}, {'Active':'no'}, {'State':'closing'}, {'User':'1000;id'}):
        assert session_uid(good | changes) is None


def test_active_autostart_sensor_handoff_preserves_disabled_boot_policy():
    from pc_agent.platform.linux.installation_user_sessions import eligible_owned_unit
    properties = {'LoadState':'loaded','UnitFileState':'disabled','ActiveState':'active',
        'FragmentPath':'/usr/lib/systemd/user/endpoint-user-sensor.service','DropInPaths':''}
    assert eligible_owned_unit(properties)
    assert not eligible_owned_unit(properties | {'ActiveState':'inactive'})
    assert not eligible_owned_unit(properties | {'UnitFileState':'masked'})
    assert not eligible_owned_unit(properties | {'DropInPaths':'/home/user/override.conf'})
    assert not eligible_owned_unit(properties | {'FragmentPath':'/home/user/foreign.service'})
