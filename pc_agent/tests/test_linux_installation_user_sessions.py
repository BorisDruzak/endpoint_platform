import pytest
from pathlib import Path
from pc_agent.tests.test_linux_installation_lifecycle import MemoryStore


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


@pytest.mark.parametrize('manager_unloaded', [False, True])
def test_owned_stop_remove_reinstall_resumes_same_disabled_session_once(monkeypatch, manager_unloaded):
    from pc_agent.platform.linux import installation_user_sessions as s
    store = MemoryStore()
    store.data['state.json'] = {'operation':{'id':'a'*32,'action':'remove'}}
    context = {'sid':'6','uid':1000,'session':{'TimestampMonotonic':'123','Leader':'321'},
        'environment':{'digest':'a'*64},'boot':'boot','prefix':['user-manager']}
    props = {'LoadState':'loaded','UnitFileState':'disabled','ActiveState':'active',
        'FragmentPath':'/usr/lib/systemd/user/endpoint-user-sensor.service','DropInPaths':'',
        'InactiveEnterTimestampMonotonic':'10'}
    monkeypatch.setattr(s,'session_ids',lambda: ['6'])
    monkeypatch.setattr(s,'session_context',lambda _: context.copy())
    monkeypatch.setattr(s,'unit_properties',lambda _: props.copy())
    calls = []
    def command(argv, **_):
        calls.append(argv)
        if 'stop' in argv:
            props.update(ActiveState='inactive',InactiveEnterTimestampMonotonic='20')
        if 'restart' in argv:
            props.update(ActiveState='active')
        return b''
    monkeypatch.setattr(s,'run',command)
    s.handoff_active_sensors(stop=True,store=store)
    assert props['ActiveState'] == 'inactive' and props['UnitFileState'] == 'disabled'
    # RPM removal/reinstall preserves the root receipt and the same user manager.
    store.data['receipt-'+'a'*32+'.json'] = {'action':'remove','exit_code':0,'settled':True,
        'event':{'action':'removed'}}
    if manager_unloaded:
        props['InactiveEnterTimestampMonotonic'] = '0'
    result = s.handoff_active_sensors(store=store)
    assert result[0]['status'] == 'resumed_owned_stop'
    assert props['ActiveState'] == 'active' and props['UnitFileState'] == 'disabled'
    assert not any('enable' in argv for argv in calls)
    assert store.data['sensor-handoff.json']['1000']['phase'] == 'consumed'


@pytest.mark.parametrize('change', ['session','environment','mask','unit','timestamp','unconfirmed_unload'])
def test_retained_stop_never_overrides_user_or_session_changes(monkeypatch, change):
    from pc_agent.platform.linux import installation_user_sessions as s
    store = MemoryStore()
    context = {'sid':'6','uid':1000,'session':{'TimestampMonotonic':'123'},
        'environment':{'digest':'a'},'boot':'boot','prefix':['user-manager']}
    props = {'LoadState':'loaded','UnitFileState':'disabled','ActiveState':'active',
        'FragmentPath':'/usr/lib/systemd/user/endpoint-user-sensor.service','DropInPaths':'',
        'InactiveEnterTimestampMonotonic':'10'}
    monkeypatch.setattr(s,'session_ids',lambda: ['6'])
    monkeypatch.setattr(s,'session_context',lambda _: context.copy())
    monkeypatch.setattr(s,'unit_properties',lambda _: props.copy())
    calls = []
    def command(argv, **_):
        calls.append(argv)
        if 'stop' in argv: props.update(ActiveState='inactive',InactiveEnterTimestampMonotonic='20')
        return b''
    monkeypatch.setattr(s,'run',command)
    s.handoff_active_sensors(stop=True,store=store)
    if change == 'session': context['session'] = {'TimestampMonotonic':'999'}
    if change == 'environment': context['environment'] = {'digest':'b'}
    if change == 'mask': props['UnitFileState'] = 'masked'
    if change == 'unit': props['FragmentPath'] = '/home/user/foreign.service'
    if change == 'timestamp': props['InactiveEnterTimestampMonotonic'] = '99'
    if change == 'unconfirmed_unload': props['InactiveEnterTimestampMonotonic'] = '0'
    s.handoff_active_sensors(store=store)
    assert not any('restart' in argv for argv in calls)


def test_missing_optional_environment_and_vanished_session_are_bounded_skips(monkeypatch, tmp_path):
    from pc_agent.platform.linux import installation_user_sessions as s
    assert s.read_session_environment(tmp_path, 1000) is None
    monkeypatch.setattr(s,'session_ids',lambda: ['6','7'])
    monkeypatch.setattr(s,'session_context',lambda sid: None)
    assert s.handoff_active_sensors() == [
        {'session':'6','status':'session_prerequisite_absent'},
        {'session':'7','status':'session_prerequisite_absent'}]


def test_session_vanishes_during_user_manager_handoff_without_machine_failure(monkeypatch):
    from pc_agent.platform.linux import installation_user_sessions as s
    from tools.release.linux_native_verifier import VerificationError
    context = {'sid':'6','uid':1000,'prefix':['user-manager']}
    monkeypatch.setattr(s,'session_ids',lambda:['6'])
    monkeypatch.setattr(s,'session_context',lambda _:context)
    monkeypatch.setattr(s,'unit_properties',lambda _: {'LoadState':'loaded',
        'FragmentPath':'/usr/lib/systemd/user/endpoint-user-sensor.service',
        'DropInPaths':'','UnitFileState':'disabled','ActiveState':'active'})
    def vanished(*_, **kwargs):
        monkeypatch.setattr(s,'session_context',lambda _:None)
        raise VerificationError('native_tool_failed')
    monkeypatch.setattr(s,'run',vanished)
    assert s.handoff_active_sensors() == [{'session':'6','status':'session_vanished'}]
