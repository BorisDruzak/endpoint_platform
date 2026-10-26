"""Validate the exact CommCtrl.h pshpack1 ABI before calling native UI."""
import ctypes
import os
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import worktime_notification


@pytest.mark.skipif(os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8,
                    reason='Windows SDK x64 ABI')
@pytest.mark.parametrize('selection,action',[(100,'reason'),(101,'later')])
def test_native_notification_uses_packed_sdk_layout_and_action_ids(monkeypatch,selection,action):
    calls=[]
    def process_session(pid, pointer):
        pointer._obj.value=1
        return 1
    def task_dialog(config_pointer, selected_pointer, radio_pointer, verification_pointer):
        config=config_pointer._obj
        config_type=type(config)
        button_type=config_type._fields_[10][1]._type_
        assert ctypes.sizeof(button_type)==12
        assert button_type.id.offset==0 and button_type.text.offset==4
        assert ctypes.sizeof(config_type)==160
        assert config.size==160
        expected_offsets={'parent':4,'instance':12,'title':28,'icon':36,'instruction':44,
            'content':52,'count':60,'buttons':64,'default':72,'radios':80,
            'verification':92,'footer':132,'callback':140,'callback_data':148,'width':156}
        for name,offset in expected_offsets.items():
            assert getattr(config_type,name).offset==offset,(name,getattr(config_type,name).offset)
        assert config.count==2
        assert [(config.buttons[index].id,config.buttons[index].text) for index in range(2)]==[
            (100,'Указать причину'),(101,'Позже')]
        selected_pointer._obj.value=selection
        calls.append(config)
        return 0
    monkeypatch.setattr(worktime_notification.ctypes,'WinDLL',lambda name,**kwargs:
        SimpleNamespace(ProcessIdToSessionId=process_session) if name=='kernel32'
        else SimpleNamespace(TaskDialogIndirect=task_dialog))
    assert worktime_notification.notify()==action
    assert len(calls)==1
