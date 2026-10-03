"""Production folder resolution follows native machine configuration."""
import ctypes
from pathlib import Path
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import update_paths


@pytest.mark.parametrize('result,path',[(0,'relocated'),(1,''),(-2147467259,'C:/ignored'),(0,'')])
def test_invalid_native_folder_has_no_fallback(monkeypatch,result,path):
    def query(_window,_folder,_token,_flags,buffer):
        buffer.value=path
        return result
    monkeypatch.setattr(ctypes,'WinDLL',lambda *_a,**_kw:SimpleNamespace(SHGetFolderPathW=query),raising=False)
    with pytest.raises((OSError,ValueError)): update_paths.WindowsUpdatePaths.production()


def test_production_paths_use_relocated_native_roots(monkeypatch,tmp_path):
    roots={0x26:tmp_path/'relocated-programs',0x23:tmp_path/'relocated-data'}
    calls=[]
    def query(window,folder,token,flags,buffer):
        assert window is None and token is None and flags==0
        calls.append(folder);buffer.value=str(roots[folder]);return 0
    monkeypatch.setattr(ctypes,'WinDLL',lambda *_a,**_kw:SimpleNamespace(SHGetFolderPathW=query),raising=False)
    result=update_paths.WindowsUpdatePaths.production()
    assert result.install_root==roots[0x26]/'Endpoint Platform/Agent'
    assert result.pending_path==roots[0x23]/'Endpoint Platform/Agent/updates/pending_update.json'
    assert calls==[0x26,0x23]
    assert update_paths.WindowsUpdatePaths().install_root==update_paths.INSTALL_ROOT
