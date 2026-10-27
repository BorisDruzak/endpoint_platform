"""Native task notification with explicit actions, only in the user's session."""
import ctypes
from ctypes import wintypes


def notify():
    import os
    if os.name != 'nt':
        raise OSError('Windows notification unavailable')
    session = wintypes.DWORD()
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    if not kernel.ProcessIdToSessionId(os.getpid(), ctypes.byref(session)) or session.value == 0:
        raise OSError('Interactive session required')
    class Button(ctypes.Structure):
        # CommCtrl.h wraps TASKDIALOG_BUTTON and TASKDIALOGCONFIG in pshpack1.
        # Default x64 ctypes alignment changes both the size and pointer offsets.
        _pack_ = 1
        _fields_ = [('id', ctypes.c_int), ('text', wintypes.LPCWSTR)]
    class Config(ctypes.Structure):
        _pack_ = 1
        _fields_ = [('size', wintypes.UINT), ('parent', wintypes.HWND), ('instance', wintypes.HINSTANCE),
            ('flags', wintypes.UINT), ('common', wintypes.UINT), ('title', wintypes.LPCWSTR),
            ('icon', ctypes.c_void_p), ('instruction', wintypes.LPCWSTR), ('content', wintypes.LPCWSTR),
            ('count', wintypes.UINT), ('buttons', ctypes.POINTER(Button)), ('default', ctypes.c_int),
            ('radio_count', wintypes.UINT), ('radios', ctypes.c_void_p), ('default_radio', ctypes.c_int),
            ('verification', wintypes.LPCWSTR), ('expanded', wintypes.LPCWSTR),
            ('expanded_control', wintypes.LPCWSTR), ('collapsed_control', wintypes.LPCWSTR),
            ('footer_icon', ctypes.c_void_p), ('footer', wintypes.LPCWSTR),
            ('callback', ctypes.c_void_p), ('callback_data', ctypes.c_ssize_t), ('width', wintypes.UINT)]
    buttons = (Button * 2)(Button(100, 'Указать причину'), Button(101, 'Позже'))
    config = Config(size=ctypes.sizeof(Config), flags=8, title='Рабочее время',
        instruction='Нужно пояснить период отсутствия',
        content='После возвращения за компьютер можно указать причину в личном кабинете.',
        count=2, buttons=buttons, default=101)
    selected = ctypes.c_int()
    dialog = ctypes.WinDLL('comctl32').TaskDialogIndirect
    dialog.argtypes = [ctypes.POINTER(Config), ctypes.POINTER(ctypes.c_int), ctypes.c_void_p, ctypes.c_void_p]
    dialog.restype = ctypes.c_long
    if dialog(ctypes.byref(config), ctypes.byref(selected), None, None) != 0:
        raise OSError('Windows notification unavailable')
    return {100: 'reason', 101: 'later'}.get(selected.value)
