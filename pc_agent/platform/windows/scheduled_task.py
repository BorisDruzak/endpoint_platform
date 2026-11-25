"""Task Scheduler COM lookup with exact handling for an absent task."""


def find_task(folder, name):
    from pywintypes import com_error

    try:
        return folder.GetTask(name)
    except com_error as error:
        code = error.hresult
        # Late-bound IDispatch reports DISP_E_EXCEPTION with the actual
        # Scheduler error in EXCEPINFO.scode.
        if (code & 0xffffffff) == 0x80020009 and error.excepinfo:
            scode = error.excepinfo[-1]
            if isinstance(scode, int):
                code = scode
        if (code & 0xffffffff) != 0x80070002:
            raise
        return None
