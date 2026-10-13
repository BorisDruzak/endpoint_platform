"""Exercise EXE preflight arguments through the native MSI formatter after costing."""
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import re
import shutil
import subprocess
import uuid
import xml.etree.ElementTree as ET

import pytest

ROOT = Path(__file__).resolve().parents[2]
NS = "http://wixtoolset.org/schemas/v4/wxs"


@pytest.mark.skipif(os.name != "nt", reason="native Windows Installer costing and formatting")
@pytest.mark.parametrize("remove", [False, True])
def test_preflight_receives_native_feature_states(tmp_path, remove):
    wix = shutil.which("wix") or str(Path.home() / ".dotnet/tools/wix.exe")
    if not Path(wix).is_file():
        pytest.skip("WiX compiler unavailable")
    authored = ET.parse(ROOT / "packaging/windows/wix/Services.wxs")
    actions = authored.findall(f".//{{{NS}}}CustomAction")
    preflight = next(a for a in actions if a.get("Id") == "InstallerOwnerPreflight")
    capture = [a for a in actions if a.get("Id", "").startswith(("Reset", "Capture"))]
    sequence = authored.findall(f".//{{{NS}}}Custom")
    source = ET.Element(f"{{{NS}}}Wix")
    package = ET.SubElement(source, f"{{{NS}}}Package", {
        "Name": "Native feature formatting fixture", "Manufacturer": "Test",
        "Version": "0.0.1", "UpgradeCode": str(uuid.uuid4()), "Scope": "perMachine"})
    ET.SubElement(package, f"{{{NS}}}MediaTemplate", {"EmbedCab": "yes"})
    directory = ET.SubElement(package, f"{{{NS}}}StandardDirectory", {"Id": "ProgramFiles64Folder"})
    for index, feature in enumerate(("EndpointAgentFeature", "EndpointAgentInitialRuntimeFeature")):
        payload = tmp_path / f"dummy{index}.txt"
        payload.write_text("Never install this fixture")
        component = ET.SubElement(directory, f"{{{NS}}}Component", {"Id": f"Dummy{index}", "Guid": str(uuid.uuid4())})
        ET.SubElement(component, f"{{{NS}}}File", {"Id": f"DummyFile{index}", "Source": str(payload)})
        node = ET.SubElement(package, f"{{{NS}}}Feature", {"Id": feature, "Level": "1"})
        ET.SubElement(node, f"{{{NS}}}ComponentRef", {"Id": f"Dummy{index}"})
    install_sequence = ET.SubElement(package, f"{{{NS}}}InstallExecuteSequence")
    previous = "CostFinalize"
    for action in capture:
        package.append(action)
        scheduled = next(s for s in sequence if s.get("Action") == action.get("Id"))
        attributes = {"Action": action.get("Id"), "After": previous}
        if scheduled.get("Condition"):
            attributes["Condition"] = scheduled.get("Condition")
        ET.SubElement(install_sequence, f"{{{NS}}}Custom", attributes)
        previous = action.get("Id")
    wxs, msi = tmp_path / "fixture.wxs", tmp_path / "fixture.msi"
    ET.ElementTree(source).write(wxs, encoding="utf-8", xml_declaration=True)
    built = subprocess.run([wix, "build", "-arch", "x64", "-out", str(msi), str(wxs)],
                           capture_output=True, text=True, timeout=60)
    assert built.returncode == 0, built.stdout + built.stderr
    dll = ctypes.WinDLL("msi")
    def api(name, types, result=wintypes.UINT):
        fn = getattr(dll, name)
        fn.argtypes, fn.restype = types, result
        return fn
    session = wintypes.UINT()
    assert api("MsiOpenPackageExW", [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.UINT)])(
        str(msi), 1, ctypes.byref(session)) == 0
    close = api("MsiCloseHandle", [wintypes.UINT])
    try:
        if remove:
            assert api("MsiSetPropertyW", [wintypes.UINT, wintypes.LPCWSTR, wintypes.LPCWSTR])(
                session, "REMOVE", "ALL") == 0
        do = api("MsiDoActionW", [wintypes.UINT, wintypes.LPCWSTR])
        for name in ("CostInitialize", "FileCost", "CostFinalize"):
            assert do(session, name) == 0
        evaluate = api("MsiEvaluateConditionW", [wintypes.UINT, wintypes.LPCWSTR], ctypes.c_int)
        for action in capture:
            scheduled = next(s for s in sequence if s.get("Action") == action.get("Id"))
            condition = scheduled.get("Condition", "")
            # Attempt caller-supplied input; reset/capture must derive it anew.
            if action.get("Id").startswith("Reset"):
                assert api("MsiSetPropertyW", [wintypes.UINT, wintypes.LPCWSTR, wintypes.LPCWSTR])(
                    session, action.get("Property"), "3") == 0
            if not condition or evaluate(session, condition) == 1:
                assert do(session, action.get("Id")) == 0
        expected = []
        for feature in ("EndpointAgentFeature", "EndpointAgentInitialRuntimeFeature"):
            installed, target = ctypes.c_int(), ctypes.c_int()
            assert api("MsiGetFeatureStateW", [wintypes.UINT, wintypes.LPCWSTR,
                ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int)])(
                    session, feature, ctypes.byref(installed), ctypes.byref(target)) == 0
            expected.extend((installed.value, target.value))
        record = api("MsiCreateRecord", [wintypes.UINT])(0)
        try:
            assert api("MsiRecordSetStringW", [wintypes.UINT, wintypes.UINT, wintypes.LPCWSTR])(
                record, 0, preflight.get("ExeCommand")) == 0
            buffer, length = ctypes.create_unicode_buffer(4096), wintypes.DWORD(4096)
            assert api("MsiFormatRecordW", [wintypes.UINT, wintypes.UINT, wintypes.LPWSTR,
                ctypes.POINTER(wintypes.DWORD)])(session, record, buffer, ctypes.byref(length)) == 0
            observed = re.findall(r'--(?:foundation|runtime)-(?:state|action) "([^"]*)"', buffer.value)
            assert observed == list(map(str, expected)), buffer.value
        finally:
            close(record)
    finally:
        close(session)
