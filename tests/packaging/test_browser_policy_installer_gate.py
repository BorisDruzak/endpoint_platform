"""Privileged browser policy starts only after authenticated installer finish."""
from pathlib import Path
import xml.etree.ElementTree as ET


def test_native_browser_service_is_disabled_and_has_no_start_action():
    root=ET.parse(Path(__file__).resolve().parents[2]/'packaging/windows/wix/Services.wxs').getroot()
    ns={'w':'http://wixtoolset.org/schemas/v4/wxs'}
    service=root.find(".//w:ServiceInstall[@Name='EndpointBrowserPolicy']",ns)
    control=root.find(".//w:ServiceControl[@Name='EndpointBrowserPolicy']",ns)
    assert service is not None and service.attrib['Start']=='disabled'
    assert control is not None and 'Start' not in control.attrib
