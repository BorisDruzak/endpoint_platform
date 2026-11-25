"""Bounded, synchronous parsing of Windows System event metadata."""

import xml.etree.ElementTree as ET

_FIELDS = {
    "StartTime",
    "StopTime",
    "BootMode",
    "BootType",
    "TargetState",
    "EffectiveState",
    "WakeTime",
}
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def parse_event_xml(encoded):
    if len(encoded) > 65536:
        raise ValueError("native event exceeds bound")
    root = ET.fromstring(encoded)
    system = root.find("e:System", _NS)
    return {
        "provider": system.find("e:Provider", _NS).attrib["Name"],
        "event_id": int(system.find("e:EventID", _NS).text),
        "record_id": int(system.find("e:EventRecordID", _NS).text),
        "timestamp": system.find("e:TimeCreated", _NS).attrib["SystemTime"],
        "data": {
            row.attrib["Name"]: row.text
            for row in root.findall("e:EventData/e:Data", _NS)
            if row.attrib.get("Name") in _FIELDS
        },
    }
