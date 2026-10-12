"""Device catalog published contract agrees with the service route."""
from pathlib import Path
import json


def test_device_modules_schema_is_published():
    path = Path("contracts/jsonschema/endpoint-device-modules-v1.json")
    assert path.exists(), "device-scoped published discovery needs a public schema"
    schema = json.loads(path.read_text(encoding="utf-8"))
    assert schema["properties"]["schema_version"]["const"] == "endpoint_device_modules_v1"
    assert schema["additionalProperties"] is False
