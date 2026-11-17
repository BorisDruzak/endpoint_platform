"""Read the source identity embedded by the reviewed native freeze workflow."""
import json
from pathlib import Path
import sys


def build_identity():
    if not getattr(sys, 'frozen', False):
        raise ValueError('frozen_native_build_required')
    value = json.loads((Path(sys._MEIPASS)/'linux-native-build.json').read_bytes())
    if value['schema_version'] != 'endpoint_linux_native_build_v1':
        raise ValueError('native_build_identity_invalid')
    return value
