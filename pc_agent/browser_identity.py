"""Read the pinned public extension identity shipped in this immutable Core."""
from pathlib import Path
import re
import sys


def load_packaged_extension_id() -> str:
    root = Path(sys._MEIPASS) if getattr(sys, 'frozen', False) else Path(__file__).resolve().parents[1]
    value = (root / 'browser_sensor/extension-id.txt').read_text(encoding='ascii').strip()
    if re.fullmatch(r'[a-p]{32}', value) is None:
        raise ValueError('invalid packaged Browser Sensor identity')
    return value
